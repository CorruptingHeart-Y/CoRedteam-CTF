from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import json
from datetime import datetime, timezone
from typing import Any

from agents.evaluator import run_evaluator
from agents.executor import run_executor
from agents.planner import run_planner
from agents.validator import run_validator
from control.hypothesis_tracker import HypothesisTracker, get_hypothesis_tracker
from core.challenge_adapter import ChallengeAdapter, get_adapter, list_adapters
from core.strategy_identity import (
    TRUSTED_SELECTION_FILENAME,
    build_trusted_selection,
    validate_plan_against_trusted_selection,
    write_trusted_selection,
)
from core.template_manager import TemplateManager
from core.llm_client import DeepSeekClient
from core.memory_store import LayeredMemory
from core.settings import get_settings
from core.target_context import TargetContext
from core.ui import (
    console,
    detail,
    fail,
    is_verbose,
    muted,
    ok,
    render_evaluator_feedback,
    render_iteration_header,
    render_summary_table,
    stage,
    warn,
)


def _print_agent_header(name: str) -> None:
    if is_verbose():
        console.print(f"[muted][agent:{name}] ----------------[/muted]")


def _list_json_files(folder: Path) -> list[str]:
    if not folder.exists() or not folder.is_dir():
        return []
    return sorted([p.name for p in folder.glob("*.json") if p.is_file()])


def _signal_observer_available(expected_signals: list) -> bool:
    """True only if this route has explicit expected_signals that can be checked."""
    return bool(expected_signals)


_SIGNAL_PRIMITIVE_ALIASES: dict[str, set[str]] = {
    "arithmetic_reflection_confirmed": {"ssti_reflection", "ssti_arithmetic", "template_arithmetic"},
    "template_directive_parsed": {"ssti_reflection", "ssti_arithmetic", "template_injection"},
    "object_access_confirmed": {"object_access", "java_object_access"},
    "command_execution_confirmed": {"command_execution", "rce", "runtime_exec"},
    "file_read_confirmed": {"arbitrary_file_read", "file_read"},
    "oob_callback_received": {"oob_callback", "oob_callback_received"},
}


def _signal_observer_confirm(expected_signals: list, stdout_text: str, evaluator_primitives: list) -> bool:
    """Check if any expected signal is confirmed. No generic keyword fallback."""
    if not expected_signals:
        return False
    stdout_lower = stdout_text.lower()
    detected_set = {str(p).lower() for p in (evaluator_primitives or [])}
    for sig in expected_signals:
        sig_key = str(sig).lower()
        sig_lower = sig_key.replace("_", " ")
        aliases = _SIGNAL_PRIMITIVE_ALIASES.get(sig_key, set())
        if sig_lower in stdout_lower or sig_key in detected_set or detected_set.intersection(aliases):
            return True
    # repro_success flag from evaluator is the only external confirmation
    return False


def _classify_observation(exec_out, fb, expected_signals=None):
    """Return (request_sent, observation_status, failure_class).

    Strict ordering:
      1. request_not_sent
      2. no observer contract → observation_unknown (never downgrade by summary)
      3. observer confirms signal → positive_evidence
      4. observer confirms signal absent → no_positive_evidence
    """
    expected_signals = list(expected_signals or [])
    step_results = exec_out.get("step_results") or []
    if not step_results:
        return False, "request_not_sent", None
    sent = False
    all_stdout = ""
    for r in step_results:
        http_resps = r.get("http_responses") or []
        if http_resps:
            sent = True
        rr = r.get("result") or {}
        all_stdout += str(rr.get("_stdout") or rr.get("stdout") or "") + " "
    if not sent:
        return False, "request_not_sent", None

    # ── Step 2: no observer → observation_unknown ──
    if not _signal_observer_available(expected_signals):
        return True, "observation_unknown", None

    # ── Step 3: observer confirms signal ──
    detected = fb.get("detected_primitives") or []
    if _signal_observer_confirm(expected_signals, all_stdout, detected):
        return True, "positive_evidence", None
    if fb.get("repro_success"):
        return True, "positive_evidence", None

    # ── Step 4: observer confirms signal absent ──
    return True, "no_positive_evidence", "expected_signal_missing"


def _compute_decision_fingerprint(exec_out, fb, selected_sid):
    """Produce a stable fingerprint for breaker/degradation tracking.
    Uses observation_status + canonical_id, NOT error keywords."""
    sent, obs, fail_cls = _classify_observation(exec_out, fb)
    if not sent:
        return f"request_not_sent::{selected_sid}"
    if obs == "positive_evidence":
        return f"positive::{selected_sid}"
    return f"{obs}::{fail_cls or 'unknown'}::{selected_sid}"


def should_record_strategy_attempt(exec_out: dict[str, Any]) -> bool:
    """Only real executor runs count as strategy attempts; infra/pre-gate failures do not."""
    if not exec_out.get("executed"):
        return False
    if exec_out.get("infra_failure") or exec_out.get("execution_mode") == "infra_failure":
        return False
    return bool(exec_out.get("step_results") or [])


def _record_strategy_attempt_if_executed(
    tracker: HypothesisTracker,
    selected_canonical_strategy_id: str,
    exec_out: dict[str, Any],
    feedback: dict[str, Any],
    round_number: int = 0,
    expected_signals: list | None = None,
    obs_decision: Any = None,
) -> None:
    if not selected_canonical_strategy_id or not should_record_strategy_attempt(exec_out):
        return
    # Prefer ObservationDecision when available (deterministic); fall back to legacy classifier
    if obs_decision is not None and hasattr(obs_decision, 'observation_status'):
        obs = obs_decision.observation_status
        fail_cls = obs_decision.failure_class
        sent = obs_decision.request_sent
    else:
        sent, obs, fail_cls = _classify_observation(exec_out, feedback, expected_signals=expected_signals)
    if obs == "request_not_sent":
        print(f"[coordinator] strategy attempt not recorded: request_not_sent for {selected_canonical_strategy_id}")
        return
    if obs == "observation_unknown":
        print(f"[coordinator] observation_unknown for {selected_canonical_strategy_id}: no evidence, no strategy update")
        return
    success = obs == "positive_evidence"
    failure_stage = "" if success else str(feedback.get("error_fingerprint") or "runtime_failure")
    evidence = str(feedback.get("summary") or feedback.get("feedback_for_planner") or "")[:300]
    # Dedup: if this exact outcome was already recorded this round for this strategy, skip
    tracker.record_attempt(
        selected_canonical_strategy_id,
        success=success,
        failure_stage=failure_stage,
        evidence=evidence,
        failure_class=fail_cls or "",
        round_number=round_number,
        outcome=obs,
    )


def evaluate_pre_execution_gate(
    plan: dict[str, Any],
    trusted_selection: dict[str, Any],
    tracker: HypothesisTracker,
) -> list[str]:
    """Return blocking reasons before Executor/Docker is allowed to start."""
    trusted_ok, trusted_errors = validate_plan_against_trusted_selection(plan, trusted_selection)
    pre_gate_errors = list(trusted_errors) if not trusted_ok else []
    selected_canonical_strategy_id = str(plan.get("selected_canonical_strategy_id") or "").strip()
    if selected_canonical_strategy_id:
        health = tracker.evaluate_strategy_health(selected_canonical_strategy_id)
        if health.decision in ("REJECT", "HARD_REJECT"):
            pre_gate_errors.append(
                f"STRATEGY_REJECTED: {selected_canonical_strategy_id} decision={health.decision}"
            )
    return pre_gate_errors


def _discover_form_method(target: TargetContext | None) -> str:
    """Lightweight HTML form discovery: GET root, parse form method."""
    if target is None:
        return ""
    import re, urllib.request, ssl
    url = target.url.rstrip("/") + "/"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, method="GET")
        resp = urllib.request.urlopen(req, timeout=5, context=ctx)
        body = resp.read(5000).decode("utf-8", errors="replace")
        m = re.search(r'<form[^>]+method\s*=\s*["\'](\w+)["\']', body, re.IGNORECASE)
        if m:
            print(f"[coordinator] preflight form method: {m.group(1).upper()}")
            return m.group(1).upper()
        m = re.search(r'<form[^>]+method\s*=\s*(\w+)', body, re.IGNORECASE)
        if m:
            print(f"[coordinator] preflight form method: {m.group(1).upper()}")
            return m.group(1).upper()
    except Exception as e:
        print(f"[coordinator] preflight failed: {e}")
    return ""


def _extract_injection_param(confirmed: dict[str, Any]) -> str:
    """Extract injection parameter name from confirmed_vuln source code."""
    import re
    vulns = confirmed.get("vulnerabilities", [])
    for v in vulns:
        source = v.get("source") if isinstance(v, dict) else None
        if isinstance(source, dict):
            code = str(source.get("code", ""))
        elif isinstance(source, str):
            code = source
        else:
            code = ""
        for pattern in [
            r'@RequestParam\s*\([^)]*name\s*=\s*"([^"]+)"',
            r'@RequestParam\s*\(\s*"([^"]+)"',
            r'(?:request|req)\.getParameter\s*\(\s*"([^"]+)"',
            r'\$_GET\s*\[\s*[\'"]([^\'"]+)[\'"]',
            r'\$_POST\s*\[\s*[\'"]([^\'"]+)[\'"]',
            r'\$_REQUEST\s*\[\s*[\'"]([^\'"]+)[\'"]',
        ]:
            m = re.search(pattern, code)
            if m:
                return m.group(1)
    return "text"


def _dry_run_return(
    ws: Path,
    feedback_path: Path,
    validation_passed: bool,
    validation_errors: list[str],
    selected_canonical_strategy_id: str,
    trusted_selection: dict[str, Any],
    extra_gate_errors: list[str] | None = None,
) -> dict[str, Any]:
    """Unified dry-run exit: write structured feedback; return immediately.
    Guarantees no Executor, Evaluator, attempt recording, or Consolidator."""
    pre_gate_errors = list(extra_gate_errors or [])
    if not validation_passed:
        pre_gate_errors = ["VALIDATOR_REJECTED"] + validation_errors
    fb = {
        "from": "coordinator_dry_run",
        "dry_run": True,
        "dry_run_gate_passed": not pre_gate_errors,
        "validator_passed": validation_passed,
        "selected_canonical_strategy_id": selected_canonical_strategy_id,
        "trusted_selection_status": trusted_selection.get("status"),
        "pre_gate_errors": pre_gate_errors,
        "executor_called": False,
        "evaluator_called": False,
        "attempt_recorded": False,
        "consolidator_called": False,
        "yaml_mutation": False,
    }
    feedback_path.write_text(json.dumps(fb, ensure_ascii=False, indent=2), encoding="utf-8")
    if fb["dry_run_gate_passed"]:
        ok("[dry-run] Planner→Validator→gate PASSED. Stopping before Executor.")
    else:
        warn(f"[dry-run] gate BLOCKED: {pre_gate_errors}")
    return {
        "status": "dry_run_complete",
        "workspace": str(ws),
        "feedback": fb,
    }


def _load_confirmed(path: Path) -> dict[str, Any]:
    target = path.expanduser().resolve()
    if target.is_dir():
        candidates = _list_json_files(target)
        raise FileNotFoundError(
            "你传入的是目录而不是文件。\n"
            f"当前路径: {target}\n"
            f"该目录下可用 JSON 文件: {candidates if candidates else '无'}\n"
            "请使用 --confirmed 指定具体 json 文件路径。"
        )

    if not target.exists():
        data_dir = _ROOT / "data"
        available = _list_json_files(data_dir)
        raise FileNotFoundError(
            "[!] 找不到漏洞报告，请先运行 Phase 1（python cli.py audit）\n"
            f"当前尝试路径: {path}\n"
            f"data 目录可用 JSON 文件: {available if available else '无'}"
        )

    confirmed = json.loads(target.read_text(encoding="utf-8"))

    if not confirmed.get("target_context") or not confirmed["target_context"].get("base_url"):
        fallback_context = _ROOT / "data" / "confirmed_vuln.json"
        if fallback_context.exists() and fallback_context.resolve() != target:
            try:
                fb = json.loads(fallback_context.read_text(encoding="utf-8"))
                fb_ctx = fb.get("target_context", {})
                fb_routes = fb.get("discovered_routes", fb_ctx.get("discovered_routes", []))
                if fb_ctx.get("base_url"):
                    confirmed["target_context"] = confirmed.get("target_context", {})
                    confirmed["target_context"]["base_url"] = fb_ctx["base_url"]
                    confirmed["target_context"]["app_name"] = confirmed["target_context"].get("app_name") or fb_ctx.get("app_name", "")
                    if fb_routes and not confirmed["target_context"].get("discovered_routes"):
                        confirmed["target_context"]["discovered_routes"] = fb_routes
                    print(f"[coordinator] ⚠️ 输入文件缺少 target_context，已从 {fallback_context.name} 自动补全")
            except Exception:
                pass

    return confirmed


def _override_base_url_from_env(confirmed: dict[str, Any]) -> dict[str, Any]:
    import os
    env_url = os.getenv("CO_REDTEAM_TARGET_BASE", "").strip()
    if not env_url:
        return confirmed
    tc = confirmed.get("target_context") or {}
    current = tc.get("base_url", "")
    if "host.docker.internal" in current or not current:
        tc["base_url"] = env_url
        confirmed["target_context"] = tc
        print(f"[coordinator] 🔒 CO_REDTEAM_TARGET_BASE 覆盖 base_url: {env_url}")
    return confirmed


def _count_execution_failures(exec_out: dict[str, Any]) -> dict[str, list[str]]:
    failures: dict[str, list[str]] = {"skipped": [], "error": [], "blocked": []}
    for r in exec_out.get("step_results") or []:
        rr = r.get("result") or {}
        if not rr.get("ok"):
            reason = rr.get("execution_mode", "unknown")
            step_id = str(r.get("step_id", "?"))
            purpose = r.get("purpose", "")
            detail = f"step[{step_id}]: {purpose} (mode={reason})"
            if reason == "skipped_syntax_error":
                failures["skipped"].append(detail)
            elif reason == "security_blocked":
                failures["blocked"].append(detail)
            else:
                failures["error"].append(detail)
    return failures


def _build_retry_prompt(failures: dict[str, list[str]], confirmed: dict[str, Any]) -> str:
    prompt = "【定向修复迭代】上一轮虽然整体成功，但以下步骤失败，需要修复后重试：\n"
    for category, items in failures.items():
        if items:
            prompt += f"\n[{category}]类失败：\n" + "\n".join(f"  - {item}" for item in items)
    prompt += (
        "\n\n请只针对上述失败步骤生成修复版计划。已经成功的漏洞无需再测。"
        "每个失败步骤生成 1-2 个修复变体，重点关注 payload 语法、URL 路径、参数格式等常见错误。"
    )
    return prompt


_HTTP_SEMANTIC_ERRORS = {
    "All fields are required!": (
        "请求格式或字段名不匹配！排查顺序："
        "1) 所有API使用 data= (form-encoded)，因为证据代码全是 request.form.get()"
        "2) 检查字段名：从证据代码中找 request.form.get('REAL_NAME') — 极可能不是 username！"
        "   Register/Login 需要 email+password，Profile 需要 email+fullName+username"
        "3) 如果上轮已试过 data= 和 json= 都失败，99%是字段名问题"
    ),
    "All fields are required": (
        "请求格式或字段名不匹配！排查顺序："
        "1) 所有API使用 data= (form-encoded)，因为证据代码全是 request.form.get()"
        "2) 检查字段名：从证据代码中找 request.form.get('REAL_NAME') — 极可能不是 username！"
        "   Register/Login 需要 email+password，Profile 需要 email+fullName+username"
        "3) 如果上轮已试过 data= 和 json= 都失败，99%是字段名问题"
    ),
    "Invalid Email Address": (
        "邮箱字段存在格式校验，SSTI/注入payload无法通过。"
        "应换用其他字段（username/fullName等）注入payload"
    ),
    "Unauthorised access detected!": (
        "认证未通过：首先确认上一步登录/注册是否真的200OK了，"
        "如果登录一直失败（All fields required），先修登录格式再管后续"
    ),
    "Method Not Allowed": (
        "HTTP方法错误：GET/POST混用。立即尝试另一种方法"
    ),
}


def _detect_http_failures_from_chain(
    step_results: list[dict[str, Any]],
    adapter: ChallengeAdapter | None = None,
) -> list[dict[str, Any]]:
    all_errors = dict(_HTTP_SEMANTIC_ERRORS)
    if adapter is not None:
        all_errors.update(adapter.http_semantic_errors())

    http_failures: list[dict[str, Any]] = []
    for r in step_results:
        rr = r.get("result") or {}
        if not rr.get("ok"):
            continue
        chain_output = r.get("chain_output")
        chain_str = ""
        if isinstance(chain_output, dict):
            chain_str = json.dumps(chain_output, ensure_ascii=False)
        stdout = rr.get("stdout") or ""
        search_text = f"{chain_str} {stdout}"
        for pattern, fix_hint in all_errors.items():
            if pattern in search_text:
                http_failures.append({
                    "step_id": r.get("step_id", "?"),
                    "purpose": r.get("purpose", ""),
                    "pattern": pattern,
                    "fix_hint": fix_hint,
                    "chain_output_snippet": search_text[:300],
                })
                break
    return http_failures


def _save_failure_lessons(
    memory: LayeredMemory,
    exec_out: dict[str, Any],
    last_plan: dict[str, Any],
    confirmed: dict[str, Any],
    adapter: ChallengeAdapter | None = None,
) -> None:
    step_results = exec_out.get("step_results") or []
    cwe_ids = []
    for v in confirmed.get("vulnerabilities", []):
        cwe = v.get("cwe_id", "")
        if cwe:
            cwe_ids.append(cwe)

    lesson_count = 0

    for r in step_results:
        rr = r.get("result") or {}
        if rr.get("ok"):
            continue
        stderr = (rr.get("stderr") or "")[:500]
        step_id = r.get("step_id", "?")
        purpose = r.get("purpose", "")

        if not stderr.strip():
            continue

        error_summary = ""
        if "Invalid URL" in stderr:
            error_summary = "URL格式错误：base变量未从 CO_REDTEAM_CONTEXT 动态读取，请检查代码中是否使用了硬编码域名。"
        elif "Connection refused" in stderr or "ConnectionError" in stderr:
            error_summary = "目标连接失败：请检查目标是否在运行以及端口是否正确。"
        elif "SSLError" in stderr or "CERTIFICATE" in stderr:
            error_summary = "SSL证书验证失败：HTTPS请求必须使用 verify=False (Python) 或 -k (curl)。"
        elif "SyntaxError" in stderr or "NameError" in stderr or "IndentationError" in stderr:
            error_summary = "Python语法错误：单行代码使用了def/for/if等需要缩进的语句，请用lambda/列表推导替代。"
        elif "KeyError" in stderr:
            error_summary = "JSON字段不存在：从CO_REDTEAM_CONTEXT提取数据时键名错误，检查cookies/token字段名。"
        elif "401" in stderr or "Unauthorized" in stderr:
            error_summary = "认证失败(401)：session或token未正确传递，请在前一步输出正确的cookies信息。"
        elif "404" in stderr or "Not Found" in stderr:
            error_summary = "端点不存在(404)：URL路径错误，请从已知endpoint列表中选择正确路径。"
        elif "500" in stderr or "Internal Server" in stderr:
            error_summary = "服务器内部错误(500)：payload可能触发但未正确利用，检查payload格式。"
        else:
            error_summary = f"步骤失败(step={step_id}): {stderr[:200]}"

        lesson = (
            f"[RCW-{','.join(cwe_ids[:3])}] {error_summary} "
            f"目的: {purpose[:100]}. "
            f"stderr片段: {stderr[:300]}"
        )
        memory.upsert_strategy(lesson, "failure", {
            "cwe_ids": cwe_ids,
            "step_id": step_id,
            "from": "auto-failure-logger",
        })
        lesson_count += 1

    http_failures = _detect_http_failures_from_chain(step_results, adapter=adapter)
    for hf in http_failures:
        lesson = (
            f"[RCW-{','.join(cwe_ids[:3])}] HTTP语义错误(step={hf['step_id']}): {hf['pattern']}. "
            f"修复: {hf['fix_hint']}. "
            f"目的: {hf['purpose'][:100]}. "
            f"响应片段: {hf['chain_output_snippet'][:300]}"
        )
        memory.upsert_strategy(lesson, "failure", {
            "cwe_ids": cwe_ids,
            "step_id": hf["step_id"],
            "from": "auto-http-semantic-detector",
        })
        lesson_count += 1

    if lesson_count > 0:
        print(f"[coordinator] �� 已自动记录 {lesson_count} 条失败教训到长期记忆")


def _build_breaker_memory_context(
    memory: LayeredMemory,
    vuln_summary: str,
    confirmed: dict[str, Any],
) -> str:
    """
    查询长期记忆三个层次，构建注入到 Planner 的历史经验上下文。
    论文 Co-RedTeam §3.4：长期记忆通过 ChromaDB 向量检索，为 Planner 提供
    相似漏洞的成功/失败经验，避免重蹈覆辙。
    """
    cwe_ids = [
        v.get("cwe_id", "")
        for v in confirmed.get("vulnerabilities", [])
        if v.get("cwe_id")
    ]
    query = f"{vuln_summary} {' '.join(cwe_ids)} 漏洞利用 攻击策略 payload"
    parts: list[str] = []

    # ── 漏洞模式层 ────────────────────────────────
    try:
        patterns = memory.query_patterns(query, n_results=3)
        if patterns:
            parts.append("\n【�� 长期记忆 — 相关漏洞模式】：")
            for i, item in enumerate(patterns):
                parts.append(f"  模式{i + 1}: {item['content']}")
    except Exception:
        pass

    # ── 利用策略层（成功 / 失败分开展示）──────────────
    try:
        strategies = memory.query_strategies(query, n_results=6)
        if strategies:
            success_items = [
                s for s in strategies
                if s.get("metadata", {}).get("strategy_type") != "failure"
            ]
            failure_items = [
                s for s in strategies
                if s.get("metadata", {}).get("strategy_type") == "failure"
            ]
            if success_items:
                parts.append("\n【✅ 长期记忆 — 历史成功策略】：")
                for i, item in enumerate(success_items[:3]):
                    parts.append(f"  成功策略{i + 1}: {item['content']}")
            if failure_items:
                parts.append("\n【❌ 长期记忆 — 已知失败教训（禁止重蹈覆辙）】：")
                for i, item in enumerate(failure_items[:3]):
                    parts.append(f"  失败教训{i + 1}: {item['content']}")
    except Exception:
        pass

    # ── 技术操作层 ────────────────────────────────
    try:
        tech = memory.query_tech_payloads(query, n_results=8)
        if tech:
            parts.append("\n【长期记忆 — 可复用 Payload / 命令 / 脚本】：")
            _payload_seen_coord: set[str] = set()
            for i, item in enumerate(tech):
                payload = item.get("payload") or ""
                cmd = item.get("command") or ""
                script = item.get("script") or ""
                meta = item.get("metadata", {})
                name = meta.get("name", "") or meta.get("context", "") or ""
                source = meta.get("source", "")
                source_tag = f" [来源:{source}]" if source else ""

                if payload and payload not in _payload_seen_coord:
                    _payload_seen_coord.add(payload)
                    parts.append(f"  Payload({name}){source_tag}: {payload[:400]}")
                elif cmd and cmd not in _payload_seen_coord:
                    _payload_seen_coord.add(cmd)
                    parts.append(f"  Command{source_tag}: {cmd[:300]}")
                elif script and script not in _payload_seen_coord:
                    _payload_seen_coord.add(script)
                    parts.append(f"  Script({name}):\n{script[:600]}")
                else:
                    parts.append(f"  {item['content'][:250]}")
    except Exception:
        pass

    if not parts:
        return ""
    return "\n" + "\n".join(parts)


def _extract_step_error_fingerprint(step_results: list[dict[str, Any]]) -> str:
    """Produce a short fingerprint of the dominant failure pattern.

    Checks both failed steps AND successful steps with no positive evidence.
    HTTP 200 + no reflection → "http_ok_no_reflection" (triggers stagnation).
    """
    error_tokens: list[str] = []
    for r in step_results:
        rr = r.get("result") or {}
        stderr = (rr.get("stderr") or "")[:300]
        stdout = (rr.get("_stdout") or rr.get("stdout") or "")[:500]
        if not rr.get("ok"):
            text = f"{stderr} {stdout}"
            for keyword in (
                "Invalid URL", "ConnectionError", "Connection refused",
                "SSLError", "SyntaxError", "NameError", "IndentationError",
                "KeyError", "401", "403", "404", "405", "500",
                "All fields are required", "Invalid Email",
                "CSRF Detected", "Unauthorised",
                "security_blocked", "skipped_syntax_error",
                "STEP_FAIL",
            ):
                if keyword in text:
                    error_tokens.append(keyword)
                    break
            else:
                error_tokens.append("unknown_error")
        else:
            # ok=True: check for silent non-reflection
            has_http = any(kw in stdout.lower() for kw in ("[http]", "<!doctype", "<html"))
            has_signal = any(kw in stdout.lower() for kw in ("49", "uid=", "root:", "flag{", "step_ok"))
            if has_http and not has_signal:
                error_tokens.append("http_ok_no_reflection")
    return "|".join(sorted(set(error_tokens))) or "no_failures"


class _VulnRotator:
    """Tracks which vulnerabilities have been attempted and rotates to the next one.

    When a vuln is declared fully BLOCKED (all steps BLOCKED in the plan), the
    rotator advances to the next unblocked vuln in confirmed["vulnerabilities"].
    The coordinator calls `rotate()` to get a modified `confirmed` dict that
    focuses on the next candidate.
    """

    def __init__(self, confirmed: dict[str, Any]) -> None:
        self._original = confirmed
        vulns = confirmed.get("vulnerabilities") or []
        self._vuln_ids: list[str] = [v.get("id", str(i)) for i, v in enumerate(vulns)]
        self._attempted: set[str] = set()
        self._current_idx: int = 0

    def mark_attempted(self, vuln_id: str) -> None:
        self._attempted.add(vuln_id)

    def current_vuln_id(self) -> str:
        vulns = self._original.get("vulnerabilities") or []
        if self._current_idx < len(vulns):
            return vulns[self._current_idx].get("id", str(self._current_idx))
        return ""

    def rotate(self) -> tuple[dict[str, Any], str] | None:
        """Return (new_confirmed_focused_on_next_vuln, vuln_id) or None if exhausted."""
        vulns = self._original.get("vulnerabilities") or []
        for i, v in enumerate(vulns):
            vid = v.get("id", str(i))
            if vid not in self._attempted:
                self._current_idx = i
                self._attempted.add(vid)
                # Build a focused confirmed dict with only this vuln
                import copy
                focused = copy.deepcopy(self._original)
                focused["vulnerabilities"] = [v]
                focused["_rotated_from"] = self.current_vuln_id()
                focused["_rotation_note"] = (
                    f"攻击面轮换：已跳过 {sorted(self._attempted - {vid})}，"
                    f"当前聚焦漏洞 {vid} ({v.get('title', '?')})"
                )
                return focused, vid
        return None

    def all_attempted(self) -> bool:
        vulns = self._original.get("vulnerabilities") or []
        return all(
            v.get("id", str(i)) in self._attempted
            for i, v in enumerate(vulns)
        )


def _is_plan_fully_blocked(plan: dict[str, Any]) -> bool:
    """Return True if every step in the plan has status BLOCKED."""
    steps = plan.get("steps") or []
    if not steps:
        return False
    return all(
        isinstance(st, dict) and st.get("status") == "BLOCKED"
        for st in steps
    )


def _cleanup_sandbox_workspace(ws: Path) -> None:
    """迭代上限到达后清理工作区临时文件（Docker 容器已由 executor 自动清理）。"""
    import shutil
    tmp_dirs = [ws / "tmp", ws / "__pycache__"]
    for d in tmp_dirs:
        if d.exists():
            try:
                shutil.rmtree(d, ignore_errors=True)
                print(f"[coordinator] �� 已清理临时目录: {d.name}")
            except Exception:
                pass
    # 清理步骤脚本文件
    for f in ws.glob("step_*.py"):
        try:
            f.unlink()
        except Exception:
            pass


def run_pipeline(
    confirmed_path: Path | None = None,
    challenge_name: str = "generic",
    target: TargetContext | None = None,
) -> int:
    settings = get_settings()
    memory = LayeredMemory(settings.memory_dir)
    ws = settings.workspace_dir
    ws.mkdir(parents=True, exist_ok=True)

    import core.adapters  # noqa: F401  trigger adapter registration
    adapter = get_adapter(challenge_name)
    stage("CLI", f"挑战适配器: [bold]{adapter.challenge_name}[/bold]")

    confirmed_file = confirmed_path or settings.confirmed_vuln_path
    confirmed = _load_confirmed(confirmed_file)

    # ── 兜底：用环境变量覆盖 JSON 中残留的 host.docker.internal ──
    confirmed = _override_base_url_from_env(confirmed)

    if target is not None:
        tc = confirmed.setdefault("target_context", {})
        tc["base_url"] = target.url
        tc["locked_host"] = target.hostname
        tc["locked_ip"] = target.ip
        tc["locked_port"] = target.port
        stage("CLI", f"目标白名单已锁定 → [bold]{target.url}[/bold] (ip={target.ip})")

    muted(f"输入漏洞文件: {confirmed_file}")
    muted(f"mock_llm={settings.mock_llm}, model={settings.deepseek_model}, max_iter={settings.max_iterations}")

    llm: DeepSeekClient | None = None
    if settings.deepseek_api_key and not settings.mock_llm:
        llm = DeepSeekClient(settings)

    plan_path = ws / "plan.json"
    validated_path = ws / "validated_plan.json"
    exec_path = ws / "execution_result.json"
    feedback_path = ws / "feedback.json"
    trusted_selection_path = ws / TRUSTED_SELECTION_FILENAME

    feedback: dict[str, Any] | None = None
    last_plan: dict[str, Any] | None = None
    success_log: list[dict[str, Any]] = []
    run_id = datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%S%fZ")
    _hypothesis_tracker = get_hypothesis_tracker()
    _retry_iteration_done = False

    # ── Per-run lifecycle: reset evidence ledger ──
    from core.evidence_ledger import reset_ledger, load_confirmed_signals
    reset_ledger(ws, run_id=run_id)
    from control.surface_state import build_surface_key, reset_surface_state
    reset_surface_state(ws, build_surface_key(confirmed))

    # ── 熔断器状态（论文 §3.3 防死循环机制）──────────────
    _consecutive_failures  = 0
    _BREAKER_THRESHOLD     = 3
    _breaker_triggered     = False
    _error_fingerprints: list[str] = []   # rolling window of per-iteration error patterns

    # ── 攻击面轮换器 ──────────────────────────────────────
    _rotator = _VulnRotator(confirmed)
    _rotator.mark_attempted(_rotator.current_vuln_id())

    # ── 衰减式动态迭代引擎 ────────────────────────────────
    # 初始预算 5，每次质变里程碑奖励 max(1, 5-milestone_count) 次，
    # 硬性上限 MAX_HARD_LIMIT（settings.max_iterations_cap，默认 20）。
    _MAX_HARD_LIMIT   = settings.max_iterations_cap
    _iter_budget      = settings.max_iterations        # current_budget，动态增长
    _milestone_count  = 0                              # 累计质变次数（用于衰减）
    _no_progress_streak = 0                            # 连续无任何进展计数
    _NO_PROGRESS_ABORT  = 4                            # 连续 N 次无进展则主动放弃

    # ── 滑动窗口上下文（防上下文爆炸）────────────────────
    # 保留最近 3 轮的完整执行摘要；更早的只保留 summary 一行。
    _CONTEXT_WINDOW   = 3
    _iter_history: list[dict[str, Any]] = []           # [{iteration, summary, guidance, ok_count}]

    iteration = 0
    _strategy_exhausted = False
    while iteration < _iter_budget and iteration < _MAX_HARD_LIMIT:
        iteration += 1
        render_iteration_header(iteration, _iter_budget)

        # ── Preflight: HTML form discovery (first round only) ──
        if iteration == 1:
            from memory.runtime_truths import get_runtime_truths
            _rtt = get_runtime_truths()
            if not _rtt.has("injection_method"):
                _preflight_method = _discover_form_method(target)
                if _preflight_method:
                    _rtt.set_fact("injection_method", _preflight_method, "html_form_preflight")
                    _rtt.set_fact("injection_endpoint", "/", "html_form_preflight")
                    _rtt.set_fact("injection_parameter", _extract_injection_param(confirmed), "confirmed_vuln_source")
                    print(f"[coordinator] preflight discovered: method={_preflight_method} endpoint=/ parameter=text")
                else:
                    warn("[coordinator] preflight: could not determine form method from target root")

        # ── Surface hard gate ──
        from control.surface_state import build_surface_key, is_surface_blocked
        _surface_key = build_surface_key(confirmed)
        if is_surface_blocked(ws, _surface_key):
            fb_block = {
                "from": "coordinator_surface_gate",
                "iteration": iteration,
                "surface_key": _surface_key,
                "surface_blocked": True,
                "why_blocked": "surface_confidence_below_threshold",
                "required_action": "alternate_surface_or_discovery",
                "feedback_for_planner": (
                    f"Surface {_surface_key} is blocked. "
                    "All distinct strategies on this surface produced no positive evidence. "
                    "Switch to a different CWE/endpoint/parameter or run discovery."
                ),
            }
            feedback_path.write_text(json.dumps(fb_block, ensure_ascii=False, indent=2), encoding="utf-8")
            warn(f"[coordinator] surface hard gate blocked: {_surface_key}")
            from core.long_term_write_policy import write_terminal_condition
            write_terminal_condition(ws, "surface_blocked", {
                "surface_key": _surface_key,
                "surface_blocked": True,
            }, round_number=iteration)
            break

        # ── Planner ────────────────────────────────────────────────────────
        _print_agent_header("planner")
        stage("Planner", "构建攻击链...")
        template_selection = TemplateManager().select_templates_for_target(
            confirmed,
            state=(feedback or {}).get("current_exploit_state", ""),
            rejected_strategy_ids=_hypothesis_tracker.get_rejected_strategy_ids(),
            strategy_health_resolver=lambda sid: _hypothesis_tracker.evaluate_strategy_health(sid).to_dict(),
            confirmed_signals=load_confirmed_signals(ws),
        )
        trusted_selection = build_trusted_selection(
            run_id=run_id,
            round_index=iteration,
            template_selection=template_selection.to_dict(),
        )
        write_trusted_selection(trusted_selection_path, trusted_selection)

        last_plan = run_planner(
            settings=settings,
            memory=memory,
            confirmed=confirmed,
            feedback=feedback,
            out_path=plan_path,
            llm=llm,
            adapter=adapter,
            trusted_selection=trusted_selection,
        )
        muted(
            f"plan_id={last_plan.get('plan_id')} steps={len(last_plan.get('steps') or [])} "
            f"→ {plan_path.name}"
        )
        if last_plan.get("error") == "config":
            fail("配置错误，无法继续。请检查 target_context.base_url 或 CO_REDTEAM_TARGET_BASE")
            return 1
        for st in (last_plan.get("steps") or []):
            if isinstance(st, dict) and st.get("type") == "python":
                detail(f"step_id={st.get('id')} python_cmd={repr(st.get('command', ''))[:220]}")

        # ── Validator ──────────────────────────────────────────────────────
        _print_agent_header("validator")
        stage("Validator", "校验计划安全策略与语法...")
        v = run_validator(
            plan_path,
            validated_path,
            prior_feedback=feedback,
            trusted_selection_path=trusted_selection_path,
        )
        val = v.get("validation", {})
        warnings = v.get("warnings") or []
        muted(
            f"passed={val.get('passed')} errors={len(val.get('errors') or [])} "
            f"warnings={len(warnings)} → {validated_path.name}"
        )
        if warnings:
            detail(f"自动修复/提示: {warnings}")
        if not v["validation"]["passed"]:
            selection_status = str(trusted_selection.get("status") or "")
            feedback = {
                "from": "validator",
                "iteration": iteration,
                "errors": v["validation"]["errors"],
                "warnings": warnings,
                "hint": "Revise plan.json according to validator errors.",
            }
            if selection_status in ("NO_MATCHED_TEMPLATE", "ALL_MATCHED_STRATEGIES_REJECTED"):
                feedback.update({
                    "reason": "trusted_selection_unavailable",
                    "trusted_selection_status": selection_status,
                    "strategy_exhausted": selection_status == "ALL_MATCHED_STRATEGIES_REJECTED",
                    "needs_strategy_evolution": selection_status == "ALL_MATCHED_STRATEGIES_REJECTED",
                    "feedback_for_planner": (
                        "NO_AVAILABLE_STRATEGY_FOR_SURFACE: no executable canonical strategy "
                        "is currently allowed for this confirmed surface."
                    ),
                })
                feedback_path.write_text(json.dumps(feedback, ensure_ascii=False, indent=2), encoding="utf-8")
                warn(f"trusted selection unavailable; stopping run: {selection_status}")
                from core.long_term_write_policy import write_terminal_condition
                write_terminal_condition(ws, "STAGE_BLOCKED_NO_APPROVED_ROUTE", {
                    "selection_status": selection_status,
                    "strategy_exhausted": selection_status == "ALL_MATCHED_STRATEGIES_REJECTED",
                }, round_number=iteration)
                if settings.dry_run:
                    return _dry_run_return(
                        ws, feedback_path,
                        validation_passed=False,
                        validation_errors=list(val.get("errors") or []),
                        selected_canonical_strategy_id=str(last_plan.get("selected_canonical_strategy_id") or "").strip(),
                        trusted_selection=trusted_selection,
                    )
                _strategy_exhausted = selection_status == "ALL_MATCHED_STRATEGIES_REJECTED"
                break
            warn(f"validator rejected plan: {v['validation']['errors']}")
            if settings.dry_run:
                return _dry_run_return(
                    ws, feedback_path,
                    validation_passed=False,
                    validation_errors=list(val.get("errors") or []),
                    selected_canonical_strategy_id=str(last_plan.get("selected_canonical_strategy_id") or "").strip(),
                    trusted_selection=trusted_selection,
                )
            continue

        # Executor
        selected_canonical_strategy_id = str(last_plan.get("selected_canonical_strategy_id") or "").strip()
        pre_gate_errors = evaluate_pre_execution_gate(last_plan, trusted_selection, _hypothesis_tracker)
        if pre_gate_errors:
            feedback = {
                "from": "coordinator_pre_exec_gate",
                "iteration": iteration,
                "errors": pre_gate_errors,
                "strategy_exhausted": trusted_selection.get("status") == "ALL_MATCHED_STRATEGIES_REJECTED",
                "reason": "pre_execution_gate_blocked",
                "feedback_for_planner": "Choose another trusted canonical strategy for the same confirmed surface.",
            }
            feedback_path.write_text(json.dumps(feedback, ensure_ascii=False, indent=2), encoding="utf-8")
            warn(f"pre-exec gate blocked execution: {pre_gate_errors}")
            if settings.dry_run:
                return _dry_run_return(
                    ws, feedback_path,
                    validation_passed=True,
                    validation_errors=[],
                    selected_canonical_strategy_id=selected_canonical_strategy_id,
                    trusted_selection=trusted_selection,
                    extra_gate_errors=pre_gate_errors,
                )
            continue

        if settings.dry_run:
            return _dry_run_return(
                ws, feedback_path,
                validation_passed=True,
                validation_errors=[],
                selected_canonical_strategy_id=selected_canonical_strategy_id,
                trusted_selection=trusted_selection,
            )

        _print_agent_header("executor")
        stage("Executor", "执行沙箱脚本...")
        try:
            exec_out = run_executor(
                validated_path=validated_path,
                result_path=exec_path,
                workdir=settings.project_root,
                timeout_sec=settings.docker_timeout,
                docker_image=settings.docker_image,
                dockerfile_dir=_ROOT,
                target=target,
            )
        except Exception as e:
            fail(f"FATAL: {e}")
            exec_out = {
                "version": 1,
                "executed": False,
                "execution_mode": "security_blocked",
                "step_results": [],
                "error": str(e),
            }
        step_results = exec_out.get("step_results") or []
        ok_cnt = sum(1 for r in step_results if (r.get("result") or {}).get("ok"))
        fail_cnt = len(step_results) - ok_cnt
        muted(
            f"executed={exec_out.get('executed')} steps={len(step_results)} "
            f"ok={ok_cnt} fail={fail_cnt} → {exec_path.name}"
        )
        if fail_cnt > 0:
            for r in step_results:
                rr = r.get("result") or {}
                if not rr.get("ok"):
                    detail(
                        f"step_id={r.get('step_id')} exit={rr.get('exit_code')} "
                        f"stderr={(rr.get('stderr') or '')[:160]}"
                    )

        # ── Evaluator ──────────────────────────────────────────────────────
        _print_agent_header("evaluator")
        stage("Evaluator", "评估复现结果...")

        # 自动记录失败教训到长期记忆
        _save_failure_lessons(memory, exec_out, last_plan, confirmed, adapter=adapter)

        # 检测 HTTP 语义错误
        http_failures = _detect_http_failures_from_chain(step_results)
        http_feedback_parts: list[str] = []
        if http_failures:
            seen_hints: set[str] = set()
            for hf in http_failures:
                if hf["fix_hint"] not in seen_hints:
                    seen_hints.add(hf["fix_hint"])
                    http_feedback_parts.append(
                        f"• step[{hf['step_id']}] {hf['pattern']} → {hf['fix_hint']}"
                    )
            print(f"[coordinator] HTTP semantic errors detected: {len(http_failures)}")

        polyglot_errors = []
        for r in step_results:
            rr = r.get("result") or {}
            stdout_all = (rr.get("stdout") or "") + (rr.get("stderr") or "")
            step_id = r.get("step_id", "?")
            if "Invalid base64-encoded string" in stdout_all:
                polyglot_errors.append(f"step[{step_id}]: Base64 decode failure in JWT polyglot. FIX: use string concat, injected key FIRST")
            elif "Invalid JWS Object" in stdout_all:
                polyglot_errors.append(f"step[{step_id}]: JWT format rejected. Use VERBATIM template forge function.")
        if polyglot_errors:
            err_msg = "; ".join(polyglot_errors)
            http_feedback_parts.append(f"POLYGLOT: {err_msg}")
            print(f"[coordinator] POLYGLOT construction errors: {len(polyglot_errors)} detected")

        from memory.runtime_truths import get_runtime_truths as _get_runtime_truths_for_eval
        fb = run_evaluator(
            settings=settings,
            memory=memory,
            confirmed=confirmed,
            plan=last_plan,
            exec_out=exec_out,
            feedback_path=feedback_path,
            llm=llm,
            adapter=adapter,
            runtime_truths=_get_runtime_truths_for_eval().data,
            template_selection=template_selection.to_dict(),
        )
        feedback = fb
        _expected_signals = (
            template_selection.strategy_descriptors.get(selected_canonical_strategy_id, {})
            .get("expected_signals", []) if hasattr(template_selection, 'strategy_descriptors') else []
        )
        render_evaluator_feedback(fb)

        # ── ObservationDecision: single deterministic source of truth ──
        from core.observation_decision import make_observation_decision
        _surface_key = build_surface_key(confirmed)
        _obs_decision = make_observation_decision(
            exec_out=exec_out,
            expected_signals=_expected_signals,
            run_id=run_id,
            surface_key=_surface_key,
            selected_strategy_id=selected_canonical_strategy_id,
            evidence_ledger_path=ws,
        )
        print(f"[observation_decision] status={_obs_decision.observation_status} "
              f"matched_signals={_obs_decision.matched_signal_ids} "
              f"is_new_evidence={_obs_decision.is_new_evidence} "
              f"is_new_state_transition={_obs_decision.is_new_state_transition}")

        # ── Record strategy attempt (consumes ObservationDecision) ──
        _record_strategy_attempt_if_executed(
            _hypothesis_tracker,
            selected_canonical_strategy_id,
            exec_out,
            fb,
            round_number=iteration,
            expected_signals=_expected_signals,
            obs_decision=_obs_decision,
        )

        # ── OUTCOME_CONSISTENCY_VIOLATION check ──
        _old_sent, _old_obs, _old_fail = _classify_observation(exec_out, fb, expected_signals=_expected_signals)
        if _obs_decision.observation_status != _old_obs:
            _violation_msg = (
                f"OUTCOME_CONSISTENCY_VIOLATION: deterministic={_obs_decision.observation_status} "
                f"vs legacy_classifier={_old_obs} for {selected_canonical_strategy_id} "
                f"surface={_surface_key} fp={_obs_decision.execution_fingerprint}"
            )
            print(f"[coordinator] ⚠️ {_violation_msg}")
            # Use ObservationDecision as authority; log legacy discrepancy for audit
            fb.setdefault("_consistency_violations", []).append(_violation_msg)
            from core.long_term_write_policy import write_terminal_condition
            write_terminal_condition(ws, "OUTCOME_CONSISTENCY_VIOLATION", {
                "deterministic": _obs_decision.observation_status,
                "legacy_classifier": _old_obs,
                "strategy_id": selected_canonical_strategy_id,
            }, round_number=iteration)

        # ── Evidence Ledger: write signals from ObservationDecision only ──
        if _obs_decision.is_new_evidence and _obs_decision.matched_signal_ids:
            from core.evidence_ledger import write_signals_deduped
            _new_signals: list[dict] = []
            for i, sig in enumerate(_obs_decision.matched_signal_ids):
                ek = _obs_decision.evidence_keys[i] if i < len(_obs_decision.evidence_keys) else ""
                _new_signals.append({
                    "signal_id": sig,
                    "evidence_key": ek,
                    "run_id": run_id,
                    "round": iteration,
                    "surface_key": _surface_key,
                    "execution_fingerprint": _obs_decision.execution_fingerprint,
                    "source_strategy_id": selected_canonical_strategy_id,
                    "evidence_reference": f"deterministic observer confirmed: {sig}",
                })
            if _new_signals:
                _written, _skipped = write_signals_deduped(ws, _new_signals)
                print(f"[evidence_ledger] {_written} new signals, {_skipped} duplicates: "
                      f"{[s['signal_id'] for s in _new_signals]}")
        elif _obs_decision.matched_signal_ids and not _obs_decision.is_new_evidence:
            print(f"[evidence_ledger] duplicate_evidence: all signals already in ledger for "
                  f"fp={_obs_decision.execution_fingerprint}, skipping write")
            from core.long_term_write_policy import write_terminal_condition
            write_terminal_condition(ws, "duplicate_evidence", {
                "execution_fingerprint": _obs_decision.execution_fingerprint,
                "signal_ids": _obs_decision.matched_signal_ids,
            }, round_number=iteration)

        # ── Surface State update (consumes ObservationDecision) ──
        from control.surface_state import (
            update_surface_after_strategy_failure, boost_surface_after_positive_evidence
        )
        if _obs_decision.request_sent and _obs_decision.observation_status == "no_positive_evidence":
            _surface_state = update_surface_after_strategy_failure(
                ws,
                _surface_key,
                selected_canonical_strategy_id,
                iteration,
                execution_fingerprint=_obs_decision.execution_fingerprint or None,
                request_sent=True,
                observation_status="no_positive_evidence",
            )
            print(
                f"[surface_state] negative evidence: {selected_canonical_strategy_id} "
                f"on {_surface_key} reason={_surface_state.decision_reason}"
            )
        elif _obs_decision.request_sent and _obs_decision.observation_status == "positive_evidence":
            boost_surface_after_positive_evidence(ws, _surface_key, iteration)
            print(f"[surface_state] positive evidence on {_surface_key}")

        # ── AI 主动熔断（suggest_abort）────────────────────────────────────
        if fb.get("suggest_abort"):
            fail("[coordinator] AI 判断已无利用可能，主动终止迭代。")
            break

        # ── 滑动窗口：记录本轮摘要，裁剪旧历史 ──────────────────────────
        cur_ok_count = sum(
            1 for r in step_results if (r.get("result") or {}).get("ok")
        )
        _iter_history.append({
            "iteration":  iteration,
            "summary":    fb.get("summary", ""),
            "guidance":   (fb.get("analysis") or {}).get("guidance", ""),
            "ok_count":   cur_ok_count,
            "confidence": float(fb.get("confidence") or 0.0),
        })
        # 将滑动窗口摘要注入 feedback，供 Planner 参考（替代原始 stdout 堆积）
        if len(_iter_history) > _CONTEXT_WINDOW:
            old_entries = _iter_history[:-_CONTEXT_WINDOW]
            collapsed = "\n".join(
                f"  [iter{e['iteration']}] {e['summary']}"
                for e in old_entries
            )
            fb["_collapsed_history"] = collapsed
            print(f"[coordinator] 📦 上下文折叠：{len(old_entries)} 轮旧历史已压缩为摘要")

        # ── 衰减式里程碑奖励 (consumes ObservationDecision.is_new_state_transition) ──
        if _obs_decision.is_new_state_transition:
            _milestone_count += 1
            extension = max(1, 5 - _milestone_count)
            old_budget = _iter_budget
            _iter_budget = min(_iter_budget + extension, _MAX_HARD_LIMIT)
            _no_progress_streak = 0
            stage(
                "CLI",
                f"质变里程碑 #{_milestone_count}！奖励 +{extension} 次迭代。"
                f"预算 {old_budget}→{_iter_budget}（上限 {_MAX_HARD_LIMIT}）",
            )
        else:
            _no_progress_streak += 1
            print(f"[coordinator] ⏳ 无质变进展计数: {_no_progress_streak}/{_NO_PROGRESS_ABORT}")

        # ── 连续无进展主动放弃 ────────────────────────────────────────────
        if _no_progress_streak >= _NO_PROGRESS_ABORT:
            fail(f"[coordinator] 连续 {_NO_PROGRESS_ABORT} 轮无质变进展，主动终止迭代。")
            break

        # ── 熔断器逻辑 (consumes ObservationDecision.observation_status) ──
        if _obs_decision.observation_status == "positive_evidence":
            _consecutive_failures = 0
            _breaker_triggered    = False
            _error_fingerprints.clear()
            print(f"[coordinator] ✅ positive_evidence: consecutive_failures reset to 0")
        elif _obs_decision.observation_status == "no_positive_evidence":
            _consecutive_failures += 1
            fp = _extract_step_error_fingerprint(step_results)
            _error_fingerprints.append(fp)
            if len(_error_fingerprints) > _BREAKER_THRESHOLD:
                _error_fingerprints.pop(0)
            print(f"[coordinator] ⚠️  连续失败计数: {_consecutive_failures}/{_BREAKER_THRESHOLD} | 错误指纹: {fp}")
        # request_not_sent / observation_unknown: do not modify failure counter

        # Stagnation check: same error fingerprint repeated across the window
        # "no_failures" excluded (no step ran). "http_ok_no_reflection" IS stagnation.
        _NON_STAGNATING = frozenset({"no_failures"})
        _stagnating = (
            len(_error_fingerprints) >= _BREAKER_THRESHOLD
            and len(set(_error_fingerprints)) == 1
            and _error_fingerprints[0] not in _NON_STAGNATING
        )

        # ── 攻击面轮换：计划全部 BLOCKED 时强制切换漏洞 ──────────────────
        if last_plan and _is_plan_fully_blocked(last_plan) and not _rotator.all_attempted():
            rotation = _rotator.rotate()
            if rotation is not None:
                confirmed, rotated_vid = rotation
                note = confirmed.get("_rotation_note", "")
                warn(f"[coordinator] 攻击面轮换 → 切换至漏洞 {rotated_vid}")
                print(f"[coordinator] {note}")
                # Reset breaker state for the new attack surface
                _consecutive_failures = 0
                _breaker_triggered    = False
                _error_fingerprints.clear()
                fb["feedback_for_planner"] = (
                    f"\n\n【攻击面强制轮换】\n{note}\n"
                    "上一个漏洞的所有步骤均已 BLOCKED，系统已切换到新漏洞。\n"
                    "请针对新漏洞重新设计完整攻击链，不要沿用上一轮的 payload 或端点。"
                ) + "\n" + (fb.get("feedback_for_planner") or "")
                feedback = fb
                continue
            else:
                warn("[coordinator] 所有漏洞均已尝试，无可轮换目标。")

        if (_consecutive_failures >= _BREAKER_THRESHOLD or _stagnating) and not _breaker_triggered:
            # ── 触发熔断：CWE 记忆增强 + 强制策略切换 ────────────────────
            _breaker_triggered = True
            trigger_reason = "策略停滞（相同错误重复）" if _stagnating else f"连续 {_BREAKER_THRESHOLD} 次失败"
            print(f"[coordinator] 🔴 熔断器触发！{trigger_reason}，强制策略切换！")
            from core.long_term_write_policy import write_terminal_condition
            write_terminal_condition(ws, "breaker_triggered", {
                "trigger_reason": trigger_reason,
                "consecutive_failures": _consecutive_failures,
                "error_fingerprints": list(_error_fingerprints),
            }, round_number=iteration)

            vuln_summary = (
                confirmed.get("title", "")
                or confirmed.get("description", "")
                or ""
            )
            cwe_ids = [
                v.get("cwe_id", "")
                for v in confirmed.get("vulnerabilities", [])
                if v.get("cwe_id")
            ]

            # CWE-keyed memory retrieval: query each CWE separately for targeted recall
            cwe_memory_parts: list[str] = []
            for cwe in cwe_ids[:4]:
                try:
                    results = memory.query_strategies(
                        query_text=f"{cwe} 漏洞利用 成功 失败 payload 攻击",
                        n_results=3,
                    )
                    if results:
                        cwe_memory_parts.append(f"\n  [{cwe}] 历史经验：")
                        for item in results:
                            stype = item.get("metadata", {}).get("strategy_type", "unknown")
                            label = "✅" if stype != "failure" else "❌"
                            cwe_memory_parts.append(f"    {label} {item['content'][:200]}")
                except Exception:
                    pass

            _mem_ctx = _build_breaker_memory_context(memory, vuln_summary, confirmed)
            cwe_block = "\n".join(cwe_memory_parts) if cwe_memory_parts else ""

            breaker_injection = (
                "\n\n"
                "╔══════════════════════════════════════════════════════════════╗\n"
                f"║  🔴 熔断器硬中断 — {trigger_reason}，强制策略切换！\n"
                "╚══════════════════════════════════════════════════════════════╝\n"
                "当前路径已被判定为死路，必须满足以下要求：\n"
                "1. 【禁止重复】不得再次使用上两轮相同的 payload、端点、参数组合\n"
                "2. 【更换漏洞路径】选择 confirmed_vuln 中尚未尝试的其他漏洞类型\n"
                "3. 【降级策略】若复杂漏洞链失败，改用最简单的单步验证\n"
                "4. 【探测优先】生成计划第一步必须是纯探测步骤（验证连通性 + 枚举接口）\n"
            )
            if cwe_block:
                breaker_injection += f"\n【CWE 专项记忆检索结果（{', '.join(cwe_ids[:4])}）】：{cwe_block}\n"
            if _mem_ctx:
                breaker_injection += f"\n{_mem_ctx}"

            fb["feedback_for_planner"] = breaker_injection
            feedback = fb
            print("[coordinator] 熔断器指令已注入 feedback_for_planner")

        elif not fb.get("repro_success") and _consecutive_failures < _BREAKER_THRESHOLD:
            # ── 未达熔断阈值的普通失败：注入记忆经验辅助决策 ─────────────
            vuln_summary = (
                confirmed.get("title", "")
                or confirmed.get("description", "")
                or ""
            )
            _mem_ctx = _build_breaker_memory_context(memory, vuln_summary, confirmed)
            if _mem_ctx:
                existing = fb.get("feedback_for_planner") or ""
                fb["feedback_for_planner"] = existing + "\n\n【长期记忆辅助参考】" + _mem_ctx
                feedback = fb
                print(f"[coordinator] 已将长期记忆经验注入 feedback（失败 {_consecutive_failures}/{_BREAKER_THRESHOLD}）")

        # ── HTTP 语义错误修复注入（独立于熔断器，始终追加）──────────────────
        if http_feedback_parts:
            fix_block = (
                "\n\n"
                "══════════════════════════════════════════\n"
                "【�� HTTP 语义错误自动诊断 — 必须在下轮修复！】\n"
                "══════════════════════════════════════════\n"
                + "\n".join(http_feedback_parts)
                + "\n══════════════════════════════════════════"
            )
            fb["feedback_for_planner"] = fix_block + "\n" + (fb.get("feedback_for_planner") or "")
            feedback = fb
            print(f"[coordinator] �� 已将 {len(http_feedback_parts)} 条HTTP语义修复注入下轮planning")

        # ── 全部步骤失败时注入 URL 修正指令 ──────────────────────────────
        if fail_cnt == len(step_results) and fail_cnt > 0:
            target_base = confirmed.get("target_context", {}).get("base_url", "")
            if target_base:
                fb["feedback_for_planner"] = (
                    f"【URL 修正指令】目标基础 URL 是 {target_base}，"
                    "所有请求必须以该地址为前缀。请检查并修正所有步骤中的 base 变量。\n"
                ) + (fb.get("feedback_for_planner") or "")
                feedback = fb
                print(f"[coordinator] �� 全部步骤失败，已注入目标 URL 修正指令: {target_base}")

        # ── 成功处理逻辑 ───────────────────────────────────────────────────
        if fb.get("repro_success"):
            conf = fb.get("confidence", 0)
            ok(f"本轮复现成功！confidence={conf}")
            success_log.append({
                "iteration": iteration,
                "plan_id": last_plan.get("plan_id"),
                "confidence": fb.get("confidence"),
                "summary": fb.get("summary", ""),
            })
            fb["repro_success"] = True
            fb["success_log"] = success_log
            if conf >= 0.65:
                failures = _count_execution_failures(exec_out)
                has_failures = any(v for v in failures.values())
                if has_failures and not _retry_iteration_done and iteration < _iter_budget:
                    _retry_iteration_done = True
                    warn(
                        f"置信度达标但存在失败步骤: "
                        f"skipped={len(failures['skipped'])} "
                        f"error={len(failures['error'])} "
                        f"blocked={len(failures['blocked'])}"
                    )
                    stage("CLI", "启动定向修复迭代，专攻失败步骤...")
                    retry_prompt = _build_retry_prompt(failures, confirmed)
                    fb["feedback_for_planner"] = retry_prompt
                    fb["should_continue"] = True
                    feedback = fb
                    continue
                ok(f"置信度 {conf:.0%} 达标，停止迭代。")
                break
            vulns = confirmed.get("vulnerabilities") or []
            remaining = [f"{v.get('cwe_id', '?')} {v.get('title', '')}" for v in vulns]
            fb["feedback_for_planner"] = (
                (fb.get("feedback_for_planner") or "")
                + f" 【继续探索】目标系统仍有漏洞待验证。confirmed_vuln 中共 {len(remaining)} 个漏洞：\n"
                + "\n".join(f"  - {r}" for r in remaining)
                + "\n请根据 confirmed_vuln 中各条目生成新计划。已成功的漏洞可跳过，集中攻击尚未验证的漏洞。确保每个漏洞类型至少一个步骤。"
            )
            feedback = fb
            continue

        if fb.get("should_continue") is False:
            warn("评估建议终止迭代。")
            break

    # ── 迭代循环结束 — 唤醒全局复盘导师 ───────────────────────────
    if _strategy_exhausted:
        _cleanup_sandbox_workspace(ws)
        fail("No executable canonical strategy remains; waiting for reviewed strategy evolution.")
        return 4

    final_is_success = len(success_log) > 0
    final_max_iter = iteration >= _iter_budget or iteration >= _MAX_HARD_LIMIT

    print("\n[Consolidator] 🏁 迭代任务结束，正在唤醒高级复盘导师进行全局经验提炼...")
    try:
        from agents.consolidator import run_global_consolidation
        run_global_consolidation(
            workdir=ws,
            max_iter_reached=final_max_iter,
            is_success=final_is_success,
        )
        print("[Consolidator] ✅ 全局经验已成功提炼并写入永久记忆库 (patterns.json / tech.json)。")
    except Exception as e:
        print(f"[Consolidator] ⚠️ 复盘过程发生异常，但不影响本次任务结果: {e}")

    # ── 退出状态处理 ────────────────────────────────────────
    if final_max_iter:
        warn(f"已达迭代上限（budget={_iter_budget}, hard_limit={_MAX_HARD_LIMIT}），安全退出。")
    _cleanup_sandbox_workspace(ws)

    if success_log:
        ok(f"总计复现成功 {len(success_log)} 次！")
        render_summary_table(success_log)
        return 0

    fail("达到最大迭代次数，未判定成功。")
    return 3


def main() -> None:
    import argparse

    import core.adapters  # noqa: F401
    from core.target_context import lock_target, TargetLockError

    parser = argparse.ArgumentParser(
        description="Co-RedTeam 协调器（多智能体 + 分层长期记忆）"
    )
    parser.add_argument(
        "--confirmed",
        type=Path,
        default=None,
        help="confirmed_vuln.json 路径，默认 data/confirmed_vuln.json",
    )
    parser.add_argument(
        "--challenge",
        type=str,
        default="generic",
        choices=["generic"] + list_adapters(),
        help="挑战适配器名称（加载挑战专属规则）。可用: %(choices)s",
    )
    parser.add_argument(
        "--url",
        type=str,
        default=None,
        help="目标 URL 白名单（如 https://192.168.1.100:9443）。省略时从 confirmed_vuln 读取",
    )
    args = parser.parse_args()

    target: TargetContext | None = None
    if args.url:
        try:
            target = lock_target(args.url)
        except TargetLockError as e:
            fail(str(e))
            raise SystemExit(2)

    code = run_pipeline(
        confirmed_path=args.confirmed,
        challenge_name=args.challenge,
        target=target,
    )
    raise SystemExit(code)


if __name__ == "__main__":
    main()
