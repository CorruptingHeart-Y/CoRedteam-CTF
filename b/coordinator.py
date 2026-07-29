from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import json
from typing import Any

from agents.evaluator import run_evaluator
from agents.executor import run_executor
from agents.planner import run_planner
from agents.validator import run_validator
from core.challenge_adapter import ChallengeAdapter, get_adapter, list_adapters
from memory.exploit_trajectory import get_trajectory, reset_trajectory
from memory.verification_memory import get_verification, reset_verification
from memory.primitive_learning import get_learning_engine, PrimitiveObservation
from memory.primitive_transition_graph import get_transition_graph
from core.llm_client import DeepSeekClient

# ═══════════════════════════════════════════════════════════════════
# Runtime Manifest — 显式能力注册 (Constrained Agency §1)
# 唯一可信的运行时能力清单。Validator 和 Planner 必须对齐此清单。
# 禁止扫描 Docker 镜像隐式 pip 依赖；所有能力必须在此显式声明。
# ═══════════════════════════════════════════════════════════════════
RUNTIME_MANIFEST: dict[str, Any] = {
    "version": 1,
    "sdk_primitives": [
        # HTTP 高层编排（禁止直接 import requests / urllib3 / socket）
        "HttpClient.get",
        "HttpClient.post",
        "HttpClient.raw_request",
        "HttpClient.last_response",
    ],
    "safe_modules": [
        # 最小可用能力闭包 — 协议数据处理辅助工具集
        # Validator AST 检查 100% 与此清单对齐
        "json", "base64", "re", "time", "struct",
        "urllib.parse", "http.cookies",
        "hashlib", "hmac",
        # 高阶数据处理（禁原生通信，仅 SDK 封装内可用）
        "redteam_sdk",
    ],
    "blocked_modules": [
        "os", "subprocess", "socket", "ctypes", "cffi", "pty",
        "signal", "multiprocessing", "importlib", "pickle", "marshal",
        "builtins", "gc", "inspect", "ast", "code", "codeop",
        "compileall", "dis", "types", "weakref",
        # 原生通信库禁直接导入 — 必须通过 redteam_sdk.HttpClient
        "requests", "urllib3", "urllib",
    ],
    "network_mode": "bridge",
    "target_access_mode": "container_ip_only",
}
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
    render_victory_banner,
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
    """Produce a short fingerprint of the dominant failure pattern this iteration.

    Used to detect when the same error repeats across iterations so the breaker
    can fire on strategy-level stagnation, not just consecutive eval failures.
    """
    error_tokens: list[str] = []
    for r in step_results:
        rr = r.get("result") or {}
        if rr.get("ok"):
            continue
        stderr = (rr.get("stderr") or "")[:300]
        stdout = (rr.get("stdout") or "")[:300]
        text = f"{stderr} {stdout}"
        for keyword in (
            "Invalid URL", "ConnectionError", "Connection refused",
            "SSLError", "SyntaxError", "NameError", "IndentationError",
            "KeyError", "401", "403", "404", "405", "500",
            "All fields are required", "Invalid Email",
            "CSRF Detected", "Unauthorised",
            "security_blocked", "skipped_syntax_error",
        ):
            if keyword in text:
                error_tokens.append(keyword)
                break
        else:
            error_tokens.append("unknown_error")
    return "|".join(sorted(set(error_tokens))) or "no_execution_error"


def _has_execution_failure(step_results: list[dict[str, Any]], fb: dict[str, Any]) -> bool:
    for r in step_results:
        rr = r.get("result") or {}
        if not rr.get("ok"):
            return True
    return fb.get("error_fingerprint") in {
        "ConnectionRefused",
        "ConnectionTimeout",
        "NameError",
        "SyntaxError",
        "ImportError",
        "security_blocked",
        "skipped_syntax_error",
    }


def _coordinator_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


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


def _compute_progress_signals(
    fb: dict[str, Any],
    last_plan: dict[str, Any],
    step_results: list[dict[str, Any]],
    prev_state: dict[str, Any] | None,
) -> tuple[bool, list[str]]:
    """Multi-dimensional progress detection beyond binary is_milestone.

    Returns (has_progress, list_of_reasons).
    """
    reasons: list[str] = []

    if prev_state is None:
        return True, ["initial_round"]

    # 1. State machine advancement
    state_order = ["init", "probe_success", "payload_injected", "gadget_triggered", "oob_received"]
    cur_state = fb.get("current_exploit_state", "init")
    prev_es = prev_state.get("exploit_state", "init")
    try:
        if state_order.index(cur_state) > state_order.index(prev_es):
            reasons.append(f"state_advance: {prev_es} → {cur_state}")
    except (ValueError, IndexError):
        pass

    # 2. New primitive detected (or confidence increase on existing)
    cur_prims = set(fb.get("detected_primitives", []))
    prev_prims = prev_state.get("primitives", set())
    new_prims = cur_prims - prev_prims
    if new_prims:
        reasons.append(f"new_primitive: {new_prims}")

    cur_conf = fb.get("primitive_confidence", {})
    prev_conf = prev_state.get("primitive_confidence", {})
    for pid, conf in cur_conf.items():
        prev_c = prev_conf.get(pid, 0.0)
        if conf - prev_c >= 0.1:
            reasons.append(f"confidence_increase: {pid} {prev_c:.2f}→{conf:.2f}")

    # 3. New endpoint accessed
    cur_endpoints: set[str] = set()
    for sr in step_results:
        for h in sr.get("http_responses") or []:
            url = h.get("url", "")
            if url:
                cur_endpoints.add(url)
    prev_endpoints = prev_state.get("endpoints", set())
    new_eps = cur_endpoints - prev_endpoints
    if new_eps:
        reasons.append(f"new_endpoint: {new_eps}")

    # 4. New HTTP status code observed
    cur_codes: set[int] = set()
    for sr in step_results:
        for h in sr.get("http_responses") or []:
            code = h.get("status_code", 0)
            if code:
                cur_codes.add(code)
    prev_codes = prev_state.get("http_codes", set())
    new_codes = cur_codes - prev_codes
    if new_codes:
        reasons.append(f"new_status_code: {new_codes}")

    # 5. Payload mutation: significant change from previous plan
    cur_payloads = " ".join(
        _coordinator_text(st.get("command")) for st in (last_plan.get("steps") or [])
    )
    prev_payloads = prev_state.get("payloads", "")
    if cur_payloads and prev_payloads:
        # Simple similarity heuristic: if <60% of tokens overlap, it's a mutation
        cur_tokens = set(cur_payloads.lower().split())
        prev_tokens = set(prev_payloads.lower().split())
        if cur_tokens and prev_tokens:
            overlap = len(cur_tokens & prev_tokens) / max(len(cur_tokens), len(prev_tokens))
            if overlap < 0.6:
                reasons.append(f"payload_mutation: overlap={overlap:.1%}")

    # 6. New verified fact recorded (from verification_memory module)
    try:
        from memory.verification_memory import get_verification
        verif = get_verification()
        fresh = getattr(verif, '_last_round_new_facts', 0)
        if fresh > 0:
            reasons.append(f"verified_facts: {fresh} new")
    except Exception:
        pass

    # 7. is_milestone from Evaluator (existing signal — always counts)
    if fb.get("is_milestone"):
        reasons.append("evaluator_milestone")

    # 8. Partial primitive confidence sum ≥ 0.30 (incremental progress)
    partial_keys = (
        "response_length_change", "payload_reflection", "oob_attempt",
        "error_triggered", "timing_anomaly", "uid_fragment",
        "file_listing_fragment", "command_usage_fragment",
    )
    partial_sum = sum(cur_conf.get(k, 0.0) for k in partial_keys)
    prev_partial_sum = sum(prev_conf.get(k, 0.0) for k in partial_keys)
    if partial_sum - prev_partial_sum >= 0.20:
        reasons.append(f"partial_progress: +{partial_sum - prev_partial_sum:.2f}")

    # 9. ok_count increase (more steps succeeding)
    cur_ok = sum(1 for r in step_results if (r.get("result") or {}).get("ok"))
    prev_ok = prev_state.get("ok_count", 0)
    if cur_ok > prev_ok:
        reasons.append(f"ok_count: {prev_ok} → {cur_ok}")

    # 10. EPE progress_score increase (Exploit Progress Engine)
    cur_ps = fb.get("progress_score", 0.0)
    prev_ps = prev_state.get("progress_score", 0.0)
    if cur_ps > prev_ps + 0.03:
        reasons.append(f"progress_score: {prev_ps:.2f}→{cur_ps:.2f}")

    # 11. EPE exploit_momentum (strongest signal — surface perturbation confirmed)
    if fb.get("exploit_momentum"):
        reasons.append("exploit_momentum_active")

    # 12. State transition probability increase
    cur_stp = fb.get("state_transition_probability", 0.0)
    prev_stp = prev_state.get("state_transition_probability", 0.0)
    if cur_stp > prev_stp + 0.05:
        reasons.append(f"stp_increase: {prev_stp:.2f}→{cur_stp:.2f}")

    return bool(reasons), reasons


def _snapshot_round_state(
    fb: dict[str, Any],
    last_plan: dict[str, Any],
    step_results: list[dict[str, Any]],
) -> dict[str, Any]:
    """Capture round state for next-iteration comparison."""
    endpoints: set[str] = set()
    http_codes: set[int] = set()
    for sr in step_results:
        for h in sr.get("http_responses") or []:
            if h.get("url"):
                endpoints.add(h["url"])
            code = h.get("status_code", 0)
            if code:
                http_codes.add(code)

    payloads = " ".join(
        _coordinator_text(st.get("command")) for st in (last_plan.get("steps") or [])
    )

    return {
        "exploit_state": fb.get("current_exploit_state", "init"),
        "primitives": set(fb.get("detected_primitives", [])),
        "primitive_confidence": fb.get("primitive_confidence", {}),
        "endpoints": endpoints,
        "http_codes": http_codes,
        "payloads": payloads,
        "ok_count": sum(1 for r in step_results if (r.get("result") or {}).get("ok")),
        "progress_score": fb.get("progress_score", 0.0),
        "state_transition_probability": fb.get("state_transition_probability", 0.0),
        "exploit_momentum": fb.get("exploit_momentum", False),
        "suggested_next_action": fb.get("suggested_next_action", ""),
    }


def _is_plan_fully_blocked(plan: dict[str, Any]) -> bool:
    """Return True if every step in the plan has status BLOCKED."""
    steps = plan.get("steps") or []
    if not steps:
        return False
    return all(
        isinstance(st, dict) and st.get("status") == "BLOCKED"
        for st in steps
    )


def _build_last_exec_raw(exec_out: dict[str, Any]) -> dict[str, Any]:
    """Build a compact raw execution summary from executor output for Planner injection.

    Token budget: each step keeps tail 500 chars of stdout/stderr + first 300 chars of HTTP body.
    """
    steps_raw = []
    for r in exec_out.get("step_results") or []:
        res = r.get("result") or {}
        stdout_full = res.get("stdout", "")
        stderr_full = res.get("stderr", "")
        http_responses = r.get("http_responses") or []
        entry = {
            "step_id": r.get("step_id"),
            "ok": res.get("ok", False),
            "exit_code": res.get("exit_code", -1),
            "stdout_tail": stdout_full[-500:] if len(stdout_full) > 500 else stdout_full,
            "stderr_tail": stderr_full[-500:] if len(stderr_full) > 500 else stderr_full,
        }
        if http_responses:
            entry["http_responses"] = [
                {
                    "status_code": h.get("status_code"),
                    "method": h.get("method", ""),
                    "url": h.get("url", ""),
                    "response_body": (h.get("response_body", "") or "")[:300],
                }
                for h in http_responses[:5]
            ]
        # Extract exception from STEP_FAIL marker
        if "STEP_FAIL:" in stdout_full:
            idx = stdout_full.index("STEP_FAIL:")
            entry["exception_snippet"] = stdout_full[idx:idx + 500]
        steps_raw.append(entry)
    return {"steps": steps_raw}


def _record_trajectory_entry(
    iteration: int,
    fb: dict[str, Any],
    plan: dict[str, Any],
    exec_out: dict[str, Any],
    step_results: list[dict[str, Any]],
) -> None:
    """每轮结束后记录 exploit 路径节点到 trajectory memory (含 primitive 信息)。"""
    traj = get_trajectory()

    # 从 feedback 提取状态机字段
    current_state = fb.get("current_exploit_state", "init")
    blocker = fb.get("state_transition_blocker", "")
    milestones = fb.get("milestones_achieved", [])
    next_action = fb.get("next_required_action", "")
    success = fb.get("repro_success", False)

    # Primitive detection from feedback
    detected_primitives = fb.get("detected_primitives", [])
    primitive_confidence = fb.get("primitive_confidence", {})
    primitive_evidence = fb.get("primitive_evidence", {})
    primary_primitive = detected_primitives[0] if detected_primitives else ""
    primary_primitive_conf = primitive_confidence.get(primary_primitive, 0.0) if primary_primitive else 0.0
    primary_primitive_ev = primitive_evidence.get(primary_primitive, "") if primary_primitive else ""

    # 确定 target_state（下一个目标状态）
    state_order = ["init", "probe_success", "payload_injected", "gadget_triggered", "oob_received"]
    try:
        cur_idx = state_order.index(current_state) if current_state in state_order else 0
        target_state = state_order[min(cur_idx + 1, len(state_order) - 1)]
    except ValueError:
        target_state = "probe_success"

    # 从 plan 中提取 action_type / endpoint / method
    action_type = "probe"
    endpoint = ""
    method = ""
    payload = ""
    for st in plan.get("steps", []):
        cmd = _coordinator_text(st.get("command"))
        purpose = (_coordinator_text(st.get("purpose"))).lower()
        # Detect action_type from purpose
        if any(kw in purpose for kw in ("inject", "注入", "payload", "exploit", "trigger", "触发")):
            action_type = "inject"
        elif any(kw in purpose for kw in ("exfiltrate", "外传", "oob", "flag", "读取", "read")):
            action_type = "exfiltrate"
        elif any(kw in purpose for kw in ("trigger", "gadget", "rce", "执行", "execute")):
            action_type = "trigger"
        # Extract first endpoint from command (cmd="" for AST steps → no match)
        if cmd and not endpoint:
            import re
            ep_match = re.search(r"['\"](/[\w/\-._]+)['\"]", cmd)
            if ep_match:
                endpoint = ep_match.group(1)
        if cmd and not method:
            for m in ("post", "get", "put", "delete"):
                if f".{m}(" in cmd.lower():
                    method = m.upper()
                    break
        if cmd and not payload:
            # Capture first meaningful payload pattern
            payload_match = re.search(r"payload\s*=\s*['\"]([^'\"]+)['\"]", cmd)
            if payload_match:
                payload = payload_match.group(1)[:200]

    # 构建 evidence
    all_http = []
    for r in exec_out.get("step_results") or []:
        for h in r.get("http_responses") or []:
            all_http.append(f"HTTP {h.get('status_code')} {h.get('method')} {h.get('url', '')}")

    evidence = "; ".join(all_http[:3]) if all_http else "no HTTP responses"

    # 检测是否产生了状态转换
    state_transition = ""
    if milestones and isinstance(milestones, list):
        for m in milestones:
            if isinstance(m, str) and ":" in m:
                state_transition = f"{current_state} -> {m.split(':')[0].strip()}"
                break

    # 失败原因
    why_failed = ""
    if not success:
        why_failed = f"{fb.get('error_fingerprint', '')}: {blocker}"

    traj.append(
        round_id=iteration,
        current_state=current_state,
        target_state=target_state,
        action_type=action_type,
        payload=payload,
        endpoint=endpoint,
        method=method,
        evidence=evidence,
        success=success,
        blocker=blocker,
        state_transition=state_transition,
        why_failed=why_failed,
        reusable=success and len(payload) > 0,
        detected_primitive=primary_primitive,
        primitive_confidence=primary_primitive_conf,
        primitive_evidence=primary_primitive_ev,
    )

    traj_stats = traj.get_stats()
    print(
        f"[coordinator] 📈 轨迹已记录: R{iteration} | state={current_state} | "
        f"primitive={primary_primitive}({primary_primitive_conf:.0%}) | "
        f"success={success} | chain={' -> '.join(traj_stats['chain'])}"
    )


def _record_primitive_learning(
    fb: dict[str, Any],
    plan: dict[str, Any],
    step_results: list[dict[str, Any]],
) -> None:
    """从单轮的执行结果中学习 exploit primitive。"""
    engine = get_learning_engine()
    detected_primitives = fb.get("detected_primitives", [])
    primitive_confidence = fb.get("primitive_confidence", {})
    primitive_evidence = fb.get("primitive_evidence", {})

    if not detected_primitives:
        return

    # 构建 observation
    all_stdout = " ".join(
        _coordinator_text((r.get("result") or {}).get("stdout", "")) for r in step_results
    )
    all_http_bodies = " ".join(
        h.get("response_body", "")
        for r in step_results
        for h in r.get("http_responses") or []
    )

    endpoint = ""
    method = "GET"
    payload = ""
    for st in plan.get("steps", []):
        cmd = _coordinator_text(st.get("command"))
        if cmd and not endpoint:
            import re
            ep_match = re.search(r"['\"](/[\w/\-._]+)['\"]", cmd)
            if ep_match:
                endpoint = ep_match.group(1)
        if cmd and not payload:
            payload_match = re.search(r"payload\s*=\s*['\"]([^'\"]+)['\"]", cmd)
            if payload_match:
                payload = payload_match.group(1)[:300]

    obs = PrimitiveObservation(
        payload=payload,
        endpoint=endpoint,
        method=method,
        response_status=200,
        response_body_snippet=all_http_bodies[:500],
        stdout_snippet=all_stdout[:500],
        success=fb.get("repro_success", False),
    )

    learned = engine.learn_from_observation(obs)
    if learned:
        learned_ids = [lp.primitive_id for lp in learned]
        print(f"[coordinator] 🧠 Primitive 学习引擎: 新学习到 {' | '.join(learned_ids)}")
        # Auto-generalize high-confidence primitives
        for lp in learned:
            if lp.confidence >= 0.7:
                engine.generalize_primitive(lp.primitive_id)


def _record_verified_facts(
    fb: dict[str, Any],
    step_results: list[dict[str, Any]],
) -> None:
    """从单轮的执行结果中提取已确认的事实并写入 verification memory。"""
    verif = get_verification()
    success = fb.get("repro_success", False)
    milestones = fb.get("milestones_achieved", [])
    state = fb.get("current_exploit_state", "init")
    detected_primitives = fb.get("detected_primitives", [])
    primitive_confidence = fb.get("primitive_confidence", {})
    primitive_evidence = fb.get("primitive_evidence", {})

    all_stdout = " ".join(
        _coordinator_text((r.get("result") or {}).get("stdout", "")) for r in step_results
    )

    # 至少 probe_success 才记录端点
    if state in ("probe_success", "payload_injected", "gadget_triggered", "oob_received"):
        # 从 HTTP 日志中提取确认可达的端点
        for r in step_results:
            for h in r.get("http_responses") or []:
                status = h.get("status_code", 0)
                url = h.get("url", "")
                if 200 <= status < 400 and url:
                    verif.confirm_endpoint(url)

    # 如果至少 payload_injected，记录 template engine / reflection
    if state in ("payload_injected", "gadget_triggered", "oob_received"):
        if "49" in all_stdout and ("7*7" in all_stdout or "multiply" in all_stdout.lower()):
            verif.confirm("reflection_confirmed", True)
            verif.confirm("template_engine", "jinja2")

    # Record structured primitive knowledge from evaluator
    for pid in detected_primitives:
        conf = primitive_confidence.get(pid, 0.6)
        ev = primitive_evidence.get(pid, "")
        engine_hint = ""
        if "jinja" in all_stdout.lower() or "flask" in all_stdout.lower() or "werkzeug" in all_stdout.lower():
            engine_hint = "jinja2"
        verif.add_working_primitive({
            "primitive_id": pid,
            "confidence": conf,
            "evidence": ev[:200],
            "engine": engine_hint,
        })

    # gadged_triggered/oob_received: record working primitives
    if state in ("gadget_triggered", "oob_received"):
        all_stdout = " ".join(
            _coordinator_text((r.get("result") or {}).get("stdout", "")) for r in step_results
        )
        if any(kw in all_stdout.lower() for kw in ("uid=", "root:", "www-data")):
            verif.add_working_primitive({
                "primitive_id": "command_execution",
                "confidence": 0.95,
                "evidence": "System command output detected in stdout",
                "engine": "",
            })
        if "flag{" in all_stdout.lower() or "htb{" in all_stdout.lower():
            import re
            flag_match = re.search(r'(?:flag|htb|ctf)\{[^}]+\}', all_stdout, re.IGNORECASE)
            if flag_match:
                verif.add_flag(flag_match.group(0))

    # Record payload blacklist from error fingerprint
    error_fp = fb.get("error_fingerprint", "")
    if error_fp == "AllFieldsRequired":
        verif.add_rejected_field("email" if "email" in fb.get("raw_evidence", "") else "username")

    # Record WAF detection
    evidence = fb.get("raw_evidence", "").lower()
    if any(kw in evidence for kw in ("waf", "cloudflare", "modsecurity", "blocked by")):
        verif.confirm("waf_detected", True)

    verif_stats = verif.get_stats()
    if verif_stats["facts_count"] > 0:
        print(
            f"[coordinator] 🔬 已验证事实: {verif_stats['facts_count']} 条 "
            f"(端点:{verif_stats['confirmed_endpoints']}, "
            f"注入点:{verif_stats['injectable_endpoints']}, "
            f"原语:{verif_stats['working_primitives']})"
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
    import time as _time
    _pipeline_start = _time.time()

    settings = get_settings()
    memory = LayeredMemory(settings.memory_dir)
    ws = settings.workspace_dir
    ws.mkdir(parents=True, exist_ok=True)

    reset_verification(settings.memory_dir / "memory" / "verification_memory.json", clear_current_run=True)
    reset_trajectory(settings.memory_dir / "memory" / "exploit_trajectory.json", clear_current_run=True)
    print("[coordinator] run isolation: reset current-run verification facts and trajectory")

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

    feedback: dict[str, Any] | None = None
    last_plan: dict[str, Any] | None = None
    success_log: list[dict[str, Any]] = []
    _retry_iteration_done = False

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
    _SUGGEST_ABORT_MIN_ITER = 4                         # AI 熔断最低迭代次数：前 N 轮强制忽略

    # ── 滑动窗口上下文（防上下文爆炸）────────────────────
    # 保留最近 3 轮的完整执行摘要；更早的只保留 summary 一行。
    _CONTEXT_WINDOW   = 3
    _iter_history: list[dict[str, Any]] = []           # [{iteration, summary, guidance, ok_count}]

    # ── Multi-dimensional progress tracking ──
    _prev_round_state: dict[str, Any] | None = None

    iteration = 0
    while iteration < _iter_budget and iteration < _MAX_HARD_LIMIT:
        iteration += 1
        render_iteration_header(iteration, _iter_budget)

        # ── Planner ────────────────────────────────────────────────────────
        _print_agent_header("planner")
        stage("Planner", "构建攻击链...")
        last_plan = run_planner(
            settings=settings,
            memory=memory,
            confirmed=confirmed,
            feedback=feedback,
            out_path=plan_path,
            llm=llm,
            adapter=adapter,
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
        from agents.validator import _extract_parameter_contract
        parameter_contract = _extract_parameter_contract(confirmed)
        v = run_validator(plan_path, validated_path, prior_feedback=feedback,
                         parameter_contract=parameter_contract)
        val = v.get("validation", {})
        warnings = v.get("warnings") or []
        muted(
            f"passed={val.get('passed')} errors={len(val.get('errors') or [])} "
            f"warnings={len(warnings)} → {validated_path.name}"
        )
        if warnings:
            detail(f"自动修复/提示: {warnings}")
        if not (val.get("passed") if isinstance(val, dict) else True):
            feedback = {
                "from": "validator",
                "iteration": iteration,
                "errors": v["validation"]["errors"],
                "warnings": warnings,
                "hint": "根据校验错误修订 plan.json 结构与安全策略",
            }
            warn(f"验证未通过，反馈规划智能体: {val.get('errors', [])}")
            continue

        # ── Executor ───────────────────────────────────────────────────────
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

        # ── GoalVerifier: deterministic flag scan BEFORE Evaluator ──────────
        # Runs first so a verified flag capture skips the Evaluator LLM call
        # and terminates immediately — no wasted tokens, no [FAILED] override.
        from core.goal_verifier import verify_goal
        goal_verification = verify_goal(exec_out, plan=last_plan)

        if goal_verification["verified"]:
            # Build a minimal feedback block directly (Evaluator is skipped)
            feedback = {
                "repro_success": True,
                "success_source": "goal_verifier",
                "goal_verification": goal_verification,
                "current_exploit_state": "objective_verified",
                "should_continue": False,
                "suggest_abort": True,
                "is_milestone": False,
                "confidence": 1.0,
                "summary": (
                    f"VERIFIED FLAG CAPTURED: {goal_verification['artifact']} "
                    f"from HTTP response body (step {goal_verification['step_id']})"
                ),
                "last_execution_raw": _build_last_exec_raw(exec_out),
            }
            print(f"[coordinator] 🏆 GoalVerifier: flag confirmed in response body "
                  f"(step {goal_verification['step_id']}, {goal_verification['source_kind']}) "
                  f"— Evaluator skipped")

            # Render victory screen and terminate immediately
            from ui.victory_screen import render_victory_screen
            render_victory_screen(
                verification=goal_verification,
                target_info=confirmed.get("target_context", {}),
                plan=last_plan,
                step_results=step_results,
                runtime_sec=_time.time() - _pipeline_start,
                workspace_dir=settings.workspace_dir,
                challenge_name=challenge_name,
            )
            return 0  # IMMEDIATE STOP — Evaluator never called

        # ── NOT verified — fall through to Evaluator ────────────────────────
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

        fb = run_evaluator(
            settings=settings,
            memory=memory,
            confirmed=confirmed,
            plan=last_plan,
            exec_out=exec_out,
            feedback_path=feedback_path,
            llm=llm,
            adapter=adapter,
        )
        feedback = fb

        # 注入上一轮原始执行结果到 feedback，供 Planner 参考
        fb["last_execution_raw"] = _build_last_exec_raw(exec_out)
        print(f"[coordinator] 📋 已注入原始执行数据到 feedback ({len(fb['last_execution_raw'].get('steps', []))} 步)")
        structured_feedback_parts: list[str] = []
        if isinstance(fb.get("failure_analysis"), dict) and fb.get("failure_analysis"):
            structured_feedback_parts.append(f"failure_analysis={fb['failure_analysis']}")
        if isinstance(fb.get("possible_next_direction"), list) and fb.get("possible_next_direction"):
            structured_feedback_parts.append(
                "possible_next_direction=" + ", ".join(str(x) for x in fb["possible_next_direction"][:5])
            )
        if structured_feedback_parts:
            existing_feedback = fb.get("feedback_for_planner") or ""
            structured_block = "【结构化失败反馈】\n" + "\n".join(structured_feedback_parts)
            fb["feedback_for_planner"] = (existing_feedback + "\n\n" + structured_block).strip()
            feedback = fb
            print("[coordinator] structured evaluator feedback attached for next Planner")


        # ── Exploit Trajectory Recording ──
        _record_trajectory_entry(iteration, fb, last_plan, exec_out, step_results)

        # ── Primitive Learning Engine ──
        _record_primitive_learning(fb, last_plan, step_results)

        # ── Verification Facts Recording ──
        _record_verified_facts(fb, step_results)

        render_evaluator_feedback(fb)

        # ── AI 主动熔断（suggest_abort） — 前 N 轮强制忽略 ──────
        if fb.get("suggest_abort"):
            if iteration < _SUGGEST_ABORT_MIN_ITER:
                print(f"[coordinator] ⚠️ AI 建议熔断，但迭代次数({iteration}) < 最低阈值({_SUGGEST_ABORT_MIN_ITER})，强制忽略")
                fb["suggest_abort"] = False
            else:
                print("✗ AI 判断已无利用可能")
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

        # ── Multi-dimensional progress detection ────────────────────────
        has_progress, progress_reasons = _compute_progress_signals(
            fb, last_plan, step_results, _prev_round_state,
        )
        _prev_round_state = _snapshot_round_state(fb, last_plan, step_results)

        if progress_reasons:
            progress_label = "; ".join(progress_reasons[:4])
            print(f"[coordinator] 📈 多维进展信号: {progress_label}")

        # ── Classify progress signals: only hard evidence resets no-progress ──
        # Hard evidence: new_primitive, deterministic response_delta,
        # parameter_reached, deterministic capability/objective evidence.
        # verified_facts is NOT included — facts lack source/provenance tracking.
        _hard_evidence_prefixes = {
            "new_primitive",
        }
        # Soft signals (never reset alone): state_advance, payload_mutation,
        #   progress_score, exploit_momentum, stp_increase, evaluator_milestone,
        #   ok_count, new_endpoint, new_status_code, initial_round,
        #   verified_facts, confidence_increase, partial_progress
        _hard_reasons = [r for r in progress_reasons
                         if any(r.startswith(p) for p in _hard_evidence_prefixes)]
        _has_hard_evidence = bool(_hard_reasons)

        # ── 衰减式里程碑奖励（Decaying Extension）────────────────────────
        if fb.get("is_milestone"):
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
        elif has_progress:
            if _has_hard_evidence:
                _no_progress_streak = 0
                print(f"[coordinator] 🔄 硬证据进展 ({'; '.join(_hard_reasons[:3])})，重置无进展计数")
            else:
                _no_progress_streak += 1
                print(f"[coordinator] ⚙️ 仅软信号/执行健康 ({progress_label})，不算进展 "
                      f"| 无进展计数: {_no_progress_streak}/{_NO_PROGRESS_ABORT}")
        else:
            _no_progress_streak += 1
            print(f"[coordinator] ⏳ 无任何进展计数: {_no_progress_streak}/{_NO_PROGRESS_ABORT}")

        # ── 连续无进展主动放弃 ────────────────────────────────────────────
        if _no_progress_streak >= _NO_PROGRESS_ABORT:
            fail(f"[coordinator] 连续 {_NO_PROGRESS_ABORT} 轮无任何多维进展信号，主动终止迭代。")
            break

        # ── 熔断器逻辑（论文 §3.3 Long-Term Memory & 纠偏机制）────────────
        if fb.get("repro_success"):
            _consecutive_failures = 0
            _breaker_triggered    = False
            _error_fingerprints.clear()
        else:
            fp = _extract_step_error_fingerprint(step_results)
            if _has_execution_failure(step_results, fb):
                _consecutive_failures += 1
                _error_fingerprints.append(fp)
                if len(_error_fingerprints) > _BREAKER_THRESHOLD:
                    _error_fingerprints.pop(0)
            else:
                _consecutive_failures = 0
                _error_fingerprints.clear()
            print(f"[coordinator] execution failure streak: {_consecutive_failures}/{_BREAKER_THRESHOLD} | fingerprint: {fp}")

        # Stagnation check: same error fingerprint repeated across the window
        _stagnating = (
            len(_error_fingerprints) >= _BREAKER_THRESHOLD
            and len(set(_error_fingerprints)) == 1
            and _error_fingerprints[0] != "no_execution_error"
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
            # ── EPE Momentum Anti-Regression ──────────────────────────────
            if fb.get("exploit_momentum"):
                cur_ps = fb.get("progress_score", 0.0)
                prev_ps = _prev_round_state.get("progress_score", 0.0) if _prev_round_state else 0.0
                suggested = fb.get("suggested_next_action", "DEEP_DIVE")
                momentum_injection = (
                    "\n\n"
                    "╔══════════════════════════════════════════════════════════════╗\n"
                    f"║  🔵 EPE Momentum Active — exploit chain continuity enforced  ║\n"
                    "╚══════════════════════════════════════════════════════════════╝\n"
                    f"[progress_score={cur_ps:.2f} | Δ={cur_ps - prev_ps:+.2f} | action={suggested}]\n"
                    "Side-effect signals detected — payload is perturbing backend state.\n"
                    "🛑 ANTI-REGRESSION CONSTRAINT:\n"
                    "  1. DO NOT restart fuzzing from scratch\n"
                    "  2. DO NOT pivot to a different vulnerability type\n"
                    "  3. DO NOT abandon the current injection point/endpoint\n"
                    "  4. STAY on the current chain and incrementally escalate payload complexity\n"
                    "  5. Refine: add more stages, tune encoding, or amplify the side-effect\n"
                )
                existing = fb.get("feedback_for_planner") or ""
                fb["feedback_for_planner"] = momentum_injection + "\n" + existing
                feedback = fb
                print(f"[coordinator] 🔵 EPE 动量锁定: 禁止路径回退 (score={cur_ps:.2f})")

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
            if iteration < _SUGGEST_ABORT_MIN_ITER:
                warn(
                    f"评估建议终止迭代，但迭代次数({iteration}) < 最低阈值({_SUGGEST_ABORT_MIN_ITER})，强制忽略"
                )
                fb["should_continue"] = True
            else:
                warn("评估建议终止迭代。")
                break

    # ── 迭代循环结束 — 唤醒全局复盘导师 ───────────────────────────
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
