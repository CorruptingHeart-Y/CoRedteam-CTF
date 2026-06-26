"""
Global Consolidator — 全局复盘智能体 (Dual-Model Architecture)

在微观 4-agent 闭环 (Planner->Validator->Executor->Evaluator) 耗尽迭代预算后，
唤醒一个使用独立高级大模型（GPT-4o / Claude-3.5）的"导师智能体"，
对整个打靶轨迹进行跨任务战略级经验提炼（Verbal Reinforcement Learning），
并将提炼出的 patterns 和 techs 持久化写入永久记忆库。

论文对齐：Reflexion / Voyager / ExpeL — LLM-Driven Experiential Learning
"""

from __future__ import annotations

import json
import os
import re
import sys
import yaml
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.llm_client import SchemaValidationError

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# ═══════════════════════════════════════════════════════════════════
# Expert System Prompt — 原封不动的全局复盘导师指令
# ═══════════════════════════════════════════════════════════════════

CONSOLIDATOR_SYSTEM_PROMPT = """你是一个顶级的红队渗透测试导师与架构师。
你的初级特工刚刚结束了一次长达数轮的自动化打靶任务。现在，请你阅读它最后留下的执行计划(plan)、沙箱输出(execution_result)、实时反馈(feedback)以及初始情报(confirmed_vuln)。

你的核心任务不是纠正语法，而是进行"跨任务的战略级经验提炼 (Experiential Learning)"：
1. 为什么它卡在了死胡同？它是被哪种安全机制（如 WAF、特定依赖库的底层解析机制）拦截了？
2. 它是否使用了陈旧无效的 Payload（如 alg:none、#号截断）？
3. 从这次失败（或成功）中，我们应该向系统的全局记忆库中写入什么"思想钢印"，以确保未来的特工面对同类组件时，绝对不会犯同样的错，并直接使用最高维的打法？

【[!!] 沙箱冲突诊断 — 最高优先级】

你的特工运行在一个受限沙箱中，有以下两类拦截层：
  - Validator (AST import 检查)：拦截 import os / pickle / subprocess 等
  - Executor (运行时正则扫描)：拦截代码文本中的 os.system( / os.popen( / subprocess.run( / __import__( 等字面量

当你在执行报告中看到以下信号时，必须诊断出"沙箱约束 vs 攻击手法"的冲突：
  - "[SECURITY] PYTHON_BLOCKED pattern='os_system_exec'" -> Planner 写了 os.system 字面量
  - "[SECURITY] PYTHON_BLOCKED pattern='dynamic_import'" -> Planner 尝试 __import__() 绕过
  - Validator passed=True 但 Executor 有 SECURITY_BLOCKED -> 说明是通过了 import 检查但代码文本被正则拦截
  - 同一类 PYTHON_BLOCKED 出现 ≥ 2 轮 -> Planner 陷入了死循环，需要你介入

针对每种冲突，你必须在 techs 中输出一条具有完整可执行代码的 technique，教会 Planner 如何在不触发拦截的前提下构造 payload。例如：
  - pickle 反序列化攻击 -> 用 struct/bytes 硬编码 pickle 操作码字节序列，0 行 import，0 个被拦截字面量
  - CRLF + Memcached 协议注入 -> 用 bytes 构造 HTTP cookie 原始字节，用 raw_request() 发送
  - 需要执行系统命令 -> 使用 redteam_sdk.OOBReceiver 带外反连，不要在代码中写 os.system

【[!!] 高级代码 Patch 固化 — executable_patch 强制输出】

你必须在每个 tech 条目中额外输出一个 `executable_patch` 字段。这不是文字描述，而是一段完整的、可以直接复制到 Python step 中运行的代码块。
该代码块必须：
  1. 仅使用白名单模块（requests, json, re, base64, hashlib, hmac, struct, binascii, bs4, jwt, html, xml, lxml, Crypto, cryptography, time, datetime, random, string, itertools, functools, collections, copy, io, pathlib, threading, urllib, urllib3, httpx, http, redteam_sdk, typing, dataclasses, enum, abc, codecs, unicodedata, math, decimal, fractions）
  2. 零行 import 黑名单模块（os, subprocess, socket, pickle, ctypes, cffi, importlib, builtins 等）
  3. 代码文本中不出现 os.system( / os.popen( / subprocess.run( / __import__( 等被拦截字面量
  4. 包含完整的 import 语句和入口逻辑，Planner 可直接复制使用
  5. 如果是绕过类 payload（如手搓 pickle opcode 字节流），必须包含完整的构造与发送逻辑

【[!!] YAML 武器库自愈演进 — CWE 模板增量/创建指令】

你需要根据当前打靶目标的 CWE 编号，决定对 b/templates/ 武器库的操作：
  1. 如果提炼出的 payload 对应已知 CWE（如 CWE-502），且 b/templates/builtin/cwe-502-*.yaml 已存在 -> 在该 YAML 的 payload_templates 列表中追加新条目
  2. 如果当前目标的漏洞类别在 b/templates/ 中完全没有对应规则 -> 生成一个全新的 cwe-xxx-<name>.yaml 文件骨架
  3. 每个 payload_templates 条目必须包含: name, description, lang, template, tags, source, severity 字段

请严格输出以下 JSON 格式：
{
  "diagnosis": "对整个打靶轨迹的深度剖析（指出死因、被忽略的沙箱约束、以及为什么 Planner 反复犯同一类错误）",
  "memory_patch": {
    "patterns": [
      {
        "error_type": "提取高度泛化的错误指纹（如 SECURITY_BLOCKED: os_system_exec — Planner tried to write os.system literal）",
        "root_cause": "深层死因（如 Planner 不知道 Executor 会正则扫描代码文本，以为只检查 import 语句）",
        "fix_suggestion": "【[!!] 绝对禁令与新战术】下次绝对不能怎么做，必须用什么思路替代"
      }
    ],
    "techs": [
      {
        "vulnerability": "提取有效的攻击手法名称（如 pickle-deserialization-via-raw-bytes）",
        "cwe_ids": ["CWE-502"],
        "tags": ["关联的技术栈标签，如 pickle, deserialization, crlf, memcached, sandbox-bypass"],
        "payload_template": "完整可执行的 Python 代码片段（必须只用 requests/json/struct/base64/bs4 等白名单模块），供 Planner 直接复制使用",
        "executable_patch": "完整的、可直接运行的 Python 代码块，包含所有 import 和入口逻辑，零黑名单模块，零被拦截字面量。这是真正会被执行的代码！",
        "description": "该高阶手法的适用场景、规避了哪个沙箱拦截规则、以及为什么这个做法能通过 Validator + Executor 双重检查"
      }
    ],
    "yaml_operations": [
      {
        "cwe_id": "CWE-502",
        "operation": "update",
        "target_file": "b/templates/builtin/cwe-502-deserialization.yaml",
        "new_payload_name": "pickle-opcode-bypass-via-struct",
        "description": "基于 struct 手搓 pickle 操作码字节流的沙箱安全手法"
      }
    ]
  }
}"""


# ═══════════════════════════════════════════════════════════════════
# Helper: collect battle reports from workspace
# ═══════════════════════════════════════════════════════════════════

def _collect_reports(workdir: Path) -> dict[str, Any]:
    """从工作区读取最后一轮的战报文件，组装为完整上下文。

    按优先级尝试读取：
      - plan.json (最终攻击计划)
      - execution_result.json (沙箱执行输出)
      - feedback.json (评估反馈)
      - confirmed_vuln.json (初始情报)
    """
    reports: dict[str, Any] = {}

    def _safe_read(path: Path) -> dict[str, Any] | str | None:
        try:
            raw = path.read_text(encoding="utf-8")
            return json.loads(raw)
        except (json.JSONDecodeError, OSError):
            try:
                if path.exists():
                    return path.read_text(encoding="utf-8")
                return None
            except OSError:
                return None

    # 1. 初始情报（从 data/ 或工作区查找）
    confirmed_candidates = [
        workdir / "confirmed_vuln.json",
        _ROOT / "data" / "confirmed_vuln.json",
    ]
    for p in confirmed_candidates:
        data = _safe_read(p)
        if data:
            reports["confirmed_vuln"] = data
            break

    # 2. 最终攻击计划
    plan = _safe_read(workdir / "plan.json")
    if plan:
        reports["plan"] = plan

    # 3. 执行结果
    exec_out = _safe_read(workdir / "execution_result.json")
    if exec_out:
        # 精简 step_results 只保留摘要，避免 token 爆炸
        if isinstance(exec_out, dict):
            step_results = exec_out.get("step_results") or []
            slim_steps = []
            for sr in step_results:
                rr = sr.get("result") or {}
                slim_steps.append({
                    "step_id":    sr.get("step_id"),
                    "type":       sr.get("type"),
                    "purpose":    sr.get("purpose"),
                    "ok":         rr.get("ok"),
                    "exit_code":  rr.get("exit_code"),
                    "stdout":     (rr.get("stdout", "") or "")[:800],
                    "stderr":     (rr.get("stderr", "") or "")[:500],
                })
            exec_out["step_results"] = slim_steps
        reports["execution_result"] = exec_out

    # 4. 评估反馈
    fb = _safe_read(workdir / "feedback.json")
    if fb:
        reports["feedback"] = fb

    # 5. 收集滑动窗口中的历史摘要（如果有）
    if isinstance(fb, dict) and fb.get("_collapsed_history"):
        reports["historical_context"] = fb["_collapsed_history"]

    # 6. 收集 success_log（如果有）
    if isinstance(fb, dict) and fb.get("success_log"):
        reports["success_log"] = fb["success_log"]

    return reports


def _build_consolidator_context(reports: dict[str, Any]) -> str:
    """将收集到的案卷拼接为紧凑的上下文，供高级 LLM 审阅。"""

    parts: list[str] = []

    # ── 初始情报摘要 ──
    confirmed = reports.get("confirmed_vuln")
    if isinstance(confirmed, dict):
        vulns = confirmed.get("vulnerabilities", [])
        tc = confirmed.get("target_context", {})
        parts.append("═══ 初始情报 (confirmed_vuln) ═══")
        parts.append(f"目标: {tc.get('base_url', '?')} | 应用: {tc.get('app_name', '?')}")
        for v in vulns[:5]:
            parts.append(
                f"  [{v.get('severity', '?')}] {v.get('cwe_id', '?')} {v.get('title', '')}: "
                f"{v.get('description', '')[:300]}"
            )

    # ── 最终攻击计划摘要 ──
    plan = reports.get("plan")
    if isinstance(plan, dict):
        steps = plan.get("steps") or []
        parts.append("\n═══ 最终攻击计划 (plan) ═══")
        parts.append(f"plan_id={plan.get('plan_id')} rationale={plan.get('rationale', '')[:200]}")
        for st in steps[:15]:
            parts.append(
                f"  step[{st.get('id')}] {st.get('type')} {st.get('purpose', '')} "
                f"status={st.get('status')}"
            )
        history = plan.get("history_state")
        if isinstance(history, dict):
            parts.append(f"  历史轨迹: tried={history.get('tried_payloads', [])} "
                         f"fails={history.get('failed_reasons', [])}")

    # ── 执行结果摘要 ──
    exec_out = reports.get("execution_result")
    security_blocks: list[str] = []
    if isinstance(exec_out, dict):
        step_results = exec_out.get("step_results") or []
        parts.append("\n═══ 沙箱执行结果 (execution_result) ═══")
        for sr in step_results:
            stderr = sr.get('stderr', '')
            # Detect security blocks from stderr
            if '[SECURITY_BLOCKED]' in stderr or 'PYTHON_BLOCKED' in stderr:
                security_blocks.append(
                    f"  step[{sr.get('step_id')}] SECURITY_BLOCKED: {stderr[:300]}"
                )
            parts.append(
                f"  step[{sr.get('step_id')}] ok={sr.get('ok')} "
                f"exit={sr.get('exit_code')} "
                f"stdout={sr.get('stdout', '')[:200]} "
                f"stderr={stderr[:200]}"
            )
        # Surface security blocks prominently so the mentor can't miss them
        if security_blocks:
            parts.append("\n═══ [!!] 安全拦截汇总（必须诊断！） ═══")
            parts.extend(security_blocks)

    # ── 评估反馈 ──
    fb = reports.get("feedback")
    if isinstance(fb, dict):
        parts.append("\n═══ 评估反馈 (feedback) ═══")
        parts.append(f"repro_success={fb.get('repro_success')} "
                     f"confidence={fb.get('confidence')} "
                     f"evidence_level={fb.get('evidence_level', '?')} "
                     f"is_milestone={fb.get('is_milestone')} "
                     f"suggest_abort={fb.get('suggest_abort')}")
        summary = fb.get("summary", "")
        if summary:
            parts.append(f"  summary: {summary}")
        analysis = fb.get("analysis") or {}
        if isinstance(analysis, dict):
            parts.append(f"  what_happened: {analysis.get('what_happened', '')[:400]}")
            parts.append(f"  guidance: {analysis.get('guidance', '')[:400]}")
        fb_planner = fb.get("feedback_for_planner", "")
        if fb_planner:
            parts.append(f"  -> planner: {fb_planner[:500]}")
        # 注入环境故障信号，供导师诊断（即使当前已熔断，仍保留上下文供未来分析）
        env_failure = fb.get("environment_failure")
        if env_failure:
            parts.append(f"  ⚠️ environment_failure=True reason={fb.get('reason', 'unknown')}")

    # ── 历史上下文 ──
    hist = reports.get("historical_context")
    if hist:
        parts.append(f"\n═══ 历史迭代摘要 ═══\n{hist}")

    # ── 成功日志 ──
    success_log = reports.get("success_log")
    if success_log and isinstance(success_log, list):
        parts.append(f"\n═══ 成功日志 ({len(success_log)} entries) ═══")
        for s in success_log[-5:]:
            parts.append(f"  iter={s.get('iteration')} conf={s.get('confidence')} "
                         f"summary={s.get('summary', '')}")

    return "\n".join(parts)


# ═══════════════════════════════════════════════════════════════════
# Independent LLM client for the Consolidator
# ═══════════════════════════════════════════════════════════════════

class _ConsolidatorClient:
    """独立的大模型客户端，使用 CONSOLIDATOR_ 环境变量配置。"""

    def __init__(self, workdir: Path | None = None, debug_label: str = "raw") -> None:
        # 强制重载 b/.env，防止父目录 .env 里的 BLSC 配置污染 env
        from dotenv import load_dotenv as _ld
        _ld(_ROOT.parent / ".env")
        _ld(_ROOT / ".env", override=True)

        api_key = os.getenv("CONSOLIDATOR_API_KEY", "").strip()
        base_url = os.getenv("CONSOLIDATOR_BASE_URL", "").strip()
        model = os.getenv("CONSOLIDATOR_MODEL", "").strip()

        # CONSOLIDATOR_ 配置完全由用户 .env 控制，不做自动旁路切换。
        # 用户为全局复盘专门选定了模型和端点，尊重其选择。

        if not api_key:
            raise RuntimeError(
                "CONSOLIDATOR_API_KEY 未配置。请在 .env 中设置 CONSOLIDATOR_API_KEY、"
                "CONSOLIDATOR_BASE_URL、CONSOLIDATOR_MODEL 以启用全局复盘功能。"
            )
        if not model:
            raise RuntimeError("CONSOLIDATOR_MODEL 未配置")

        from openai import OpenAI
        import httpx

        self._model = model
        self._base_url = base_url
        self._api_key = api_key
        self._workdir = workdir
        self._debug_label = debug_label
        self._client = OpenAI(
            api_key=api_key,
            base_url=base_url or None,
            max_retries=1,
            timeout=httpx.Timeout(300.0, connect=15.0),
        )

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        import re
        import time
        import openai

        max_retries = 3
        last_exception: Exception | None = None

        for attempt in range(max_retries):
            try:
                resp = self._client.chat.completions.create(
                    model=self._model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    temperature=0.3,
                    max_tokens=4096,
                    timeout=300.0,
                )
                content = resp.choices[0].message.content or ""

                # ── DIAG: Consolidator API response metadata ──
                finish = getattr(resp.choices[0], "finish_reason", "N/A")
                usage = getattr(resp, "usage", None)
                reasoning = getattr(resp.choices[0].message, "reasoning_content", None)
                print(f"[consolidator] DIAG — finish_reason: {finish}")
                print(f"[consolidator] DIAG — content length: {len(content)} chars / {len(content.encode('utf-8'))} bytes")
                if usage is not None:
                    print(f"[consolidator] DIAG — usage: prompt_tokens={usage.prompt_tokens}, "
                          f"completion_tokens={usage.completion_tokens}, total_tokens={usage.total_tokens}")
                if reasoning is not None:
                    print(f"[consolidator] DIAG — reasoning_content length: {len(reasoning)} chars")
                print(f"[consolidator] DIAG — content[:500]: {content[:500]!r}")

                # Save raw response for debugging
                if self._workdir is not None:
                    try:
                        debug_path = self._workdir / f"debug_consolidator_{self._debug_label}.txt"
                        debug_path.write_text(content, encoding="utf-8")
                    except Exception:
                        pass

                # Parse JSON (handle potential markdown wrapping)
                text = content.strip()
                text = re.sub(r'```json\s*', '', text)
                text = re.sub(r'\s*```', '', text)
                try:
                    result = json.loads(text)
                    if isinstance(result, str):
                        raise SchemaValidationError(
                            f"[consolidator] LLM 返回了纯字符串而非 dict: {result[:200]}..."
                        )
                    return result
                except json.JSONDecodeError:
                    m = re.search(r"(\{[\s\S]*\}|\[[\s\S]*\])", text)
                    if m:
                        result = json.loads(m.group(0))
                        if isinstance(result, str):
                            raise SchemaValidationError(
                                f"[consolidator] LLM 返回了纯字符串而非 dict: {result[:200]}..."
                            )
                        return result
                    raise

            except (json.JSONDecodeError, ValueError, SchemaValidationError) as e:
                last_exception = e
                print(f"[consolidator] [WARN] JSON 解析失败，重试 {attempt + 1}/{max_retries}: {e}")
                continue

            except (openai.APITimeoutError, openai.APIConnectionError,
                    openai.RateLimitError, openai.InternalServerError) as e:
                last_exception = e
                wait = 2 ** attempt
                print(f"[consolidator] [WARN] API 网络层错误，{wait}s 后重试 ({attempt + 1}/{max_retries}): {e}")
                time.sleep(wait)
                continue

        raise last_exception or RuntimeError("Consolidator LLM 调用失败")

    def complete_text(self, system: str, user: str) -> str:
        """调用 LLM 返回纯文本（非 JSON 模式），用于代码生成等场景。"""
        import time
        import openai

        for attempt in range(3):
            try:
                resp = self._client.chat.completions.create(
                    model=self._model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    temperature=0.3,
                    max_tokens=4096,
                    timeout=300.0,
                )
                text = (resp.choices[0].message.content or "").strip()

                # Save raw response for debugging
                if self._workdir is not None:
                    try:
                        debug_path = self._workdir / f"debug_consolidator_{self._debug_label}.txt"
                        debug_path.write_text(text, encoding="utf-8")
                    except Exception:
                        pass

                # Strip markdown code fences if present
                text = re.sub(r'^```(?:python)?\s*\n?', '', text)
                text = re.sub(r'\n?```\s*$', '', text)
                return text
            except (openai.APITimeoutError, openai.APIConnectionError,
                    openai.RateLimitError, openai.InternalServerError) as e:
                wait = 2 ** attempt
                print(f"[consolidator] [WARN] 纯文本调用失败，{wait}s 后重试 ({attempt + 1}/3): {e}")
                time.sleep(wait)
                continue
            except Exception as e:
                print(f"[consolidator] [WARN] 纯文本调用失败，重试 {attempt + 1}/3: {type(e).__name__}: {e}")
                continue
        return ""


# ═══════════════════════════════════════════════════════════════════
# Memory persistence — 直接写回 JSON 文件（硬持久化）
# ═══════════════════════════════════════════════════════════════════

def _persist_patterns_to_json(memory_dir: Path, patterns: list[dict[str, Any]]) -> int:
    """将全局复盘提炼的 patterns 追加写入 b/memory/pattern.json。

    JSON 结构：{"patterns": [...]}
    每个新 pattern 会被追加到数组末尾。若 error_type 完全相同则跳过。
    """
    pattern_file = memory_dir / "pattern.json"
    existing: list[dict[str, Any]] = []
    existing_error_types: set[str] = set()

    if pattern_file.exists():
        try:
            data = json.loads(pattern_file.read_text(encoding="utf-8"))
            existing = data.get("patterns") or data.get("pattern") or []
            for p in existing:
                et = p.get("error_type", "")
                if et:
                    existing_error_types.add(et)
        except (json.JSONDecodeError, OSError):
            existing = []

    added = 0
    for p in patterns:
        error_type = p.get("error_type", "").strip()
        if not error_type:
            continue
        if error_type in existing_error_types:
            print(f"[consolidator] [SKIP] pattern 已存在，跳过: {error_type[:60]}")
            continue
        existing.append({
            "id": f"consolidator_{hash(error_type) & 0xFFFF:04x}",
            "error_type": error_type,
            "root_cause": p.get("root_cause", ""),
            "fix_suggestion": p.get("fix_suggestion", ""),
        })
        existing_error_types.add(error_type)
        added += 1

    if added:
        pattern_file.write_text(
            json.dumps({"patterns": existing}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"[consolidator] [OK] {added} 条 pattern 已持久化 -> {pattern_file}")

    return added


def _persist_techs_to_json(memory_dir: Path, techs: list[dict[str, Any]]) -> int:
    """将全局复盘提炼的 techs 追加写入 b/memory/tech.json。

    JSON 结构：{"payload_templates": [...], "commands": [...], "scripts": [...]}
    新条目追加到 payload_templates 数组。通过指纹去重。
    """
    from core.payload_registry import PayloadRegistry

    tech_file = memory_dir / "tech.json"
    registry = PayloadRegistry(memory_dir)

    existing_data: dict[str, Any] = {}
    if tech_file.exists():
        try:
            existing_data = json.loads(tech_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            existing_data = {}

    existing_payloads = existing_data.get("payload_templates") or []
    added = 0
    for t in techs:
        name = t.get("vulnerability", "").strip()
        payload = t.get("payload_template", "").strip()
        if not name or not payload:
            continue

        entry = {
            "name": name,
            "context": t.get("description", ""),
            "lang": "python",
            "template": payload,
            "executable_patch": t.get("executable_patch", ""),
            "description": t.get("description", ""),
            "source": "consolidator",
            "cwe_ids": t.get("cwe_ids", []),
            "tags": t.get("tags", []),
            "severity": "critical",
        }

        if registry.is_duplicate(entry):
            print(f"[consolidator] [SKIP]  tech 指纹重复，跳过: {name[:60]}")
            continue

        registry.register(entry)
        existing_payloads.append(entry)
        added += 1

    if added:
        existing_data["payload_templates"] = existing_payloads
        tech_file.write_text(
            json.dumps(existing_data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"[consolidator] [OK] {added} 条 tech 已持久化 -> {tech_file}")

    return added


# ═══════════════════════════════════════════════════════════════════
# YAML Weapon Library — Self-Healing Incremental / From-Scratch Generation
# ═══════════════════════════════════════════════════════════════════

_YAML_TEMPLATE_SKELETON = """metadata:
  id: {template_id}
  name: {name}
  cwe_ids:
{tags_block}
  target_type: generic
  tags:
{tags_yaml}
  author: co-redteam-consolidator
  severity: critical
initial_prechecks: []

payload_templates:
{payloads_yaml}
"""


def _normalize_cwe_slug(cwe_id: str) -> str:
    """CWE-502 -> cwe-502"""
    return cwe_id.lower().replace("_", "-").strip()


def _find_existing_yaml_for_cwe(templates_dir: Path, cwe_id: str) -> Path | None:
    """在 templates 目录树中查找匹配 CWE 编号的已有 YAML 文件。"""
    if not templates_dir.exists():
        return None
    slug = _normalize_cwe_slug(cwe_id)
    for yf in templates_dir.rglob("*.yaml"):
        if slug in yf.stem.lower():
            return yf
    return None


def _append_payload_to_yaml(yaml_path: Path, payload_entry: dict[str, Any]) -> bool:
    """向已有 YAML 文件的 payload_templates 列表追加一条新条目。

    Args:
        yaml_path: 目标 YAML 文件路径
        payload_entry: 包含 name, description, lang, template, tags, source, severity 的字典

    Returns:
        True 如果成功写入
    """
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except (yaml.YAMLError, OSError) as e:
        print(f"[consolidator] [WARN] YAML 读取失败 {yaml_path}: {e}")
        return False

    if not isinstance(data, dict):
        data = {}

    existing: list[dict[str, Any]] = data.get("payload_templates") or []
    # 去重：同名 + 同 template 跳过
    sig = f"{payload_entry.get('name', '')}::{payload_entry.get('template', '')}"
    for ep in existing:
        ep_sig = f"{ep.get('name', '')}::{ep.get('template', '')}"
        if ep_sig == sig:
            print(f"[consolidator] [SKIP]  YAML payload 已存在，跳过: {payload_entry.get('name', '')[:60]}")
            return False

    new_entry = {
        "name": payload_entry.get("name", ""),
        "description": payload_entry.get("description", ""),
        "lang": payload_entry.get("lang", "python"),
        "template": payload_entry.get("template", ""),
        "tags": payload_entry.get("tags", []),
        "source": payload_entry.get("source", "consolidator"),
        "severity": payload_entry.get("severity", "critical"),
    }
    existing.append(new_entry)
    data["payload_templates"] = existing

    try:
        with open(yaml_path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        print(f"[consolidator] [OK] YAML payload 已追加至 {yaml_path.name}: {new_entry['name']}")
        return True
    except OSError as e:
        print(f"[consolidator] [WARN] YAML 写入失败 {yaml_path}: {e}")
        return False


def _create_new_cwe_yaml(
    templates_dir: Path,
    cwe_id: str,
    cwe_name: str,
    description: str,
    payload_entries: list[dict[str, Any]],
) -> Path | None:
    """从零创建全新的 cwe-xxx-<name>.yaml 攻防行为模型文件。

    Args:
        templates_dir: b/templates/ 根目录
        cwe_id: CWE 编号 (如 CWE-918)
        cwe_name: 人类可读的漏洞名 (如 Server-Side Request Forgery)
        description: 该漏洞类别的描述
        payload_entries: payload_templates 条目列表

    Returns:
        创建的文件路径，失败返回 None
    """
    slug = _normalize_cwe_slug(cwe_id)
    # 从 cwe_name 构造安全的文件名片段
    safe_name = re.sub(r"[^\w-]", "-", cwe_name.lower().replace(" ", "-").replace("_", "-"))
    safe_name = re.sub(r"-{2,}", "-", safe_name).strip("-")
    template_id = f"{slug}-{safe_name}" if safe_name else slug

    target_dir = templates_dir / "builtin"
    target_dir.mkdir(parents=True, exist_ok=True)
    output_path = target_dir / f"{template_id}.yaml"

    if output_path.exists():
        print(f"[consolidator] [WARN] YAML 已存在，转增量模式: {output_path.name}")
        for pe in payload_entries:
            _append_payload_to_yaml(output_path, pe)
        return output_path

    # 构造 YAML 内容
    cwe_ids_list = [cwe_id]
    tags = [slug, safe_name] if safe_name else [slug]
    # 从 payload_entries 收集 tags
    for pe in payload_entries:
        for t in (pe.get("tags") or []):
            if t not in tags:
                tags.append(t)

    tags_block = "\n".join(f"  - {c}" for c in cwe_ids_list)
    tags_yaml = "\n".join(f"  - {t}" for t in tags)

    payloads_yaml_lines: list[str] = []
    for pe in payload_entries:
        payloads_yaml_lines.append(f"  - name: {pe.get('name', 'unnamed-payload')}")
        payloads_yaml_lines.append(f"    description: {pe.get('description', '')}")
        payloads_yaml_lines.append(f"    lang: {pe.get('lang', 'python')}")
        # 多行 template 需要缩进处理
        template_text = pe.get("template", "")
        if "\n" in template_text:
            payloads_yaml_lines.append("    template: |")
            for line in template_text.split("\n"):
                payloads_yaml_lines.append(f"      {line}")
        else:
            payloads_yaml_lines.append(f"    template: {template_text}")
        pe_tags = pe.get("tags", [])
        if pe_tags:
            payloads_yaml_lines.append("    tags:")
            for t in pe_tags:
                payloads_yaml_lines.append(f"      - {t}")
        payloads_yaml_lines.append(f"    source: {pe.get('source', 'consolidator')}")
        payloads_yaml_lines.append(f"    severity: {pe.get('severity', 'critical')}")

    payloads_yaml = "\n".join(payloads_yaml_lines)

    content_block = ""
    if description:
        content_block = f"content: |-\n  {description}\n"

    yaml_text = f"""metadata:
  id: {template_id}
  name: {cwe_name}
  cwe_ids:
{tags_block}
  target_type: generic
  tags:
{tags_yaml}
  author: co-redteam-consolidator
  severity: critical
initial_prechecks: []
{content_block}
payload_templates:
{payloads_yaml}
"""

    try:
        output_path.write_text(yaml_text, encoding="utf-8")
        print(f"[consolidator] [OK] 全新 YAML 武器库文件已创建: {output_path.name}")
        return output_path
    except OSError as e:
        print(f"[consolidator] [WARN] YAML 创建失败 {output_path}: {e}")
        return None


def _sync_to_yaml_weapon_library(
    templates_dir: Path,
    memory_patch: dict[str, Any],
) -> list[str]:
    """根据 memory_patch 中的 yaml_operations 指令执行 YAML 武器库演进。

    同时，如果 memory_patch.techs 中包含 executable_patch，将其嵌入对应模板。

    Returns:
        受影响的 YAML 文件路径列表（用于日志输出）
    """
    affected: list[str] = []
    yaml_ops = memory_patch.get("yaml_operations") or []

    # ── 显式 yaml_operations（导师指明了操作类型）──
    for op in yaml_ops:
        cwe_id = op.get("cwe_id", "")
        operation = op.get("operation", "update")
        target_file = op.get("target_file", "")

        if not cwe_id:
            continue

        # 构造 payload 条目
        payload_entry = {
            "name": op.get("new_payload_name", op.get("vulnerability", "unnamed")),
            "description": op.get("description", ""),
            "lang": "python",
            "template": op.get("payload_template", ""),
            "tags": op.get("tags", []),
            "source": "consolidator",
            "severity": op.get("severity", "critical"),
        }

        if operation == "update":
            if target_file:
                yaml_path = templates_dir / target_file
                if not yaml_path.exists():
                    yaml_path = _ROOT / target_file
            else:
                yaml_path = _find_existing_yaml_for_cwe(templates_dir, cwe_id)

            if yaml_path and yaml_path.exists():
                if _append_payload_to_yaml(yaml_path, payload_entry):
                    affected.append(str(yaml_path))
            else:
                # 找不到已有 YAML -> 降级为创建
                print(f"[consolidator] [SEARCH] 未找到 {cwe_id} 已有 YAML，将创建新文件")
                result = _create_new_cwe_yaml(
                    templates_dir, cwe_id,
                    op.get("cwe_name", cwe_id),
                    op.get("description", ""),
                    [payload_entry],
                )
                if result:
                    affected.append(str(result))

        elif operation == "create":
            result = _create_new_cwe_yaml(
                templates_dir, cwe_id,
                op.get("cwe_name", cwe_id),
                op.get("description", ""),
                [payload_entry],
            )
            if result:
                affected.append(str(result))

    # ── 隐式推导：从 techs 中没有 yaml_operations 时自动匹配 ──
    if not yaml_ops:
        techs = memory_patch.get("techs") or []
        for t in techs:
            cwe_ids = t.get("cwe_ids") or []
            for cwe_id in cwe_ids:
                payload_entry = {
                    "name": t.get("vulnerability", "unnamed"),
                    "description": t.get("description", ""),
                    "lang": "python",
                    "template": t.get("executable_patch") or t.get("payload_template", ""),
                    "tags": t.get("tags", []),
                    "source": "consolidator",
                    "severity": "critical",
                }
                if not payload_entry["template"]:
                    continue

                yaml_path = _find_existing_yaml_for_cwe(templates_dir, cwe_id)
                if yaml_path:
                    if _append_payload_to_yaml(yaml_path, payload_entry):
                        affected.append(str(yaml_path))
                else:
                    result = _create_new_cwe_yaml(
                        templates_dir, cwe_id,
                        t.get("vulnerability", cwe_id),
                        t.get("description", ""),
                        [payload_entry],
                    )
                    if result:
                        affected.append(str(result))

    return list(set(affected))  # 去重

def _dehydrate_context(text: str) -> str:
    """硬脱水：切除冗余日志，只保留 [CRITICAL] 报错和核心执行结果。

    针对 5 轮迭代后战报膨胀至 3000+ 字符导致导师 JSON 被截断的问题，
    用正则批量切除以下纯噪声行：
      - ChromaDB tag-filter fallback 日志
      - HTTP Request 握手包 / TLS 协商日志
      - 连续空行 / 纯分隔线
      - timeout/retry/backoff 等连接池噪音
      - 重复的 [SKIP] / [INFO] 信息行
    """
    lines = text.split("\n")
    stripped: list[str] = []
    skip_patterns = [
        r"tag.filter.fallback",
        r"TLS.*handshake",
        r"HTTP/1\.\d \d{3}",
        r"ssl.SSL",
        r"Retry\(total=",
        r"Backoff\(",
        r"urllib3\.connectionpool",
        r"ConnectionError",
        r"ReadTimeout",
        r"RemoteDisconnected",
        r"^[-=]{10,}$",
        r"^\[consolidator\].*\[SKIP\]",
        r"^\[consolidator\].*\[INFO\]",
        r"^\s*$",
    ]
    keep_keywords = ["CRITICAL", "SECURITY_BLOCKED", "PYTHON_BLOCKED", "ERROR",
                     "Blocked", "FAIL", "SANDBOX", "os_system", "__import__",
                     "feedback", "plan", "execution_result", "step[",
                     "diagnosis", "diagno", "vuln", "exploit", "payload",
                     "sandbox-bypass", "bypass"]

    for line in lines:
        upper = line.upper()

        # Always keep lines with critical keywords
        if any(kw.upper() in upper for kw in keep_keywords):
            stripped.append(line)
            continue

        # Strip known noise patterns
        skip = False
        for pat in skip_patterns:
            if re.search(pat, line, re.IGNORECASE):
                skip = True
                break
        if not skip:
            stripped.append(line)

    # Remove consecutive blank lines (collapse to single)
    collapsed: list[str] = []
    prev_blank = False
    for line in stripped:
        is_blank = not line.strip()
        if is_blank and prev_blank:
            continue
        collapsed.append(line)
        prev_blank = is_blank

    result = "\n".join(collapsed)
    reduction = len(text) - len(result)
    if reduction > 0:
        delta = f"[consolidator] [CLEAN] Context: {len(text)} -> {len(result)} chars ({reduction} trimmed)"
        if len(delta) < len(result):
            result = f"{delta}\\n\\n{result}"
    return result


def is_yaml_auto_evolve_enabled() -> bool:
    return os.getenv("CONSOLIDATOR_AUTO_EVOLVE_YAML", "0").strip().lower() in {"1", "true", "yes", "on"}


def _slug_strategy(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "*", value.strip().lower()).strip("*")
    return slug or "reviewed*strategy*suggestion"


def write_consolidator_suggestion_artifact(workdir: Path, memory_patch: dict[str, Any], diagnosis: str = "") -> Path:
    """Write reviewed strategy suggestions without mutating YAML or active health state."""
    suggestions: list[dict[str, Any]] = []
    for tech in memory_patch.get("techs") or []:
        if not isinstance(tech, dict):
            continue
        raw_id = tech.get("proposed_canonical_strategy_id") or tech.get("canonical_strategy_id") or tech.get("strategy_id")
        if raw_id:
            proposed = str(raw_id).strip()
        else:
            cwes = tech.get("cwe_ids") or []
            cwe_part = str(cwes[0]).lower() if cwes else "unknown-cwe"
            proposed = _slug_strategy(f"{cwe_part} {tech.get('vulnerability') or tech.get('name') or 'strategy'}")
        suggestions.append({
            "proposed_canonical_strategy_id": proposed,
            "reason": tech.get("description") or diagnosis or "consolidator_suggestion",
            "needs_human_review": True,
            "source": "consolidator",
            "active": False,
        })
    for op in memory_patch.get("yaml_operations") or []:
        if not isinstance(op, dict):
            continue
        raw_id = op.get("proposed_canonical_strategy_id") or op.get("canonical_strategy_id")
        proposed = str(raw_id).strip() if raw_id else _slug_strategy(f"{op.get('cwe_id') or 'unknown-cwe'} {op.get('new_payload_name') or op.get('operation') or 'strategy'}")
        suggestions.append({
            "proposed_canonical_strategy_id": proposed,
            "reason": op.get("description") or diagnosis or "yaml_operation_review_required",
            "needs_human_review": True,
            "source": "consolidator_yaml_operation",
            "active": False,
        })
    artifact = {
        "version": 1,
        "auto_evolve_yaml": False,
        "needs_human_review": True,
        "suggestions": suggestions,
    }
    path = workdir / "consolidator_strategy_suggestions.json"
    path.write_text(json.dumps(artifact, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def run_global_consolidation(
    workdir: Path,
    max_iter_reached: bool = False,
    is_success: bool = False,
    feedback: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """全局复盘入口 — 在迭代循环结束后调用。

    Args:
        workdir: 工作区目录（包含 plan.json / execution_result.json / feedback.json）
        max_iter_reached: 是否因达到迭代上限而退出
        is_success: 最终是否判定为成功
        feedback: 最后一轮的 evaluator feedback dict，用于检测环境故障

    Returns:
        复盘结果 dict（包含 diagnosis 和 memory_patch），若跳过则返回 None
    """
    # ── 0. 环境故障熔断: 后端不可达时不写入长期记忆 ──────────
    if feedback and feedback.get("environment_failure") is True:
        reason = feedback.get("reason", "unknown")
        print(f"[consolidator] [SKIP] Skipping consolidation: environment failure detected ({reason})")
        return None

    # ── 1. 前置检查：是否配置了独立模型 ──────────────────────
    api_key = os.getenv("CONSOLIDATOR_API_KEY", "").strip()
    model = os.getenv("CONSOLIDATOR_MODEL", "").strip()
    if not api_key or not model:
        print("[consolidator] [SKIP]  未配置 CONSOLIDATOR_API_KEY/MODEL，跳过全局复盘。")
        print("[consolidator]    请在 .env 中设置 CONSOLIDATOR_API_KEY / CONSOLIDATOR_BASE_URL / CONSOLIDATOR_MODEL")
        return None

    # ── 2. 收集案卷 ─────────────────────────────────────────
    print("[consolidator] [INFO] 正在收集打靶案卷...")
    reports = _collect_reports(workdir)
    if not reports:
        print("[consolidator] [WARN] 工作区无可用案卷，跳过复盘。")
        return None

    context = _build_consolidator_context(reports)

    # 添加任务元信息
    meta_header = (
        f"═══ 任务元信息 ═══\n"
        f"迭代结束原因: {'达到迭代上限' if max_iter_reached else '正常退出'}\n"
        f"最终判定: {'成功 [OK]' if is_success else '失败 [FAIL]'}\n"
        f"工作区: {workdir}\n\n"
    )
    context = meta_header + context

    print(f"[consolidator] [INFO] 上下文战报大小: {len(context)} chars")

    # ── 硬脱水：切除冗余日志，防止导师 JSON 被物理截断 ──
    context = _dehydrate_context(context)

    # ── 3. 调用高级 LLM ─────────────────────────────────────
    print(f"[consolidator] [LLM] 正在调用高级导师模型 ({model}) 进行战略复盘...")
    try:
        client = _ConsolidatorClient(workdir=workdir)
        result = client.complete_json(CONSOLIDATOR_SYSTEM_PROMPT, context)
    except Exception as e:
        print(f"[consolidator] [WARN] LLM 调用失败: {e}")
        return None

    diagnosis = result.get("diagnosis", "")
    print(f"[consolidator] [DIAG] 诊断结论:\n  {diagnosis[:300]}...")

    # ── 4. 持久化经验 ───────────────────────────────────────
    # LongTermWritePolicy gate: check terminal conditions before any permanent write
    from core.long_term_write_policy import is_long_term_write_blocked
    _ltw_blocked, _ltw_reason = is_long_term_write_blocked(workdir)
    if _ltw_blocked:
        print(f"[consolidator] [POLICY] Long-term writes BLOCKED: {_ltw_reason}")
        print(f"[consolidator] [POLICY] Writing only workspace-local diagnostics (strategy_gap / run_diagnostics)")
        # Write workspace-local diagnostic artifact instead of permanent memory
        _diag_path = workdir / "run_diagnostics.json"
        _diag = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "blocked_by_terminal_condition": _ltw_reason,
            "diagnosis": result.get("diagnosis", ""),
            "llm_suggested_patterns_count": len(result.get("memory_patch", {}).get("patterns", [])),
            "llm_suggested_techs_count": len(result.get("memory_patch", {}).get("techs", [])),
            "_note": "Long-term writes were blocked. Patterns and techs below are for human review only.",
            "patterns_not_persisted": result.get("memory_patch", {}).get("patterns", []),
            "techs_not_persisted": result.get("memory_patch", {}).get("techs", []),
        }
        _diag_path.parent.mkdir(parents=True, exist_ok=True)
        _diag_path.write_text(json.dumps(_diag, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[consolidator] [DIAG] Wrote run diagnostics to {_diag_path}")
        return result

    memory_patch = result.get("memory_patch") or {}
    patterns: list[dict[str, Any]] = memory_patch.get("patterns") or []
    techs: list[dict[str, Any]] = memory_patch.get("techs") or []

    if not patterns and not techs:
        print("[consolidator] [WARN] 导师未产出可持久化的经验（patterns/techs 均为空）。")
        return result

    memory_dir = _ROOT / "memory"
    memory_dir.mkdir(parents=True, exist_ok=True)

    pattern_count = _persist_patterns_to_json(memory_dir, patterns)
    tech_count = _persist_techs_to_json(memory_dir, techs)

    # ── 5. YAML 武器库自愈演进 ───────────────────────────────
    templates_dir = _ROOT / "templates"
    yaml_affected: list[str] = []
    if is_yaml_auto_evolve_enabled():
        yaml_affected = _sync_to_yaml_weapon_library(templates_dir, memory_patch)
        for yf_path in yaml_affected:
            rel_path = Path(yf_path).relative_to(_ROOT) if Path(yf_path).is_relative_to(_ROOT) else yf_path
            print(f"[+] YAML Base Evolved: Updated/Created {rel_path}")
    else:
        suggestion_path = write_consolidator_suggestion_artifact(workdir, memory_patch, diagnosis=diagnosis)
        print(f"[consolidator] [SUGGEST] YAML auto evolution disabled; wrote {suggestion_path.name}")

    # ── 6. 同步写入 ChromaDB（让后续 Planner 的 RAG 检索可以命中）──
    if pattern_count + tech_count > 0:
        try:
            from core.memory_store import LayeredMemory
            from core.settings import get_settings
            settings = get_settings()
            memory = LayeredMemory(settings.memory_dir)
            memory.apply_evaluator_patch({
                "pattern": {"add_patterns": patterns},
                "tech": {"add_payload_templates": techs},
            })
            print("[consolidator] [SYNC] 经验已同步至 ChromaDB 向量索引")
        except Exception as e:
            print(f"[consolidator] [WARN] ChromaDB 同步失败（JSON 文件已保存）: {e}")

    total = pattern_count + tech_count
    yaml_total = len(yaml_affected)
    print(f"[consolidator] [DONE] 全局复盘完成！共提炼 {total} 条战略经验 -> patterns({pattern_count}) + techs({tech_count}) + yaml_evolved({yaml_total})")

    return result


def run_model_health_check(workdir: Path | None = None) -> dict[str, dict[str, str]]:
    """启动前模型健康检查 — 验证 Planner / Evaluator / Consolidator 三个模型的连通性和 JSON 合规性。

    对每个模型发送请求要求返回 {"status": "ok"}，检验 API 调用成功、HTTP 200、json.loads() 成功。
    """
    import json as _json
    from core.llm_client import DeepSeekClient, SchemaValidationError
    from core.settings import get_settings

    settings = get_settings()
    health_prompt = '请仅输出一个 JSON 对象: {"status": "ok"}，不要输出任何其他内容。'

    results: dict[str, dict[str, str]] = {}

    print("\n" + "=" * 50)
    print("MODEL HEALTH CHECK")
    print("=" * 50)

    # ── Planner ──
    print("\nPlanner:")
    planner_result: dict[str, str] = {"model": settings.deepseek_model}
    print(f"  model = {settings.deepseek_model}")
    if settings.mock_llm:
        planner_result["api"] = "SKIP (mock)"
        planner_result["json"] = "SKIP (mock)"
        print("  api   = SKIP (mock mode)")
        print("  json  = SKIP (mock mode)")
    elif not settings.deepseek_api_key:
        planner_result["api"] = "SKIP (no key)"
        planner_result["json"] = "SKIP (no key)"
        print("  api   = SKIP (DEEPSEEK_API_KEY not set)")
        print("  json  = SKIP (DEEPSEEK_API_KEY not set)")
    else:
        try:
            client = DeepSeekClient(settings)
            result = client.complete_json("", health_prompt)
            if isinstance(result, dict) and result.get("status") == "ok":
                planner_result["api"] = "OK"
                planner_result["json"] = "OK"
                print("  api   = OK")
                print("  json  = OK")
            else:
                planner_result["api"] = "OK"
                planner_result["json"] = f"FAIL (unexpected: {_json.dumps(result)[:80]})"
                print(f"  api   = OK")
                print(f"  json  = FAIL (unexpected response: {_json.dumps(result)[:80]})")
        except Exception as e:
            planner_result["api"] = f"FAIL ({e})"
            planner_result["json"] = "N/A"
            print(f"  api   = FAIL ({e})")
            print(f"  json  = N/A")
    results["planner"] = planner_result

    # ── Evaluator ── (same model as Planner, separate invocation)
    print("\nEvaluator:")
    eval_result: dict[str, str] = {"model": settings.deepseek_model}
    print(f"  model = {settings.deepseek_model}")
    if settings.mock_llm:
        eval_result["api"] = "SKIP (mock)"
        eval_result["json"] = "SKIP (mock)"
        print("  api   = SKIP (mock mode)")
        print("  json  = SKIP (mock mode)")
    elif not settings.deepseek_api_key:
        eval_result["api"] = "SKIP (no key)"
        eval_result["json"] = "SKIP (no key)"
        print("  api   = SKIP (DEEPSEEK_API_KEY not set)")
        print("  json  = SKIP (DEEPSEEK_API_KEY not set)")
    else:
        try:
            client = DeepSeekClient(settings)
            result = client.complete_json("", health_prompt)
            if isinstance(result, dict) and result.get("status") == "ok":
                eval_result["api"] = "OK"
                eval_result["json"] = "OK"
                print("  api   = OK")
                print("  json  = OK")
            else:
                eval_result["api"] = "OK"
                eval_result["json"] = f"FAIL (unexpected: {_json.dumps(result)[:80]})"
                print(f"  api   = OK")
                print(f"  json  = FAIL (unexpected response: {_json.dumps(result)[:80]})")
        except Exception as e:
            eval_result["api"] = f"FAIL ({e})"
            eval_result["json"] = "N/A"
            print(f"  api   = FAIL ({e})")
            print(f"  json  = N/A")
    results["evaluator"] = eval_result

    # ── Consolidator ──
    print("\nConsolidator:")
    cons_model = os.getenv("CONSOLIDATOR_MODEL", "").strip()
    cons_result: dict[str, str] = {"model": cons_model or "(not set)"}
    print(f"  model = {cons_model or '(not set)'}")
    cons_api_key = os.getenv("CONSOLIDATOR_API_KEY", "").strip()
    if not cons_api_key or not cons_model:
        cons_result["api"] = "SKIP (not configured)"
        cons_result["json"] = "SKIP (not configured)"
        print("  api   = SKIP (CONSOLIDATOR_API_KEY or CONSOLIDATOR_MODEL not set)")
        print("  json  = SKIP (CONSOLIDATOR_API_KEY or CONSOLIDATOR_MODEL not set)")
    else:
        try:
            client = _ConsolidatorClient(workdir=workdir, debug_label="healthcheck")
            result = client.complete_json("", health_prompt)
            if isinstance(result, dict) and result.get("status") == "ok":
                cons_result["api"] = "OK"
                cons_result["json"] = "OK"
                print("  api   = OK")
                print("  json  = OK")
            else:
                cons_result["api"] = "OK"
                cons_result["json"] = f"FAIL (unexpected: {_json.dumps(result)[:80]})"
                print(f"  api   = OK")
                print(f"  json  = FAIL (unexpected response: {_json.dumps(result)[:80]})")
        except Exception as e:
            cons_result["api"] = f"FAIL ({e})"
            cons_result["json"] = "N/A"
            print(f"  api   = FAIL ({e})")
            print(f"  json  = N/A")
    results["consolidator"] = cons_result

    print("\n" + "=" * 50)
    return results


# ═══════════════════════════════════════════════════════════════════
# Seed Warmup — Phase 2 预热：在 Planner 循环前用 Consolidator 生成
# 高质量可执行 YAML 模板，让 Planner 第一轮就直接拿到正确写法。
# ═══════════════════════════════════════════════════════════════════

_WARMUP_SYSTEM = """你是一个顶级的红队渗透测试攻击脚本工程师。
你的任务是根据提供的漏洞情报，生成一个**完整可执行的 Python 攻击脚本**。

【沙箱约束 — 必须遵守】
1. 只能用白名单 import: requests, json, re, base64, hashlib, hmac, struct, binascii, html, xml, lxml, bs4, http, http.client, jwt, time, datetime, random, string, itertools, functools, collections, copy, io, pathlib, threading, urllib, urllib.parse, httpx, Crypto, cryptography, redteam_sdk, typing, dataclasses, enum, abc, codecs, unicodedata, math, decimal, fractions, sys, os.path
2. 禁止 import: os, subprocess, socket, pickle, ctypes, cffi, importlib, builtins, pty, signal, multiprocessing, marshal, gc, inspect, ast, code, codeop, compileall, dis, types, weakref
3. 代码文本中绝对不能出现这些字面量: os.system( / os.popen( / subprocess.run( / subprocess.call( / subprocess.Popen( / __import__(
4. 用 redteam_sdk.HttpClient(base_url=TARGET_URL) 发 HTTP 请求
5. 用 redteam_sdk.OOBReceiver(port=8765) 做带外回调，URL 从 oob.url 获取
6. 用 redteam_sdk.save_context() / load_context() 做步骤间通信
7. 脚本末尾必须 print("STEP_OK") 标记成功完成
8. 所有 HTTP 调用必须包裹在 try/except 中

【特殊技法】
- pickle 反序列化攻击 → 用 struct.pack / bytes 硬编码 pickle 操作码字节序列，绝对不写 import pickle 也不写 os.system(
- CRLF 注入 → 用 bytes 拼接 \\r\\n，用 http.client.HTTPConnection 或 redteam_sdk.HttpClient.raw_request 发送，不经过 requests 的 header 编码
- 命令执行结果外带 → 用 OOBReceiver，payload 中嵌入 oob.url，命令输出通过 curl/wget 发送到 oob.url

输出纯 Python 代码，不要 markdown 包裹。"""

_WARMUP_USER_TEMPLATE = """目标信息：
{target_context}

漏洞清单：
{vuln_summary}

沙箱安全策略：
- 白名单 import: {allowlist}
- 黑名单 import: {blocklist}
- 代码文本扫描禁止: os.system(, os.popen(, subprocess.run(, subprocess.call(, subprocess.Popen(, __import__(

请为此目标生成一个完整可执行的攻击脚本。脚本必须：
1. 从确认的第一个注入点开始（CRLF Cookie 注入 / XSS / 其他）
2. 如果涉及 CRLF + memcached 注入链，直接用 http.client 或 raw_request 发送原始字节，编写 set/get 注入
3. 如果涉及 pickle 反序列化，用 struct/bytes 手搓 opcode 字节流
4. 最终目标：读取 flag 文件内容或执行 id/whoami 命令并通过 OOBReceiver 回传
5. 包含完整的 import、入口逻辑、异常处理
6. 脚本末尾 print("STEP_OK")

只输出纯 Python 代码。"""


def run_seed_warmup(
    confirmed_path: Path,
    templates_dir: Path | None = None,
) -> dict[str, str]:
    """Phase 2 预热：调用 Consolidator 模型生成可执行攻击模板，写入 YAML 武器库。

    在 Planner 循环启动前运行一次，让 Planner 第一轮就能从 YAML 中检索到
    完整可执行代码，无需从零猜测沙箱安全写法。

    返回: {cwe_id: template_code} 字典
    """
    if templates_dir is None:
        templates_dir = _ROOT / "templates" / "builtin"

    # 强制重载 .env：先加载父目录，再用 b/.env 覆盖（b/.env 有直连 DeepSeek key）
    from dotenv import load_dotenv
    load_dotenv(_ROOT.parent / ".env")
    load_dotenv(_ROOT / ".env", override=True)

    # ── 1. 读取 confirmed_vuln.json ──
    try:
        confirmed = json.loads(confirmed_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        print(f"[warmup] [SKIP] 无法读取 confirmed_vuln.json: {e}")
        return {}

    vulns = confirmed.get("vulnerabilities", [])
    if not vulns:
        print("[warmup] [SKIP] 无漏洞记录")
        return {}

    target_ctx = confirmed.get("target_context", {})
    target_url = target_ctx.get("base_url", "http://localhost:9082")

    # ── 2. 自动推断 CWE 类别 ──
    from agents.planner import _infer_vuln_classification

    cwe_targets: dict[str, str] = {}  # cwe_id -> vuln title
    for v in vulns:
        inferred = _infer_vuln_classification(v)
        if not inferred:
            continue
        parts = inferred.split()
        cwe_id = parts[0]  # e.g. "CWE-502"
        if cwe_id not in cwe_targets:
            cwe_targets[cwe_id] = v.get("title", "")

    if not cwe_targets:
        print("[warmup] [SKIP] 无法推断任何 CWE 类别")
        return {}

    # 3. 读沙箱策略
    policy_path = _ROOT / "policies" / "sandbox_policy.yaml"
    try:
        with open(policy_path, encoding="utf-8") as f:
            policies = yaml.safe_load(f)
    except Exception:
        policies = {}
    allowlist = ", ".join((policies.get("import_rules") or {}).get("allowlist", [])[:20])
    blocklist = ", ".join((policies.get("import_rules") or {}).get("blocklist", [])[:15])

    # 4. 汇总漏洞摘要（精简版，避免 BLSC 代理请求体大小限制）
    vuln_lines = []
    for v in vulns:
        src = v.get("source", {})
        snk = v.get("sink", {})
        vuln_lines.append(
            f"  [{v.get('id', '?')}] {v.get('title', '')}\n"
            f"    注入位置: {src.get('type', '')} — {src.get('location', '')}\n"
            f"    触发点: {snk.get('type', '')} — {snk.get('location', '')}\n"
            f"    链路: {v.get('data_flow', '')[:250]}"
        )
    vuln_summary = "\n".join(vuln_lines)

    # 5. 调用 Consolidator LLM 生成可执行代码
    user_prompt = _WARMUP_USER_TEMPLATE.format(
        target_context=f"base_url: {target_url}",
        vuln_summary=vuln_summary,
        allowlist=allowlist,
        blocklist=blocklist,
    )

    try:
        consolidator = _ConsolidatorClient()
        print(f"[warmup] [LLM] 正在调用 {consolidator._model} 生成种子攻击模板...")
        code = consolidator.complete_text(_WARMUP_SYSTEM, user_prompt)
    except Exception as e:
        print(f"[warmup] [FAIL] LLM 调用失败: {e}")
        return {}

    if not code or len(code.strip()) < 50:
        print("[warmup] [FAIL] 模型返回空或过短的代码")
        return {}

    code = code.strip()

    # 6. 写入 YAML 模板（找到空缺或新建 entry）
    written: dict[str, str] = {}
    for cwe_id, vuln_title in cwe_targets.items():
        slug = cwe_id.lower().replace("-", "-")
        # 查找匹配的 YAML 文件
        candidates = list(templates_dir.glob(f"*{slug}*.yaml"))
        if not candidates:
            # 无已有 YAML → 新建文件，不跳过 LLM 输出
            new_path = templates_dir / f"{slug}-{slug}.yaml"
            new_doc = {
                "metadata": {
                    "id": f"{slug}-{slug}",
                    "name": cwe_id,
                    "cwe_ids": [cwe_id],
                    "target_type": "generic",
                    "tags": [slug, slug],
                    "author": "co-redteam-consolidator",
                    "severity": "critical",
                },
                "initial_prechecks": [],
                "content": f"{cwe_id} seed template generated by warmup",
                "payload_templates": [
                    {
                        "name": f"seed-warmup-{slug}-template",
                        "description": f"Warmup-generated executable exploit template for {cwe_id} {vuln_title}",
                        "lang": "python",
                        "template": code,
                        "tags": [slug, "warmup", "seed"],
                        "source": "warmup",
                        "severity": "critical",
                    }
                ],
            }
            with open(new_path, "w", encoding="utf-8") as f:
                yaml.safe_dump(new_doc, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
            print(f"[warmup] [NEW] 未找到 {cwe_id} 已有 YAML，已新建: {new_path.name}")
            written[cwe_id] = code
            continue

        yaml_path = candidates[0]
        with open(yaml_path, encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}

        payloads = doc.get("payload_templates") or []
        # 找到第一个 template 为空的条目，填入代码
        filled = False
        for pt in payloads:
            tpl = pt.get("template")
            if not tpl or (isinstance(tpl, str) and len(tpl.strip()) < 20):
                pt["template"] = code
                pt["source"] = "warmup"
                filled = True
                break

        if not filled:
            # 无空位则追加新条目
            payloads.append({
                "name": f"seed-warmup-{cwe_id.lower()}-template",
                "description": f"预热生成的可执行攻击模板: {vuln_title}",
                "lang": "python",
                "template": code,
                "tags": [slug, "warmup", "seed"],
                "source": "warmup",
                "severity": "critical",
            })

        doc["payload_templates"] = payloads
        with open(yaml_path, "w", encoding="utf-8") as f:
            yaml.dump(doc, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        written[cwe_id] = str(yaml_path)
        print(f"[warmup] [OK] {cwe_id} → {yaml_path.name} ({len(code)} chars)")

    if not written:
        return {}

    # 7. 同步到 tech.json 和 ChromaDB，让 Planner 的 RAG 检索能命中
    try:
        from core.payload_registry import PayloadRegistry
        tech_json_path = _ROOT / "memory" / "tech.json"
        if tech_json_path.exists():
            tech_data = json.loads(tech_json_path.read_text(encoding="utf-8"))
        else:
            tech_data = {}

        registry = PayloadRegistry(_ROOT / "memory")
        pt_list = tech_data.get("payload_templates") or []
        entry = {
            "name": f"seed-warmup-{len(written)}-cwes",
            "description": f"预热生成的可执行攻击模板 (覆盖 {', '.join(written.keys())})",
            "lang": "python",
            "template": code,
            "tags": list(written.keys()) + ["warmup", "seed", "sandbox-bypass"],
            "source": "warmup",
            "severity": "critical",
        }
        if registry.is_duplicate(entry):
            print(f"[warmup] [SYNC] 指纹重复，跳过 tech.json 同步")
        else:
            registry.register(entry)
            pt_list.append(entry)
            tech_data["payload_templates"] = pt_list
            tech_json_path.write_text(
                json.dumps(tech_data, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            print(f"[warmup] [SYNC] 模板已同步到 tech.json")
    except Exception as e:
        print(f"[warmup] [WARN] tech.json 同步失败: {e}")

    try:
        from core.memory_store import LayeredMemory
        from core.settings import get_settings
        settings = get_settings()
        memory = LayeredMemory(settings.memory_dir)
        memory.apply_evaluator_patch({
            "tech": {
                "add_payload_templates": [{
                    "name": f"seed-warmup-{len(written)}-cwes",
                    "description": f"预热生成的可执行攻击模板 (覆盖 {', '.join(written.keys())})",
                    "lang": "python",
                    "template": code,
                    "tags": list(written.keys()) + ["warmup", "seed", "sandbox-bypass"],
                    "source": "warmup",
                    "severity": "critical",
                    "content": code,
                }]
            }
        })
        print(f"[warmup] [SYNC] 模板已同步到 ChromaDB")
    except Exception as e:
        print(f"[warmup] [WARN] ChromaDB 同步失败 (不影响运行): {e}")

    return written