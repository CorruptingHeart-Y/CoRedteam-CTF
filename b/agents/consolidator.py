"""
Global Consolidator — 全局复盘智能体 (Dual-Model Architecture)

在微观 4-agent 闭环 (Planner→Validator→Executor→Evaluator) 耗尽迭代预算后，
唤醒一个使用独立高级大模型（GPT-4o / Claude-3.5）的"导师智能体"，
对整个打靶轨迹进行跨任务战略级经验提炼（Verbal Reinforcement Learning），
并将提炼出的 patterns 和 techs 持久化写入永久记忆库。

论文对齐：Reflexion / Voyager / ExpeL — LLM-Driven Experiential Learning
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

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

请严格输出以下 JSON 格式：
{
  "diagnosis": "对整个打靶轨迹的深度剖析（指出死因和被忽略的底层协议细节）",
  "memory_patch": {
    "patterns": [
      {
        "error_type": "提取高度泛化的错误指纹（如 Invalid base64-encoded string）",
        "root_cause": "深层死因（如 遗漏了Base64的=号填充）",
        "fix_suggestion": "【🔴 绝对禁令与新战术】下次绝对不能怎么做，必须用什么思路替代"
      }
    ],
    "techs": [
      {
        "vulnerability": "提取有效的攻击手法名称",
        "tags": ["关联的技术栈标签，如 haproxy, jwt"],
        "payload_template": "高阶攻击的 Python 代码片段",
        "description": "该高阶手法的适用场景和规避机制"
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
    if isinstance(exec_out, dict):
        step_results = exec_out.get("step_results") or []
        parts.append("\n═══ 沙箱执行结果 (execution_result) ═══")
        for sr in step_results:
            parts.append(
                f"  step[{sr.get('step_id')}] ok={sr.get('ok')} "
                f"exit={sr.get('exit_code')} "
                f"stdout={sr.get('stdout', '')[:200]} "
                f"stderr={sr.get('stderr', '')[:200]}"
            )

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
            parts.append(f"  → planner: {fb_planner[:500]}")

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

    def __init__(self) -> None:
        api_key = os.getenv("CONSOLIDATOR_API_KEY", "").strip()
        base_url = os.getenv("CONSOLIDATOR_BASE_URL", "").strip()
        model = os.getenv("CONSOLIDATOR_MODEL", "").strip()

        if not api_key:
            raise RuntimeError(
                "CONSOLIDATOR_API_KEY 未配置。请在 .env 中设置 CONSOLIDATOR_API_KEY、"
                "CONSOLIDATOR_BASE_URL、CONSOLIDATOR_MODEL 以启用全局复盘功能。"
            )
        if not model:
            raise RuntimeError("CONSOLIDATOR_MODEL 未配置")

        from openai import OpenAI

        self._model = model
        self._client = OpenAI(api_key=api_key, base_url=base_url or None)

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        import re

        max_retries = 2
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
                )
                content = resp.choices[0].message.content or ""

                # Parse JSON (handle potential markdown wrapping)
                text = content.strip()
                text = re.sub(r'```json\s*', '', text)
                text = re.sub(r'\s*```', '', text)
                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    m = re.search(r"(\{[\s\S]*\}|\[[\s\S]*\])", text)
                    if m:
                        return json.loads(m.group(0))
                    raise

            except (json.JSONDecodeError, ValueError) as e:
                last_exception = e
                print(f"[consolidator] ⚠️ JSON 解析失败，重试 {attempt + 1}/{max_retries}: {e}")
                continue

        raise last_exception or RuntimeError("Consolidator LLM 调用失败")


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
            print(f"[consolidator] ⏭️  pattern 已存在，跳过: {error_type[:60]}")
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
        print(f"[consolidator] ✅ {added} 条 pattern 已持久化 → {pattern_file}")

    return added


def _persist_techs_to_json(memory_dir: Path, techs: list[dict[str, Any]]) -> int:
    """将全局复盘提炼的 techs 追加写入 b/memory/tech.json。

    JSON 结构：{"payload_templates": [...], "commands": [...], "scripts": [...]}
    新条目追加到 payload_templates 数组。若 vulnerability + payload_template 完全相同则跳过。
    """
    tech_file = memory_dir / "tech.json"
    existing_payloads: list[dict[str, Any]] = []
    existing_signatures: set[str] = set()

    # Load existing structure
    existing_data: dict[str, Any] = {}
    if tech_file.exists():
        try:
            existing_data = json.loads(tech_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            existing_data = {}

    existing_payloads = existing_data.get("payload_templates") or []
    for ep in existing_payloads:
        sig = f"{ep.get('name', '')}::{ep.get('template', '')}"
        existing_signatures.add(sig)

    added = 0
    for t in techs:
        name = t.get("vulnerability", "").strip()
        payload = t.get("payload_template", "").strip()
        if not name or not payload:
            continue
        sig = f"{name}::{payload}"
        if sig in existing_signatures:
            print(f"[consolidator] ⏭️  tech 已存在，跳过: {name[:60]}")
            continue

        existing_payloads.append({
            "name": name,
            "context": t.get("description", ""),
            "lang": "python",
            "template": payload,
            "description": t.get("description", ""),
            "source": "consolidator",
            "cwe_ids": [],
            "tags": t.get("tags", []),
            "severity": "critical",
        })
        existing_signatures.add(sig)
        added += 1

    if added:
        existing_data["payload_templates"] = existing_payloads
        tech_file.write_text(
            json.dumps(existing_data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"[consolidator] ✅ {added} 条 tech 已持久化 → {tech_file}")

    return added


# ═══════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════

def run_global_consolidation(
    workdir: Path,
    max_iter_reached: bool = False,
    is_success: bool = False,
) -> dict[str, Any] | None:
    """全局复盘入口 — 在迭代循环结束后调用。

    Args:
        workdir: 工作区目录（包含 plan.json / execution_result.json / feedback.json）
        max_iter_reached: 是否因达到迭代上限而退出
        is_success: 最终是否判定为成功

    Returns:
        复盘结果 dict（包含 diagnosis 和 memory_patch），若跳过则返回 None
    """
    # ── 0. 前置检查：是否配置了独立模型 ──────────────────────
    api_key = os.getenv("CONSOLIDATOR_API_KEY", "").strip()
    model = os.getenv("CONSOLIDATOR_MODEL", "").strip()
    if not api_key or not model:
        print("[consolidator] ⏭️  未配置 CONSOLIDATOR_API_KEY/MODEL，跳过全局复盘。")
        print("[consolidator]    请在 .env 中设置 CONSOLIDATOR_API_KEY / CONSOLIDATOR_BASE_URL / CONSOLIDATOR_MODEL")
        return None

    # ── 1. 收集案卷 ─────────────────────────────────────────
    print("[consolidator] 📋 正在收集打靶案卷...")
    reports = _collect_reports(workdir)
    if not reports:
        print("[consolidator] ⚠️ 工作区无可用案卷，跳过复盘。")
        return None

    context = _build_consolidator_context(reports)

    # 添加任务元信息
    meta_header = (
        f"═══ 任务元信息 ═══\n"
        f"迭代结束原因: {'达到迭代上限' if max_iter_reached else '正常退出'}\n"
        f"最终判定: {'成功 ✅' if is_success else '失败 ❌'}\n"
        f"工作区: {workdir}\n\n"
    )
    context = meta_header + context

    print(f"[consolidator] 📦 上下文战报大小: {len(context)} chars")

    # ── 2. 调用高级 LLM ─────────────────────────────────────
    print(f"[consolidator] 🧠 正在调用高级导师模型 ({model}) 进行战略复盘...")
    try:
        client = _ConsolidatorClient()
        result = client.complete_json(CONSOLIDATOR_SYSTEM_PROMPT, context)
    except Exception as e:
        print(f"[consolidator] ⚠️ LLM 调用失败: {e}")
        return None

    diagnosis = result.get("diagnosis", "")
    print(f"[consolidator] 📝 诊断结论:\n  {diagnosis[:300]}...")

    # ── 3. 持久化经验 ───────────────────────────────────────
    memory_patch = result.get("memory_patch") or {}
    patterns: list[dict[str, Any]] = memory_patch.get("patterns") or []
    techs: list[dict[str, Any]] = memory_patch.get("techs") or []

    if not patterns and not techs:
        print("[consolidator] ⚠️ 导师未产出可持久化的经验（patterns/techs 均为空）。")
        return result

    memory_dir = _ROOT / "memory"
    memory_dir.mkdir(parents=True, exist_ok=True)

    pattern_count = _persist_patterns_to_json(memory_dir, patterns)
    tech_count = _persist_techs_to_json(memory_dir, techs)

    # ── 4. 同步写入 ChromaDB（让后续 Planner 的 RAG 检索可以命中）──
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
            print("[consolidator] 🔄 经验已同步至 ChromaDB 向量索引")
        except Exception as e:
            print(f"[consolidator] ⚠️ ChromaDB 同步失败（JSON 文件已保存）: {e}")

    total = pattern_count + tech_count
    print(f"[consolidator] 🏁 全局复盘完成！共提炼 {total} 条战略经验 → patterns({pattern_count}) + techs({tech_count})")

    return result