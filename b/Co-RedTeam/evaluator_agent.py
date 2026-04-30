"""
Evaluator agent: converts low-level execution traces into high-level reasoning signals.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Optional

from dotenv import load_dotenv
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from langchain_openai import ChatOpenAI

from execution_types import EvaluationResult
from vul_doc import VULN_TOOLS

load_dotenv()

_TOOL_MAP = {t.name: t for t in VULN_TOOLS}


def _extract_json_object(text: str) -> dict[str, Any]:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError("No JSON object in model output")
    return json.loads(match.group(0))


def _build_llm() -> ChatOpenAI:
    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        raise RuntimeError("DEEPSEEK_API_KEY is not set")
    return ChatOpenAI(
        model="deepseek-chat",
        api_key=api_key,
        base_url="https://api.deepseek.com",
        temperature=0.1,
    )


EVALUATION_SYSTEM = """你是漏洞利用阶段的评估智能体。
你接收“拟执行步骤 + 执行轨迹(trace)”并做高层评估，不进行执行。

输出必须是纯 JSON 对象（不要 Markdown），格式：
{
  "decision": "SUCCESS" | "PARTIAL_SUCCESS" | "FAILED" | "INCONCLUSIVE",
  "confidence": 0.0-1.0,
  "rationale": "简洁中文分析",
  "evidence_summary": "从trace中提取的关键证据",
  "suggested_next_action": "下一步建议，可空"
}
"""


def evaluate_execution_trace(
    proposed_operation: dict[str, Any],
    execution_trace: dict[str, Any] | str,
    phase1_context: Optional[str] = None,
    *,
    use_cwe_tools: bool = False,
) -> EvaluationResult:
    llm = _build_llm()

    trace_payload = (
        execution_trace
        if isinstance(execution_trace, str)
        else json.dumps(execution_trace, ensure_ascii=False, indent=2)
    )
    human_parts = [
        "请评估以下步骤与执行轨迹：",
        "proposed_operation:\n" + json.dumps(proposed_operation, ensure_ascii=False, indent=2),
        "execution_trace:\n" + trace_payload[:12000],
    ]
    if phase1_context:
        human_parts.append("phase1_context:\n" + phase1_context[:8000])
    messages = [
        SystemMessage(content=EVALUATION_SYSTEM),
        HumanMessage(content="\n\n".join(human_parts)),
    ]

    if use_cwe_tools and proposed_operation.get("related_cwe"):
        llm_tools = llm.bind_tools(VULN_TOOLS)
        res = llm_tools.invoke(messages)
        if getattr(res, "tool_calls", None):
            messages.append(res)
            for tc in res.tool_calls:
                fn = _TOOL_MAP.get(tc["name"])
                out = fn.invoke(tc["args"]) if fn else "unknown tool"
                messages.append(ToolMessage(content=str(out), tool_call_id=tc["id"]))
            res = llm.invoke(messages + [HumanMessage(content="请仅输出最终 JSON 评估结果。")])
        else:
            messages.append(res)
            res = llm.invoke(messages + [HumanMessage(content="请仅输出最终 JSON 评估结果。")])
    else:
        res = llm.invoke(messages)

    raw = _extract_json_object(res.content)
    decision = raw.get("decision", "INCONCLUSIVE")
    if decision not in ("SUCCESS", "PARTIAL_SUCCESS", "FAILED", "INCONCLUSIVE"):
        decision = "INCONCLUSIVE"

    confidence = raw.get("confidence", 0.0)
    try:
        confidence = float(confidence)
    except Exception:
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))

    return EvaluationResult(
        decision=decision,
        confidence=confidence,
        rationale=str(raw.get("rationale", "")),
        evidence_summary=str(raw.get("evidence_summary", "")),
        suggested_next_action=raw.get("suggested_next_action"),
        raw_json=raw,
    )
