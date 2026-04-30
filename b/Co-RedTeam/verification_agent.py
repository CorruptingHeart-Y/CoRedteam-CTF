"""
Verification agent: reviews each proposed exploit step before execution.
Calls teammate tooling only through public APIs (e.g. vul_doc tools), no edits to their files.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Optional

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from langchain_openai import ChatOpenAI
from dotenv import load_dotenv

from execution_types import VerificationResult

# Optional: grounding in CWE docs (same tools as Phase 1 analysis)
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
        temperature=0.0,
    )


VERIFICATION_SYSTEM = """你是漏洞利用阶段的「验证智能体」。你只负责审核「拟执行操作」，不执行任何命令。

【输入】
- proposed_operation: 规划智能体给出的单步操作（含 command 字段时，那是将要在隔离环境中运行的命令意图）。
- phase1_context: 可选，来自 Phase 1 的漏洞描述 / 证据链摘要，用于检查操作是否与声明漏洞一致。

【原则】
1. 安全：拒绝明显破坏宿主机、扫描外网、持久化后门、删除系统目录等意图（如 rm -rf /、格式化磁盘、反弹公网 shell）。
2. 一致性：操作应服务于已声明的漏洞验证；若 command 与漏洞类型明显无关且无法解释，标记 NEEDS_REVISION。
3.  proportionality：在可验证前提下优先更小权限的方式；若命令过于模糊或无法核查其意图，要求修订。
4. 你「不能」假设命令已在沙箱中执行；你只基于文本做合规与合理性审查。

【输出】
仅输出一个 JSON 对象，不要 Markdown 围栏，格式如下：
{
  "decision": "APPROVE" | "REJECT" | "NEEDS_REVISION",
  "reason": "简短中文理由",
  "risk_notes": ["可选的风险提示"]
}
"""


def verify_proposed_operation(
    proposed_operation: dict[str, Any],
    phase1_context: Optional[str] = None,
    *,
    use_cwe_tools: bool = False,
) -> VerificationResult:
    """
    Review a single planned step.

    proposed_operation: e.g. {"step_id", "title", "description", "command", "related_cwe", ...}
    phase1_context: optional raw string from Phase 1 (vulnerability JSON or critique-approved summary).
    use_cwe_tools: if True, may call vul_doc tools once for CWE grounding (extra latency).
    """
    llm = _build_llm()
    human_parts = [
        "请审核以下拟执行操作：",
        json.dumps(proposed_operation, ensure_ascii=False, indent=2),
    ]
    if phase1_context:
        human_parts.append("Phase1 漏洞上下文（可选）：\n" + phase1_context[:8000])
    human_content = "\n\n".join(human_parts)

    messages = [
        SystemMessage(content=VERIFICATION_SYSTEM),
        HumanMessage(content=human_content),
    ]

    if use_cwe_tools and proposed_operation.get("related_cwe"):
        llm_tools = llm.bind_tools(VULN_TOOLS)
        res = llm_tools.invoke(messages)
        if getattr(res, "tool_calls", None):
            messages.append(res)
            for tc in res.tool_calls:
                name = tc["name"]
                fn = _TOOL_MAP.get(name)
                out = fn.invoke(tc["args"]) if fn else "unknown tool"
                messages.append(ToolMessage(content=str(out), tool_call_id=tc["id"]))
            res = llm.invoke(messages + [HumanMessage(content="请仅输出最终 JSON 审核结果。")])
        else:
            messages.append(res)
            res = llm.invoke(messages + [HumanMessage(content="请仅输出最终 JSON 审核结果。")])
    else:
        res = llm.invoke(messages)

    raw = _extract_json_object(res.content)
    decision = raw.get("decision", "REJECT")
    if decision not in ("APPROVE", "REJECT", "NEEDS_REVISION"):
        decision = "REJECT"
    return VerificationResult(
        decision=decision,
        reason=str(raw.get("reason", "")),
        risk_notes=list(raw.get("risk_notes") or []),
        raw_json=raw,
    )
