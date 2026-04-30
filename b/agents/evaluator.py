from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.llm_client import DeepSeekClient
from core.memory_store import LayeredMemory
from core.settings import Settings


EVAL_SYSTEM = """你是 Co-RedTeam 评估智能体。基于漏洞上下文、计划与执行输出，判断**复现验证是否达到预期**（课程/研究语义），并输出可写入长期记忆的结构化增量。
输出要求：单个 JSON 对象，字段如下：
{
  "repro_success": bool,
  "confidence": number,
  "summary": string,
  "feedback_for_planner": string,
  "should_continue": bool,
  "memory_patch": {
    "pattern": { "add_patterns": [ { ... } ] },
    "strategy": { "add_success": [ { ... } ], "add_failures": [ { ... } ] },
    "tech": { "add_commands": [ { ... } ], "add_payload_templates": [ { ... } ], "add_scripts": [ { ... } ] }
  }
}
规则：
- repro_success：只要**任意一个步骤**的 stdout 中包含明确的漏洞触发证据（如数据库报错、敏感数据泄露、SSTI计算成功 `{{7*7}}→49`、XSS反射、SSRF连通内网等），就可设为 true。
- confidence：根据成功步骤的比例评估，9/17成功≈0.5-0.6，5+/10成功≈0.7-0.85，几乎所有步骤成功≈0.9+。
- memory_patch 只填**本次真正有增量价值**的条目，可留空对象。
- should_continue：若显然无法通过再规划改进则为 false。

【评估指南 - 部分成功即成功】：
1. 如果所有步骤的 stdout 全部为空 → repro_success **必须为** False。
2. 如果**部分步骤**的 stdout 包含明确的漏洞触发证据（500错误+Flask Debugger、敏感数据JSON、SSTI计算正确、XSS payload反射、SSRF连通内网等）→ repro_success **应为** True。
3. `"rendered": "49"` 表示 SSTI 成功、`<script>` 标签原样反射表示 XSS 成功、包含 `api_keys`/`jwt_secret`/`database_password` 的 JSON 表示配置泄露成功。
4. 不要因为少数步骤失败就判整个计划失败。安全测试中 50%+ 的成功率已经是优秀的复现结果。
5. 如果 stdout 中包含 "Werkzeug Debugger" 或同时出现 "Traceback (most recent call last)" 与 "SECRET" 字样，说明 Flask 调试模式未关闭，错误时泄露完整堆栈和调试 SECRET。这本身是高危漏洞证据，应将 repro_success 判定为 True。
"""


def _mock_evaluate(confirmed: dict[str, Any], plan: dict[str, Any], exec_out: dict[str, Any]) -> dict[str, Any]:
    executed = exec_out.get("executed")
    if not executed:
        return {
            "version": 1,
            "repro_success": False,
            "confidence": 0.2,
            "summary": "未执行：验证失败或计划被阻止。",
            "feedback_for_planner": "根据验证错误修订计划，避免高危命令并保证 step 结构合法。",
            "should_continue": True,
            "memory_patch": {
                "strategy": {
                    "add_failures": [
                        {
                            "summary": "计划在验证阶段失败，应缩小步骤粒度并自查命令安全性",
                            "context": confirmed.get("vuln_id", "unknown"),
                        }
                    ]
                }
            },
        }

    results = exec_out.get("step_results") or []
    all_ok = all((r.get("result") or {}).get("ok") for r in results)
    success = all_ok and "mock" in json.dumps(exec_out).lower()
    memory_patch: dict[str, Any] = {}
    if all_ok:
        memory_patch = {
            "strategy": {
                "add_success": [
                    {
                        "summary": "MOCK：全部步骤本地退出码为 0，可作为演示基线",
                        "context": plan.get("plan_id", ""),
                        "when_to_use": "演示/环境自检",
                    }
                ]
            },
            "tech": {
                "add_commands": [
                    {
                        "description": "最后一次运行的计划摘要",
                        "command": f"# plan_id={plan.get('plan_id')}",
                    }
                ]
            },
        }
    else:
        memory_patch = {
            "strategy": {
                "add_failures": [
                    {
                        "summary": "部分步骤非零退出码，应检查依赖、路径与命令兼容性（Windows/Linux）",
                        "context": confirmed.get("vuln_id", "unknown"),
                    }
                ]
            }
        }

    return {
        "version": 1,
        "repro_success": success,
        "confidence": 0.75 if all_ok else 0.4,
        "summary": "MOCK：基于退出码的粗略判断；真实场景请接入大模型评估日志语义。",
        "feedback_for_planner": "若失败：拆分命令、增加探测步骤；若成功：固化可复用命令到技术记忆。",
        "should_continue": not success,
        "memory_patch": memory_patch,
    }


def run_evaluator(
    settings: Settings,
    memory: LayeredMemory,
    confirmed: dict[str, Any],
    plan: dict[str, Any],
    exec_out: dict[str, Any],
    feedback_path: Path,
    llm: DeepSeekClient | None,
) -> dict[str, Any]:
    if settings.mock_llm or llm is None:
        fb = _mock_evaluate(confirmed, plan, exec_out)
        memory.apply_evaluator_patch(fb.get("memory_patch") or {})
        feedback_path.parent.mkdir(parents=True, exist_ok=True)
        feedback_path.write_text(json.dumps(fb, ensure_ascii=False, indent=2), encoding="utf-8")
        return fb

    user = {
        "confirmed_vuln": confirmed,
        "plan": plan,
        "execution_result": exec_out,
    }
    fb = llm.complete_json(EVAL_SYSTEM, json.dumps(user, ensure_ascii=False))
    fb.setdefault("version", 1)
    memory.apply_evaluator_patch(fb.get("memory_patch") or {})
    feedback_path.parent.mkdir(parents=True, exist_ok=True)
    feedback_path.write_text(json.dumps(fb, ensure_ascii=False, indent=2), encoding="utf-8")
    return fb
