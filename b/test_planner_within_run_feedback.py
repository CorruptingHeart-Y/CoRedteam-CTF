from __future__ import annotations

import copy
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[1]
B_DIR = ROOT / "b"
if str(B_DIR) not in sys.path:
    sys.path.insert(0, str(B_DIR))

from agents import planner
from agents.evaluator import _apply_failure_taxonomy


_TEMPLATE_MARKER = "【CWE TEMPLATE REFERENCE】 STATIC_TEMPLATE_CHOICE"


class _MemoryStub:
    def planning_context(self) -> str:
        return "{}"


class _RouteKnowledgeStub:
    def for_confirmed(self, confirmed: dict[str, Any]) -> list[Any]:
        return []

    def build_planner_context(self, confirmed: dict[str, Any]) -> str:
        return ""


class _VerificationStub:
    def build_planner_context(self) -> str:
        return ""

    def get_stats(self) -> dict[str, int]:
        return {"facts_count": 0}


class _TrajectoryStub:
    nodes: list[Any] = []


class _CapturingLLM:
    def __init__(self) -> None:
        self.system_prompt = ""
        self.user_prompt = ""

    def complete_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        self.system_prompt = system_prompt
        self.user_prompt = user_prompt
        return {
            "version": 1,
            "plan_id": "within-run-feedback",
            "vuln_summary": "test",
            "rationale": "test",
            "chain_design": [],
            "steps": [],
            "history_state": {},
            "primitive_context": {},
        }


def _feedback() -> dict[str, Any]:
    return {
        "current_exploit_state": "probe_success",
        "primitive_state": {
            "template_expression_execution": "confirmed",
            "command_execution": "blocked",
        },
        "detected_primitives": ["template_expression_execution"],
        "primitive_confidence": {"template_expression_execution": 0.93},
        "failure_analysis": {
            "type": "verification_failure",
            "detail": "execution completed but the required signal was absent",
        },
        "state_transition_blocker": "required verification signal was absent",
        "next_required_action": "select an evidence-compatible next action",
        "exploit_momentum": False,
        "confidence": 0.93,
        "repro_success": False,
        "feedback_for_planner": "do not repeat the previous objective",
    }


def _isolate_prompt(monkeypatch: Any) -> None:
    monkeypatch.setattr(planner, "_build_memory_context", lambda *args: "")
    monkeypatch.setattr(
        planner,
        "_extract_user_goal_dense",
        lambda *args, **kwargs: _TEMPLATE_MARKER,
    )
    monkeypatch.setattr(planner, "_build_runtime_manifest_block", lambda: "runtime")
    monkeypatch.setattr(planner, "_build_hard_constraints_block", lambda: "constraints")
    monkeypatch.setattr(planner, "_build_sdk_contract_block", lambda: "sdk")
    monkeypatch.setattr(planner, "_build_primitive_context", lambda *args: "")
    monkeypatch.setattr(planner, "_build_trajectory_context", lambda *args: "")
    monkeypatch.setattr(planner, "_build_candidate_routes_layer", lambda *args: "")
    monkeypatch.setattr(planner, "_build_exploit_transition_context", lambda: {})
    monkeypatch.setattr(planner, "_resolve_planning_primitive", lambda *args: "")
    monkeypatch.setattr(
        planner,
        "_build_plan_generation_contract",
        lambda *args: {"contract_name": "test"},
    )
    monkeypatch.setattr(planner, "RouteKnowledgeProvider", _RouteKnowledgeStub)
    monkeypatch.setattr(planner, "get_verification", lambda: _VerificationStub())
    monkeypatch.setattr(planner, "get_trajectory", lambda: _TrajectoryStub())


def _run_planner(
    monkeypatch: Any,
    tmp_path: Path,
    feedback: dict[str, Any],
) -> tuple[dict[str, Any], _CapturingLLM]:
    _isolate_prompt(monkeypatch)
    llm = _CapturingLLM()
    result = planner.run_planner(
        settings=SimpleNamespace(mock_llm=False),
        memory=_MemoryStub(),
        confirmed={
            "vulnerabilities": [
                {
                    "id": "VULN-1",
                    "cwe_id": "CWE-79",
                    "title": "test vulnerability",
                }
            ],
            "target_context": {"base_url": "http://target.test"},
        },
        feedback=feedback,
        out_path=tmp_path / "plan.json",
        llm=llm,
    )
    return result, llm


def test_evaluator_feedback_fields_enter_planner_system_prompt(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    feedback = _feedback()
    _, llm = _run_planner(monkeypatch, tmp_path, feedback)

    for field in (
        "current_exploit_state",
        "primitive_state",
        "detected_primitives",
        "primitive_confidence",
        "failure_analysis",
        "state_transition_blocker",
        "next_required_action",
        "exploit_momentum",
    ):
        assert f'"{field}":' in llm.system_prompt

    assert "[VERIFIED FACT]" in llm.system_prompt
    assert "[HARD CONSTRAINT]" in llm.system_prompt
    assert "[OPTIONAL STRATEGY]" in llm.system_prompt
    assert "probe_success" in llm.system_prompt
    assert "template_expression_execution" in llm.system_prompt
    assert "required verification signal was absent" in llm.system_prompt

    compact = planner._build_feedback_block(
        feedback,
        planner._FEEDBACK_MIN_BUDGET,
    )
    assert planner._FEEDBACK_MIN_BUDGET >= len(compact) >= 300


@pytest.mark.parametrize(
    "failure_marker",
    ["verification_failure", "reflection_blocked", "strategy_stagnation"],
)
def test_failure_feedback_outranks_but_does_not_remove_template(
    monkeypatch: Any,
    tmp_path: Path,
    failure_marker: str,
) -> None:
    feedback = _feedback()
    feedback["failure_type"] = ""
    feedback["failure_analysis"] = {"type": ""}
    if failure_marker == "reflection_blocked":
        feedback["failure_analysis"] = {"type": failure_marker}
    elif failure_marker == "strategy_stagnation":
        feedback["strategy_stagnation"] = True
    else:
        feedback["failure_type"] = failure_marker

    _, llm = _run_planner(monkeypatch, tmp_path, feedback)

    assert _TEMPLATE_MARKER in llm.system_prompt
    assert "[VERIFIED FACT]" in llm.system_prompt
    assert llm.system_prompt.index("[VERIFIED FACT]") < llm.system_prompt.index(
        _TEMPLATE_MARKER
    )
    assert "cannot change verified facts" in llm.system_prompt
    assert failure_marker in llm.system_prompt


def test_runtime_target_missing_does_not_mutate_exploit_state() -> None:
    feedback = _feedback()
    feedback["failure_analysis"] = {"type": "payload_failure"}
    feedback["memory_patch"] = {"tech": {"add_payload_templates": ["polluted"]}}
    exploit_fields = (
        "current_exploit_state",
        "primitive_state",
        "detected_primitives",
        "primitive_confidence",
        "exploit_momentum",
    )
    before = {key: copy.deepcopy(feedback[key]) for key in exploit_fields}
    stdout = "runtime_targets missing grpc:50045; StopIteration"
    exec_out = {
        "step_results": [
            {
                "step_id": 1,
                "result": {
                    "ok": True,
                    "exit_code": 0,
                    "stdout": stdout,
                    "stderr": "",
                },
            }
        ]
    }

    _apply_failure_taxonomy(feedback, exec_out, stdout)

    assert feedback["failure_type"] == "runtime_target_missing"
    assert feedback["memory_patch"] == {}
    assert {key: feedback[key] for key in exploit_fields} == before


def test_success_feedback_keeps_existing_template_order_and_plan_flow(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    feedback = _feedback()
    feedback.update(
        {
            "failure_type": None,
            "failure_analysis": {},
            "repro_success": True,
            "exploit_momentum": True,
        }
    )

    result, llm = _run_planner(monkeypatch, tmp_path, feedback)

    assert llm.system_prompt.index("[VERIFIED FACT]") < (
        llm.system_prompt.index(_TEMPLATE_MARKER)
    )
    assert "dynamic failure feedback overrides" not in llm.system_prompt
    assert result["plan_id"] == "within-run-feedback"
    assert result["steps"] == []
