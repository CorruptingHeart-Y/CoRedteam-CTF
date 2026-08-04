from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
B_DIR = ROOT / "b"
if str(B_DIR) not in sys.path:
    sys.path.insert(0, str(B_DIR))

from agents import planner


class _Memory:
    def planning_context(self) -> str:
        return "{}"


class _RouteKnowledge:
    def for_confirmed(self, confirmed: dict[str, Any]) -> list[Any]:
        return []

    def build_planner_context(self, confirmed: dict[str, Any]) -> str:
        return ""


class _ConflictingRoute:
    primitive = "ssti_reflection"
    possible_transitions = ["ssti_execution", "command_execution"]
    expected_signals = ["velocity-ssti-rce"]

    def to_plain(self) -> dict[str, Any]:
        return {
            "primitive": self.primitive,
            "possible_transitions": self.possible_transitions,
            "expected_signals": self.expected_signals,
            "template": "velocity-ssti-rce",
        }


class _ConflictingRouteKnowledge(_RouteKnowledge):
    def for_confirmed(self, confirmed: dict[str, Any]) -> list[Any]:
        return [_ConflictingRoute()]


class _Verification:
    def build_planner_context(self) -> str:
        return ""

    def get_stats(self) -> dict[str, int]:
        return {"facts_count": 0}


class _Trajectory:
    nodes: list[Any] = []

    def get_current_primitive(self) -> str:
        return ""


class _LLM:
    def __init__(self, plan: dict[str, Any]) -> None:
        self.plan = plan
        self.system_prompt = ""
        self.user_context: dict[str, Any] = {}

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        self.system_prompt = system
        self.user_context = json.loads(user)
        return self.plan


def _plan(target: str) -> dict[str, Any]:
    return {
        "version": 1,
        "plan_id": "primitive-feedback",
        "steps": [{"id": 1, "type": "python", "target_primitive": target}],
        "primitive_context": {
            "current_primitive": "input_processed",
            "target_primitive": target,
            "transition_edge": f"input_processed->{target}",
        },
    }


def _feedback(recommended: bool, blocked: bool) -> dict[str, Any]:
    transition = {
        "from_state": "input_processed",
        "to_state": "template_evaluation_confirmed",
    }
    return {
        "confirmed_primitives": ["input_processed"],
        "current_primitive": "input_processed",
        "recommended_transition": transition if recommended else None,
        "blocked_transition": transition if blocked else None,
    }


def _isolate(monkeypatch: Any) -> None:
    monkeypatch.setattr(planner, "_build_memory_context", lambda *args: "")
    monkeypatch.setattr(planner, "_extract_user_goal_dense", lambda *args, **kwargs: "goal")
    monkeypatch.setattr(planner, "_build_runtime_manifest_block", lambda: "runtime")
    monkeypatch.setattr(planner, "_build_hard_constraints_block", lambda: "constraints")
    monkeypatch.setattr(planner, "_build_sdk_contract_block", lambda: "sdk")
    monkeypatch.setattr(planner, "_build_primitive_context", lambda *args: "")
    monkeypatch.setattr(planner, "_build_trajectory_context", lambda *args: "")
    monkeypatch.setattr(planner, "_build_candidate_routes_layer", lambda *args: "")
    monkeypatch.setattr(planner, "_build_exploit_transition_context", lambda: {})
    monkeypatch.setattr(planner, "_resolve_planning_primitive", lambda *args: "")
    monkeypatch.setattr(planner, "_build_plan_generation_contract", lambda *args: {})
    monkeypatch.setattr(planner, "RouteKnowledgeProvider", _RouteKnowledge)
    monkeypatch.setattr(planner, "get_verification", lambda: _Verification())
    monkeypatch.setattr(planner, "get_trajectory", lambda: _Trajectory())


def _run(monkeypatch: Any, tmp_path: Path, plan: dict[str, Any], feedback):
    _isolate(monkeypatch)
    llm = _LLM(plan)
    result = planner.run_planner(
        settings=SimpleNamespace(mock_llm=False),
        memory=_Memory(),
        confirmed={"title": "test", "target_context": {}},
        feedback=feedback,
        out_path=tmp_path / "plan.json",
        llm=llm,
    )
    return result, llm


def test_current_primitive_and_recommendation_drive_plan_target(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    result, llm = _run(
        monkeypatch,
        tmp_path,
        _plan("output_confirmed"),
        _feedback(recommended=True, blocked=False),
    )

    assert result["steps"][0]["target_primitive"] == "template_evaluation_confirmed"
    assert result["primitive_context"]["target_primitive"] == "template_evaluation_confirmed"
    assert "Primitive Progress Context" in llm.system_prompt
    assert "Current verified capabilities:\n- input_processed" in llm.system_prompt
    assert "Current primitive:\ninput_processed" in llm.system_prompt
    assert (
        "Recommended next transition:\ninput_processed -> template_evaluation_confirmed"
        in llm.system_prompt
    )
    assert list(llm.user_context) == ["FACT_BLOCK", "CONSTRAINT_BLOCK", "STRATEGY_BLOCK", "REFERENCE_BLOCK"]
    assert "route_knowledge" not in llm.user_context["STRATEGY_BLOCK"]


def test_blocked_transition_is_not_selected(monkeypatch: Any, tmp_path: Path) -> None:
    result, llm = _run(
        monkeypatch,
        tmp_path,
        _plan("template_evaluation_confirmed"),
        _feedback(recommended=False, blocked=True),
    )

    assert result["steps"] == []
    assert result["primitive_context"]["target_primitive"] == ""
    assert (
        "Forbidden transitions:\ninput_processed -> template_evaluation_confirmed"
        in llm.system_prompt
    )


def test_no_primitive_feedback_preserves_legacy_behavior(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    result, llm = _run(monkeypatch, tmp_path, _plan("legacy_target"), None)

    assert result["steps"][0]["target_primitive"] == "legacy_target"
    assert result["primitive_context"]["current_primitive"] == "input_processed"
    assert result["primitive_context"]["target_primitive"] == "legacy_target"
    assert "Primitive Progress Context" not in llm.system_prompt
    assert "Primitive Progress Context" not in llm.user_context.get("CONSTRAINT_BLOCK", "")


def test_primitive_progress_outranks_conflicting_route_and_template(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    _isolate(monkeypatch)
    monkeypatch.setattr(planner, "RouteKnowledgeProvider", _ConflictingRouteKnowledge)
    monkeypatch.setattr(
        planner,
        "_extract_user_goal_dense",
        lambda *args, **kwargs: "CWE_TEMPLATE\nvelocity-ssti-rce",
    )
    llm = _LLM(_plan("arbitrary_file_read"))
    monkeypatch.setattr(planner, "_build_cwe_templates", lambda *args: "CWE_TEMPLATE\nvelocity-ssti-rce")
    feedback = {
        "confirmed_primitives": ["command_execution"],
        "current_primitive": "command_execution",
        "allowed_next": ["arbitrary_file_read"],
    }

    planner.run_planner(
        settings=SimpleNamespace(mock_llm=False),
        memory=_Memory(),
        confirmed={"title": "test", "target_context": {}},
        feedback=feedback,
        out_path=tmp_path / "plan.json",
        llm=llm,
    )
    result = llm.plan

    prompt = llm.system_prompt
    user_keys = list(llm.user_context)
    assert "current_primitive=command_execution" in prompt
    assert "CONFLICT RULE: do not return to ssti_reflection" not in prompt
    assert "ssti_reflection exploration hint" in llm.user_context["REFERENCE_BLOCK"]
    assert "ssti_reflection exploration hint" not in llm.user_context["STRATEGY_BLOCK"]
    assert "ssti_reflection exploration hint" not in llm.user_context["CONSTRAINT_BLOCK"]
    assert prompt.index("[HARD CONSTRAINT]") < prompt.index("[REFERENCE ONLY]")
    assert user_keys == ["FACT_BLOCK", "CONSTRAINT_BLOCK", "STRATEGY_BLOCK", "REFERENCE_BLOCK"]
    assert result["primitive_context"]["current_primitive"] == "command_execution"
    assert result["primitive_context"]["target_primitive"] == "arbitrary_file_read"


def test_verified_current_primitive_overrides_llm_without_changing_target(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    result, _ = _run(
        monkeypatch,
        tmp_path,
        _plan("file_read"),
        {"current_primitive": "command_execution"},
    )

    assert result["primitive_context"]["current_primitive"] == "command_execution"
    assert result["primitive_context"]["target_primitive"] == "file_read"

