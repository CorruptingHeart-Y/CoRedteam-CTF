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
from coordinator import _next_no_progress_streak
from core.route_candidate_generator import _is_reflection_blocked


class _Memory:
    def planning_context(self) -> str:
        return "{}"


class _RouteKnowledge:
    context = ""

    def for_confirmed(self, confirmed: dict[str, Any]) -> list[Any]:
        return []

    def build_planner_context(self, confirmed: dict[str, Any]) -> str:
        return self.context


class _Verification:
    def build_planner_context(self) -> str:
        return "VERIFIED_SENTINEL current_state=A"

    def get_stats(self) -> dict[str, int]:
        return {"facts_count": 1}


class _Trajectory:
    nodes: list[Any] = []

    def get_current_primitive(self) -> str:
        return ""


class _LLM:
    def __init__(self) -> None:
        self.system_prompt = ""
        self.user_prompt = ""

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        self.system_prompt = system
        self.user_prompt = user
        json.loads(user)
        return {
            "version": 1,
            "plan_id": "budget-test",
            "steps": [],
            "primitive_context": {},
        }


def _isolate(monkeypatch: Any, *, history: str = "", reference: str = "") -> None:
    route_type = type("_LongRouteKnowledge", (_RouteKnowledge,), {"context": reference})
    monkeypatch.setattr(planner, "_build_memory_context", lambda *args: history)
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
    monkeypatch.setattr(planner, "_build_cwe_templates", lambda *args: "")
    monkeypatch.setattr(planner, "RouteKnowledgeProvider", route_type)
    monkeypatch.setattr(planner, "get_verification", lambda: _Verification())
    monkeypatch.setattr(planner, "get_trajectory", lambda: _Trajectory())


def _capture_prompt(monkeypatch: Any, tmp_path: Path, *, history: str = "", reference: str = "") -> str:
    _isolate(monkeypatch, history=history, reference=reference)
    llm = _LLM()
    planner.run_planner(
        settings=SimpleNamespace(mock_llm=False),
        memory=_Memory(),
        confirmed={"title": "test", "target_context": {}, "vulnerabilities": []},
        feedback=None,
        out_path=tmp_path / "plan.json",
        llm=llm,
    )
    return llm.system_prompt


def test_long_reference_is_compacted_before_verified_fact(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    prompt = _capture_prompt(
        monkeypatch,
        tmp_path,
        reference="REFERENCE_SENTINEL " + ("R" * 12000),
    )

    assert len(prompt) <= planner._FINAL_PAYLOAD_HARD_CAP
    assert "VERIFIED_SENTINEL current_state=A" in prompt
    assert "R" * 1000 not in prompt


def test_long_history_does_not_displace_verified_state(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    prompt = _capture_prompt(
        monkeypatch,
        tmp_path,
        history="HISTORY_SENTINEL " + ("H" * 12000),
    )

    assert len(prompt) <= planner._FINAL_PAYLOAD_HARD_CAP
    assert "VERIFIED_SENTINEL current_state=A" in prompt
    assert "H" * 1000 not in prompt


def test_oversized_l6_contains_only_compacted_user_goal() -> None:
    confirmed = {
        "target_context": {
            "base_url": "http://target.invalid",
            "app_name": "goal-test",
        },
        "vulnerabilities": [
            {
                "cwe_id": "CWE-94",
                "title": f"goal-{index}-" + ("T" * 300),
                "severity": "HIGH",
                "source": "/",
                "sink": "template",
            }
            for index in range(40)
        ],
    }

    l6 = planner._extract_user_goal_dense(confirmed)

    assert len(l6) <= planner._USER_GOAL_SOFT_LIMIT
    assert "http://target.invalid" in l6
    assert "sdk_calls" not in l6
    assert "HttpClient" not in l6
    assert "primitive_context" not in l6
    assert planner._COMMON_RULES not in l6


def test_candidate_route_is_not_an_unclassified_user_message_field(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    _isolate(monkeypatch)
    monkeypatch.setattr(
        planner,
        "_build_candidate_routes_layer",
        lambda *args: "ROUTE_CANDIDATE_SENTINEL",
    )
    llm = _LLM()
    planner.run_planner(
        settings=SimpleNamespace(mock_llm=False),
        memory=_Memory(),
        confirmed={"title": "test", "target_context": {}, "vulnerabilities": []},
        feedback=None,
        out_path=tmp_path / "plan.json",
        llm=llm,
    )
    user = json.loads(llm.user_prompt)

    assert set(user) <= {
        "FACT_BLOCK",
        "CONSTRAINT_BLOCK",
        "STRATEGY_BLOCK",
        "REFERENCE_BLOCK",
    }
    assert "candidate_routes" not in user
    assert "ROUTE_CANDIDATE_SENTINEL" in user["STRATEGY_BLOCK"]
    assert len(llm.system_prompt) <= planner._FINAL_PAYLOAD_HARD_CAP


def test_first_successful_probe_is_not_reflection_blocked() -> None:
    feedback = {
        "primitive_confirmed": True,
        "current_exploit_state": "probe_success",
        "primitive_state": {"ssti": True, "arithmetic": True, "rce": False},
        "detected_primitives": ["ssti_reflection"],
        "same_primitive_attempts": 1,
        "no_progress_streak": 0,
        "repro_success": True,
        "new_evidence": True,
    }

    assert planner._detect_strategy_stagnation(feedback) is None
    assert not _is_reflection_blocked(feedback)


def test_repeated_same_primitive_failures_trigger_stagnation() -> None:
    feedback = {
        "primitive_confirmed": True,
        "current_exploit_state": "probe_success",
        "primitive_state": {"ssti": True, "arithmetic": False, "rce": False},
        "detected_primitives": ["ssti_reflection"],
        "same_primitive_attempts": 3,
        "no_progress_streak": 3,
        "failure_reason": "reflection_blocked",
        "failure_analysis": {"type": "reflection_blocked"},
    }

    assert planner._detect_strategy_stagnation(feedback) == "reflection_blocked"
    assert _is_reflection_blocked(feedback)


def test_state_advance_resets_zero_progress_counter() -> None:
    next_streak, hard_reasons = _next_no_progress_streak(
        4,
        ["state_advance: init → probe_success"],
    )

    assert next_streak == 0
    assert hard_reasons == ["state_advance: init → probe_success"]
