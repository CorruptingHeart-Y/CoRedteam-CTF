from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
B_DIR = ROOT / "b"
if str(B_DIR) not in sys.path:
    sys.path.insert(0, str(B_DIR))

from agents import planner
from memory.primitive_transition_graph import PrimitiveTransitionGraph
from routes.knowledge_provider import (
    RouteKnowledgeProvider,
    build_route_knowledge_context,
)

_SSTI_REFLECTION_TRANSITIONS = [
    "ssti_execution",
    "blind_ssti",
    "template_access",
    "configuration_disclosure",
    "file_read",
    "command_execution",
]


def _write_route(route_root: Path) -> Path:
    route_dir = route_root / "challenge"
    route_dir.mkdir(parents=True)
    route_path = route_dir / "route.yaml"
    route_path.write_text(
        """
schema_version: 1.1.0
canonical_id: cwe-94:init:ssti-reflection:arithmetic-probe
cwe_id: CWE-94
current_state: init
technique: arithmetic_probe
metadata:
  strategy_class: reflection_probe
activation:
  state: draft
target_primitive: ssti_reflection
payload_template_ref: primitive:ssti_reflection:sha256:008b15dab525fb94
expected_signals:
  - arithmetic_result_in_response
materialization:
  type: http_request
  body: challenge-specific-secret
  raw_payload: do-not-leak
  payload_template: do-not-leak-template
generation_status: candidate_only
historical_outcome: success
""".strip(),
        encoding="utf-8",
    )
    return route_path


def _confirmed(cwe: str = "CWE-94") -> dict:
    return {"vulnerabilities": [{"cwe_id": cwe}]}


def test_manual_yaml_metadata_reaches_planner_context(tmp_path):
    route_root = tmp_path / "manual_routes"
    _write_route(route_root)
    provider = RouteKnowledgeProvider(route_root)

    knowledge = provider.for_confirmed(_confirmed())
    assert len(knowledge) == 1
    assert knowledge[0].to_plain() == {
        "cwe": "CWE-94",
        "primitive": "ssti_reflection",
        "route_state": "init",
        "possible_transitions": _SSTI_REFLECTION_TRANSITIONS,
        "expected_signals": ["arithmetic_result_in_response"],
        "strategy_class": "reflection_probe",
        "route_status": "candidate_only",
        "historical_outcome": "success",
    }
    context = build_route_knowledge_context(_confirmed(), route_root)
    assert "Route Intelligence Block" in context
    assert f"possible_transitions={_SSTI_REFLECTION_TRANSITIONS}" in context
    assert "expected_signals=['arithmetic_result_in_response']" in context


def test_route_knowledge_omits_payload_and_materialization_data(tmp_path):
    route_root = tmp_path / "manual_routes"
    _write_route(route_root)
    provider = RouteKnowledgeProvider(route_root)

    serialized = json.dumps(
        [item.to_plain() for item in provider.for_confirmed(_confirmed())]
    )
    context = provider.build_planner_context(_confirmed())
    for forbidden in (
        "payload_template",
        "raw_payload",
        "materialization",
        "http_request",
        "challenge-specific-secret",
        "008b15dab525fb94",
    ):
        assert forbidden not in serialized
        assert forbidden not in context


class _FakeVerification:
    def build_planner_context(self) -> str:
        return ""

    def get_stats(self) -> dict:
        return {"facts_count": 0}


class _FakeMemory:
    def planning_context(self) -> str:
        return "{}"


class _CapturingLlm:
    def __init__(self) -> None:
        self.system = ""
        self.user = ""

    def complete_json(self, system: str, user: str) -> dict:
        self.system = system
        self.user = user
        return {
            "version": 1,
            "plan_id": "llm-generated",
            "rationale": "chosen by the LLM Planner",
            "steps": [],
        }


def _capture_planner_prompt(tmp_path, monkeypatch, provider, feedback=None):
    monkeypatch.setattr(planner, "RouteKnowledgeProvider", lambda: provider)
    monkeypatch.setattr(
        planner, "_build_memory_context", lambda *args: "ordinary-memory-marker"
    )
    monkeypatch.setattr(
        planner, "_build_primitive_context", lambda *args: "confirmed-fact-marker"
    )
    monkeypatch.setattr(planner, "get_verification", lambda: _FakeVerification())
    monkeypatch.setattr(planner, "_build_trajectory_context", lambda traj: "")
    monkeypatch.setattr(planner, "get_trajectory", lambda: object())
    monkeypatch.setattr(planner, "_build_candidate_routes_layer", lambda *args: "")
    monkeypatch.setattr(planner, "_build_exploit_transition_context", lambda: {})
    monkeypatch.setattr(planner, "_resolve_planning_primitive", lambda *args: "")
    monkeypatch.setattr(planner, "_build_plan_generation_contract", lambda *args: {})
    monkeypatch.setattr(planner, "_normalized_cwe_template_sources", lambda *args: [])
    monkeypatch.setattr(
        planner, "_extract_user_goal_dense", lambda *args, **kwargs: "JSON user goal"
    )
    monkeypatch.setattr(planner, "_extract_plan_ast", lambda plan: plan)

    llm = _CapturingLlm()
    result = planner.run_planner(
        settings=SimpleNamespace(mock_llm=False),
        memory=_FakeMemory(),
        confirmed=_confirmed(),
        feedback=feedback,
        out_path=tmp_path / "plan.json",
        llm=llm,
    )
    assert result["plan_id"] == "llm-generated"
    return llm


def test_a_no_route_keeps_planner_behavior_and_prompt_route_free(
    tmp_path, monkeypatch
):
    provider = RouteKnowledgeProvider(tmp_path / "does-not-exist")
    feedback = {
        "primitive_confirmed": True,
        "exploit_completed": False,
        "failure_reason": "reflection_blocked",
        "same_primitive_attempts": 3,
        "no_progress_streak": 3,
        "failure_analysis": {"type": "reflection_blocked"},
    }
    llm = _capture_planner_prompt(tmp_path, monkeypatch, provider, feedback)

    assert "Route Intelligence Block" not in llm.system
    assert "[DIVERSIFY]" in llm.system
    assert "ssti_reflection exploration hint" not in llm.user
    assert "ordinary-memory-marker" in llm.system


def test_b_route_metadata_is_in_planner_prompt(tmp_path, monkeypatch):
    route_root = tmp_path / "manual_routes"
    _write_route(route_root)
    provider = RouteKnowledgeProvider(route_root)
    llm = _capture_planner_prompt(tmp_path, monkeypatch, provider)

    user = json.loads(llm.user)
    assert "ssti_reflection exploration hint" in user["REFERENCE_BLOCK"]
    assert "ssti_reflection exploration hint" not in user.get("STRATEGY_BLOCK", "")
    assert "ssti_reflection exploration hint" not in user.get("CONSTRAINT_BLOCK", "")
    assert "current_state" not in user["REFERENCE_BLOCK"]
    for transition in _SSTI_REFLECTION_TRANSITIONS:
        assert transition not in user["REFERENCE_BLOCK"]
    assert "arithmetic_result_in_response" in llm.system


def test_planner_fact_outranks_route_factory_candidate_hint(tmp_path, monkeypatch):
    route_root = tmp_path / "manual_routes"
    _write_route(route_root)
    provider = RouteKnowledgeProvider(route_root)
    llm = _capture_planner_prompt(
        tmp_path,
        monkeypatch,
        provider,
        feedback={
            "current_primitive": "command_execution",
            "confirmed_primitives": ["command_execution"],
        },
    )
    user = json.loads(llm.user)

    assert "command_execution" in user["FACT_BLOCK"]
    assert "ssti_reflection exploration hint" in user["REFERENCE_BLOCK"]
    assert "ssti_reflection exploration hint" not in user.get("STRATEGY_BLOCK", "")
    assert "ssti_reflection exploration hint" not in user.get("CONSTRAINT_BLOCK", "")
    assert list(user).index("FACT_BLOCK") < list(user).index("REFERENCE_BLOCK")


def test_c_reflection_blocked_prompt_has_route_intelligence_and_diversify(
    tmp_path, monkeypatch
):
    route_root = tmp_path / "manual_routes"
    _write_route(route_root)
    provider = RouteKnowledgeProvider(route_root)
    feedback = {
        "primitive_confirmed": True,
        "exploit_completed": False,
        "failure_reason": "reflection_blocked",
        "current_exploit_state": "probe_success",
        "same_primitive_attempts": 3,
        "no_progress_streak": 3,
        "failure_analysis": {"type": "reflection_blocked"},
    }
    llm = _capture_planner_prompt(tmp_path, monkeypatch, provider, feedback)
    user = json.loads(llm.user)
    assert "ssti_reflection exploration hint" in user["REFERENCE_BLOCK"]
    assert "ssti_reflection exploration hint" not in user.get("CONSTRAINT_BLOCK", "")
    assert "ssti_reflection exploration hint" not in user.get("STRATEGY_BLOCK", "")
    assert "[DIVERSIFY]" in llm.system


def test_no_manual_routes_keeps_route_context_empty(tmp_path):
    missing_root = tmp_path / "does-not-exist"
    provider = RouteKnowledgeProvider(missing_root)
    assert provider.for_confirmed(_confirmed()) == []
    assert provider.build_planner_context(_confirmed()) == ""
    assert build_route_knowledge_context(_confirmed(), missing_root) == ""


def test_candidate_only_route_is_advisory_not_an_execution_plan(tmp_path):
    route_root = tmp_path / "manual_routes"
    _write_route(route_root)
    provider = RouteKnowledgeProvider(route_root)
    plain = provider.for_confirmed(_confirmed())[0].to_plain()
    context = provider.build_planner_context(_confirmed())

    assert plain["route_status"] == "candidate_only"
    assert set(plain).isdisjoint(
        {"steps", "command", "sdk_calls", "request_body", "materialization"}
    )
    assert "execution_authority: none" in context
    assert "must never be copied into execution steps" in context
    assert "LLM Planner remains the sole plan decision-maker" in context


def test_d_route_context_has_no_payload_or_request_material(tmp_path, monkeypatch):
    route_root = tmp_path / "manual_routes"
    _write_route(route_root)
    provider = RouteKnowledgeProvider(route_root)
    llm = _capture_planner_prompt(tmp_path, monkeypatch, provider)
    route_block = json.loads(llm.user)["REFERENCE_BLOCK"].lower()
    route_user_context = route_block

    for forbidden in ("payload", "raw_payload", "materialization", "request body"):
        assert forbidden not in route_block
        assert forbidden not in route_user_context

    for secret in ("challenge-specific-secret", "do-not-leak"):
        assert secret not in llm.system
        assert secret not in llm.user


def test_cwe_alias_uses_authoritative_entry_primitive(tmp_path):
    route_root = tmp_path / "manual_routes"
    _write_route(route_root)
    provider = RouteKnowledgeProvider(route_root)
    assert provider.for_confirmed(_confirmed("CWE-917"))[0].primitive == "ssti_reflection"


def test_ssti_reflection_graph_keeps_execution_and_adds_optional_objectives():
    graph = PrimitiveTransitionGraph()

    assert graph.get_next_primitives("ssti_reflection") == (
        _SSTI_REFLECTION_TRANSITIONS
    )
    for objective in (
        "template_access",
        "configuration_disclosure",
        "file_read",
    ):
        condition = graph.get_transition_condition("ssti_reflection", objective)
        assert "Optional objective" in condition
        assert "does not require command execution" in condition


def test_ssti_reflection_objectives_are_possible_not_forced():
    graph = PrimitiveTransitionGraph()

    targets = graph.get_all_upgrade_targets(["ssti_reflection"])
    assert [target for _, target, _ in targets] == _SSTI_REFLECTION_TRANSITIONS
    path = graph.find_shortest_path("ssti_reflection", "template_access")
    assert path is not None
    assert path.path == [
        "ssti_reflection",
        "template_access",
    ]
