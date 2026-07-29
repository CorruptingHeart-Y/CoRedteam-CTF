from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
B_DIR = ROOT / "b"
if str(B_DIR) not in sys.path:
    sys.path.insert(0, str(B_DIR))

from agents import planner


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
    def __init__(
        self,
        response: dict[str, Any] | Callable[[dict[str, Any]], dict[str, Any]],
    ) -> None:
        self.response = response
        self.last_system = ""
        self.last_user = ""
        self.calls = 0

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        self.calls += 1
        self.last_system = system
        self.last_user = user
        user_context = json.loads(user)
        if callable(self.response):
            return self.response(user_context)
        return dict(self.response)


def _confirmed_metadata() -> dict[str, Any]:
    return {
        "vulnerabilities": [
            {
                "id": "VULN-001",
                "title": "Template injection",
                "cwe_id": "CWE-917",
                "severity": "CRITICAL",
                "source": {
                    "code": '@RequestParam(name = "text") String textString'
                },
                "sink": {"code": "template.parse(input)"},
                "evidence": [
                    {"code_snippet": '@PostMapping("/endpoint")'}
                ],
                "exploitation": "POST to /endpoint with the required parameter",
            }
        ],
        "target_context": {"base_url": "http://target.test"},
    }


def _base_plan() -> dict[str, Any]:
    return {
        "version": 1,
        "plan_id": "legacy-plan",
        "vuln_summary": "test",
        "rationale": "test",
        "chain_design": "test",
        "steps": [],
        "history_state": {},
        "primitive_context": {},
    }


def _isolate_planner(monkeypatch: Any, candidate_routes: str) -> None:
    monkeypatch.setattr(planner, "_build_memory_context", lambda *args: "")
    monkeypatch.setattr(
        planner,
        "_extract_user_goal_dense",
        lambda *args, **kwargs: "legacy goal",
    )
    monkeypatch.setattr(planner, "_build_primitive_context", lambda *args, **kwargs: "")
    monkeypatch.setattr(planner, "RouteKnowledgeProvider", _RouteKnowledgeStub)
    monkeypatch.setattr(planner, "get_verification", lambda: _VerificationStub())
    monkeypatch.setattr(planner, "get_trajectory", lambda: _TrajectoryStub())
    monkeypatch.setattr(
        planner,
        "_build_candidate_routes_layer",
        lambda confirmed, feedback=None: candidate_routes,
    )


def _run_planner(tmp_path: Path, llm: _CapturingLLM) -> dict[str, Any]:
    return planner.run_planner(
        settings=SimpleNamespace(mock_llm=False),
        memory=_MemoryStub(),
        confirmed=_confirmed_metadata(),
        feedback=None,
        out_path=tmp_path / "plan.json",
        llm=llm,
    )


def test_complete_metadata_context_contains_candidates_inputs_and_interface(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    _isolate_planner(monkeypatch, "Route #1: reflection -> file_read")
    llm = _CapturingLLM(_base_plan())

    _run_planner(tmp_path, llm)
    context = json.loads(llm.last_user)
    contract = context["plan_generation_contract"]

    assert "candidate_routes" in context
    assert contract["required_inputs"] == [
        {"name": "text", "accepted_locations": ["query", "form"]}
    ]
    assert contract["http_method"] == "POST"
    assert contract["endpoint"] == "/endpoint"
    assert contract["interface_contract"] == {
        "sdk_calls_location": "steps[].sdk_calls[]",
        "query_location": "sdk_calls[].query",
        "form_location": "sdk_calls[].body",
        "form_requires": "body_format=form",
    }


def test_required_parameter_is_generated_in_an_accepted_sdk_location(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    _isolate_planner(monkeypatch, "Route #1: reflection -> command_execution")

    def _contract_aware_response(context: dict[str, Any]) -> dict[str, Any]:
        contract = context["plan_generation_contract"]
        required = contract["required_inputs"][0]
        assert required["name"] == "text"
        assert required["accepted_locations"] == ["query", "form"]
        return {
            **_base_plan(),
            "steps": [
                {
                    "id": 1,
                    "status": "PLANNED",
                    "type": "python",
                    "imports": ["redteam_sdk.HttpClient"],
                    "sdk_calls": [
                        {
                            "primitive": "HttpClient.post",
                            "target": contract["endpoint"],
                            "body": {required["name"]: "<value>"},
                            "body_format": "form",
                        }
                    ],
                }
            ],
        }

    plan = _run_planner(tmp_path, _CapturingLLM(_contract_aware_response))
    call = plan["steps"][0]["sdk_calls"][0]

    in_query = "text" in (call.get("query") or {})
    in_form = (
        "text" in (call.get("body") or {})
        and call.get("body_format") == "form"
    )
    assert in_query or in_form
    assert "text" not in call


def test_many_candidate_routes_do_not_override_generation_contract(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    many_routes = "\n".join(
        f"Route #{index}: primitive_{index} -> objective_{index}"
        for index in range(1, 201)
    )
    _isolate_planner(monkeypatch, many_routes)
    llm = _CapturingLLM(_base_plan())

    _run_planner(tmp_path, llm)
    context = json.loads(llm.last_user)
    contract = context["plan_generation_contract"]

    assert context["candidate_routes"] == many_routes
    assert contract["contract_name"] == "PLAN GENERATION CONTRACT"
    assert contract["required_inputs"][0]["name"] == "text"
    assert contract["interface_contract"]["form_location"] == "sdk_calls[].body"


def test_no_candidate_routes_preserves_existing_planner_flow(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    _isolate_planner(monkeypatch, "")
    llm = _CapturingLLM(_base_plan())

    plan = _run_planner(tmp_path, llm)
    context = json.loads(llm.last_user)

    assert "candidate_routes" not in context
    assert context["confirmed_vuln"] == _confirmed_metadata()
    assert "layered_memory" in context
    assert "prior_feedback" in context
    assert llm.calls == 1
    assert plan["plan_id"] == "legacy-plan"


def test_contract_priority_is_explicit_in_prompt(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    _isolate_planner(monkeypatch, "Route #1: advisory only")
    llm = _CapturingLLM(_base_plan())

    _run_planner(tmp_path, llm)
    contract = json.loads(llm.last_user)["plan_generation_contract"]

    assert contract["priority_order"] == [
        "Output schema contract",
        "Interface contract",
        "Required input placement",
        "Route candidate selection",
        "Optimization objective",
    ]
    assert (
        "Schema compliance has higher priority than route selection."
        in llm.last_user
    )
    assert (
        "Candidate routes describe WHAT strategy to consider."
        in llm.last_user
    )
    assert (
        "They do NOT override HOW the generated plan must satisfy interface contracts."
        in llm.last_user
    )
