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
    def __init__(self, verified_input_context: list[dict[str, str]] | None = None) -> None:
        self.verified_input_context = verified_input_context or []

    def build_planner_context(self) -> str:
        if not self.verified_input_context:
            return ""
        return json.dumps(
            {"verified_input_context": self.verified_input_context},
            ensure_ascii=False,
        )

    def get_stats(self) -> dict[str, int]:
        return {"facts_count": int(bool(self.verified_input_context))}

    def get_fact(self, key: str, default: Any = None) -> Any:
        if key == "verified_input_context":
            return self.verified_input_context
        return default


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


def _authority_source(
    context: dict[str, str],
    block_name: str,
    source_name: str,
) -> Any:
    marker = f"SOURCE: {source_name}\n"
    body = context[block_name].split(marker, 1)[1]
    if "\nSOURCE: " in body:
        body = body.split("\nSOURCE: ", 1)[0]
    return json.loads(body.strip())




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


def _run_planner(
    tmp_path: Path,
    llm: _CapturingLLM,
    confirmed: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return planner.run_planner(
        settings=SimpleNamespace(mock_llm=False),
        memory=_MemoryStub(),
        confirmed=confirmed or _confirmed_metadata(),
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
    contract = _authority_source(context, "CONSTRAINT_BLOCK", "hard_constraints")

    assert "candidate_routes" in context["STRATEGY_BLOCK"]
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
    assert contract["output_schema_contract"]["code_fallback"] == {
        "location": "steps[].code",
        "required_when": "Any sdk_call cannot be represented by the standard HTTP inflater",
        "content": "Complete non-empty Python implementing the same declared operation",
        "declaration_rule": "Keep sdk_calls structurally valid; put complex bytes and framing in code",
        "omit_when": "All sdk_calls are representable by the standard HTTP inflater",
        "runtime_target_contract": {
            "required_input": "Every complex code fallback must read target_context.runtime_targets",
            "source": "/workspace/context.json -> target_context.runtime_targets",
            "match": "Select by logical.protocol and logical.port",
            "consume": "Use runtime.host and runtime.port for the selected non-primary service",
            "forbidden": "Never hardcode localhost or 127.0.0.1 for a non-primary service",
            "primary_http_compat": "Primary HTTP keeps execution_base_url with base_url fallback",
            "resolver_pattern": "next(item['runtime'] for item in runtime_targets if item['logical']['protocol'] == protocol and item['logical']['port'] == port)",
        },
    }


def test_code_fallback_contract_requires_runtime_target_lookup(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    _isolate_planner(monkeypatch, "Route #1: arbitrary_file_write")
    llm = _CapturingLLM(_base_plan())

    _run_planner(tmp_path, llm, _grpc_file_write_metadata())
    context = json.loads(llm.last_user)
    contract = _authority_source(context, "CONSTRAINT_BLOCK", "hard_constraints")
    runtime_contract = contract["output_schema_contract"]["code_fallback"][
        "runtime_target_contract"
    ]

    assert runtime_contract["source"].endswith("target_context.runtime_targets")
    assert runtime_contract["match"] == "Select by logical.protocol and logical.port"
    assert runtime_contract["consume"] == (
        "Use runtime.host and runtime.port for the selected non-primary service"
    )
    assert "localhost or 127.0.0.1" in runtime_contract["forbidden"]
    assert runtime_contract["primary_http_compat"] == (
        "Primary HTTP keeps execution_base_url with base_url fallback"
    )


def test_required_parameter_is_generated_in_an_accepted_sdk_location(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    _isolate_planner(monkeypatch, "Route #1: reflection -> command_execution")

    def _contract_aware_response(context: dict[str, Any]) -> dict[str, Any]:
        contract = _authority_source(context, "CONSTRAINT_BLOCK", "hard_constraints")
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


def test_verified_get_surface_controls_contract_example(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        planner,
        "get_verification",
        lambda: _VerificationStub([
            {"method": "GET", "path": "/", "parameter": "text"}
        ]),
    )

    contract = planner._build_plan_generation_contract(_confirmed_metadata())

    assert contract["http_method"] == "GET"
    assert contract["endpoint"] == "/"
    assert contract["required_inputs"] == [
        {"name": "text", "accepted_locations": ["query"]}
    ]
    assert contract["examples"]["correct"] == {
        "primitive": "HttpClient.get",
        "target": "/",
        "query": {"text": "<value>"},
    }


def test_missing_verified_surface_preserves_parameter_contract_inference(
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr(planner, "get_verification", lambda: _VerificationStub())

    contract = planner._build_plan_generation_contract(_confirmed_metadata())

    assert contract["http_method"] == "POST"
    assert contract["endpoint"] == "/endpoint"
    assert contract["required_inputs"] == [
        {"name": "text", "accepted_locations": ["query", "form"]}
    ]
    assert contract["examples"]["correct"] == {
        "primitive": "HttpClient.post",
        "target": "/endpoint",
        "body": {"text": "<value>"},
        "body_format": "form",
    }


def test_planner_uses_verified_get_example_without_post_bias(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    _isolate_planner(monkeypatch, "")
    monkeypatch.setattr(
        planner,
        "get_verification",
        lambda: _VerificationStub([
            {"method": "GET", "path": "/", "parameter": "text"}
        ]),
    )

    def _contract_example_response(context: dict[str, Any]) -> dict[str, Any]:
        contract = _authority_source(
            context,
            "CONSTRAINT_BLOCK",
            "hard_constraints",
        )
        return {
            **_base_plan(),
            "steps": [{
                "id": 1,
                "status": "PLANNED",
                "type": "python",
                "imports": ["redteam_sdk.HttpClient"],
                "sdk_calls": [contract["examples"]["correct"]],
            }],
        }

    plan = _run_planner(tmp_path, _CapturingLLM(_contract_example_response))
    call = plan["steps"][0]["sdk_calls"][0]

    assert call["primitive"] == "HttpClient.get"
    assert call["target"] == "/"
    assert call["query"] == {"text": "<value>"}
    assert "body" not in call


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
    contract = _authority_source(context, "CONSTRAINT_BLOCK", "hard_constraints")
    strategies = _authority_source(
        context, "STRATEGY_BLOCK", "strategy_options"
    )

    assert strategies["candidate_routes"].startswith(
        "Route #1: primitive_1 -> objective_1"
    )
    assert "[authority content compacted]" in strategies["candidate_routes"]
    assert strategies["candidate_routes"].endswith(
        "Route #200: primitive_200 -> objective_200"
    )
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

    assert list(context) == ["FACT_BLOCK", "CONSTRAINT_BLOCK", "STRATEGY_BLOCK", "REFERENCE_BLOCK"]
    assert _authority_source(
        context, "FACT_BLOCK", "verified_state"
    ) == _confirmed_metadata()
    assert context["REFERENCE_BLOCK"].startswith("[REFERENCE ONLY]")
    assert "SOURCE:" in context["REFERENCE_BLOCK"]
    assert "confirmed_vuln" not in context
    assert "prior_feedback" not in context
    assert llm.calls == 1
    assert plan["plan_id"] == "legacy-plan"


def test_contract_priority_is_explicit_in_prompt(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    _isolate_planner(monkeypatch, "Route #1: advisory only")
    llm = _CapturingLLM(_base_plan())

    _run_planner(tmp_path, llm)
    context = json.loads(llm.last_user)
    contract = _authority_source(context, "CONSTRAINT_BLOCK", "hard_constraints")

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


def _grpc_file_write_metadata() -> dict[str, Any]:
    return {
        "vulnerabilities": [
            {
                "id": "VULN-GRPC-WRITE",
                "cwe_id": "CWE-22",
                "name": "Arbitrary file write via gRPC",
                "source": {"code": "rpc SubmitTestimonial(TestimonialSubmission)"},
                "sink": {"code": "os.WriteFile(req.Customer, req.Testimonial, 0644)"},
                "evidence": ["gRPC server listens on tcp :50045"],
            }
        ],
        "target_context": {"base_url": "http://target.test"},
    }


def test_grpc_file_write_prompt_contains_primitive_interface_contract(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    _isolate_planner(monkeypatch, "Route #1: arbitrary_file_write")
    llm = _CapturingLLM(_base_plan())

    _run_planner(tmp_path, llm, _grpc_file_write_metadata())
    context = json.loads(llm.last_user)
    contract = _authority_source(context, "CONSTRAINT_BLOCK", "hard_constraints")

    assert contract["primitive_interface_requirements"] == {
        "primitive": "arbitrary_file_write",
        "transport_requirements": {
            "protocol": "grpc",
            "network_transport": "tcp",
            "port": 50045,
        },
        "interface_requirements": {
            "rpc_method": "SubmitTestimonial",
        },
        "user_input_requirements": {
            "customer": True,
        },
    }
    assert contract["transport_requirements"] == {
        "protocol": "grpc",
        "network_transport": "tcp",
        "port": 50045,
    }
    assert contract["interface_requirements"] == {
        "rpc_method": "SubmitTestimonial",
    }
    assert contract["user_input_requirements"] == {"customer": True}


def test_primitive_interface_contract_outranks_route_objective() -> None:
    contract = planner._build_plan_generation_contract(
        _grpc_file_write_metadata(),
        "arbitrary_file_write",
    )

    assert contract["priority_order"].index("Interface contract") < (
        contract["priority_order"].index("Route candidate selection")
    )
    assert (
        "Primitive interface requirements override route objective preferences."
        in contract["candidate_route_policy"]
    )


def test_http_primitive_does_not_receive_grpc_interface_contract() -> None:
    contract = planner._build_plan_generation_contract(
        _confirmed_metadata(),
        "ssti_reflection",
    )

    assert "primitive_interface_requirements" not in contract
    assert contract["interface_contract"] == {
        "sdk_calls_location": "steps[].sdk_calls[]",
        "query_location": "sdk_calls[].query",
        "form_location": "sdk_calls[].body",
        "form_requires": "body_format=form",
    }
