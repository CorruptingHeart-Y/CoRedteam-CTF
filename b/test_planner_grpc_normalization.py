from __future__ import annotations

from copy import deepcopy
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
B_DIR = ROOT / "b"
if str(B_DIR) not in sys.path:
    sys.path.insert(0, str(B_DIR))

from agents import planner, validator  # noqa: E402
from core.capability_contract import validate_capability_contract  # noqa: E402
from core.plan_contract import validate_plan_structure  # noqa: E402


_RUNTIME_TARGETS = [{
    "logical": {"protocol": "grpc", "host": "target.test", "port": 50045},
    "runtime": {"host": "host.docker.internal", "port": 50045},
}]


def _plan(protocol: str, step: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": 1,
        "steps": [step],
        "primitive_context": {
            "transport_requirements": {"protocol": protocol, "port": 50045},
            "interface_requirements": {
                "service": "ricky.RickyService",
                "rpc_method": "SubmitTestimonial",
            },
        },
    }


def _assert_validator_contract_closed(plan: dict[str, Any]) -> None:
    assert validate_plan_structure(plan).passed is True
    assert validate_capability_contract(plan) == []
    assert validator._check_transport_execution_contract(plan) == []
    assert validator.validate_plan(plan)["passed"] is True


def test_grpc_without_execution_interface_is_normalized() -> None:
    plan = _plan("grpc", {
        "id": 1,
        "type": "python",
        "payload": {"customer": "../proof", "testimonial": "proof"},
    })

    normalized = planner._normalize_generated_plan(plan, _RUNTIME_TARGETS)
    step = normalized["steps"][0]
    call = step["sdk_calls"][0]

    assert step["execution_interface"] == {"adapter": "grpc_client"}
    assert call["adapter"] == "grpc_client"
    assert call["method"] == "call"
    assert call["service"] == "ricky.RickyService"
    assert call["rpc_method"] == "SubmitTestimonial"
    _assert_validator_contract_closed(normalized)


def test_grpc_httpclient_is_replaced_by_grpc_client() -> None:
    plan = _plan("grpc", {
        "id": 1,
        "type": "python",
        "execution_interface": {"adapter": "http_client"},
        "sdk_calls": [{
            "primitive": "HttpClient.post",
            "target": "/api/testimonial",
            "body": {"customer": "../proof", "testimonial": "proof"},
        }],
    })

    plan["primitive_context"]["interface_requirements"] = {
        "service": "llm.WrongService",
        "rpc_method": "WrongMethod",
    }
    resolver_evidence = {
        "transport_requirements": {"protocol": "grpc", "port": 50045},
        "interface_requirements": {
            "service": "ricky.RickyService",
            "rpc_method": "SubmitTestimonial",
        },
    }
    normalized = planner._normalize_generated_plan(
        plan,
        _RUNTIME_TARGETS,
        resolver_evidence,
    )
    step = normalized["steps"][0]

    assert step["execution_interface"] == {"adapter": "grpc_client"}
    assert step["sdk_calls"][0]["primitive"] == "GrpcClient.call"
    assert step["sdk_calls"][0]["service"] == "ricky.RickyService"
    assert step["sdk_calls"][0]["rpc_method"] == "SubmitTestimonial"
    assert all(
        not str(call.get("primitive", "")).startswith("HttpClient.")
        for call in step["sdk_calls"]
    )
    _assert_validator_contract_closed(normalized)


def test_http_plan_is_unchanged() -> None:
    plan = _plan("http", {
        "id": 1,
        "type": "python",
        "sdk_calls": [{"primitive": "HttpClient.post", "target": "/"}],
    })
    expected = deepcopy(plan)

    assert planner._normalize_generated_plan(plan, _RUNTIME_TARGETS) == expected
