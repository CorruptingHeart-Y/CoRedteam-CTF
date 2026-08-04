from __future__ import annotations

import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
B_DIR = ROOT / "b"
if str(B_DIR) not in sys.path:
    sys.path.insert(0, str(B_DIR))

from agents import planner, validator  # noqa: E402


def _plan(protocol: str, step: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": 1,
        "steps": [step],
        "primitive_context": {
            "transport_requirements": {"protocol": protocol},
        },
    }


def test_http_transport_allows_httpclient_post() -> None:
    plan = _plan("http", {
        "sdk_calls": [{"primitive": "HttpClient.post", "target": "/"}],
    })

    assert validator._check_transport_execution_contract(plan) == []


def test_grpc_transport_rejects_httpclient_post() -> None:
    plan = _plan("grpc", {
        "sdk_calls": [{"primitive": "HttpClient.post", "target": "/"}],
    })

    errors = validator._check_transport_execution_contract(plan)

    assert errors == [
        "transport mismatch: grpc protocol cannot use HttpClient primitive"
    ]


def test_grpc_transport_accepts_grpc_client_interface() -> None:
    plan = _plan("grpc", {
        "execution_interface": {"adapter": "grpc_client"},
        "sdk_calls": [{
            "primitive": "GrpcClient.call",
            "target": "localhost:50045",
            "service": "testimonial.TestimonialService",
            "method": "SubmitTestimonial",
            "payload": {"customer": "test"},
        }],
    })

    assert validator._check_transport_execution_contract(plan) == []


def test_grpc_transport_rejects_explicit_code_mode() -> None:
    plan = _plan("grpc", {
        "execution_mode": "code",
        "code": "# gRPC-compatible code path supplied later",
    })

    assert validator._check_transport_execution_contract(plan) == [
        "transport mismatch: grpc protocol requires "
        "execution_interface.adapter=grpc_client"
    ]


def test_validate_plan_surfaces_grpc_httpclient_mismatch_as_blocking_error() -> None:
    plan = {
        "version": 1,
        "plan_id": "grpc-mismatch",
        "vuln_summary": "gRPC arbitrary file write",
        "rationale": "exercise transport contract",
        "chain_design": "single step",
        "history_state": {},
        "primitive_context": {
            "current_primitive": "arbitrary_file_write",
            "target_primitive": "arbitrary_file_write",
            "transport_requirements": {"protocol": "grpc", "port": 50045},
        },
        "steps": [{
            "id": 1,
            "type": "python",
            "imports": [],
            "sdk_calls": [{"primitive": "HttpClient.post", "target": "/"}],
            "target_primitive": "arbitrary_file_write",
        }],
    }

    result = validator.validate_plan(plan)

    assert result["passed"] is False
    assert "transport mismatch: grpc protocol cannot use HttpClient primitive" in (
        result["errors"]
    )


def test_grpc_planner_contract_requires_compatible_execution_interface() -> None:
    confirmed = {
        "vulnerabilities": [{
            "cwe_id": "CWE-22",
            "source": {"code": "rpc SubmitTestimonial(TestimonialSubmission)"},
            "evidence": ["gRPC server listens on tcp :50045"],
        }],
    }

    contract = planner._build_plan_generation_contract(
        confirmed,
        "arbitrary_file_write",
    )
    execution = contract["execution_requirements"]

    assert execution["forbidden_sdk_primitives"] == [
        "HttpClient.get",
        "HttpClient.post",
        "HttpClient.raw_request",
    ]
    assert execution["one_of"] == [
        {"execution_interface": {"adapter": "grpc_client"}},
    ]
    assert "Do not use HttpClient for a gRPC target." in execution["planner_rules"]
    assert "Do not generate an HTTP JSON body for a gRPC target." in (
        execution["planner_rules"]
    )
    assert "Use only the structured GrpcClient.call execution primitive." in execution["planner_rules"]
    assert execution["sdk_call_contract"] == {
        "primitive": "GrpcClient.call",
        "required_fields": ["target", "service", "method", "payload", "metadata"],
        "payload_type": "object",
    }
    assert "implemented by redteam_sdk.GrpcClient" in execution[
        "adapter_scope"
    ]
