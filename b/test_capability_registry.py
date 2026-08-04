from __future__ import annotations

import sys
from pathlib import Path


B_DIR = Path(__file__).resolve().parent
if str(B_DIR) not in sys.path:
    sys.path.insert(0, str(B_DIR))

from agents import evaluator, executor, validator  # noqa: E402
from core.capability_contract import validate_capability_contract  # noqa: E402
from core.capability_memory import gate_executable_tech_memory  # noqa: E402
from core.capability_registry import get_capability_registry  # noqa: E402


def _grpc_plan(adapter: str = "grpc_client") -> dict:
    return {
        "version": 1,
        "primitive_context": {
            "transport_requirements": {"protocol": "grpc", "port": 50051},
        },
        "steps": [{
            "id": 1,
            "type": "python",
            "execution_interface": {"adapter": adapter},
            "sdk_calls": [{
                "primitive": "GrpcClient.call",
                "target": "localhost:50051",
                "service": "example.Echo",
                "method": "Send",
                "payload": {"message": "hello"},
                "metadata": {"authorization": "Bearer token"},
            }],
        }],
    }


def test_registered_capability_is_available() -> None:
    registry = get_capability_registry()

    decision = registry.validate(
        capability_id="grpc_client",
        call="GrpcClient.call",
    )

    assert decision.allowed is True
    assert decision.code == "CAPABILITY_AVAILABLE"
    assert registry.get("grpc_client").adapter == "GrpcClient"


def test_unregistered_capability_is_rejected() -> None:
    errors = validate_capability_contract(_grpc_plan("invented_adapter"))

    assert errors[0] == (
        "[CAPABILITY_NOT_REGISTERED] steps[0].execution_interface.adapter=invented_adapter"
    )



    result = validator.validate_plan(_grpc_plan("invented_adapter"))
    assert (
        "[CAPABILITY_NOT_REGISTERED] "
        "steps[0].execution_interface.adapter=invented_adapter"
    ) in result["errors"]


def test_planner_grpc_declaration_builds_deterministic_sdk_contract() -> None:
    plan = _grpc_plan()
    step = plan["steps"][0]

    assert validate_capability_contract(plan) == []
    assert validator.validate_plan(plan)["passed"] is True
    assert executor._sdk_calls_fully_supported_by_inflater(step["sdk_calls"])

    script = executor._inflate_ast_to_script(step)
    compile(script, "<grpc-contract>", "exec")
    assert "GrpcClient.call(" in script
    assert "###EXECUTION_RESULT###" in script
    assert "grpc.insecure_channel" in executor.GRPC_SDK_SOURCE

    stdout = '###EXECUTION_RESULT###{"protocol":"grpc","ok":true}\n'
    results = executor._extract_execution_results_from_stdout(stdout)
    assert results == [{"protocol": "grpc", "ok": True}]
    assert evaluator._local_evidence_state(
        "", {}, "", "", False, [{"execution_results": results}]
    ) == "probe_success"


def test_missing_dependency_cannot_enter_executable_tech_memory() -> None:
    memory_patch = {
        "techs": [{
            "vulnerability": "example grpc technique",
            "description": "use a registered high-level adapter",
            "payload_template": "GrpcClient.call(...) discarded",
            "executable_patch": "from redteam_sdk import GrpcClient",
            "capability_id": "grpc_client",
            "required_modules": ["unregistered_dependency"],
        }],
        "patterns": [],
        "yaml_operations": [{"operation": "create"}],
    }

    gated = gate_executable_tech_memory(memory_patch)

    assert gated["techs"] == []
    assert gated["yaml_operations"] == []
    assert len(gated["patterns"]) == 1
    pattern = gated["patterns"][0]
    assert pattern["non_executable"] is True
    assert pattern["type"] == "strategy"
    assert pattern["capability_diagnostics"] == [
        "CAPABILITY_DEPENDENCY_UNAVAILABLE"
    ]
    assert "payload_template" not in pattern
    assert "executable_patch" not in pattern
