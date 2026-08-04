from __future__ import annotations

import sys
from pathlib import Path


B_DIR = Path(__file__).resolve().parent
if str(B_DIR) not in sys.path:
    sys.path.insert(0, str(B_DIR))

from agents.consolidator import _admit_memory_result  # noqa: E402
from core.capability_registry import (  # noqa: E402
    CapabilityRegistry,
    get_capability_registry,
    is_capability_available,
)


def _reports(failure_type: str) -> dict:
    return {"feedback": {"failure_type": failure_type}}


def test_payload_failure_grpcurl_tech_is_downgraded_when_tool_unavailable() -> None:
    assert is_capability_available("shell_command:grpcurl") is False
    result = {
        "memory_patch": {
            "patterns": [],
            "techs": [{
                "type": "command",
                "content": "grpcurl -plaintext localhost:50051 list",
                "description": "gRPC endpoints require a protocol-aware client.",
            }],
            "yaml_operations": [{"operation": "create"}],
        },
    }

    admitted = _admit_memory_result(result, _reports("payload_failure"))
    patch = admitted["memory_patch"]

    assert patch["techs"] == []
    assert patch["yaml_operations"] == []
    assert len(patch["patterns"]) == 1
    strategy = patch["patterns"][0]
    assert strategy["type"] == "strategy"
    assert strategy["non_executable"] is True
    assert strategy["capability_diagnostics"] == [
        "CAPABILITY_TOOL_UNAVAILABLE"
    ]
    assert "content" not in strategy


def test_payload_failure_httpclient_tech_is_admitted() -> None:
    assert is_capability_available("http_client") is True
    tech = {
        "type": "python",
        "content": (
            "from redteam_sdk import HttpClient\n"
            "response = HttpClient('http://target').get('/health')"
        ),
        "description": "Use the registered HTTP execution primitive.",
    }
    result = {
        "memory_patch": {
            "patterns": [],
            "techs": [tech],
            "yaml_operations": [],
        },
    }

    admitted = _admit_memory_result(result, _reports("payload_failure"))

    assert admitted["memory_patch"]["techs"] == [tech]
    assert admitted["memory_patch"]["patterns"] == []


def test_runtime_target_missing_still_blocks_all_memory() -> None:
    result = {
        "memory_patch": {
            "patterns": [{"name": "must not persist"}],
            "techs": [{"type": "python", "content": "HttpClient('/')"}],
            "yaml_operations": [{"operation": "create"}],
        },
    }

    admitted = _admit_memory_result(result, _reports("runtime_target_missing"))
    patch = admitted["memory_patch"]

    assert patch.get("patterns", []) == []
    assert patch.get("techs", []) == []
    assert patch.get("yaml_operations", []) == []


def test_query_uses_registered_manifest_for_modules_and_capabilities() -> None:
    http_only = CapabilityRegistry((
        get_capability_registry().get("http_client"),
    ))

    assert is_capability_available("http_client", http_only) is True
    assert is_capability_available("grpc_client", http_only) is False
    assert is_capability_available(
        {"kind": "python_module", "name": "grpc"}, http_only
    ) is False
    assert is_capability_available("redis_client", http_only) is False
    assert is_capability_available("memcached_client", http_only) is False
