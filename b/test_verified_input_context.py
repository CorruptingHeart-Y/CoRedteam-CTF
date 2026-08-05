from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
B_DIR = ROOT / "b"
if str(B_DIR) not in sys.path:
    sys.path.insert(0, str(B_DIR))

import coordinator
from core.context_authority import compile_context_authority
from memory.verification_memory import VerificationMemory


def _ast_plan() -> dict:
    return {"steps": [{"id": 1, "sdk_calls": [{
        "primitive": "HttpClient.post",
        "target": "/render",
        "query": None,
        "body": {"text": "{{7*7}}"},
        "body_format": "form",
    }]}]}


def test_verified_input_context_is_persisted_and_rendered_in_fact_authority(
    tmp_path: Path,
) -> None:
    memory = VerificationMemory(tmp_path / "verification_memory.json")
    memory.confirm_input_context("post", "/render", "text")
    memory.confirm_input_context("POST", "/render", "text")

    reloaded = VerificationMemory(memory.path)
    assert reloaded.get_fact("verified_input_context") == [
        {"method": "POST", "path": "/render", "parameter": "text"}
    ]
    authority = compile_context_authority(
        verified_state=reloaded.build_planner_context()
    )
    assert "method=POST path=/render parameter=text" in authority.fact_block
    assert "reuse before exploring alternatives" in authority.fact_block


def test_record_verified_facts_extracts_request_context_from_ast_sdk_calls(
    monkeypatch,
    tmp_path: Path,
) -> None:
    memory = VerificationMemory(tmp_path / "verification_memory.json")
    monkeypatch.setattr(coordinator, "get_verification", lambda: memory)

    coordinator._record_verified_facts(
        {
            "current_exploit_state": "probe_success",
            "confirmed_primitives": ["input_processed"],
        },
        [{"step_id": 1, "result": {"ok": True, "stdout": "", "stderr": ""}}],
        _ast_plan(),
    )
    assert memory.get_fact("verified_input_context") == [
        {"method": "POST", "path": "/render", "parameter": "text"}
    ]


def test_unverified_or_failed_sdk_call_is_not_recorded(
    monkeypatch,
    tmp_path: Path,
) -> None:
    memory = VerificationMemory(tmp_path / "verification_memory.json")
    monkeypatch.setattr(coordinator, "get_verification", lambda: memory)

    coordinator._record_verified_facts(
        {"current_exploit_state": "probe_success", "confirmed_primitives": []},
        [{"step_id": 1, "result": {"ok": True, "stdout": "", "stderr": ""}}],
        _ast_plan(),
    )
    coordinator._record_verified_facts(
        {
            "current_exploit_state": "payload_injected",
            "confirmed_primitives": ["input_processed"],
        },
        [{"step_id": 1, "result": {"ok": False, "stderr": "failed"}}],
        _ast_plan(),
    )
    assert memory.get_fact("verified_input_context") == []
