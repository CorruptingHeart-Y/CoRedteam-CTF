from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
B_DIR = ROOT / "b"
if str(B_DIR) not in sys.path:
    sys.path.insert(0, str(B_DIR))

from agents.consolidator import _build_consolidator_context, _guard_failure_memory
from agents.evaluator import _classify_failure_type, run_evaluator
from agents.validator import _normalize_plan
from coordinator import _save_failure_lessons


class _Memory:
    def __init__(self) -> None:
        self.patch = None

    def apply_evaluator_patch(self, patch):
        self.patch = patch


class _StrategyMemory:
    def __init__(self) -> None:
        self.lessons = []

    def upsert_strategy(self, *args):
        self.lessons.append(args)


class _PollutingLLM:
    def complete_json(self, system, user):
        return {
            "repro_success": False,
            "confidence": 0.0,
            "error_fingerprint": "NameError",
            "summary": "wrong diagnosis",
            "analysis": {"guidance": "use host.docker.internal directly"},
            "memory_patch": {
                "tech": {"add_payload_templates": [{"payload": "polluted"}]},
                "strategy": {"add_failures": [{"fix": "bypass runtime_targets"}]},
            },
        }


def _exec_out(stdout: str, *, ok: bool) -> dict:
    return {
        "executed": True,
        "step_results": [{
            "step_id": 1,
            "result": {
                "ok": ok,
                "exit_code": 0 if ok else 1,
                "stdout": stdout,
                "stderr": "",
            },
        }],
    }


@pytest.mark.parametrize(
    ("stdout", "ok", "fingerprint", "expected"),
    [
        (
            "runtime_targets has no matching grpc target; StopIteration",
            True,
            "NameError",
            "runtime_target_missing",
        ),
        ("Connection refused", False, "ConnectionRefused", "transport_failure"),
        ("[HTTP] 400 invalid payload", False, "HTTPError4xx", "payload_failure"),
        ("[HTTP] 200 normal page", True, "NoError", "verification_failure"),
    ],
)
def test_failure_taxonomy_is_deterministic(stdout, ok, fingerprint, expected):
    feedback = {"repro_success": False, "error_fingerprint": fingerprint}
    assert _classify_failure_type(feedback, _exec_out(stdout, ok=ok), stdout) == expected


def test_runtime_target_missing_repairs_context_and_drops_payload_memory(tmp_path):
    memory = _Memory()
    feedback = run_evaluator(
        settings=SimpleNamespace(mock_llm=False),
        memory=memory,
        confirmed={},
        plan={
            "steps": [{
                "id": 1,
                "type": "python",
                "code": "targets = ctx['target_context']['runtime_targets']",
                "expected_outcome": "connect grpc",
            }],
        },
        exec_out=_exec_out(
            "STEP_FAIL: runtime_targets missing grpc:50045; StopIteration",
            ok=True,
        ),
        feedback_path=tmp_path / "feedback.json",
        llm=_PollutingLLM(),
        adapter=None,
    )

    assert feedback["failure_type"] == "runtime_target_missing"
    assert "runtime resolver/context" in feedback["next_required_action"]
    assert "不要硬编码 host.docker.internal" in feedback["next_required_action"]
    assert feedback["memory_patch"] == {}
    assert memory.patch == {}


def test_consolidator_fails_closed_for_runtime_target_missing():
    result = {
        "diagnosis": "bypass runtime_targets",
        "memory_patch": {
            "patterns": [{"fix": "hardcode host"}],
            "techs": [{"payload_template": "polluted"}],
        },
    }
    reports = {
        "feedback": {
            "failure_type": "runtime_target_missing",
            "next_required_action": "repair runtime resolver/context",
        },
    }

    guarded = _guard_failure_memory(result, reports)

    assert guarded["memory_patch"] == {}
    assert "runtime resolver/context" in guarded["diagnosis"]
    assert result["memory_patch"]
    context = _build_consolidator_context(reports)
    assert "failure_type=runtime_target_missing" in context
    assert "repair runtime resolver/context" in context


def test_chain_design_locks_target_primitive_against_llm_override():
    plan = {
        "chain_design": ["filesystem_traversal", "arbitrary_file_write"],
        "primitive_context": {"target_primitive": "random_llm_choice"},
        "steps": [],
    }

    normalized, warnings = _normalize_plan(plan)

    assert normalized["primitive_context"]["target_primitive"] == "arbitrary_file_write"
    assert plan["primitive_context"]["target_primitive"] == "random_llm_choice"
    assert any("locked to chain_design" in warning for warning in warnings)

    without_context, _ = _normalize_plan({
        "chain_design": ["filesystem_traversal", "arbitrary_file_write"],
        "steps": [],
    })
    assert without_context["primitive_context"]["target_primitive"] == "arbitrary_file_write"

def test_pre_evaluator_failure_logger_skips_runtime_target_missing():
    memory = _StrategyMemory()
    exec_out = _exec_out("", ok=False)
    exec_out["step_results"][0]["result"]["stderr"] = (
        "runtime_targets has no matching grpc target; StopIteration"
    )

    _save_failure_lessons(memory, exec_out, {}, {"vulnerabilities": []})

    assert memory.lessons == []
