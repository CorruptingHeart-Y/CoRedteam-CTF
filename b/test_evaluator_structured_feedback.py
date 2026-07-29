from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
B_DIR = ROOT / "b"
if str(B_DIR) not in sys.path:
    sys.path.insert(0, str(B_DIR))

from agents.evaluator import run_evaluator


class _Memory:
    def apply_evaluator_patch(self, patch):
        self.patch = patch


def test_velocity_arithmetic_confirms_primitive_not_exploit(tmp_path):
    plan = {
        "version": 1,
        "plan_id": "plan_arithmetic_probe",
        "steps": [
            {
                "id": 1,
                "type": "python",
                "sdk_calls": [
                    {
                        "primitive": "HttpClient.post",
                        "target": "/",
                        "body": {"text": "#set($x=49*2)$x"},
                        "body_format": "form",
                    }
                ],
                "expected_outcome": "arithmetic_result_in_response",
                "target_primitive": "ssti_reflection",
            }
        ],
    }
    exec_out = {
        "version": 1,
        "executed": True,
        "step_results": [
            {
                "step_id": 1,
                "result": {
                    "ok": True,
                    "exit_code": 0,
                    "stdout": "[HTTP] 200 OK\n<html>98</html>",
                    "stderr": "",
                },
            }
        ],
    }

    feedback = run_evaluator(
        settings=SimpleNamespace(mock_llm=True),
        memory=_Memory(),
        confirmed={"vulnerabilities": [{"cwe_id": "CWE-94"}]},
        plan=plan,
        exec_out=exec_out,
        feedback_path=tmp_path / "feedback.json",
        llm=None,
        adapter=None,
    )

    assert feedback["primitive_confirmed"] is True
    assert feedback["primitive_state"]["ssti"] is True
    assert feedback["primitive_state"]["arithmetic"] is True
    assert feedback["flag_found"] is False
    assert feedback["exploit_completed"] is False
    assert feedback["repro_success"] is False
    assert feedback["failure_analysis"]["type"] == "primitive_only"
    assert "processbuilder" in feedback["possible_next_direction"]
