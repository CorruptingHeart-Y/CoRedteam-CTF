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


def _primitive_feedback(tmp_path, stdout):
    plan = {'version': 1, 'plan_id': 'primitive-state', 'steps': []}
    result = {'ok': True, 'exit_code': 0, 'stdout': stdout, 'stderr': ''}
    exec_out = {
        'version': 1, 'executed': True,
        'step_results': [{'step_id': 1, 'result': result}],
    }
    return run_evaluator(
        settings=SimpleNamespace(mock_llm=True),
        memory=_Memory(),
        confirmed={'vulnerabilities': []},
        plan=plan,
        exec_out=exec_out,
        feedback_path=tmp_path / 'primitive-feedback.json',
        llm=None,
        adapter=None,
    )


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


def test_probe_signal_confirms_primitive_and_recommends_transition(tmp_path):
    feedback = _primitive_feedback(tmp_path, 'input_processed_by_template_layer')

    assert feedback['confirmed_primitives'] == ['input_processed']
    assert feedback['current_primitive'] == 'input_processed'
    assert feedback['recommended_transition']['from_state'] == 'input_processed'
    assert feedback['recommended_transition']['to_state'] == 'template_evaluation_confirmed'
    assert feedback['blocked_transition'] is None


def test_failure_signal_blocks_current_transition(tmp_path):
    feedback = _primitive_feedback(
        tmp_path,
        'input_processed_by_template_layer input_rejected_before_template_processing',
    )

    assert feedback['current_primitive'] == 'input_processed'
    assert feedback['recommended_transition'] is None
    assert feedback['blocked_transition']['from_state'] == 'input_processed'
    assert feedback['blocked_transition']['to_state'] == 'template_evaluation_confirmed'


def test_legacy_evaluator_output_remains_compatible(tmp_path):
    feedback = _primitive_feedback(tmp_path, '[HTTP] 200 OK')

    assert feedback['version'] == 1
    assert feedback['repro_success'] is False
    assert feedback['should_continue'] is True
    assert feedback['current_exploit_state'] == 'probe_success'
    assert feedback['detected_primitives'] == []
    assert feedback['confirmed_primitives'] == []
    assert feedback['current_primitive'] is None
    assert feedback['recommended_transition'] is None
    assert feedback['blocked_transition'] is None


def test_process_object_confirms_command_execution(tmp_path):
    feedback = _primitive_feedback(tmp_path, 'Process(pid=4242)')

    assert 'command_execution' in feedback['confirmed_primitives']
    assert feedback['current_primitive'] == 'command_execution'


def test_command_execution_recommends_output_extraction(tmp_path):
    feedback = _primitive_feedback(
        tmp_path,
        'Runtime.exec invocation confirmed; returned Process[pid=4242, exitValue="not exited"]',
    )

    assert feedback['recommended_transition']['from_state'] == 'command_execution'
    assert feedback['recommended_transition']['to_state'] == 'output_extraction'


def test_command_execution_without_output_is_not_final_success(tmp_path):
    feedback = _primitive_feedback(tmp_path, 'Process(pid=4242)')

    assert feedback['repro_success'] is False
    assert feedback['exploit_completed'] is False
    assert feedback['should_continue'] is True


def test_legacy_fsm_success_and_failure_remain_unchanged(tmp_path):
    success = _primitive_feedback(tmp_path, '[HTTP] 200 OK flag{legacy_fsm_success_123}')
    failure = _primitive_feedback(tmp_path, '[HTTP] 200 OK ordinary response')

    assert success['repro_success'] is True
    assert success['current_exploit_state'] == 'gadget_triggered'
    assert failure['repro_success'] is False
    assert failure['current_exploit_state'] == 'probe_success'
