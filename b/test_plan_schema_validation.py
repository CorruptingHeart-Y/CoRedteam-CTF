"""Offline regression tests for the Planner-to-Validator schema contract."""

from __future__ import annotations

from agents.validator import _normalize_plan, validate_plan


def _plan(step: dict) -> dict:
    return {
        "version": 1,
        "plan_id": "plan-schema-validation",
        "primitive_context": {
            "current_primitive": "information_disclosure",
            "target_primitive": "information_disclosure",
        },
        "steps": [step],
    }


def _ast_step(**overrides) -> dict:
    step = {
        "id": 1,
        "type": "python",
        "imports": [],
        "sdk_calls": [
            {
                "primitive": "HttpClient.get",
                "target": "/",
                "query": {"q": "1"},
                "body": None,
            }
        ],
        "target_primitive": "information_disclosure",
    }
    step.update(overrides)
    return step


def test_validator_rejects_ast_step_with_null_type() -> None:
    result = validate_plan(_plan(_ast_step(type=None)))

    assert result["passed"] is False
    assert result["valid"] is False
    assert "[plan_structure] step[0].type missing or invalid" in result["errors"]


def test_validator_accepts_python_step() -> None:
    result = validate_plan(
        _plan({"id": 1, "type": "python", "code": "print('ok')"})
    )

    assert result["passed"] is True
    assert result["valid"] is True


def test_validator_rejects_ast_step_with_missing_type() -> None:
    step = _ast_step()
    del step["type"]

    result = validate_plan(_plan(step))

    assert result["passed"] is False
    assert result["valid"] is False
    assert "[plan_structure] step[0].type missing or invalid" in result["errors"]


def test_validator_accepts_normal_ast_plan() -> None:
    result = validate_plan(_plan(_ast_step()))

    assert result["passed"] is True
    assert result["valid"] is True


def test_validator_rejects_non_object_ast_sdk_call() -> None:
    result = validate_plan(_plan(_ast_step(sdk_calls=["HttpClient.get"])))

    assert result["passed"] is False
    assert result["valid"] is False


def test_normalizer_auto_fills_missing_step_id() -> None:
    normalized, warnings = _normalize_plan(
        _plan({"type": "python", "code": "print('ok')"})
    )

    assert normalized["steps"][0]["id"] == 1
    assert any("step[0].id" in warning for warning in warnings)
