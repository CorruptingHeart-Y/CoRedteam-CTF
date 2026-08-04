"""Offline tests for the Planner compact step-type contract."""

from __future__ import annotations

from agents import planner
from core.plan_contract import validate_plan_structure


class _MockPlanner:
    def complete_json(self) -> dict:
        return {
            "version": 1,
            "steps": [
                {
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
                }
            ],
        }


def test_compact_planner_schema_requires_step_type() -> None:
    compact_contract = planner._build_sdk_contract_block()

    assert 'Every steps[] item MUST include type: "python" or "shell".' in compact_contract


def test_mock_planner_ast_output_with_type_passes_plan_contract() -> None:
    plan = _MockPlanner().complete_json()
    sdk_calls_before = list(plan["steps"][0]["sdk_calls"])

    normalized = planner._extract_plan_ast(plan)
    result = validate_plan_structure(normalized)

    assert normalized["steps"][0]["type"] == "python"
    assert normalized["steps"][0]["sdk_calls"] == sdk_calls_before
    assert result.passed is True, result.diagnostics
