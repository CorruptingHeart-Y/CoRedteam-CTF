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


class _MockCodePlanner:
    def complete_json(self) -> dict:
        return {
            "version": 1,
            "steps": [
                {
                    "id": 1,
                    "type": "python",
                    "command": (
                        "from redteam_sdk import HttpClient\n"
                        "s = HttpClient('http://target.test')\n"
                        "response = s.get('/', params={'text': 'probe'})\n"
                        "print(response.text)"
                    ),
                }
            ],
        }


def test_compact_planner_prompt_contains_httpclient_usage_contract() -> None:
    compact_contract = planner._build_sdk_contract_block()

    assert "HttpClient.get(url, params=None, headers=None, **kwargs)" in compact_contract
    assert (
        "HttpClient.post(url, params=None, data=None, json=None, headers=None)"
        in compact_contract
    )
    assert "HttpClient.raw_request(method, path, headers, body)" in compact_contract
    assert "Do not use query= as HttpClient.get argument." in compact_contract
    assert "Use params= for URL query parameters." in compact_contract
    assert "HttpClient.get(url, query=" not in compact_contract
    assert "s.get(path, query=" not in compact_contract


def test_mock_planner_code_output_with_params_passes_plan_contract() -> None:
    plan = _MockCodePlanner().complete_json()
    command_before = plan["steps"][0]["command"]

    normalized = planner._extract_plan_ast(plan)
    result = validate_plan_structure(normalized)

    assert normalized["steps"][0]["command"] == command_before
    assert normalized["steps"][0]["_ast_valid"] is True
    assert result.passed is True, result.diagnostics


def test_sdk_calls_query_remains_a_logical_ast_field() -> None:
    compact_contract = planner._build_sdk_contract_block()
    plan = _MockPlanner().complete_json()
    sdk_calls_before = list(plan["steps"][0]["sdk_calls"])

    normalized = planner._extract_plan_ast(plan)

    assert (
        "query is a logical HTTP parameter category, not a Python function argument."
        in compact_contract
    )
    assert normalized["steps"][0]["sdk_calls"] == sdk_calls_before
    assert normalized["steps"][0]["_ast_sdk_calls"] == sdk_calls_before
