from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
B_DIR = ROOT / "b"
if str(B_DIR) not in sys.path:
    sys.path.insert(0, str(B_DIR))

from core.context_authority import (
    AUTHORITY_BLOCK_BUDGETS,
    AUTHORITY_TOTAL_BUDGET,
    compile_context_authority,
)


def test_verified_fact_precedes_conflicting_reference() -> None:
    compiled = compile_context_authority(
        verified_state={"current_state": "A"},
        knowledge_templates="old example suggests current_state=B",
    )
    prompt = compiled.render()

    assert prompt.index("[VERIFIED FACT]") < prompt.index("[REFERENCE ONLY]")
    assert prompt.index('"current_state":"A"') < prompt.index("current_state=B")
    assert "must not be modified by the Planner" in compiled.fact_block
    assert "cannot establish or change current state" in compiled.reference_block


def test_no_regression_rule_is_a_hard_constraint() -> None:
    compiled = compile_context_authority(
        transition_information={"forbidden": "return to old state"},
    )

    assert "[HARD CONSTRAINT]" in compiled.constraint_block
    assert "return to old state" in compiled.constraint_block
    assert "must not override" in compiled.constraint_block


def test_strategy_and_reference_cannot_change_fact_authority() -> None:
    compiled = compile_context_authority(
        verified_state={"current_state": "A"},
        historical_experience={"candidate_state": "B"},
        knowledge_templates={"example_state": "C"},
    )
    payload = compiled.to_prompt_payload()

    assert list(payload) == ["FACT_BLOCK", "STRATEGY_BLOCK", "REFERENCE_BLOCK"]
    assert '"current_state":"A"' in payload["FACT_BLOCK"]
    assert '"candidate_state":"B"' not in payload["FACT_BLOCK"]
    assert '"example_state":"C"' not in payload["FACT_BLOCK"]
    assert "cannot change verified facts" in payload["STRATEGY_BLOCK"]


def test_empty_compiler_is_a_legacy_no_op() -> None:
    compiled = compile_context_authority()

    assert compiled.render() == ""
    assert compiled.to_prompt_payload() == {}


def test_oversized_fact_evicts_reference_before_fact() -> None:
    compiled = compile_context_authority(
        verified_state="FACT_SENTINEL " + ("F" * 10000),
        reference_knowledge="REFERENCE_SENTINEL " + ("R" * 10000),
    )

    assert "FACT_SENTINEL" in compiled.fact_block
    assert len(compiled.fact_block) <= AUTHORITY_BLOCK_BUDGETS["FACT"]
    assert compiled.reference_block == ""
    assert len(compiled.render()) <= AUTHORITY_TOTAL_BUDGET


def test_each_authority_block_has_an_independent_budget() -> None:
    cases = (
        ({"verified_state": "F" * 10000}, "fact_block", "FACT"),
        ({"hard_constraints": "C" * 10000}, "constraint_block", "HARD CONSTRAINT"),
        ({"strategy_options": "S" * 10000}, "strategy_block", "STRATEGY"),
        ({"reference_knowledge": "R" * 10000}, "reference_block", "REFERENCE"),
    )

    for kwargs, attribute, budget_name in cases:
        block = getattr(compile_context_authority(**kwargs), attribute)
        assert block
        assert len(block) <= AUTHORITY_BLOCK_BUDGETS[budget_name]
