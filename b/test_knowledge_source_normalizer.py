from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
B_DIR = ROOT / "b"
if str(B_DIR) not in sys.path:
    sys.path.insert(0, str(B_DIR))

from core.context_authority import compile_context_authority
from core.knowledge_source_normalizer import (
    CANDIDATE_HINT,
    HARD_CONSTRAINT,
    VERIFIED_FACT,
    VERIFIED_STRATEGY,
    group_knowledge_by_authority,
    normalize_knowledge_source,
)


def test_route_factory_candidate_is_reference_hint_without_state_authority() -> None:
    item = normalize_knowledge_source(
        source="route_factory",
        content={
            "current_state": "init",
            "target_primitive": "ssti_reflection",
            "generation_status": "candidate_only",
            "expected_signals": ["arithmetic_result_in_response"],
        },
        metadata={"generated_by": "route_factory", "generation_status": "candidate_only"},
    )

    assert item["knowledge_type"] == CANDIDATE_HINT
    assert item["authority_level"] == "REFERENCE"
    assert item["content"]["candidate"] == "ssti_reflection exploration hint"
    assert "current_state" not in item["content"]
    assert "primitive" not in item["content"]


def test_evaluator_verified_primitive_is_fact() -> None:
    item = normalize_knowledge_source(
        source="evaluator",
        content={"current_primitive": "command_execution", "verified": True},
    )

    assert item["knowledge_type"] == VERIFIED_FACT
    assert item["authority_level"] == "FACT"


def test_primitive_graph_transition_is_hard_constraint() -> None:
    item = normalize_knowledge_source(
        source="primitive_transition_graph",
        content={"from": "ssti_reflection", "to": "command_execution"},
    )

    assert item["knowledge_type"] == HARD_CONSTRAINT
    assert item["authority_level"] == "HARD CONSTRAINT"


def test_consolidator_success_template_is_verified_strategy() -> None:
    item = normalize_knowledge_source(
        source="consolidator",
        content="weaponized template",
        metadata={"success_trajectory": True, "validation_status": "validated"},
    )

    assert item["knowledge_type"] == VERIFIED_STRATEGY
    assert item["authority_level"] == "STRATEGY"


def test_candidate_hint_cannot_override_verified_fact_in_authority() -> None:
    fact = normalize_knowledge_source(
        source="evaluator",
        content={"current_primitive": "command_execution"},
    )
    candidate = normalize_knowledge_source(
        source="route_factory",
        content={
            "current_state": "init",
            "target_primitive": "ssti_reflection",
            "generation_status": "candidate_only",
        },
    )
    grouped = group_knowledge_by_authority((candidate, fact))
    compiled = compile_context_authority(
        verified_state=grouped["FACT"],
        reference_knowledge=grouped["REFERENCE"],
    )
    prompt = compiled.render()

    assert prompt.index("command_execution") < prompt.index("ssti_reflection exploration hint")
    assert "current_state" not in compiled.reference_block
    assert "ssti_reflection exploration hint" not in compiled.fact_block

class _TemplateRecord:
    def __init__(self, author: str, tags: list[str], text: str) -> None:
        self.author = author
        self.tags = tags
        self.metadata = {"author": author, "tags": tags}
        self._text = text

    def to_prompt_text(self) -> str:
        return self._text


def test_template_manager_records_keep_consolidator_validation_provenance(
    monkeypatch,
) -> None:
    from agents import planner

    records = [
        _TemplateRecord(
            "co-redteam-consolidator",
            [],
            "validated weaponized template",
        ),
        _TemplateRecord(
            "co-redteam-consolidator",
            ["consolidator_reviewed:false"],
            "unverified candidate template",
        ),
        _TemplateRecord(
            "co-redteam",
            ["ssti"],
            "manual CWE reference",
        ),
    ]

    class _Manager:
        def get_template_records_for_target(self, *args, **kwargs):
            return records

    monkeypatch.setattr(planner, "TemplateManager", _Manager)
    normalized = planner._normalized_cwe_template_sources([], {})

    assert normalized[0]["knowledge_type"] == VERIFIED_STRATEGY
    assert normalized[1]["knowledge_type"] == CANDIDATE_HINT
    assert normalized[1]["authority_level"] == "REFERENCE"
    assert normalized[2]["knowledge_type"] == "REFERENCE"
