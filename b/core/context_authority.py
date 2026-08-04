from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


AUTHORITY_BLOCK_BUDGETS = {
    "FACT": 4500,
    "HARD CONSTRAINT": 3800,
    "STRATEGY": 1400,
    "REFERENCE": 900,
}
AUTHORITY_TOTAL_BUDGET = 5000


def _plain_text(value: Any) -> str:
    if value is None or value == "" or value == [] or value == {} or value == ():
        return ""
    if isinstance(value, str):
        return value.strip()
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _limit_nested_strings(value: Any, limit: int) -> Any:
    if isinstance(value, str):
        return _compact_text(value, limit)
    if isinstance(value, dict):
        return {
            key: _limit_nested_strings(item, limit)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_limit_nested_strings(item, limit) for item in value]
    return value


def _bounded_plain_text(value: Any, limit: int) -> str:
    text = _plain_text(value)
    if len(text) <= limit:
        return text
    if isinstance(value, str):
        return _compact_text(value, limit)
    for string_limit in (512, 256, 128, 64, 32, 16):
        compacted = _plain_text(_limit_nested_strings(value, string_limit))
        if len(compacted) <= limit:
            return compacted
    summary = json.dumps(
        {"summary": "structured authority content omitted: exceeded budget"},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return summary if len(summary) <= limit else ""


def _compact_text(text: str, limit: int) -> str:
    """Keep a deterministic head/tail representation within the limit."""
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    marker = "\n[authority content compacted]\n"
    if limit <= len(marker):
        return marker.strip()[:limit]
    available = limit - len(marker)
    head = max(available * 3 // 4, 1)
    tail = available - head
    return text[:head] + marker + (text[-tail:] if tail else "")


def _render_block(
    header: str,
    rule: str,
    entries: tuple[tuple[str, Any], ...],
    budget: int,
) -> str:
    raw_entries: list[tuple[str, Any]] = []
    for source, value in entries:
        values = value if isinstance(value, tuple) else (value,)
        for index, item in enumerate(values):
            if _plain_text(item):
                label = source if index == 0 else f"{source}[{index}]"
                raw_entries.append((label, item))
    if not raw_entries or budget <= 0:
        return ""
    prefix = "\n".join((header, f"AUTHORITY RULE: {rule}"))
    body_budget = budget - len(prefix) - 1
    if body_budget <= 0:
        return _compact_text(prefix, budget)
    rendered: list[str] = []
    remaining = body_budget
    for label, item in raw_entries:
        separator = 1 if rendered else 0
        entry_prefix = f"SOURCE: {label}\n"
        text_budget = remaining - separator - len(entry_prefix)
        if text_budget <= 0:
            break
        text = _bounded_plain_text(item, text_budget)
        if not text:
            break
        rendered.append(entry_prefix + text)
        remaining -= separator + len(rendered[-1])
    return f"{prefix}\n" + "\n".join(rendered)


def _shrink_rendered_block(block: str, budget: int) -> str:
    if not block or len(block) <= budget:
        return block
    lines = block.split("\n", 2)
    if len(lines) < 3:
        return _compact_text(block, budget)
    prefix = "\n".join(lines[:2])
    body_budget = budget - len(prefix) - 1
    if body_budget <= 0:
        return _compact_text(prefix, budget)
    rendered: list[str] = []
    remaining = body_budget
    for entry in lines[2].split("\nSOURCE: "):
        normalized = entry if entry.startswith("SOURCE: ") else f"SOURCE: {entry}"
        entry_lines = normalized.split("\n", 1)
        if len(entry_lines) < 2:
            continue
        entry_prefix = entry_lines[0] + "\n"
        separator = 1 if rendered else 0
        text_budget = remaining - separator - len(entry_prefix)
        if text_budget <= 0:
            break
        raw = entry_lines[1]
        try:
            value = json.loads(raw) if raw[:1] in "[{" else raw
        except json.JSONDecodeError:
            value = raw
        text = _bounded_plain_text(value, text_budget)
        if not text:
            break
        rendered.append(entry_prefix + text)
        remaining -= separator + len(rendered[-1])
    return f"{prefix}\n" + "\n".join(rendered)


@dataclass(frozen=True)
class ContextAuthorityBlocks:
    fact_block: str = ""
    constraint_block: str = ""
    strategy_block: str = ""
    reference_block: str = ""

    def render(self) -> str:
        """Render the only supported Planner authority order."""
        return "\n\n".join(
            block
            for block in (
                self.fact_block,
                self.constraint_block,
                self.strategy_block,
                self.reference_block,
            )
            if block
        )

    def to_prompt_payload(self) -> dict[str, str]:
        """Return ordered blocks without exposing their raw source objects."""
        return {
            name: block
            for name, block in (
                ("FACT_BLOCK", self.fact_block),
                ("CONSTRAINT_BLOCK", self.constraint_block),
                ("STRATEGY_BLOCK", self.strategy_block),
                ("REFERENCE_BLOCK", self.reference_block),
            )
            if block
        }


def _fit_total_budget(blocks: ContextAuthorityBlocks) -> ContextAuthorityBlocks:
    """Fit the combined prompt by compacting lower authority first."""
    values = {
        "fact_block": blocks.fact_block,
        "constraint_block": blocks.constraint_block,
        "strategy_block": blocks.strategy_block,
        "reference_block": blocks.reference_block,
    }

    def rendered_length() -> int:
        return len("\n\n".join(value for value in values.values() if value))

    if rendered_length() > AUTHORITY_TOTAL_BUDGET:
        values["reference_block"] = ""
    if rendered_length() > AUTHORITY_TOTAL_BUDGET:
        overflow = rendered_length() - AUTHORITY_TOTAL_BUDGET
        strategy = values["strategy_block"]
        target = max(len(strategy) - overflow, 400)
        values["strategy_block"] = _shrink_rendered_block(strategy, target)
    if rendered_length() > AUTHORITY_TOTAL_BUDGET:
        values["strategy_block"] = ""
    # Hard constraints keep their complete compiled representation whenever
    # possible; FACT remains present but may use a shorter representation.
    for key, floor in (("fact_block", 600), ("constraint_block", 600)):
        if rendered_length() <= AUTHORITY_TOTAL_BUDGET:
            break
        overflow = rendered_length() - AUTHORITY_TOTAL_BUDGET
        current = values[key]
        target = max(len(current) - overflow, floor)
        values[key] = _shrink_rendered_block(current, target)

    fitted = ContextAuthorityBlocks(**values)
    if len(fitted.render()) > AUTHORITY_TOTAL_BUDGET:
        raise ValueError("authority blocks cannot fit the total prompt budget")
    return fitted


def compile_context_authority(
    *,
    verified_state: Any = None,
    trajectory_information: Any = None,
    transition_information: Any = None,
    historical_experience: Any = None,
    knowledge_templates: Any = None,
    environment_facts: Any = None,
    evidence: Any = None,
    hard_constraints: Any = None,
    strategy_options: Any = None,
    reference_knowledge: Any = None,
) -> ContextAuthorityBlocks:
    """Compile existing Planner sources into four deterministic authority blocks.

    The compiler deliberately does not infer or reconcile state. Callers must
    provide system-owned facts and constraints from their authoritative stores.
    """
    blocks = ContextAuthorityBlocks(
        fact_block=_render_block(
            "[VERIFIED FACT]",
            "Highest priority. These system-owned facts describe current state and must not be modified by the Planner.",
            (
                ("verified_state", verified_state),
                ("trajectory_information", trajectory_information),
                ("evidence", evidence),
                ("environment_facts", environment_facts),
            ),
            AUTHORITY_BLOCK_BUDGETS["FACT"],
        ),
        constraint_block=_render_block(
            "[HARD CONSTRAINT]",
            "Mandatory. The Planner must obey these rules and must not override them.",
            (
                ("hard_constraints", hard_constraints),
                ("transition_information", transition_information),
            ),
            AUTHORITY_BLOCK_BUDGETS["HARD CONSTRAINT"],
        ),
        strategy_block=_render_block(
            "[OPTIONAL STRATEGY]",
            "Advisory only. The Planner may select or reject these candidate directions; they cannot change verified facts.",
            (
                ("historical_experience", historical_experience),
                ("strategy_options", strategy_options),
            ),
            AUTHORITY_BLOCK_BUDGETS["STRATEGY"],
        ),
        reference_block=_render_block(
            "[REFERENCE ONLY]",
            "Background only. Templates and documentation cannot establish or change current state.",
            (
                ("knowledge_templates", knowledge_templates),
                ("reference_knowledge", reference_knowledge),
            ),
            AUTHORITY_BLOCK_BUDGETS["REFERENCE"],
        ),
    )
    return _fit_total_budget(blocks)


def partition_feedback_authority(
    feedback: dict[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Keep Evaluator suggestions from masquerading as verified facts."""
    if not isinstance(feedback, dict):
        return {}, {}, {}

    fact_keys = (
        "current_exploit_state",
        "primitive_state",
        "confirmed_primitives",
        "current_primitive",
        "detected_primitives",
        "primitive_confidence",
        "failure_analysis",
        "confidence",
        "failure_type",
        "failure_reason",
        "strategy_stagnation",
        "repro_success",
        "errors",
        "milestones_achieved",
        "exploit_momentum",
        "last_execution_raw",
    )
    constraint_keys = (
        "allowed_next",
        "allowed_next_primitives",
        "blocked_transition",
        "state_transition_blocker",
    )
    strategy_keys = (
        "recommended_transition",
        "next_required_action",
        "possible_next_direction",
        "feedback_for_planner",
        "summary",
    )

    def select(keys: tuple[str, ...]) -> dict[str, Any]:
        return {
            key: feedback[key]
            for key in keys
            if key in feedback and feedback[key] not in (None, "", [], {})
        }

    return select(fact_keys), select(constraint_keys), select(strategy_keys)

