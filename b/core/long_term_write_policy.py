"""LongTermWritePolicy — gates all permanent memory writes.

Terminal conditions that indicate the current run should NOT produce
permanent patterns/tech/ChromaDB entries, only workspace-local diagnostics:

  - duplicate_evidence: same signal+fp already confirmed
  - COMPLETED_DISCOVERY_REPLAY: discovery already completed for this surface
  - STAGE_BLOCKED_NO_APPROVED_ROUTE: no eligible strategy remains
  - OUTCOME_CONSISTENCY_VIOLATION: deterministic vs legacy classifier disagree
  - surface_blocked: surface confidence below threshold
  - breaker_triggered: stagnation detected

Reason: these conditions mean the run terminated for operational reasons,
not because of a genuine knowledge gap. Writing permanent "lessons" based
on these conditions would pollute the long-term memory with noise.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TERMINAL_CONDITION_FILENAME = "terminal_condition.json"

# Conditions that gate long-term writes
LONG_TERM_WRITE_BLOCKED_CONDITIONS = frozenset({
    "duplicate_evidence",
    "COMPLETED_DISCOVERY_REPLAY",
    "STAGE_BLOCKED_NO_APPROVED_ROUTE",
    "OUTCOME_CONSISTENCY_VIOLATION",
    "surface_blocked",
    "breaker_triggered",
})


@dataclass
class TerminalCondition:
    condition: str
    detected_at: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    round_number: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "condition": self.condition,
            "detected_at": self.detected_at or datetime.now(timezone.utc).isoformat(),
            "details": self.details,
            "round_number": self.round_number,
        }


def write_terminal_condition(
    workdir: Path,
    condition: str,
    details: dict[str, Any] | None = None,
    round_number: int = 0,
) -> None:
    """Record a terminal condition in the workspace."""
    tc = TerminalCondition(
        condition=condition,
        detected_at=datetime.now(timezone.utc).isoformat(),
        details=details or {},
        round_number=round_number,
    )
    path = workdir / TERMINAL_CONDITION_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    # Append to existing conditions list
    existing: list[dict] = []
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            existing = data.get("conditions", [])
        except (json.JSONDecodeError, OSError):
            pass
    existing.append(tc.to_dict())
    path.write_text(
        json.dumps({"conditions": existing}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def read_terminal_conditions(workdir: Path) -> list[TerminalCondition]:
    """Read all terminal conditions from the workspace."""
    path = workdir / TERMINAL_CONDITION_FILENAME
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    result: list[TerminalCondition] = []
    for item in data.get("conditions", []):
        result.append(TerminalCondition(
            condition=item.get("condition", ""),
            detected_at=item.get("detected_at", ""),
            details=item.get("details", {}),
            round_number=item.get("round_number", 0),
        ))
    return result


def is_long_term_write_blocked(workdir: Path) -> tuple[bool, str]:
    """Check if long-term memory writes should be blocked.

    Returns (blocked: bool, reason: str).
    """
    conditions = read_terminal_conditions(workdir)
    blocking: list[str] = []
    for tc in conditions:
        if tc.condition in LONG_TERM_WRITE_BLOCKED_CONDITIONS:
            blocking.append(f"{tc.condition} (round {tc.round_number})")
    if blocking:
        return True, "; ".join(blocking)
    return False, ""


def get_allowed_write_targets(workdir: Path) -> set[str]:
    """Return the set of allowed write targets given current terminal conditions.

    Returns empty set if all writes are allowed, or a restricted set.
    """
    blocked, _ = is_long_term_write_blocked(workdir)
    if not blocked:
        return set()  # empty = all allowed
    # Only workspace-local artifacts
    return {"workspace_artifact_only"}
