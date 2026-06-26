"""Workspace-level surface confidence tracking.

SurfaceHealth is about the confirmed attack surface, not a specific strategy.
StrategyHealth remains keyed by exact canonical_strategy_id. Surface confidence
only decays for distinct materialized execution fingerprints that were actually
sent and produced no_positive_evidence.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

SURFACE_STATE_FILENAME = "surface_state.json"

SURFACE_CONFIDENCE_DECAY = 0.10
SURFACE_BLOCK_THRESHOLD = 0.40
SURFACE_DEFAULT_CONFIDENCE = 1.0
SURFACE_POSITIVE_EVIDENCE_BOOST = 0.20


@dataclass
class SurfaceState:
    surface_key: str
    confidence: float = SURFACE_DEFAULT_CONFIDENCE
    failed_strategy_ids: set[str] = field(default_factory=set)
    distinct_failed_execution_fingerprints: set[str] = field(default_factory=set)
    duplicate_execution_fingerprint_count: int = 0
    last_execution_fingerprint_by_strategy: dict[str, str] = field(default_factory=dict)
    decision_reason: str = ""
    positive_evidence_count: int = 0
    blocked: bool = False
    block_reason: str = ""
    last_updated_round: int | None = None

    def to_dict(self) -> dict:
        failed = sorted(self.failed_strategy_ids)
        return {
            "surface_key": self.surface_key,
            "confidence": self.confidence,
            "failed_strategy_ids": failed,
            "distinct_failed_strategy_ids": failed,
            "distinct_failed_execution_fingerprints": sorted(self.distinct_failed_execution_fingerprints),
            "duplicate_execution_fingerprint_count": self.duplicate_execution_fingerprint_count,
            "last_execution_fingerprint_by_strategy": dict(sorted(self.last_execution_fingerprint_by_strategy.items())),
            "decision_reason": self.decision_reason,
            "positive_evidence_count": self.positive_evidence_count,
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "last_updated_round": self.last_updated_round,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SurfaceState":
        failed_ids = data.get("failed_strategy_ids", data.get("distinct_failed_strategy_ids", []))
        return cls(
            surface_key=data["surface_key"],
            confidence=data.get("confidence", SURFACE_DEFAULT_CONFIDENCE),
            failed_strategy_ids=set(failed_ids),
            distinct_failed_execution_fingerprints=set(data.get("distinct_failed_execution_fingerprints", [])),
            duplicate_execution_fingerprint_count=int(data.get("duplicate_execution_fingerprint_count", 0)),
            last_execution_fingerprint_by_strategy=dict(data.get("last_execution_fingerprint_by_strategy", {})),
            decision_reason=data.get("decision_reason", ""),
            positive_evidence_count=data.get("positive_evidence_count", 0),
            blocked=data.get("blocked", False),
            block_reason=data.get("block_reason", ""),
            last_updated_round=data.get("last_updated_round"),
        )


def build_surface_key(confirmed) -> str:
    """Derive stable surface key from confirmed_vuln."""
    vulns = confirmed.get("vulnerabilities", [])
    if not vulns:
        return "surface=unknown"
    v = vulns[0]
    cwe = v.get("cwe_id", "UNKNOWN")
    source = v.get("source", {}) if isinstance(v, dict) else {}
    if isinstance(source, dict):
        code = str(source.get("code", ""))
    elif isinstance(source, str):
        code = source
    else:
        code = ""
    import re
    param = "unknown"
    m = re.search(r'name\s*=\s*"(\w+)"', code)
    if m:
        param = m.group(1)
    endpoint = "/"
    m = re.search(r'@\w*Mapping\s*\(\s*"([^"]*)"', code)
    if m:
        endpoint = m.group(1)
    return f"cwe={cwe}|endpoint={endpoint}|parameter={param}|context=template-expression"


def load_surface_state(workspace: Path) -> SurfaceState | None:
    path = workspace / SURFACE_STATE_FILENAME
    if not path.exists():
        return None
    try:
        return SurfaceState.from_dict(json.loads(path.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None


def save_surface_state(workspace: Path, state: SurfaceState) -> None:
    path = workspace / SURFACE_STATE_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")


def reset_surface_state(workspace: Path, surface_key: str) -> SurfaceState:
    state = SurfaceState(surface_key=surface_key)
    save_surface_state(workspace, state)
    return state


def update_surface_after_strategy_failure(
    workspace: Path,
    surface_key: str,
    strategy_id: str,
    round_number: int,
    execution_fingerprint: str | None = None,
    request_sent: bool = True,
    observation_status: str = "no_positive_evidence",
) -> SurfaceState:
    """Record independent negative evidence for a surface.

    Strategy identity is retained for audit, but surface confidence only decays
    once per distinct materialized execution fingerprint.
    """
    state = load_surface_state(workspace) or SurfaceState(surface_key=surface_key)
    if strategy_id:
        state.failed_strategy_ids.add(strategy_id)
    if execution_fingerprint and strategy_id:
        state.last_execution_fingerprint_by_strategy[strategy_id] = execution_fingerprint

    if not request_sent:
        state.decision_reason = "request_not_sent"
    elif observation_status != "no_positive_evidence":
        state.decision_reason = f"observation_status={observation_status}"
    elif not execution_fingerprint:
        state.decision_reason = "missing_execution_fingerprint"
    elif execution_fingerprint in state.distinct_failed_execution_fingerprints:
        state.duplicate_execution_fingerprint_count += 1
        state.decision_reason = "duplicate_execution_fingerprint"
    else:
        state.distinct_failed_execution_fingerprints.add(execution_fingerprint)
        state.confidence = max(0.0, state.confidence - SURFACE_CONFIDENCE_DECAY)
        state.decision_reason = "new_distinct_execution_fingerprint"
        if state.confidence < SURFACE_BLOCK_THRESHOLD and not state.blocked:
            state.blocked = True
            state.block_reason = (
                f"surface confidence {state.confidence:.2f} < {SURFACE_BLOCK_THRESHOLD} "
                f"({len(state.distinct_failed_execution_fingerprints)} distinct failed executions)"
            )
    state.last_updated_round = round_number
    save_surface_state(workspace, state)
    return state


def boost_surface_after_positive_evidence(
    workspace: Path,
    surface_key: str,
    round_number: int,
) -> SurfaceState:
    """Called when a strategy produces positive_evidence."""
    state = load_surface_state(workspace) or SurfaceState(surface_key=surface_key)
    state.positive_evidence_count += 1
    state.confidence = min(1.0, state.confidence + SURFACE_POSITIVE_EVIDENCE_BOOST)
    state.decision_reason = "positive_evidence"
    if state.blocked and state.confidence >= SURFACE_BLOCK_THRESHOLD:
        state.blocked = False
        state.block_reason = ""
    state.last_updated_round = round_number
    save_surface_state(workspace, state)
    return state


def is_surface_blocked(workspace: Path, surface_key: str) -> bool:
    state = load_surface_state(workspace)
    if state is None:
        return False
    return state.blocked
