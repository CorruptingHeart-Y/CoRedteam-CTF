"""SurfaceState — workspace-level surface confidence tracking.

Only one surface state source: workspace/surface_state.json.
Reset on each new pipeline run (new run_id).

Rules:
  - Surface confidence decays only when multiple DISTINCT canonical_strategy_ids
    on the same surface_key produce no_positive_evidence.
  - Same strategy failing repeatedly affects StrategyHealth, not surface.
  - positive_evidence_count > 0 resets/boosts surface confidence.

Constants (named, not magic):
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SURFACE_STATE_FILENAME = "surface_state.json"

# ── Named constants ──
SURFACE_CONFIDENCE_DECAY = 0.10          # per distinct failed strategy
SURFACE_BLOCK_THRESHOLD = 0.40            # below this → blocked
SURFACE_DEFAULT_CONFIDENCE = 1.0
SURFACE_POSITIVE_EVIDENCE_BOOST = 0.20    # per positive evidence (capped at 1.0)


@dataclass
class SurfaceState:
    surface_key: str           # "cwe=CWE-1336|endpoint=/|parameter=text|context=template-expression"
    confidence: float = SURFACE_DEFAULT_CONFIDENCE
    distinct_failed_strategy_ids: set[str] = field(default_factory=set)
    positive_evidence_count: int = 0
    blocked: bool = False
    block_reason: str = ""
    last_updated_round: int | None = None

    def to_dict(self) -> dict:
        return {
            "surface_key": self.surface_key,
            "confidence": self.confidence,
            "distinct_failed_strategy_ids": sorted(self.distinct_failed_strategy_ids),
            "positive_evidence_count": self.positive_evidence_count,
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "last_updated_round": self.last_updated_round,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SurfaceState":
        return cls(
            surface_key=data["surface_key"],
            confidence=data.get("confidence", SURFACE_DEFAULT_CONFIDENCE),
            distinct_failed_strategy_ids=set(data.get("distinct_failed_strategy_ids", [])),
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
    source = v.get("source", {})
    code = str(source.get("code", ""))
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
    except (json.JSONDecodeError, KeyError):
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
) -> SurfaceState:
    """Called when a strategy produces no_positive_evidence and request was sent."""
    state = load_surface_state(workspace) or SurfaceState(surface_key=surface_key)
    if strategy_id not in state.distinct_failed_strategy_ids:
        state.distinct_failed_strategy_ids.add(strategy_id)
        state.confidence = max(0.0, state.confidence - SURFACE_CONFIDENCE_DECAY)
        if state.confidence < SURFACE_BLOCK_THRESHOLD and not state.blocked:
            state.blocked = True
            state.block_reason = (
                f"surface confidence {state.confidence:.2f} < {SURFACE_BLOCK_THRESHOLD} "
                f"({len(state.distinct_failed_strategy_ids)} distinct failed strategies)"
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
