"""Observe resolver candidates beside legacy routes, with alignment-based re-ranking."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from core.primitive_candidate_resolver import (
    PrimitiveCandidate,
    PrimitiveCandidateResolver,
)
from core.route_candidate_generator import CandidateRoute
from core.vulnerability_profile import normalize_vulnerability_profile

# Bonus multiplier applied to resolver confidence when a legacy
# candidate's objective matches a resolver candidate.
_RESOLVER_ALIGNMENT_BONUS = 50.0

# A high-confidence resolver primary may contradict the legacy primary.
# Discount that conflicting prior so evidence can affect ordering.
_RESOLVER_HIGH_CONFIDENCE_THRESHOLD = 0.8
_RESOLVER_CONFLICT_PENALTY = 50.0

# Base score for resolver-only candidates (not in legacy list).
# Equivalent in weight to a CWE classification match — resolver
# evidence-based discovery carries the same signal strength.
_RESOLVER_DISCOVERY_BASE = 150.0


@dataclass(frozen=True)
class LegacyCandidate:
    primitive_id: str
    score: float


@dataclass(frozen=True)
class RouteShadowReport:
    legacy_candidates: tuple[LegacyCandidate, ...]
    resolver_candidates: tuple[PrimitiveCandidate, ...]
    mismatch: bool


def _format_evidence_refs(evidence_refs: tuple[str, ...]) -> str:
    displayed = ", ".join(evidence_refs[:3])
    remaining = len(evidence_refs) - 3
    return f"{displayed} (+{remaining} more)" if remaining > 0 else displayed


def build_route_shadow_report(
    confirmed_vuln: Mapping[str, Any],
    legacy_candidates: Sequence[CandidateRoute],
    resolver: PrimitiveCandidateResolver | None = None,
) -> RouteShadowReport:
    """Compare primary legacy and resolver directions using Stage1 evidence."""
    profile = normalize_vulnerability_profile(confirmed_vuln)
    resolution = (resolver or PrimitiveCandidateResolver()).resolve(profile)
    legacy_view = tuple(
        LegacyCandidate(primitive_id=candidate.objective, score=candidate.score)
        for candidate in legacy_candidates
    )

    legacy_primary = legacy_view[0].primitive_id if legacy_view else None
    resolver_primary = (
        resolution.candidates[0].primitive_id if resolution.candidates else None
    )
    return RouteShadowReport(
        legacy_candidates=legacy_view,
        resolver_candidates=resolution.candidates,
        mismatch=legacy_primary != resolver_primary,
    )


def format_route_shadow_report(report: RouteShadowReport) -> str:
    lines = ["[route-shadow]", "", "Legacy candidates:"]
    if report.legacy_candidates:
        for candidate in report.legacy_candidates:
            lines.extend((
                f"- primitive: {candidate.primitive_id}",
                f"  score: {candidate.score:g}",
            ))
    else:
        lines.append("- none")

    lines.extend(("", "Resolver candidates:"))
    if report.resolver_candidates:
        for candidate in report.resolver_candidates:
            lines.extend((
                f"- primitive: {candidate.primitive_id}",
                f"  confidence: {candidate.confidence:.3f}",
                f"  evidence_refs: {_format_evidence_refs(candidate.evidence_refs)}",
            ))
    else:
        lines.append("- none")

    lines.extend(("", "Mismatch:", str(report.mismatch).lower()))
    return "\n".join(lines)


def _apply_resolver_alignment(
    legacy_candidates: list[CandidateRoute],
    resolver_candidates: tuple[PrimitiveCandidate, ...],
) -> list[CandidateRoute]:
    """Fuse resolver evidence into legacy ordering without removing routes.

    Bonus = resolver_confidence × _RESOLVER_ALIGNMENT_BONUS.
    Injected candidates get _RESOLVER_DISCOVERY_BASE + alignment bonus.
    A legacy primary conflicting with a high-confidence resolver primary
    receives _RESOLVER_CONFLICT_PENALTY in the sorting key only.
    Returns a new list sorted by adjusted score; does not mutate inputs.
    When resolver_candidates is empty, returns the original list unchanged.
    """
    if not resolver_candidates:
        return legacy_candidates

    # Build lookup: primitive_id → max confidence
    resolver_confidence: dict[str, float] = {}
    for c in resolver_candidates:
        existing = resolver_confidence.get(c.primitive_id)
        if existing is None or c.confidence > existing:
            resolver_confidence[c.primitive_id] = c.confidence

    resolver_primary = resolver_candidates[0]
    legacy_primary = legacy_candidates[0].objective if legacy_candidates else None
    conflicting_legacy_primary = (
        legacy_primary is not None
        and resolver_primary.confidence >= _RESOLVER_HIGH_CONFIDENCE_THRESHOLD
        and legacy_primary != resolver_primary.primitive_id
    )

    _complexity_rank = {"low": 3, "medium": 2, "high": 1}

    # Track which objectives already exist in legacy
    matched_objectives: set[str] = set()

    adjusted: list[CandidateRoute] = []
    for route in legacy_candidates:
        bonus = resolver_confidence.get(route.objective, 0.0) * _RESOLVER_ALIGNMENT_BONUS
        if bonus > 0:
            matched_objectives.add(route.objective)

        adjusted.append(CandidateRoute(
            route_id=route.route_id,
            path=list(route.path),
            objective=route.objective,
            status=route.status,
            complexity=route.complexity,
            score=route.score + bonus,
        ))

    # ── Inject resolver-only candidates not in legacy ──
    for primitive_id, confidence in resolver_confidence.items():
        if primitive_id in matched_objectives:
            continue
        injected_score = _RESOLVER_DISCOVERY_BASE + confidence * _RESOLVER_ALIGNMENT_BONUS
        adjusted.append(CandidateRoute(
            route_id=f"resolver::{primitive_id}",
            path=[primitive_id],
            objective=primitive_id,
            status="unexplored",
            complexity="low",
            score=injected_score,
        ))

    # Re-rank without rewriting the legacy score: the conflict discount is an
    # internal ordering weight, so resolver evidence cannot alter route payloads.
    conflicting_route = adjusted[0] if conflicting_legacy_primary else None
    adjusted.sort(
        key=lambda r: (
            r.score - (
                _RESOLVER_CONFLICT_PENALTY
                if r is conflicting_route
                else 0.0
            ),
            _complexity_rank.get(r.complexity, 0),
        ),
        reverse=True,
    )
    return adjusted


def run_route_shadow(
    confirmed_vuln: Mapping[str, Any],
    legacy_candidates: list[CandidateRoute],
    *,
    output: Callable[[str], Any] = print,
) -> list[CandidateRoute]:
    """Emit a fail-open comparison and return the resolver-aligned route list.

    Legacy candidates whose objective matches a resolver candidate receive
    an alignment bonus proportional to resolver confidence. The returned
    list is re-ranked accordingly.  When the resolver produces no candidates
    or errors, the original legacy ranking is preserved unchanged.
    """
    try:
        report = build_route_shadow_report(confirmed_vuln, legacy_candidates)
        output(format_route_shadow_report(report))
        return _apply_resolver_alignment(legacy_candidates, report.resolver_candidates)
    except Exception as exc:
        try:
            output(f"[route-shadow]\nstatus: unavailable\nerror: {type(exc).__name__}")
        except Exception:
            pass
    return legacy_candidates
