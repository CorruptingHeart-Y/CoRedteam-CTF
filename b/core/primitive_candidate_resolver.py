"""Resolve registry-backed primitive candidates from vulnerability facts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from core.vulnerability_profile import Fact, VulnerabilityProfile
from memory.exploit_primitives import ExploitPrimitive, PrimitiveRegistry, get_primitive_registry


_REQUIREMENT_KINDS = {
    "operations": "operation",
    "resources": "resource",
    "reachability": "reachability",
    "effects": "effect",
    "sources": "source",
    "sinks": "sink",
    "data_flows": "data_flow",
    "protocols": "protocol",
    "platforms": "platform",
}

_FACT_WEIGHTS = {
    "operation": 4.0,
    "reachability": 4.0,
    "resource": 2.0,
    "effect": 2.0,
    "source": 1.0,
    "sink": 1.0,
    "data_flow": 1.0,
    "protocol": 1.0,
    "platform": 1.0,
}


@dataclass(frozen=True)
class PrimitiveCandidate:
    """A registry primitive whose fact requirements are fully satisfied."""

    primitive_id: str
    roles: tuple[str, ...]
    confidence: float
    matched_facts: tuple[Fact, ...]
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.evidence_refs:
            raise ValueError("PRIMITIVE_CANDIDATE_EVIDENCE_REQUIRED")

    def to_dict(self) -> dict[str, Any]:
        return {
            "primitive_id": self.primitive_id,
            "roles": list(self.roles),
            "confidence": self.confidence,
            "matched_facts": [fact.to_dict() for fact in self.matched_facts],
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True)
class UnresolvedDiagnostic:
    code: str
    primitive_id: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "primitive_id": self.primitive_id,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class PrimitiveResolution:
    candidates: tuple[PrimitiveCandidate, ...]
    unresolved_diagnostics: tuple[UnresolvedDiagnostic, ...]

    @property
    def candidate_root_ids(self) -> tuple[str, ...]:
        """Only registry-backed, fact-satisfied IDs that may later seed BFS."""
        return tuple(candidate.primitive_id for candidate in self.candidates)

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "unresolved_diagnostics": [item.to_dict() for item in self.unresolved_diagnostics],
        }


class PrimitiveCandidateResolver:
    """Match profile facts against deterministic registry requirements.

    CWE identifiers are intentionally not consulted here. A CWE may describe
    a weakness class, but it does not activate a primitive without matching
    operation/resource/reachability/effect evidence.
    """

    def __init__(self, registry: PrimitiveRegistry | None = None) -> None:
        self._registry = registry or get_primitive_registry()

    def resolve(
        self,
        profile: VulnerabilityProfile,
        proposed_primitive_ids: Iterable[str] = (),
    ) -> PrimitiveResolution:
        facts_by_kind: dict[str, list[Fact]] = {}
        for fact in profile.facts:
            facts_by_kind.setdefault(fact.kind, []).append(fact)

        candidates: list[PrimitiveCandidate] = []
        matched_ids: set[str] = set()
        diagnostics: list[UnresolvedDiagnostic] = []

        for primitive_id in sorted(self._registry.get_all_ids()):
            primitive = self._registry.get(primitive_id)
            if primitive is None or not primitive.fact_requirements:
                continue
            candidate, diagnostic = self._match_primitive(primitive, facts_by_kind)
            if diagnostic is not None:
                diagnostics.append(diagnostic)
            if candidate is not None:
                candidates.append(candidate)
                matched_ids.add(candidate.primitive_id)

        proposed = tuple(dict.fromkeys(str(item).strip() for item in proposed_primitive_ids if str(item).strip()))
        for primitive_id in proposed:
            primitive = self._registry.get(primitive_id)
            if primitive is None:
                diagnostics.append(UnresolvedDiagnostic(
                    code="UNREGISTERED_PRIMITIVE",
                    primitive_id=primitive_id,
                    detail="Primitive is not present in PrimitiveRegistry and cannot become a candidate root.",
                ))
            elif primitive_id not in matched_ids:
                code = "NO_FACT_REQUIREMENTS" if not primitive.fact_requirements else "FACT_REQUIREMENTS_UNSATISFIED"
                diagnostics.append(UnresolvedDiagnostic(
                    code=code,
                    primitive_id=primitive_id,
                    detail="Registered primitive was proposed but was not activated by profile facts.",
                ))

        candidates.sort(key=lambda candidate: (-candidate.confidence, candidate.primitive_id))
        unique_diagnostics = {
            (item.code, item.primitive_id, item.detail): item
            for item in diagnostics
        }
        return PrimitiveResolution(
            candidates=tuple(candidates),
            unresolved_diagnostics=tuple(unique_diagnostics[key] for key in sorted(unique_diagnostics)),
        )

    def _match_primitive(
        self,
        primitive: ExploitPrimitive,
        facts_by_kind: dict[str, list[Fact]],
    ) -> tuple[PrimitiveCandidate | None, UnresolvedDiagnostic | None]:
        matched: list[Fact] = []
        weighted_confidence = 0.0
        total_weight = 0.0

        for requirement_name, accepted_values in primitive.fact_requirements.items():
            fact_kind = _REQUIREMENT_KINDS.get(requirement_name)
            if fact_kind is None:
                return None, UnresolvedDiagnostic(
                    code="UNSUPPORTED_FACT_REQUIREMENT",
                    primitive_id=primitive.primitive_id,
                    detail=f"Unknown fact requirement dimension: {requirement_name}",
                )
            accepted = {str(value) for value in accepted_values}
            matching = [fact for fact in facts_by_kind.get(fact_kind, ()) if fact.value in accepted]
            if not matching:
                return None, None
            matched.extend(matching)
            weight = _FACT_WEIGHTS.get(fact_kind, 1.0)
            weighted_confidence += weight * max(fact.confidence for fact in matching)
            total_weight += weight

        evidence_refs = tuple(sorted({ref for fact in matched for ref in fact.evidence_refs}))
        if not evidence_refs or total_weight == 0.0:
            return None, None
        unique_facts = tuple({(fact.kind, fact.value): fact for fact in matched}.values())
        return PrimitiveCandidate(
            primitive_id=primitive.primitive_id,
            roles=tuple(primitive.roles),
            confidence=round(weighted_confidence / total_weight, 3),
            matched_facts=unique_facts,
            evidence_refs=evidence_refs,
        ), None


def resolve_primitive_candidates(
    profile: VulnerabilityProfile,
    registry: PrimitiveRegistry | None = None,
    proposed_primitive_ids: Iterable[str] = (),
) -> PrimitiveResolution:
    """Convenience API for deterministic fact-to-primitive resolution."""
    return PrimitiveCandidateResolver(registry).resolve(profile, proposed_primitive_ids)
