from __future__ import annotations

import pytest

from core.route_candidate_generator import CandidateRoute
from core.route_shadow_resolver import (
    _apply_resolver_alignment,
    build_route_shadow_report,
    format_route_shadow_report,
    run_route_shadow,
)
from core.primitive_candidate_resolver import PrimitiveCandidate
from core.vulnerability_profile import Fact


def _legacy_read_candidate() -> CandidateRoute:
    return CandidateRoute(
        route_id="filesystem_traversal__arbitrary_file_read",
        path=["filesystem_traversal", "arbitrary_file_read"],
        objective="arbitrary_file_read",
        status="unexplored",
        complexity="low",
        score=180.0,
    )


def test_cwe22_write_evidence_resolves_arbitrary_file_write() -> None:
    confirmed = {
        "vulnerabilities": [{
            "id": "CHALLENGE2-WRITE",
            "cwe_id": "CWE-22",
            "name": "Path Traversal",
            "sink": {
                "file": "grpc.go",
                "line": 19,
                "code": "os.WriteFile(userPath, body, 0644)",
            },
            "evidence": "The write operation uses an attacker-controlled file path.",
        }],
    }

    report = build_route_shadow_report(confirmed, [_legacy_read_candidate()])

    assert report.resolver_candidates[0].primitive_id == "arbitrary_file_write"
    assert report.resolver_candidates[0].evidence_refs
    assert report.mismatch is True
    rendered = format_route_shadow_report(report)
    assert "primitive: arbitrary_file_read" in rendered
    assert "primitive: arbitrary_file_write" in rendered
    assert "Mismatch:\ntrue" in rendered


def test_cwe_only_does_not_activate_resolver_primitive() -> None:
    confirmed = {
        "vulnerabilities": [{
            "id": "CWE-ONLY",
            "cwe_id": "CWE-22",
        }],
    }

    report = build_route_shadow_report(confirmed, [_legacy_read_candidate()])

    assert report.resolver_candidates == ()


def test_shadow_injects_resolver_only_candidates() -> None:
    """Resolver-only candidates (not in legacy) are injected as new routes
    with a competitive discovery base score.  Legacy values are preserved."""
    confirmed = {
        "vulnerabilities": [{
            "id": "CHALLENGE2-WRITE",
            "cwe_id": "CWE-22",
            "sink": {"code": "os.WriteFile(userPath, body, 0644)"},
        }],
    }
    legacy_candidates = [_legacy_read_candidate()]
    output: list[str] = []

    returned = run_route_shadow(
        confirmed,
        legacy_candidates,
        output=output.append,
    )

    # Injected resolver-only candidates appear alongside legacy
    returned_objectives = {r.objective for r in returned}
    assert "arbitrary_file_write" in returned_objectives, (
        "resolver-only arbitrary_file_write should be injected"
    )
    # Legacy candidate still present with original score
    legacy_in_result = [r for r in returned if r.route_id == _legacy_read_candidate().route_id]
    assert len(legacy_in_result) == 1
    assert legacy_in_result[0].score == 180.0
    assert output and output[0].startswith("[route-shadow]")


# ═══════════════════════════════════════════════════════════════════
# Resolver Alignment Tests
# ═══════════════════════════════════════════════════════════════════

def _make_write_candidate() -> CandidateRoute:
    """arbitrary_file_write with CWE-22: 25 (base) + 100 (CWE match) + 10 (unexplored) = 135."""
    return CandidateRoute(
        route_id="filesystem_traversal__arbitrary_file_write",
        path=["filesystem_traversal", "arbitrary_file_write"],
        objective="arbitrary_file_write",
        status="unexplored",
        complexity="low",
        score=135.0,
    )


def _write_evidence_confirmed() -> dict:
    return {
        "vulnerabilities": [{
            "id": "CHALLENGE2-WRITE",
            "cwe_id": "CWE-22",
            "name": "Path Traversal",
            "sink": {
                "file": "grpc.go",
                "line": 19,
                "code": "os.WriteFile(userPath, body, 0644)",
            },
            "evidence": "The write operation uses an attacker-controlled file path.",
        }],
    }


# ── Case 1: resolver boosts matching legacy candidate ──

def test_resolver_alignment_boosts_matching_candidate() -> None:
    """When resolver finds arbitrary_file_write with confidence=1.0,
    the arbitrary_file_write legacy candidate rises above arbitrary_file_read.
    Resolver-only candidates (e.g. filesystem_traversal) may also be injected."""
    confirmed = _write_evidence_confirmed()
    read_candidate = _legacy_read_candidate()
    write_candidate = _make_write_candidate()

    # Read is ranked above Write in legacy scoring
    assert read_candidate.score > write_candidate.score

    legacy = [read_candidate, write_candidate]
    output: list[str] = []

    returned = run_route_shadow(confirmed, legacy, output=output.append)

    # Resolver-only filesystem_traversal may be injected at top;
    # key assertion: write now outranks read (was 135 < 180, now 185 > 180)
    returned_objectives = [r.objective for r in returned]
    write_idx = returned_objectives.index("arbitrary_file_write")
    read_idx = returned_objectives.index("arbitrary_file_read")
    assert write_idx < read_idx, (
        f"write (idx={write_idx}) should rank above read (idx={read_idx}): "
        f"{[(r.objective, r.score) for r in returned]}"
    )
    # Read score unchanged (no resolver match for read with write-only evidence)
    read_in_result = returned[read_idx]
    assert read_in_result.score == 180.0
    # Write score increased: 135 + 50 = 185
    write_in_result = returned[write_idx]
    assert write_in_result.score == 185.0, (
        f"Expected write score 185, got {write_in_result.score}"
    )
    assert output and output[0].startswith("[route-shadow]")


# ── Case 2: resolver empty → legacy ranking completely unchanged ──

def test_resolver_empty_preserves_legacy_ranking() -> None:
    """When resolver returns no candidates, legacy ranking is fully preserved."""
    # CWE-only record — no operation/resource facts → resolver empty
    confirmed: dict = {
        "vulnerabilities": [{
            "id": "CWE-ONLY",
            "cwe_id": "CWE-22",
        }],
    }
    read_candidate = _legacy_read_candidate()
    write_candidate = _make_write_candidate()
    legacy = [read_candidate, write_candidate]
    before = [candidate.to_dict() for candidate in legacy]

    output: list[str] = []
    returned = run_route_shadow(confirmed, legacy, output=output.append)

    # All values unchanged
    assert [candidate.to_dict() for candidate in returned] == before
    # The list object itself is preserved (no need to copy when no alignment)
    assert returned is legacy


# ── Case 3: resolver exception → fail-open, legacy continues ──

def test_resolver_error_fail_open() -> None:
    """When the resolver pipeline raises an exception, the legacy list
    is returned unchanged — no crash, no data loss."""
    # None causes AttributeError inside normalize_vulnerability_profile
    confirmed = None  # type: ignore[arg-type]

    read_candidate = _legacy_read_candidate()
    legacy = [read_candidate]
    before = [candidate.to_dict() for candidate in legacy]

    output: list[str] = []
    returned = run_route_shadow(
        confirmed,  # type: ignore[arg-type]
        legacy,
        output=output.append,
    )

    # Legacy list returned unchanged — fail-open
    assert returned is legacy
    assert [candidate.to_dict() for candidate in returned] == before
    assert output and "unavailable" in output[0]


# ── Unit: _apply_resolver_alignment ──

def test_apply_resolver_alignment_empty_candidates_returns_original() -> None:
    """Empty resolver candidates → original list returned unchanged (identity)."""
    legacy = [_legacy_read_candidate()]
    result = _apply_resolver_alignment(legacy, ())
    assert result is legacy


def test_apply_resolver_alignment_multiple_matches() -> None:
    """Multiple resolver candidates boost multiple legacy routes proportionally."""
    read = _legacy_read_candidate()   # score=180, objective=arbitrary_file_read
    write = _make_write_candidate()   # score=135, objective=arbitrary_file_write

    fact = Fact(
        kind="operation",
        value="write",
        confidence=0.8,
        evidence_refs=("VULN-001.evidence",),
    )
    resolver_candidates = (
        PrimitiveCandidate(
            primitive_id="arbitrary_file_read",
            roles=("capability",),
            confidence=0.5,
            matched_facts=(fact,),
            evidence_refs=("VULN-001.evidence",),
        ),
        PrimitiveCandidate(
            primitive_id="arbitrary_file_write",
            roles=("capability",),
            confidence=1.0,
            matched_facts=(fact,),
            evidence_refs=("VULN-001.evidence",),
        ),
    )

    result = _apply_resolver_alignment([read, write], resolver_candidates)

    # Write gets +50 (confidence 1.0 × 50), Read gets +25 (confidence 0.5 × 50)
    # Write: 135 + 50 = 185, Read: 180 + 25 = 205
    # Read should still be first (205 > 185)
    assert result[0].objective == "arbitrary_file_read"
    assert result[0].score == 205.0
    assert result[1].objective == "arbitrary_file_write"
    assert result[1].score == 185.0
