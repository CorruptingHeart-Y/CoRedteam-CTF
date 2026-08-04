from __future__ import annotations

from core.primitive_candidate_resolver import resolve_primitive_candidates
from core.vulnerability_profile import normalize_vulnerability_profile
from memory.exploit_primitives import ExploitPrimitive, PrimitiveRegistry


def _resolve(vulnerability: dict, proposed: tuple[str, ...] = ()):
    profile = normalize_vulnerability_profile({"vulnerabilities": [vulnerability]})
    return resolve_primitive_candidates(
        profile,
        registry=PrimitiveRegistry(),
        proposed_primitive_ids=proposed,
    )


def _candidate_map(resolution):
    return {candidate.primitive_id: candidate for candidate in resolution.candidates}


def test_matrix_1_unknown_cwe_with_write_sink_resolves_file_write() -> None:
    resolution = _resolve({
        "id": "V-1",
        "cwe_id": "CWE-99999",
        "name": "Path handling weakness",
        "sink": {"file": "handler.go", "line": 9, "code": "os.WriteFile(userPath, body, 0644)"},
    })

    assert resolution.candidates[0].primitive_id == "arbitrary_file_write"
    assert resolution.candidates[0].evidence_refs


def test_matrix_2_cwe22_read_sink_ranks_read_above_write() -> None:
    resolution = _resolve({
        "id": "V-2",
        "cwe_id": "CWE-22",
        "title": "Possible file read and file write",
        "sink": {"code_snippet": "fs.ReadFile(userPath)"},
    })
    candidates = _candidate_map(resolution)

    assert candidates["arbitrary_file_read"].confidence > candidates["arbitrary_file_write"].confidence


def test_matrix_3_cwe22_write_sink_ranks_write_above_read() -> None:
    resolution = _resolve({
        "id": "V-3",
        "cwe_id": "CWE-22",
        "title": "Possible file read and file write",
        "sink": {"code": "os.WriteFile(userPath, body, 0644)"},
    })
    candidates = _candidate_map(resolution)

    assert candidates["arbitrary_file_write"].confidence > candidates["arbitrary_file_read"].confidence


def test_matrix_4_wrong_cwe_cannot_override_explicit_write_sink() -> None:
    resolution = _resolve({
        "id": "V-4",
        "cwe_id": "CWE-79",
        "title": "Incorrect classification",
        "sink": {"code": "os.WriteFile(attackerPath, payload, 0600)"},
    })

    assert resolution.candidates[0].primitive_id == "arbitrary_file_write"
    assert "arbitrary_file_read" not in _candidate_map(resolution)


def test_matrix_5_cwe_order_does_not_change_candidates() -> None:
    base = {
        "id": "V-5",
        "title": "Path handling",
        "sink": {"code": "os.WriteFile(userPath, body, 0644)"},
        "evidence": [{"code_snippet": "request path reaches os.WriteFile"}],
    }
    first = _resolve({**base, "cwe_ids": ["CWE-22", "CWE-79"]})
    second = _resolve({**base, "cwe_ids": ["CWE-79", "CWE-22"]})

    first_view = [(candidate.primitive_id, candidate.confidence) for candidate in first.candidates]
    second_view = [(candidate.primitive_id, candidate.confidence) for candidate in second.candidates]
    assert first_view == second_view


def test_matrix_6_cwe306_with_unauthenticated_network_entry() -> None:
    resolution = _resolve({
        "id": "V-6",
        "cwe_id": "CWE-306",
        "name": "Missing authentication on gRPC service",
        "source": {"code": 'net.Listen("tcp", ":50045")'},
        "sink": {"code_snippet": "grpc.NewServer()  // no authentication interceptors"},
        "evidence": "The network service accepts requests without authentication",
    })

    assert "unauthenticated_access" in resolution.candidate_root_ids
    candidate = _candidate_map(resolution)["unauthenticated_access"]
    assert set(candidate.roles) == {"entry", "capability"}
    assert candidate.evidence_refs


def test_matrix_11_every_candidate_and_matched_fact_has_evidence_refs() -> None:
    resolution = _resolve({
        "id": "V-11",
        "cwe_id": "CWE-22",
        "name": "Arbitrary file write via path traversal",
        "source": {"code": "path := req.Name"},
        "sink": {"code": "os.WriteFile(path, req.Body, 0644)"},
        "data_flow": ["req.Name flows into the file path", {"code_snippet": "../public/file"}],
        "evidence": ["write reaches disk", {"code": "os.WriteFile(path, body, 0644)"}],
    })

    assert resolution.candidates
    for candidate in resolution.candidates:
        assert candidate.evidence_refs
        assert candidate.matched_facts
        assert all(fact.evidence_refs for fact in candidate.matched_facts)


def test_matrix_12_unregistered_primitive_is_diagnostic_only() -> None:
    resolution = _resolve(
        {
            "id": "V-12",
            "cwe_id": "CWE-22",
            "sink": {"code": "os.WriteFile(userPath, body, 0644)"},
        },
        proposed=("challenge_specific_magic", "arbitrary_file_write"),
    )

    assert "challenge_specific_magic" not in resolution.candidate_root_ids
    assert all(candidate.primitive_id != "challenge_specific_magic" for candidate in resolution.candidates)
    assert any(
        item.code == "UNREGISTERED_PRIMITIVE" and item.primitive_id == "challenge_specific_magic"
        for item in resolution.unresolved_diagnostics
    )


def test_registry_metadata_and_from_dict_round_trip() -> None:
    registry = PrimitiveRegistry()
    file_write = registry.get("arbitrary_file_write")
    unauthenticated = registry.get("unauthenticated_access")

    assert file_write is not None
    assert file_write.roles == ["capability", "effect"]
    assert file_write.fact_requirements == {
        "operations": ["write"],
        "resources": ["filesystem_path"],
    }
    assert unauthenticated is not None
    assert unauthenticated.fact_requirements["reachability"] == ["unauthenticated"]

    restored = ExploitPrimitive.from_dict(file_write.to_dict())
    assert restored.to_dict() == file_write.to_dict()


def test_cwe_alone_never_activates_a_primitive() -> None:
    resolution = _resolve({"id": "V-CWE-ONLY", "cwe_id": "CWE-22"})

    assert resolution.candidates == ()
    assert resolution.candidate_root_ids == ()
