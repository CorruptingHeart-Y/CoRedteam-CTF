"""Shared Plan Structural Contract — unification tests.

Verifies that:
  * ``b/core/plan_contract.py::validate_plan_structure`` is the single source
    of truth for the plan's static structural contract.
  * The runtime Validator (``b/agents/validator.py``) calls the shared contract
    before its dynamic gates, without removing or weakening those gates.
  * The Route Materializer (``b/routes/materializer.py``) delegates to the
    shared contract and no longer maintains a second, divergent contract.
  * The contract module is pure (no coordinator / memory / LLM / HTTP deps),
    deterministic, and side-effect free.

This file deliberately does NOT modify CLI, run Stage 1, send HTTP, or execute
any plan.
"""

from __future__ import annotations

import inspect
import json
import subprocess
import sys
from pathlib import Path

import pytest

# ── path setup ──
ROOT = Path(__file__).resolve().parents[1]
B_DIR = ROOT / "b"
if str(B_DIR) not in sys.path:
    sys.path.insert(0, str(B_DIR))

from core.plan_contract import (  # noqa: E402
    PlanStructureDiagnostic,
    PlanStructureErrorCode,
    PlanStructureResult,
    validate_plan_structure,
)


# ═══════════════════════════════════════════════════════════════════
# Fixture plans
# ═══════════════════════════════════════════════════════════════════


def _valid_materialized_plan() -> dict:
    """A plan structurally identical to what the Materializer produces."""
    return {
        "version": 1,
        "plan_id": "route-a1a7990d01c18e05ce4356bc",
        "vuln_summary": "CWE-94: arithmetic_probe",
        "rationale": "Offline materialization of admitted route",
        "chain_design": "single_step_route_materialization",
        "history_state": {"current_state": "init"},
        "primitive_context": {
            "current_primitive": "ssti_reflection",
            "target_primitive": "ssti_reflection",
            "transition_edge": "init",
            "fallback_primitive": None,
        },
        "target_context": {"base_url": "http://127.0.0.1:1337"},
        "metadata": {"source": "route_factory"},
        "steps": [
            {
                "id": 1,
                "status": "PLANNED",
                "type": "python",
                "imports": [],
                "sdk_calls": [
                    {
                        "primitive": "HttpClient.post",
                        "target": "/",
                        "query": None,
                        "body": {"text": "{{7*7}}"},
                        "body_format": "form",
                    }
                ],
                "purpose": "arithmetic_probe",
                "expected_outcome": "arithmetic_result_in_response",
                "depends_on": None,
                "on_failure": "BLOCK_AND_DEBUG",
                "target_primitive": "ssti_reflection",
                "why_this_step_advances_state": "Observe declared signals.",
                "why_this_payload_is_a_mutation": "Admitted route payload.",
                "why_this_is_not_regression": "Stay on admitted route.",
                "why_this_primitive_advances_chain": "Exercise primitive.",
            }
        ],
        "platform": "offline",
    }


def _ast_step(**overrides) -> dict:
    step = {
        "id": 1,
        "type": "python",
        "imports": ["json"],
        "sdk_calls": [
            {"primitive": "HttpClient.get", "target": "/", "query": {"q": "1"}, "body": None}
        ],
        "target_primitive": "information_disclosure",
    }
    step.update(overrides)
    return step


# ═══════════════════════════════════════════════════════════════════
# Section 1 — happy path
# ═══════════════════════════════════════════════════════════════════


class TestStructureContractHappyPath:
    def test_valid_materialized_plan_passes_shared_structure_contract(self):
        result = validate_plan_structure(_valid_materialized_plan())
        assert result.passed is True
        assert result.diagnostics == ()
        assert result.error_codes == ()


# ═══════════════════════════════════════════════════════════════════
# Section 2 — per-rule rejection
# ═══════════════════════════════════════════════════════════════════


class TestStructureContractRejections:
    def test_missing_version_rejected(self):
        plan = {"steps": [_ast_step()]}
        result = validate_plan_structure(plan)
        assert result.passed is False
        assert PlanStructureErrorCode.VERSION_INVALID in result.error_codes

    def test_invalid_version_rejected(self):
        plan = {"version": 2, "steps": [_ast_step()]}
        result = validate_plan_structure(plan)
        assert result.passed is False
        assert PlanStructureErrorCode.VERSION_INVALID in result.error_codes

    def test_missing_steps_rejected(self):
        plan = {"version": 1}
        result = validate_plan_structure(plan)
        assert result.passed is False
        assert PlanStructureErrorCode.STEPS_NOT_LIST in result.error_codes

    def test_empty_steps_rejected(self):
        plan = {"version": 1, "steps": []}
        result = validate_plan_structure(plan)
        assert result.passed is False
        assert PlanStructureErrorCode.STEPS_EMPTY in result.error_codes

    def test_step_wrong_type_rejected(self):
        # Legacy mode (no sdk_calls) with an invalid type.
        step = {"id": 1, "type": "ruby", "command": "puts 'hi'"}
        plan = {"version": 1, "steps": [step]}
        result = validate_plan_structure(plan)
        assert result.passed is False
        assert PlanStructureErrorCode.STEP_TYPE_INVALID in result.error_codes

    def test_command_and_sdk_calls_mixed_rejected(self):
        step = _ast_step(command="print('mixed')")
        plan = {"version": 1, "steps": [step]}
        result = validate_plan_structure(plan)
        assert result.passed is False
        assert PlanStructureErrorCode.MIXED_PROTOCOL in result.error_codes

    def test_invalid_imports_rejected(self):
        # imports present but not a list
        step = _ast_step(imports="json")
        plan = {"version": 1, "steps": [step]}
        result = validate_plan_structure(plan)
        assert result.passed is False
        assert PlanStructureErrorCode.IMPORTS_NOT_LIST in result.error_codes

        # list with a non-string element
        step2 = _ast_step(imports=["json", 123])
        plan2 = {"version": 1, "steps": [step2]}
        result2 = validate_plan_structure(plan2)
        assert result2.passed is False
        assert PlanStructureErrorCode.IMPORTS_INVALID_ELEMENT in result2.error_codes

    def test_missing_primitive_context_rejected(self):
        # primitive_context present but not an object (absent is left to the
        # runtime validator's warn+auto-create path; a non-object value is a
        # structural defect the shared contract rejects).
        plan = {"version": 1, "steps": [_ast_step()], "primitive_context": "not_an_object"}
        result = validate_plan_structure(plan)
        assert result.passed is False
        assert PlanStructureErrorCode.PRIMITIVE_CONTEXT_INVALID in result.error_codes

    def test_missing_target_primitive_rejected(self):
        # target_primitive present but not a string (absent is a runtime
        # warning gate; a non-string value is a structural defect).
        step = _ast_step()
        step["target_primitive"] = 123
        plan = {"version": 1, "steps": [step]}
        result = validate_plan_structure(plan)
        assert result.passed is False
        assert PlanStructureErrorCode.TARGET_PRIMITIVE_INVALID in result.error_codes

    def test_invalid_sdk_primitive_rejected(self):
        step = _ast_step()
        step["sdk_calls"] = [{"primitive": "", "target": "/"}]
        plan = {"version": 1, "steps": [step]}
        result = validate_plan_structure(plan)
        assert result.passed is False
        assert PlanStructureErrorCode.SDK_PRIMITIVE_INVALID in result.error_codes

        # non-string primitive
        step2 = _ast_step()
        step2["sdk_calls"] = [{"primitive": 42, "target": "/"}]
        result2 = validate_plan_structure({"version": 1, "steps": [step2]})
        assert PlanStructureErrorCode.SDK_PRIMITIVE_INVALID in result2.error_codes

    def test_invalid_sdk_target_rejected(self):
        step = _ast_step()
        step["sdk_calls"] = [{"primitive": "HttpClient.get", "target": 99}]
        plan = {"version": 1, "steps": [step]}
        result = validate_plan_structure(plan)
        assert result.passed is False
        assert PlanStructureErrorCode.SDK_TARGET_INVALID in result.error_codes

    def test_invalid_request_container_rejected(self):
        step = _ast_step()
        step["sdk_calls"] = [
            {"primitive": "HttpClient.get", "target": "/", "query": "not_a_dict"}
        ]
        plan = {"version": 1, "steps": [step]}
        result = validate_plan_structure(plan)
        assert result.passed is False
        assert PlanStructureErrorCode.REQUEST_CONTAINER_INVALID in result.error_codes


# ═══════════════════════════════════════════════════════════════════
# Section 3 — purity / determinism
# ═══════════════════════════════════════════════════════════════════


_CONTRACT_SOURCE_PATH = B_DIR / "core" / "plan_contract.py"


class TestStructureContractPurity:
    def test_structure_contract_does_not_import_coordinator(self):
        source = _CONTRACT_SOURCE_PATH.read_text(encoding="utf-8")
        assert "import coordinator" not in source
        assert "from coordinator" not in source
        loaded = self._modules_loaded_by_contract_import()
        assert not any(m == "coordinator" or m.startswith("coordinator.") for m in loaded), \
            f"contract import pulled coordinator: {[m for m in loaded if m.startswith('coordinator')]}"

    def test_structure_contract_does_not_import_memory(self):
        source = _CONTRACT_SOURCE_PATH.read_text(encoding="utf-8")
        assert "import memory" not in source
        assert "from memory" not in source
        loaded = self._modules_loaded_by_contract_import()
        assert not any(m.startswith("memory.") or m == "memory" for m in loaded), \
            f"contract import pulled memory: {[m for m in loaded if m.startswith('memory')]}"

    def test_structure_contract_does_not_load_llm(self):
        source = _CONTRACT_SOURCE_PATH.read_text(encoding="utf-8")
        for forbidden in ("openai", "anthropic", "langchain", "litellm"):
            assert forbidden not in source, f"contract references LLM lib: {forbidden}"
        loaded = self._modules_loaded_by_contract_import()
        for llm in ("openai", "anthropic", "langchain", "litellm"):
            assert llm not in loaded, f"contract import loaded LLM lib: {llm}"

    def test_structure_contract_does_not_send_http(self):
        source = _CONTRACT_SOURCE_PATH.read_text(encoding="utf-8")
        for forbidden in (
            "import requests", "from requests",
            "import httpx", "from httpx",
            "import socket", "from socket",
            "urllib.request", "urlopen",
            "import http.client", "from http.client",
        ):
            assert forbidden not in source, f"contract sends HTTP: {forbidden}"
        loaded = self._modules_loaded_by_contract_import()
        for http_mod in ("requests", "httpx", "socket", "urllib.request", "http.client"):
            assert http_mod not in loaded, f"contract import loaded HTTP lib: {http_mod}"

    @staticmethod
    def _modules_loaded_by_contract_import() -> set[str]:
        """Import core.plan_contract in a fresh subprocess; return new modules."""
        script = (
            "import sys\n"
            f"sys.path.insert(0, {str(B_DIR)!r})\n"
            "before = set(sys.modules)\n"
            "import core.plan_contract  # noqa\n"
            "after = set(sys.modules)\n"
            "print('\\n'.join(sorted(after - before)))\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=60,
        )
        assert proc.returncode == 0, f"contract import failed:\n{proc.stderr}"
        return {line for line in proc.stdout.splitlines() if line}

    def test_structure_contract_is_deterministic(self):
        plan = _valid_materialized_plan()
        r1 = validate_plan_structure(plan)
        r2 = validate_plan_structure(plan)
        assert r1 == r2
        # Same diagnostics ordering across calls.
        assert r1.diagnostics == r2.diagnostics

        # A plan with multiple errors yields a stable diagnostic order too.
        bad = {
            "version": 2,                       # VERSION_INVALID
            "steps": [
                {"id": 1, "type": "ruby", "command": "x"},   # STEP_TYPE_INVALID
                {"id": 2, "type": "python", "sdk_calls": [{"primitive": "HttpClient.get", "target": "/"}], "command": "y"},  # MIXED_PROTOCOL
            ],
            "primitive_context": "bad",         # PRIMITIVE_CONTEXT_INVALID
        }
        a = validate_plan_structure(bad).diagnostics
        b = validate_plan_structure(bad).diagnostics
        assert a == b
        assert len(a) >= 3
        # Codes are in a fixed walk order: version, step0, step1, primitive_context.
        codes_a = [d.code for d in a]
        codes_b = [d.code for d in b]
        assert codes_a == codes_b

    def test_result_types_are_immutable(self):
        diag = PlanStructureDiagnostic(
            PlanStructureErrorCode.VERSION_INVALID, "version", "msg"
        )
        result = PlanStructureResult(False, (diag,))
        with pytest.raises(Exception):
            diag.code = PlanStructureErrorCode.STEPS_EMPTY  # type: ignore
        with pytest.raises(Exception):
            result.passed = True  # type: ignore


# ═══════════════════════════════════════════════════════════════════
# Section 4 — Materializer delegation
# ═══════════════════════════════════════════════════════════════════


class TestMaterializerDelegation:
    def test_materializer_calls_shared_structure_contract(self, tmp_path, monkeypatch):
        import routes.materializer as mat

        calls = {"count": 0}

        real = mat.validate_plan_structure

        def spy(plan):
            calls["count"] += 1
            return real(plan)

        monkeypatch.setattr(mat, "validate_plan_structure", spy)

        from routes.schema import RouteProposal
        from routes.normalizer import normalize_route_proposal
        from routes.primitive_adapter import PrimitiveAdapter

        proposal = RouteProposal(
            cwe_id="CWE-94",
            current_state="init",
            target_primitive="ssti_reflection",
            technique="arithmetic_probe",
            required_runtime_facts=("endpoint", "parameter"),
            payload_template_ref="primitive:ssti_reflection:0",
            expected_signals=("arithmetic_result_in_response",),
        )
        adapter = PrimitiveAdapter()
        route = normalize_route_proposal(proposal, adapter).route
        result = mat.materialize_route_plan(
            route,
            adapter=adapter,
            runtime_facts={
                "base_url": "http://127.0.0.1:1337",
                "endpoint": "/",
                "parameter": "text",
                "method": "POST",
                "request_location": "form",
            },
            output_path=tmp_path / "plan.json",
        )
        assert result.success, result.diagnostics
        assert calls["count"] >= 1, "materializer must delegate to shared contract"

    def test_materializer_has_no_second_contract_implementation(self):
        """_plan_contract_is_valid must be a pure delegate; no second logic."""
        import routes.materializer as mat

        source = inspect.getsource(mat)
        # The divergent second-contract rules must be gone from the wrapper.
        # (The Materializer's own method/location invariants live in
        # _build_sdk_call, NOT in _plan_contract_is_valid.)
        forbidden_in_wrapper = [
            "len(steps) != 1",
            "HttpClient.get",       # the old primitive allowlist
            'startswith("/")',      # the old target-prefix rule
            "populated == 1",       # the old query-xor-body rule
        ]
        wrapper_src = inspect.getsource(mat._plan_contract_is_valid)
        for token in forbidden_in_wrapper:
            assert token not in wrapper_src, (
                f"_plan_contract_is_valid retains divergent logic: {token!r}"
            )
        # The wrapper must delegate to the shared function.
        assert "validate_plan_structure" in wrapper_src

    def test_materializer_wrapper_delegates_purely(self, monkeypatch):
        """Monkeypatch proves _plan_contract_is_valid only reflects the shared fn."""
        import routes.materializer as mat

        class _R:
            def __init__(self, passed):
                self.passed = passed

        # When shared contract says passed=False, wrapper returns False.
        monkeypatch.setattr(mat, "validate_plan_structure", lambda plan: _R(False))
        assert mat._plan_contract_is_valid({"version": 1, "steps": []}) is False

        # When shared contract says passed=True, wrapper returns True.
        monkeypatch.setattr(mat, "validate_plan_structure", lambda plan: _R(True))
        assert mat._plan_contract_is_valid({"any": "thing"}) is True


# ═══════════════════════════════════════════════════════════════════
# Section 5 — Validator wiring
# ═══════════════════════════════════════════════════════════════════


class TestValidatorWiring:
    def test_validator_calls_shared_structure_contract(self, monkeypatch):
        import agents.validator as val

        calls = {"count": 0}
        real = val.validate_plan_structure

        def spy(plan):
            calls["count"] += 1
            return real(plan)

        monkeypatch.setattr(val, "validate_plan_structure", spy)
        val.validate_plan(_valid_materialized_plan())
        assert calls["count"] >= 1

    def test_validator_rejects_structurally_invalid_plan_via_shared_contract(self):
        from agents.validator import validate_plan

        result = validate_plan({"version": 2, "steps": []})
        assert result["passed"] is False
        assert result.get("structure_invalid") is True
        assert any("plan_structure" in e for e in result["errors"])

    def test_validator_dynamic_gates_still_exist(self):
        """The dynamic gates must remain in the validator source."""
        import agents.validator as val

        source = inspect.getsource(val)
        for required in (
            "_validate_trajectory_awareness",
            "_check_request_contract",
            "_validate_step_ast_against_manifest",
            "load_policies",
            "_check_broken_dependency_chain",
        ):
            assert required in source, f"dynamic gate removed: {required}"

        # And a dynamic gate still rejects a structurally-valid but
        # manifest-invalid plan (blocked import "os").
        plan = _valid_materialized_plan()
        plan["steps"][0]["imports"] = ["os"]
        result = val.validate_plan(plan)
        assert result["passed"] is False
        # Rejected by the dynamic Manifest gate, not by the structure pre-check.
        assert result.get("structure_invalid") is not True

    def test_validator_does_not_treat_structure_pass_as_runtime_acceptance(self):
        """A structurally-valid plan can still be rejected by runtime gates."""
        from agents.validator import validate_plan

        # Structurally valid, but imports a Manifest-blocked module ("os").
        plan = _valid_materialized_plan()
        plan["steps"][0]["imports"] = ["os"]
        struct = validate_plan_structure(plan)
        assert struct.passed is True, "structure must pass (os is a dynamic gate)"
        result = validate_plan(plan)
        assert result["passed"] is False, "runtime gate must still reject"
        assert result.get("structure_invalid") is not True


# ═══════════════════════════════════════════════════════════════════
# Section 6 — Regression meta-tests
# ═══════════════════════════════════════════════════════════════════


def _run_pytest(test_file: str, timeout: int = 240) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable, "-m", "pytest",
            str(B_DIR / test_file),
            "-q", "--no-header", "-p", "no:cacheprovider",
        ],
        capture_output=True, text=True, timeout=timeout, cwd=str(B_DIR),
    )


class TestRegression:
    def test_original_313_route_tests_pass(self):
        proc = _run_pytest("test_routes.py")
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, (
            f"test_routes.py did not pass cleanly:\n{out[-2000:]}"
        )
        # Must contain 313 passed.
        assert "313 passed" in out, f"expected 313 passed:\n{out[-1500:]}"

    def test_existing_materializer_tests_all_pass(self):
        proc = _run_pytest("test_route_materializer_impl.py")
        out = proc.stdout + proc.stderr

        assert proc.returncode == 0, (
            f"test_route_materializer_impl.py did not pass cleanly:\n{out[-2000:]}"
        )
        # All tests must pass — the 3 old divergent-contract assertions have been
        # replaced with tests that respect the shared contract semantics.
        assert "failed" not in out, (
            f"Unexpected failures in materializer suite:\n{out[-2000:]}"
        )


# ═══════════════════════════════════════════════════════════════════
# Section 7 — Code-first Validator compatibility
# ═══════════════════════════════════════════════════════════════════


def _code_first_plan(**overrides) -> dict:
    """Minimal valid plan with a code field."""
    plan = {
        "version": 1,
        "plan_id": "code-first-test",
        "primitive_context": {
            "current_primitive": "information_disclosure",
            "target_primitive": "information_disclosure",
        },
        "steps": [{
            "id": 1,
            "type": "python",
            "code": "from redteam_sdk import *\ns = HttpClient('http://target')\nresp = s.get('/')\nprint(f'HTTP {resp.status_code}')",
            "purpose": "probe",
        }],
    }
    plan.update(overrides)
    return plan


class TestCodeFirstCompatibility:
    """Verify Validator does not block code-first plans on non-security gates."""

    def test_A_code_with_grpc_metadata_passes(self):
        """Case A: code + grpc sdk_calls metadata → passes (sdk_calls are metadata only)."""
        from agents.validator import validate_plan

        plan = _code_first_plan()
        plan["steps"][0]["sdk_calls"] = [{
            "primitive": "GrpcClient.call",
            "target": "localhost:50051",
            "service": "Example",
            "method": "Call",
            "payload": {},
            "metadata": {},
        }]

        result = validate_plan(plan)
        assert result["passed"] is True, (
            f"code-first + grpc metadata must pass; got errors: {result.get('errors')}"
        )

    def test_B_code_with_unknown_capability_passes_with_warning(self):
        """Case B: code + unknown capability → passes with warnings, not blocked."""
        from agents.validator import validate_plan

        plan = _code_first_plan()
        # execution_interface with adapter not in capability registry
        plan["primitive_context"]["execution_interface"] = {
            "adapter": "UnknownAdapter",
        }

        result = validate_plan(plan)
        assert result["passed"] is True, (
            f"code-first + unknown capability must pass (warnings only); "
            f"got errors: {result.get('errors')}"
        )
        # Should have at least one warning from capability contract
        warnings = result.get("syntax_warnings", [])
        assert len(warnings) >= 1, f"expected warnings for unknown capability, got none"
        assert any("capability_contract" in w or "CAPABILITY" in w for w in warnings), (
            f"expected capability_contract warning, got: {warnings}"
        )

    def test_C_import_subprocess_still_fails(self):
        """Case C: code importing subprocess → still BLOCKED (sandbox escape)."""
        from agents.validator import validate_plan

        plan = _code_first_plan()
        plan["steps"][0]["code"] = "import subprocess\nsubprocess.run(['ls'])"
        plan["steps"][0]["imports"] = ["subprocess"]

        result = validate_plan(plan)
        assert result["passed"] is False, (
            f"import subprocess must still be blocked; got: {result}"
        )
        assert any("subprocess" in e for e in result.get("errors", [])), (
            f"expected subprocess blocking error; got: {result.get('errors')}"
        )

    def test_D_os_system_still_fails(self):
        """Case D: code using os.system() → still BLOCKED (text_scan rule severity=error)."""
        from agents.validator import validate_plan

        plan = _code_first_plan()
        plan["steps"][0]["code"] = "import os\nos.system('id')"

        result = validate_plan(plan)
        assert result["passed"] is False, (
            f"os.system() must still be blocked by text_scan; got: {result}"
        )
        assert any(
            "os.system" in e.lower() or "os_system" in e.lower()
            for e in result.get("errors", [])
        ), (
            f"expected os.system blocking error; got: {result.get('errors')}"
        )

    def test_E_pure_code_step_passes_cleanly(self):
        """Pure code step (no sdk_calls, no imports field) passes all gates."""
        from agents.validator import validate_plan

        plan = _code_first_plan()
        # Remove any sdk_calls / imports metadata
        plan["steps"][0].pop("sdk_calls", None)
        plan["steps"][0].pop("imports", None)

        result = validate_plan(plan)
        assert result["passed"] is True, (
            f"pure code step must pass; got errors: {result.get('errors')}"
        )

    def test_F_sdk_calls_only_still_blocked_on_manifest(self):
        """Pure AST step (sdk_calls only, no code) still blocked by manifest gate."""
        from agents.validator import validate_plan

        plan = {
            "version": 1,
            "plan_id": "ast-only",
            "primitive_context": {
                "current_primitive": "information_disclosure",
                "target_primitive": "information_disclosure",
            },
            "steps": [{
                "id": 1,
                "type": "python",
                "sdk_calls": [{
                    "primitive": "UnknownCall.xyz",
                    "target": "/",
                }],
                "imports": ["unknown_lib"],
                "purpose": "test",
            }],
        }

        result = validate_plan(plan)
        # Without code field, manifest gates remain blocking
        assert result["passed"] is False, (
            f"AST-only with unknown primitives must be blocked; got: {result}"
        )
