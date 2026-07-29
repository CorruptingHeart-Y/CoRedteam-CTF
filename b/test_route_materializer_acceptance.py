"""Offline Route Materializer — Full Pipeline Acceptance Smoke Test.

FAIL CLOSED: every assertion that can fail will fail the test.
No warnings-as-pass, no skips, no xfails, no broad except Exception.

Runs the complete offline pipeline with REAL data flow:
  CWE-1336 RouteProposal
  → Normalizer (canonical → CWE-94)
  → YAML Writer (writes to temp file)
  → safe_load from YAML file
  → Admission (load_and_admit_candidate_route from YAML path)
  → Registry (registers Admission decision)
  → Frontier (from Registry snapshot)
  → Frontier eligible entry → Registry.get(route_id) → route
  → Materializer (using Frontier route, NOT original in-memory route)
  → plan.json
  → validate_plan_structure
  → controlled validate_plan

Side-effect guards (fail-fast counters):
  - HTTP: socket.connect, urllib.urlopen, requests/httpx (if importable)
  - Executor: run_executor, _run_step
  - Verification Memory: all write methods
  - Trajectory Memory: append, _save
  - Forbidden imports: subprocess check

This test does NOT: implement CLI, run Stage 1, send HTTP, execute exploits.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# ── path setup ──
ROOT = Path(__file__).resolve().parents[1]
B_DIR = ROOT / "b"
if str(B_DIR) not in sys.path:
    sys.path.insert(0, str(B_DIR))

from routes.schema import RouteProposal, FrontierContext
from routes.normalizer import normalize_route_proposal
from routes.primitive_adapter import PrimitiveAdapter
from routes.admission import load_and_admit_candidate_route, ADMITTED_CANDIDATE
from routes.registry import RouteRegistry
from routes.frontier import build_frontier
from routes.writer import write_candidate_route
from routes.materializer import materialize_route_plan
from core.plan_contract import validate_plan_structure


# ═══════════════════════════════════════════════════════════════════
# Full pipeline smoke — REAL data flow, fail-closed
# ═══════════════════════════════════════════════════════════════════


class TestOfflineReleaseSmoke:
    """Complete YAML→Admission→Registry→Frontier→Materializer chain with real object flow."""

    def test_full_pipeline_uses_yaml_loaded_admitted_frontier_route(self, tmp_path, monkeypatch):
        """真实贯通数据流：每一阶段消费上一阶段的输出，不绕过任何环节。

        RouteProposal → Normalizer → YAML Writer → safe_load from file
        → Admission (load_and_admit_candidate_route) → Registry
        → Frontier → eligible entry → Registry.get(route_id) → route
        → Materializer → plan.json → validate_plan_structure → controlled validate_plan

        禁止使用原始内存 route 绕过 YAML/Admission/Frontier。
        """

        # ═══════════════════════════════════════════════════════════
        # 0. Setup side-effect guards BEFORE pipeline
        # ═══════════════════════════════════════════════════════════

        # ── HTTP fail-fast counters ──
        http_calls = {"count": 0}

        import socket as _socket
        _real_socket_connect = _socket.socket.connect

        def _fail_socket_connect(self, *a, **kw):
            http_calls["count"] += 1
            raise AssertionError("socket.connect called — pipeline must not use network")

        monkeypatch.setattr(_socket.socket, "connect", _fail_socket_connect)

        import urllib.request as _ur
        _real_urlopen = _ur.urlopen

        def _fail_urlopen(*a, **kw):
            http_calls["count"] += 1
            raise AssertionError("urllib.request.urlopen called — pipeline must not use network")

        monkeypatch.setattr(_ur, "urlopen", _fail_urlopen)

        # requests (optional third-party)
        try:
            import requests as _requests

            def _fail_requests_request(*a, **kw):
                http_calls["count"] += 1
                raise AssertionError("requests.request called — pipeline must not use network")

            monkeypatch.setattr(_requests, "request", _fail_requests_request)
        except ImportError:
            pass

        # httpx (optional third-party)
        try:
            import httpx as _httpx

            def _fail_httpx_request(*a, **kw):
                http_calls["count"] += 1
                raise AssertionError("httpx.request called — pipeline must not use network")

            monkeypatch.setattr(_httpx, "request", _fail_httpx_request)
        except ImportError:
            pass

        # ── Executor fail-fast counters ──
        executor_calls = {"count": 0}
        import agents.executor  # noqa: F401 — MUST succeed, no except

        def _fail_run_executor(*a, **kw):
            executor_calls["count"] += 1
            raise AssertionError(
                "agents.executor.run_executor called — pipeline must not invoke Executor!"
            )

        def _fail_run_step(*a, **kw):
            executor_calls["count"] += 1
            raise AssertionError(
                "agents.executor._run_step called — pipeline must not invoke Executor!"
            )

        monkeypatch.setattr("agents.executor.run_executor", _fail_run_executor)
        monkeypatch.setattr("agents.executor._run_step", _fail_run_step)

        # ── Verification Memory fail-fast counters ──
        verif_writes = {"count": 0}
        from memory.verification_memory import get_verification, reset_verification
        # Use a temp path + clear_current_run to guarantee clean state
        vm_tmp_path = tmp_path / "vm_smoke_guard.json"
        reset_verification(path=vm_tmp_path, clear_current_run=True)
        verif = get_verification(path=vm_tmp_path)

        for method_name in (
            "confirm", "confirm_endpoint", "confirm_injectable",
            "add_accepted_field", "add_rejected_field", "add_blacklist",
            "add_bypass", "add_working_primitive", "add_flag", "_save",
        ):
            if hasattr(verif, method_name):
                def _make_verif_fail(name=method_name):
                    def _fail(*a, **kw):
                        verif_writes["count"] += 1
                        raise AssertionError(
                            f"VerificationMemory.{name} called — pipeline must not write memory!"
                        )
                    return _fail

                monkeypatch.setattr(verif, method_name, _make_verif_fail())

        # ── Trajectory Memory fail-fast counters ──
        traj_writes = {"count": 0}
        from memory.exploit_trajectory import get_trajectory, reset_trajectory
        # Use a temp path + clear_current_run to guarantee clean state
        traj_tmp_path = tmp_path / "trajectory_smoke_guard.json"
        reset_trajectory(path=traj_tmp_path, clear_current_run=True)
        traj = get_trajectory(path=traj_tmp_path)

        initial_state = traj.get_current_state()
        initial_node_count = len(traj.nodes)

        for method_name in ("append", "_save"):
            if hasattr(traj, method_name):
                def _make_traj_fail(name=method_name):
                    def _fail(*a, **kw):
                        traj_writes["count"] += 1
                        raise AssertionError(
                            f"ExploitTrajectoryMemory.{name} called — pipeline must not write trajectory!"
                        )
                    return _fail

                monkeypatch.setattr(traj, method_name, _make_traj_fail())

        # ═══════════════════════════════════════════════════════════
        # 1. RouteProposal → Normalizer
        # ═══════════════════════════════════════════════════════════
        adapter = PrimitiveAdapter()
        proposal = RouteProposal(
            cwe_id="CWE-1336",
            current_state="init",
            target_primitive="ssti_reflection",
            technique="arithmetic_probe",
            required_runtime_facts=("endpoint", "parameter"),
            payload_template_ref="primitive:ssti_reflection:0",
            expected_signals=(
                "arithmetic_result_in_response",
                "expression_reflected_verbatim",
            ),
        )

        norm_result = normalize_route_proposal(proposal, adapter)
        assert norm_result.ok, f"Normalizer failed: {norm_result.errors}"
        route = norm_result.route
        assert route.cwe_id == "CWE-94", (
            f"canonical CWE should be CWE-94, got {route.cwe_id}"
        )

        # ═══════════════════════════════════════════════════════════
        # 2. YAML Writer → temp YAML file
        # ═══════════════════════════════════════════════════════════
        candidates_dir = tmp_path / "candidates"
        candidates_dir.mkdir(parents=True, exist_ok=True)
        write_result = write_candidate_route(route, candidates_dir)
        assert write_result.ok, f"YAML write failed: {write_result.errors}"
        yaml_path = write_result.output_path
        assert yaml_path is not None, "YAML output_path must not be None"
        assert yaml_path.is_file(), f"YAML file must exist on disk: {yaml_path}"

        # Verify schema version in YAML text
        yaml_text = yaml_path.read_text(encoding="utf-8")
        assert "schema_version: 1.1.0" in yaml_text or "schema_version: '1.1.0'" in yaml_text, (
            "schema_version must be 1.1.0 in YAML output"
        )

        # ═══════════════════════════════════════════════════════════
        # 3. Safe-load YAML → Admission (from file, NOT memory route)
        # ═══════════════════════════════════════════════════════════
        decision = load_and_admit_candidate_route(yaml_path, adapter)
        assert decision.accepted, (
            f"Admission rejected after YAML reload: {decision.diagnostics}"
        )
        assert decision.status == ADMITTED_CANDIDATE, (
            f"Admission status should be admitted_candidate, got {decision.status}"
        )
        assert decision.route is not None, "Admission must return a non-None route"

        # ═══════════════════════════════════════════════════════════
        # 4. Registry (registers Admission output, NOT original route)
        # ═══════════════════════════════════════════════════════════
        registry = RouteRegistry(adapter=adapter)
        reg_result = registry.register_decision(decision, yaml_path)
        assert reg_result.registered, f"Registry rejected: {reg_result.diagnostics}"
        assert len(registry) == 1, f"Registry should have 1 route, got {len(registry)}"

        # ═══════════════════════════════════════════════════════════
        # 5. Frontier (from Registry snapshot)
        # ═══════════════════════════════════════════════════════════
        context = FrontierContext(
            current_state="init",
            confirmed_signals=(),
            runtime_facts={
                "endpoint": "/",
                "parameter": "text",
            },
        )
        frontier = build_frontier(registry.snapshot(), context)
        assert len(frontier.eligible_routes) == 1, (
            f"Frontier eligible must be exactly 1, got {len(frontier.eligible_routes)}"
        )

        # ═══════════════════════════════════════════════════════════
        # 6. Get route from Frontier eligible entry via Registry
        #    (NOT the original in-memory route!)
        # ═══════════════════════════════════════════════════════════
        eligible_entry = frontier.eligible_routes[0]
        registered = registry.get(eligible_entry.route_id)
        assert registered is not None, (
            f"Registry must contain route for eligible entry {eligible_entry.route_id}"
        )
        frontier_route = registered.route

        # ═══════════════════════════════════════════════════════════
        # 7. Materializer (using Frontier route, NOT original route)
        # ═══════════════════════════════════════════════════════════
        output_path = tmp_path / "plan.json"
        materialized = materialize_route_plan(
            frontier_route,
            adapter=adapter,
            runtime_facts={
                "base_url": "http://127.0.0.1:1337",
                "endpoint": "/",
                "parameter": "text",
                "method": "POST",
                "request_location": "form",
            },
            output_path=output_path,
        )
        assert materialized.success, (
            f"Materializer failed: {materialized.diagnostics}"
        )
        assert output_path.is_file(), "plan.json must exist on disk"

        plan = json.loads(output_path.read_text(encoding="utf-8"))
        assert len(plan["steps"]) == 1, (
            f"plan must have exactly 1 step, got {len(plan['steps'])}"
        )

        # ── Plan identity: must match Frontier route ──
        assert plan["metadata"]["route_id"] == frontier_route.canonical_id, (
            f"plan route_id {plan['metadata']['route_id']!r} != "
            f"Frontier route canonical_id {frontier_route.canonical_id!r}"
        )
        assert plan["metadata"]["payload_template_ref"] == frontier_route.payload_template_ref, (
            f"plan payload_template_ref mismatch: "
            f"{plan['metadata']['payload_template_ref']!r} != "
            f"{frontier_route.payload_template_ref!r}"
        )

        # ═══════════════════════════════════════════════════════════
        # 8. Plan Structure Contract
        # ═══════════════════════════════════════════════════════════
        struct = validate_plan_structure(plan)
        assert struct.passed, (
            f"validate_plan_structure rejected plan: {struct.diagnostics}"
        )

        # ═══════════════════════════════════════════════════════════
        # 9. Runtime Validator (controlled fixture)
        # ═══════════════════════════════════════════════════════════
        from agents.validator import validate_plan
        import agents.validator as val

        # Controlled Manifest
        val._manifest_imported = True
        val._MANIFEST_SAFE_MODULES = {
            "json", "base64", "re", "time", "hashlib", "urllib.parse",
        }
        val._MANIFEST_BLOCKED_MODULES = {
            "os", "subprocess", "socket", "ctypes", "requests",
        }
        val._MANIFEST_SDK_PRIMITIVES = {"HttpClient.get", "HttpClient.post"}

        # Trajectory: match Route state (already reset above)
        monkeypatch.setattr(traj, "get_current_state", lambda: "init")
        monkeypatch.setattr(traj, "get_current_chain", lambda: [])

        # Verification Memory: empty
        from memory.verification_memory import _default_facts
        verif.facts = _default_facts()

        # AntiRegression: all clear
        monkeypatch.setattr(
            "control.anti_regression.AntiRegressionController.validate_state_regression",
            lambda self, steps: (True, ""),
        )
        monkeypatch.setattr(
            "control.anti_regression.AntiRegressionController.validate_chain_break",
            lambda self, steps, chain: (True, ""),
        )
        monkeypatch.setattr(
            "control.anti_regression.AntiRegressionController.validate_payload_regression",
            lambda self, cmd: (True, ""),
        )
        monkeypatch.setattr(
            "control.anti_regression.AntiRegressionController.validate_exploit_reasoning",
            lambda self, steps, state: (True, []),
        )

        # Call counter
        called_flag = {"hit": False}
        _real_validate = validate_plan

        def _tracked(p, **kw):
            called_flag["hit"] = True
            return _real_validate(p, **kw)

        monkeypatch.setattr("agents.validator.validate_plan", _tracked)

        validation = _tracked(plan, prior_feedback=None, parameter_contract=None)

        assert called_flag["hit"], "validate_plan was never called!"
        assert validation.get("passed") is True, (
            f"Runtime Validator rejected plan in controlled fixture. "
            f"Errors: {validation.get('errors', [])}"
        )

        # ═══════════════════════════════════════════════════════════
        # 10. Side-effect assertions — ALL must be exactly 0
        # ═══════════════════════════════════════════════════════════

        # HTTP
        assert http_calls["count"] == 0, (
            f"HTTP/network calls detected: {http_calls['count']}"
        )

        # Executor
        assert executor_calls["count"] == 0, (
            f"Executor calls detected: {executor_calls['count']}"
        )

        # Verification Memory
        assert verif_writes["count"] == 0, (
            f"Verification Memory writes detected: {verif_writes['count']}"
        )

        # Trajectory Memory
        assert traj_writes["count"] == 0, (
            f"Trajectory writes detected: {traj_writes['count']}"
        )
        assert traj.get_current_state() == initial_state, (
            f"Trajectory state changed: {traj.get_current_state()} != {initial_state}"
        )
        assert len(traj.nodes) == initial_node_count, (
            f"Trajectory node count changed: {len(traj.nodes)} != {initial_node_count}"
        )

        # ═══════════════════════════════════════════════════════════
        # 11. Forbidden imports — subprocess check
        # ═══════════════════════════════════════════════════════════
        check_script = f"""
import sys
sys.path.insert(0, {str(B_DIR)!r})
before = set(sys.modules)
from routes.materializer import materialize_route_plan  # noqa: F401
after = set(sys.modules)
new = after - before
forbidden = {{'planner', 'coordinator', 'evaluator', 'consolidator',
             'openai', 'anthropic', 'langchain', 'litellm'}}
found = forbidden & {{m.split('.')[0] for m in new}}
if found:
    print(f"FORBIDDEN: {{sorted(found)}}")
else:
    print("OK: no forbidden modules")
for m in sorted(new):
    print(f"NEW: {{m}}")
"""
        proc = subprocess.run(
            [sys.executable, "-c", check_script],
            capture_output=True, text=True, timeout=60,
        )
        assert proc.returncode == 0, (
            f"Subprocess import failed with code {proc.returncode}:\n"
            f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
        assert "Traceback" not in proc.stderr, (
            f"Traceback in stderr during subprocess import:\n{proc.stderr}"
        )
        assert "FORBIDDEN:" not in proc.stdout, (
            f"Forbidden modules loaded during materializer import:\n{proc.stdout}"
        )


# ═══════════════════════════════════════════════════════════════════
# STEP_NOT_DICT regression
# ═══════════════════════════════════════════════════════════════════


class TestStepNotDictRejection:
    """Non-dict steps must be rejected by the shared structure contract."""

    def test_non_dict_step_rejected_by_structure_contract(self):
        from core.plan_contract import (
            validate_plan_structure,
            PlanStructureErrorCode,
        )
        plan = {
            "version": 1,
            "steps": [
                "this_is_a_string_not_a_dict",  # ← would crash Validator's st.get()
            ],
        }
        result = validate_plan_structure(plan)
        assert result.passed is False, "Non-dict step must be rejected"
        assert PlanStructureErrorCode.STEP_NOT_DICT in result.error_codes, (
            f"Expected STEP_NOT_DICT, got {result.error_codes}"
        )

    def test_non_dict_step_with_int_rejected(self):
        from core.plan_contract import (
            validate_plan_structure,
            PlanStructureErrorCode,
        )
        plan = {"version": 1, "steps": [42]}
        result = validate_plan_structure(plan)
        assert result.passed is False
        assert PlanStructureErrorCode.STEP_NOT_DICT in result.error_codes

    def test_non_dict_step_with_none_rejected(self):
        from core.plan_contract import (
            validate_plan_structure,
            PlanStructureErrorCode,
        )
        plan = {"version": 1, "steps": [None]}
        result = validate_plan_structure(plan)
        assert result.passed is False
        assert PlanStructureErrorCode.STEP_NOT_DICT in result.error_codes

    def test_mixed_dict_and_non_dict_steps_rejected(self):
        """Even one non-dict step among valid ones causes rejection."""
        from core.plan_contract import (
            validate_plan_structure,
            PlanStructureErrorCode,
        )
        plan = {
            "version": 1,
            "steps": [
                {"type": "python", "sdk_calls": [{"primitive": "HttpClient.get", "target": "/", "query": {"x": "1"}, "body": None}]},
                12345,
            ],
        }
        result = validate_plan_structure(plan)
        assert result.passed is False
        assert PlanStructureErrorCode.STEP_NOT_DICT in result.error_codes
