"""Manual Route CLI Bridge 鈥?Comprehensive Offline Tests.

All tests use mock Executor/Evaluator/HTTP. No real network, no Docker, no LLM.
"""

from __future__ import annotations

import inspect
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

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
from routes.materializer import MaterializationDiagnostic, MaterializationErrorCode, MaterializationResult
from routes.manual_bridge import (
    ManualRouteErrorCode,
    ManualRouteResult,
    run_manual_route,
    run_manual_route_candidates,
    _resolve_runtime_facts,
    _extract_endpoint_from_confirmed,
    _extract_parameter_from_confirmed,
    _extract_method_from_confirmed,
    _extract_location_from_confirmed,
    _collect_text_nodes,
)
from core.plan_contract import validate_plan_structure


# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?
# Helpers
# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?

def _make_candidate_yaml(
    adapter: PrimitiveAdapter | None = None,
    *,
    required_runtime_facts: tuple[str, ...] = ('endpoint', 'parameter'),
    technique: str = "arithmetic_probe",
) -> tuple[PrimitiveAdapter, NormalizedRoute, str]:
    """Create a valid candidate YAML route string and return (adapter, route, yaml_text)."""
    if adapter is None:
        adapter = PrimitiveAdapter()
    proposal = RouteProposal(
        cwe_id="CWE-1336",
        current_state="init",
        target_primitive="ssti_reflection",
        technique=technique,
        required_runtime_facts=required_runtime_facts,
        payload_template_ref="primitive:ssti_reflection:0",
        expected_signals=(
            "arithmetic_result_in_response",
            "expression_reflected_verbatim",
        ),
    )
    norm_result = normalize_route_proposal(proposal, adapter)
    assert norm_result.ok, f"Route setup failed: {norm_result.errors}"
    route = norm_result.route
    assert route.cwe_id == "CWE-94"

    # Write to temp dir to get YAML text
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        write_result = write_candidate_route(route, tdp)
        assert write_result.ok
        yaml_path = write_result.output_path
        assert yaml_path is not None
        yaml_text = yaml_path.read_text(encoding="utf-8")

    return adapter, route, yaml_text


def _make_route_dir(routes: list[tuple[str, str]]) -> Path:
    """Create a temp directory with route YAML files. Each tuple is (filename, yaml_content)."""
    td = tempfile.mkdtemp(prefix="route_dir_")
    tdp = Path(td)
    for filename, content in routes:
        (tdp / filename).write_text(content, encoding="utf-8")
    return tdp


def _make_confirmed_dict(
    endpoint: str = "/",
    parameter: str = "text",
    method: str | None = None,
    source_hint: str = "HTTP GET/POST parameter `text`",
    exploitation: str = "",
) -> dict:
    """Build a minimal confirmed_vuln-style dict for runtime fact extraction."""
    vuln = {
        "id": "VULN-001",
        "cwe_id": "CWE-94",
        "source": source_hint,
        "evidence": [
            {"code_snippet": f'@RequestMapping("{endpoint}")'},
        ],
    }
    if exploitation:
        vuln["exploitation"] = exploitation
    if method:
        vuln["exploitation"] = f"The attacker sends a {method} request to..."
    return {"vulnerabilities": [vuln]}


def _mock_settings():
    """Create a minimal mock Settings object."""
    from core.settings import Settings
    return Settings(
        project_root=B_DIR.parent,
        deepseek_api_key=None,
        deepseek_base_url="https://api.deepseek.com",
        deepseek_model="deepseek-chat",
        mock_llm=True,
        max_iterations=1,
        max_iterations_cap=1,
        workspace_dir=Path(tempfile.mkdtemp(prefix="ws_")),
        memory_dir=B_DIR,
        confirmed_vuln_path=B_DIR / "data" / "confirmed_vuln.json",
        docker_enabled=False,
        docker_image="co-redteam-sandbox:latest",
        docker_timeout=300,
        docker_memory_limit="512m",
        docker_cpu_quota=100000,
        json_mode=False,
    )


def _mock_target():
    """Create a minimal mock TargetContext."""
    from core.target_context import TargetContext
    return TargetContext(
        url="http://127.0.0.1:1337",
        scheme="http",
        hostname="127.0.0.1",
        port=1337,
        ip="127.0.0.1",
    )


_MOCK_EXEC_OUT = {
    "version": 1,
    "executed": True,
    "execution_mode": "docker",
    "step_results": [{
        "step_id": 1,
        "result": {
            "ok": True,
            "exit_code": 0,
            "stdout": "HTTP 200: 49\narithmetic_result_in_response detected",
            "stderr": "",
        },
    }],
}

_MOCK_EVALUATION_SUCCESS = {
    "repro_success": True,
    "confidence": 0.9,
    "detected_primitives": ["ssti_reflection"],
    "current_exploit_state": "probe_success",
    "should_continue": False,
    "memory_patch": {},
}

_MOCK_EVALUATION_NO_SIGNAL = {
    "repro_success": False,
    "confidence": 0.0,
    "detected_primitives": [],
    "current_exploit_state": "init",
    "should_continue": False,
    "memory_patch": {},
}


# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?
# 1. CLI Parser
# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?

class TestCLIParser:
    def test_manual_route_accepts_explicit_single_run_limits(self, monkeypatch):
        """Explicit 1/1/1 limits parse and configure manual-route execution."""
        from cli import _build_parser, _configure_exploit_limits
        monkeypatch.setenv("CO_REDTEAM_MAX_ITER", "8")
        monkeypatch.setenv("CO_REDTEAM_MAX_ITER_CAP", "20")
        monkeypatch.setenv("CO_REDTEAM_MAX_RUNS", "5")
        p = _build_parser()
        args = p.parse_args([
            "exploit", "--url", "http://127.0.0.1:1337",
            "--manual-route", "--route-dir", "/tmp/r", "--route-id", "abc",
            "--max-iter", "1", "--max-iters-cap", "1", "--max-runs", "1",
        ])

        assert _configure_exploit_limits(args) is True
        assert args.max_iter == 1
        assert args.max_iters_cap == 1
        assert args.max_runs == 1
        assert os.environ["CO_REDTEAM_MAX_ITER"] == "1"
        assert os.environ["CO_REDTEAM_MAX_ITER_CAP"] == "1"
        assert os.environ["CO_REDTEAM_MAX_RUNS"] == "1"

    def test_manual_route_omitted_limits_are_single_run(self, monkeypatch):
        """Omitted manual-route limits resolve to 1/1/1, ignoring ambient defaults."""
        from cli import _build_parser, _configure_exploit_limits
        monkeypatch.setenv("CO_REDTEAM_MAX_ITER", "8")
        monkeypatch.setenv("CO_REDTEAM_MAX_ITER_CAP", "20")
        monkeypatch.setenv("CO_REDTEAM_MAX_RUNS", "5")
        p = _build_parser()
        args = p.parse_args([
            "exploit", "--url", "http://127.0.0.1:1337",
            "--manual-route", "--route-dir", "/tmp/r", "--route-id", "abc",
        ])

        assert _configure_exploit_limits(args) is True
        assert args.max_iter is None
        assert args.max_iters_cap is None
        assert args.max_runs is None
        assert os.environ["CO_REDTEAM_MAX_ITER"] == "1"
        assert os.environ["CO_REDTEAM_MAX_ITER_CAP"] == "1"
        assert os.environ["CO_REDTEAM_MAX_RUNS"] == "1"

    def test_manual_route_rejects_non_single_run_limit(self, monkeypatch):
        """Any manual-route limit other than one fails closed with the stable code."""
        import cli
        monkeypatch.setenv("CO_REDTEAM_MAX_ITER", "8")
        monkeypatch.setenv("CO_REDTEAM_MAX_ITER_CAP", "20")
        monkeypatch.setenv("CO_REDTEAM_MAX_RUNS", "5")
        failures = []
        monkeypatch.setattr(cli, "fail", failures.append)
        args = cli._build_parser().parse_args([
            "exploit", "--url", "http://127.0.0.1:1337",
            "--manual-route", "--route-dir", "/tmp/r", "--route-id", "abc",
            "--max-runs", "2",
        ])

        assert cli.cmd_exploit(args) == 1
        assert failures == ["MANUAL_ROUTE_SINGLE_RUN_REQUIRED"]
        assert os.environ["CO_REDTEAM_MAX_ITER"] == "8"
        assert os.environ["CO_REDTEAM_MAX_ITER_CAP"] == "20"
        assert os.environ["CO_REDTEAM_MAX_RUNS"] == "5"

    def test_non_manual_limits_keep_existing_environment_semantics(self, monkeypatch):
        """Normal exploit limits still feed the existing environment-backed loops."""
        from cli import _build_parser, _configure_exploit_limits
        monkeypatch.setenv("CO_REDTEAM_MAX_ITER", "8")
        monkeypatch.setenv("CO_REDTEAM_MAX_ITER_CAP", "20")
        monkeypatch.setenv("CO_REDTEAM_MAX_RUNS", "5")
        p = _build_parser()
        default_args = p.parse_args([
            "exploit", "--url", "http://127.0.0.1:1337",
        ])
        assert _configure_exploit_limits(default_args) is True
        assert os.environ["CO_REDTEAM_MAX_ITER"] == "8"
        assert os.environ["CO_REDTEAM_MAX_ITER_CAP"] == "20"
        assert os.environ["CO_REDTEAM_MAX_RUNS"] == "5"
        args = p.parse_args([
            "exploit", "--url", "http://127.0.0.1:1337",
            "--max-iter", "3", "--max-iters-cap", "7", "--max-runs", "4",
        ])

        assert _configure_exploit_limits(args) is True
        assert os.environ["CO_REDTEAM_MAX_ITER"] == "3"
        assert os.environ["CO_REDTEAM_MAX_ITER_CAP"] == "7"
        assert os.environ["CO_REDTEAM_MAX_RUNS"] == "4"

    def test_manual_route_flags_registered(self):
        """--manual-route and related flags are parsed correctly."""
        from cli import _build_parser
        p = _build_parser()
        args = p.parse_args([
            "exploit", "--url", "http://127.0.0.1:1337",
            "--manual-route", "--route-dir", "/tmp/r", "--route-id", "abc",
        ])
        assert args.manual_route is True
        assert args.route_dir == "/tmp/r"
        assert args.route_id == "abc"

    def test_manual_route_requires_route_dir(self):
        """--manual-route without --route-dir is caught."""
        from cli import _build_parser
        p = _build_parser()
        args = p.parse_args([
            "exploit", "--url", "http://127.0.0.1:1337",
            "--manual-route", "--route-id", "abc",
        ])
        assert args.route_dir is None

    def test_manual_route_requires_route_id(self):
        """--manual-route without --route-id is caught."""
        from cli import _build_parser
        p = _build_parser()
        args = p.parse_args([
            "exploit", "--url", "http://127.0.0.1:1337",
            "--manual-route", "--route-dir", "/tmp/r",
        ])
        assert args.route_id is None

    def test_non_manual_cli_unchanged(self):
        """Without --manual-route, all existing behavior is preserved."""
        from cli import _build_parser
        p = _build_parser()
        args = p.parse_args([
            "exploit", "--url", "http://127.0.0.1:1337",
            "--confirmed", "data/confirmed_vuln.json",
            "--challenge", "generic",
        ])
        assert args.manual_route is False
        assert args.route_dir is None
        assert args.route_id is None
        assert args.url == "http://127.0.0.1:1337"
        assert args.confirmed == "data/confirmed_vuln.json"

    def test_route_method_and_location_flags(self):
        """--route-method and --route-location parse correctly."""
        from cli import _build_parser
        p = _build_parser()
        args = p.parse_args([
            "exploit", "--url", "http://127.0.0.1:1337",
            "--manual-route", "--route-dir", "/tmp/r", "--route-id", "abc",
            "--route-method", "POST", "--route-location", "form",
        ])
        assert args.route_method == "POST"
        assert args.route_location == "form"


# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?
# 2. Route Loading
# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?

class TestRouteLoading:
    def test_rejects_missing_route_directory(self):
        """Non-existent route directory 鈫?ROUTE_DIRECTORY_NOT_FOUND."""
        adapter, route, yaml_text = _make_candidate_yaml()
        confirmed = _make_confirmed_dict(exploitation="POST")
        target = _mock_target()
        settings = _mock_settings()
        result = run_manual_route(
            route_dir=Path("/nonexistent/dir"),
            route_id=route.canonical_id,
            confirmed=confirmed,
            target=target,
            settings=settings,
            workspace_dir=Path(tempfile.mkdtemp()),
            cli_method="POST",
            cli_location="form",
        )
        assert not result.success
        assert result.error_code == ManualRouteErrorCode.ROUTE_DIRECTORY_NOT_FOUND

    def test_rejects_unknown_route_id(self):
        """Known directory but unknown route_id 鈫?ROUTE_ID_NOT_FOUND."""
        adapter, route, yaml_text = _make_candidate_yaml()
        route_dir = _make_route_dir([
            (f"{route.canonical_id.replace(':', '-')}.yaml", yaml_text),
        ])
        confirmed = _make_confirmed_dict(exploitation="POST")
        target = _mock_target()
        settings = _mock_settings()
        try:
            result = run_manual_route(
                route_dir=route_dir,
                route_id="nonexistent:route:id",
                confirmed=confirmed,
                target=target,
                settings=settings,
                workspace_dir=Path(tempfile.mkdtemp()),
                cli_method="POST",
                cli_location="form",
            )
            assert not result.success
            assert result.error_code == ManualRouteErrorCode.ROUTE_ID_NOT_FOUND
        finally:
            import shutil
            shutil.rmtree(route_dir, ignore_errors=True)

    def test_registers_only_admitted_routes(self, monkeypatch):
        """Non-admitted YAML files are silently skipped; only admitted routes registered."""
        adapter, route, yaml_text = _make_candidate_yaml()
        # Create a second YAML with a bad CWE that won't admit
        bad_yaml = yaml_text.replace("CWE-94", "CWE-9999")
        route_dir = _make_route_dir([
            (f"{route.canonical_id.replace(':', '-')}.yaml", yaml_text),
            ("bad_route.yaml", bad_yaml),
        ])
        confirmed = _make_confirmed_dict(exploitation="POST")
        target = _mock_target()
        settings = _mock_settings()

        # Mock executor + evaluator to avoid real execution
        monkeypatch.setattr(
            "agents.executor.run_executor",
            lambda **kw: _MOCK_EXEC_OUT,
        )
        monkeypatch.setattr(
            "agents.evaluator.run_evaluator",
            lambda **kw: _MOCK_EVALUATION_SUCCESS,
        )

        try:
            result = run_manual_route(
                route_dir=route_dir,
                route_id=route.canonical_id,
                confirmed=confirmed,
                target=target,
                settings=settings,
                workspace_dir=Path(tempfile.mkdtemp()),
                cli_method="POST",
                cli_location="form",
            )
            # The good route should succeed
            assert result.success, f"Expected success, got: {result.error_code} 鈥?{result.diagnostics}"
        finally:
            import shutil
            shutil.rmtree(route_dir, ignore_errors=True)


# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?
# 3. Frontier
# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?

class TestFrontier:
    def test_uses_frontier_selected_route(self, monkeypatch):
        """Verify materializer receives the route from Frontier via Registry."""
        adapter, route, yaml_text = _make_candidate_yaml()
        route_dir = _make_route_dir([
            (f"{route.canonical_id.replace(':', '-')}.yaml", yaml_text),
        ])
        confirmed = _make_confirmed_dict(exploitation="POST")
        target = _mock_target()
        settings = _mock_settings()

        captured_route_ids = []

        def _fake_materialize(r, **kw):
            captured_route_ids.append(r.canonical_id)
            from routes.materializer import MaterializationResult
            # Actually materialize for real
            return materialize_route_plan(r, **kw)

        monkeypatch.setattr(
            "agents.executor.run_executor",
            lambda **kw: _MOCK_EXEC_OUT,
        )
        monkeypatch.setattr(
            "agents.evaluator.run_evaluator",
            lambda **kw: _MOCK_EVALUATION_SUCCESS,
        )

        try:
            result = run_manual_route(
                route_dir=route_dir,
                route_id=route.canonical_id,
                confirmed=confirmed,
                target=target,
                settings=settings,
                workspace_dir=Path(tempfile.mkdtemp()),
                cli_method="POST",
                cli_location="form",
            )
            assert result.success
            assert len(captured_route_ids) == 0, "Materializer was not patched 鈥?verify via plan metadata"
            # Plan route_id should match the requested route
            assert result.plan is not None
            assert result.plan["metadata"]["route_id"] == route.canonical_id
        finally:
            import shutil
            shutil.rmtree(route_dir, ignore_errors=True)


# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?
# 4. Runtime Facts
# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?

class TestRuntimeFacts:
    def test_extract_endpoint(self):
        """Endpoint extracted from @RequestMapping annotation."""
        confirmed = _make_confirmed_dict(endpoint="/search")
        ep = _extract_endpoint_from_confirmed(confirmed)
        assert ep == "/search"

    @pytest.mark.parametrize(
        ("field_path", "value", "expected"),
        [
            (("request_facts", "endpoint"), "/facts?from=structured", "/facts"),
            (("endpoint",), "/endpoint#fragment", "/endpoint"),
            (("path",), "/path?x=1", "/path"),
            (("route",), "/route#section", "/route"),
        ],
    )
    def test_extract_endpoint_from_structured_fields(
        self,
        field_path,
        value,
        expected,
    ):
        """All declared structured endpoint fields are supported and normalized."""
        vuln = {}
        cursor = vuln
        for key in field_path[:-1]:
            cursor[key] = {}
            cursor = cursor[key]
        cursor[field_path[-1]] = value

        endpoint = _extract_endpoint_from_confirmed({"vulnerabilities": [vuln]})

        assert endpoint == expected

    def test_extract_endpoint_from_exploit_example_root(self):
        confirmed = {
            "vulnerabilities": [{"exploit_example": "GET /?text=x"}],
        }

        assert _extract_endpoint_from_confirmed(confirmed) == "/"

    def test_extract_endpoint_from_attack_vector_with_http_version(self):
        confirmed = {
            "vulnerabilities": [
                {"attack_vector": "POST /submit HTTP/1.1"},
            ],
        }

        assert _extract_endpoint_from_confirmed(confirmed) == "/submit"

    def test_extract_endpoint_from_absolute_url_request_line(self):
        confirmed = {
            "vulnerabilities": [
                {"request_example": "GET https://example.test/search?q=x#result HTTP/1.1"},
            ],
        }

        assert _extract_endpoint_from_confirmed(confirmed) == "/search"

    @pytest.mark.parametrize(
        ("container", "annotation", "expected"),
        [
            ("evidence", '@RequestMapping("/")', "/"),
            ("source", '@PostMapping("/search")', "/search"),
            ("flow", '@PatchMapping("/items/1?dry_run=1")', "/items/1"),
        ],
    )
    def test_extract_endpoint_from_framework_annotations(
        self,
        container,
        annotation,
        expected,
    ):
        confirmed = {
            "vulnerabilities": [{container: [{"code": annotation}]}],
        }

        assert _extract_endpoint_from_confirmed(confirmed) == expected

    def test_multiple_consistent_endpoint_sources_are_accepted(self):
        confirmed = {
            "vulnerabilities": [
                {
                    "request_facts": {"endpoint": "/search?one=1"},
                    "exploit_example": "GET /search?two=2 HTTP/1.1",
                    "evidence": [{"code": '@GetMapping("/search")'}],
                },
            ],
        }

        assert _extract_endpoint_from_confirmed(confirmed) == "/search"

    def test_conflicting_endpoint_sources_fail_closed(self):
        confirmed = {
            "vulnerabilities": [
                {
                    "endpoint": "/first",
                    "attack_vector": "POST /second HTTP/1.1",
                },
            ],
        }

        with pytest.raises(Exception) as exc_info:
            _resolve_runtime_facts(
                target_url="http://127.0.0.1:1337",
                confirmed=confirmed,
                cli_method="POST",
                cli_location="form",
            )

        assert exc_info.value.code == ManualRouteErrorCode.RUNTIME_FACT_CONFLICT

    def test_missing_endpoint_fails_closed(self):
        confirmed = {
            "vulnerabilities": [
                {"source": "HTTP parameter `text`", "cwe_id": "CWE-94"},
            ],
        }

        with pytest.raises(Exception) as exc_info:
            _resolve_runtime_facts(
                target_url="http://127.0.0.1:1337/never-use-as-endpoint",
                confirmed=confirmed,
                cli_method="POST",
                cli_location="form",
            )

        assert exc_info.value.code == ManualRouteErrorCode.RUNTIME_FACT_MISSING
        assert "endpoint" in str(exc_info.value)

    @pytest.mark.parametrize("cwe", ["CWE-79", "CWE-94", "CWE-917", "CWE-1336"])
    def test_cwe_does_not_affect_endpoint_extraction(self, cwe):
        confirmed = {
            "vulnerabilities": [
                {"cwe": cwe, "cwe_id": cwe, "exploit_example": "GET /fixed?x=1"},
            ],
        }

        assert _extract_endpoint_from_confirmed(confirmed) == "/fixed"

    def test_cwe_alone_never_infers_endpoint(self):
        confirmed = {
            "vulnerabilities": [{"cwe": "CWE-1336", "cwe_id": "CWE-1336"}],
        }

        assert _extract_endpoint_from_confirmed(confirmed) is None

    def test_extract_parameter(self):
        """Parameter name extracted from source field."""
        confirmed = _make_confirmed_dict(source_hint="HTTP GET parameter `text`")
        param = _extract_parameter_from_confirmed(confirmed)
        assert param == "text"

    def test_extract_parameter_from_structured_source_code(self):
        confirmed = {
            "vulnerabilities": [{
                "source": {
                    "file": "src/main/java/Main.java",
                    "line": 21,
                    "code": (
                        "String index(@RequestParam(required = false, "
                        'name = "text") String textString)'
                    ),
                },
            }],
        }

        assert _extract_parameter_from_confirmed(confirmed) == "text"

    def test_extract_parameter_from_legacy_source_string(self):
        confirmed = {
            "vulnerabilities": [{"source": "HTTP GET parameter `text`"}],
        }

        assert _extract_parameter_from_confirmed(confirmed) == "text"

    def test_extract_parameter_from_source_code_snippet(self):
        confirmed = {
            "vulnerabilities": [{
                "source": {
                    "code_snippet": '@RequestParam(value = "text") String input',
                },
            }],
        }

        assert _extract_parameter_from_confirmed(confirmed) == "text"

    def test_extract_parameter_from_flow_code(self):
        confirmed = {
            "vulnerabilities": [{
                "flow": [
                    {"step": 1, "code": None},
                    {"step": 2, "code": "@RequestParam('text') String input"},
                ],
            }],
        }

        assert _extract_parameter_from_confirmed(confirmed) == "text"

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("parameter", "text"),
            ("parameters", ["text"]),
        ],
    )
    def test_conflicting_request_facts_parameter_is_rejected(self, field, value):
        confirmed = {
            "vulnerabilities": [{
                "request_facts": {field: value},
                "source": {"code": '@RequestParam(name = "query") String input'},
            }],
        }

        with pytest.raises(Exception) as exc_info:
            _extract_parameter_from_confirmed(confirmed)

        assert exc_info.value.code == ManualRouteErrorCode.RUNTIME_FACT_CONFLICT
    @pytest.mark.parametrize("field", ["parameter", "parameter_name"])
    def test_direct_structured_parameter_fields(self, field):
        confirmed = {"vulnerabilities": [{field: "text"}]}

        assert _extract_parameter_from_confirmed(confirmed) == "text"

    def test_parameter_mixed_types_are_ignored_safely(self):
        confirmed = {
            "vulnerabilities": [{
                "source": {
                    "code": None,
                    "code_snippet": [1, False, None, {"description": 3.14}],
                    "description": {"nested": [None, 7, True]},
                },
                "flow": [None, 0, False, {"code": None}],
                "evidence": {"code": [None, 42]},
            }],
        }

        assert _extract_parameter_from_confirmed(confirmed) is None

    def test_duplicate_parameter_sources_are_accepted(self):
        confirmed = {
            "vulnerabilities": [{
                "source": {"code": '@RequestParam(name = "text") String input'},
                "evidence": [{"description": "HTTP parameter `text`"}],
            }],
        }

        assert _extract_parameter_from_confirmed(confirmed) == "text"

    def test_conflicting_parameter_sources_fail_closed(self):
        confirmed = {
            "vulnerabilities": [{
                "request_facts": {"endpoint": "/"},
                "source": {"code": '@RequestParam(name = "text") String input'},
                "evidence": [{"code": '@RequestParam(name = "query") String input'}],
            }],
        }

        with pytest.raises(Exception) as exc_info:
            _resolve_runtime_facts(
                target_url="http://127.0.0.1:1337",
                confirmed=confirmed,
                cli_method="POST",
                cli_location="form",
            )

        assert exc_info.value.code == ManualRouteErrorCode.RUNTIME_FACT_CONFLICT

    def test_missing_parameter_keeps_runtime_fact_missing(self):
        confirmed = {
            "vulnerabilities": [{
                "request_facts": {"endpoint": "/"},
                "source": {"file": "Main.java", "line": 21, "code": "return index();"},
            }],
        }

        with pytest.raises(Exception) as exc_info:
            _resolve_runtime_facts(
                target_url="http://127.0.0.1:1337",
                confirmed=confirmed,
                cli_method="POST",
                cli_location="form",
            )

        assert exc_info.value.code == ManualRouteErrorCode.RUNTIME_FACT_MISSING
        assert "parameter" in str(exc_info.value)

    @pytest.mark.parametrize(
        "annotation",
        [
            '@RequestParam(name = "text")',
            "@RequestParam( value = 'text' )",
            '@RequestParam(  "text"  )',
        ],
    )
    def test_request_param_annotation_forms(self, annotation):
        confirmed = {"vulnerabilities": [{"source": {"code": annotation}}]}

        assert _extract_parameter_from_confirmed(confirmed) == "text"

    def test_extract_parameter_from_get_request_example(self):
        confirmed = {
            "vulnerabilities": [{"request_example": "GET /?text=value HTTP/1.1"}],
        }

        assert _extract_parameter_from_confirmed(confirmed) == "text"

    def test_extract_parameter_from_form_request_example(self):
        confirmed = {
            "vulnerabilities": [{
                "request_example": (
                    "POST /search HTTP/1.1\r\n"
                    "Content-Type: application/x-www-form-urlencoded\r\n"
                    "\r\n"
                    "text=value"
                ),
            }],
        }

        assert _extract_parameter_from_confirmed(confirmed) == "text"

    def test_parameter_fix_preserves_endpoint_method_and_location_results(self):
        confirmed = {
            "vulnerabilities": [{
                "request_facts": {"endpoint": "/search"},
                "source": "POST form parameter `text`",
            }],
        }

        assert _extract_endpoint_from_confirmed(confirmed) == "/search"
        assert _extract_method_from_confirmed(confirmed) == "POST"
        assert _extract_location_from_confirmed(confirmed) == "form"

    def test_extract_method_post(self):
        """Method extracted when exploitation says POST."""
        confirmed = _make_confirmed_dict(
            source_hint="HTTP parameter `text`",
            exploitation="The attacker sends a POST request to...",
        )
        method = _extract_method_from_confirmed(confirmed)
        assert method == "POST"

    def test_extract_method_get(self):
        """Method extracted when exploitation says GET."""
        confirmed = _make_confirmed_dict(
            source_hint="HTTP parameter `text`",
            exploitation="The attacker sends a GET request to...",
        )
        method = _extract_method_from_confirmed(confirmed)
        assert method == "GET"

    def test_extract_method_ambiguous_returns_none(self):
        """When both GET and POST appear, returns None (ambiguous)."""
        confirmed = _make_confirmed_dict(
            source_hint="HTTP parameter `text`",
            exploitation="GET or POST request can be sent",
        )
        method = _extract_method_from_confirmed(confirmed)
        assert method is None

    def test_requires_method(self):
        """Method missing 鈫?RUNTIME_FACT_MISSING."""
        with pytest.raises(Exception) as exc_info:
            _resolve_runtime_facts(
                target_url="http://127.0.0.1:1337",
                confirmed=_make_confirmed_dict(),
                cli_method=None,
                cli_location="form",
            )
        assert "method" in str(exc_info.value).lower()

    def test_requires_request_location(self):
        """request_location missing with no CLI/default 鈫?RUNTIME_FACT_MISSING."""
        with pytest.raises(Exception) as exc_info:
            _resolve_runtime_facts(
                target_url="http://127.0.0.1:1337",
                confirmed=_make_confirmed_dict(
                    source_hint="HTTP parameter `text`",
                    exploitation="The attacker sends a POST request",
                ),
                cli_method="POST",
                cli_location=None,
            )
        assert "request_location" in str(exc_info.value).lower()

    def test_cli_contract_conflict_rejected(self):
        """CLI method conflicts with confirmed 鈫?RUNTIME_FACT_CONFLICT."""
        with pytest.raises(Exception) as exc_info:
            _resolve_runtime_facts(
                target_url="http://127.0.0.1:1337",
                confirmed=_make_confirmed_dict(
                    source_hint="HTTP parameter `text`",
                    exploitation="The attacker sends a GET request",
                ),
                cli_method="POST",
                cli_location="form",
            )
        assert "conflict" in str(exc_info.value).lower()

    def test_does_not_guess_runtime_facts(self):
        """No defaults for method or location 鈥?missing 鈫?error."""
        # confirmed has no method info, no CLI override 鈫?must fail
        with pytest.raises(Exception):
            _resolve_runtime_facts(
                target_url="http://127.0.0.1:1337",
                confirmed=_make_confirmed_dict(),
                cli_method=None,
                cli_location=None,
            )


# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?
# 5. Materializer and Validator
# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?

class TestMaterializerValidator:
    def test_materializes_one_step_plan(self, monkeypatch):
        """Bridge produces a plan with exactly 1 step."""
        adapter, route, yaml_text = _make_candidate_yaml()
        route_dir = _make_route_dir([
            (f"{route.canonical_id.replace(':', '-')}.yaml", yaml_text),
        ])
        confirmed = _make_confirmed_dict(exploitation="POST")
        target = _mock_target()
        settings = _mock_settings()

        monkeypatch.setattr(
            "agents.executor.run_executor",
            lambda **kw: _MOCK_EXEC_OUT,
        )
        monkeypatch.setattr(
            "agents.evaluator.run_evaluator",
            lambda **kw: _MOCK_EVALUATION_SUCCESS,
        )

        try:
            result = run_manual_route(
                route_dir=route_dir,
                route_id=route.canonical_id,
                confirmed=confirmed,
                target=target,
                settings=settings,
                workspace_dir=Path(tempfile.mkdtemp()),
                cli_method="POST",
                cli_location="form",
            )
            assert result.success
            assert result.plan is not None
            assert len(result.plan["steps"]) == 1
        finally:
            import shutil
            shutil.rmtree(route_dir, ignore_errors=True)

    def test_calls_shared_structure_contract(self, monkeypatch):
        """Plan passes validate_plan_structure."""
        adapter, route, yaml_text = _make_candidate_yaml()
        route_dir = _make_route_dir([
            (f"{route.canonical_id.replace(':', '-')}.yaml", yaml_text),
        ])
        confirmed = _make_confirmed_dict(exploitation="POST")
        target = _mock_target()
        settings = _mock_settings()

        monkeypatch.setattr(
            "agents.executor.run_executor",
            lambda **kw: _MOCK_EXEC_OUT,
        )
        monkeypatch.setattr(
            "agents.evaluator.run_evaluator",
            lambda **kw: _MOCK_EVALUATION_SUCCESS,
        )

        try:
            result = run_manual_route(
                route_dir=route_dir,
                route_id=route.canonical_id,
                confirmed=confirmed,
                target=target,
                settings=settings,
                workspace_dir=Path(tempfile.mkdtemp()),
                cli_method="POST",
                cli_location="form",
            )
            assert result.success
            # Verify structure contract was applied
            assert result.plan is not None
            struct = validate_plan_structure(result.plan)
            assert struct.passed
        finally:
            import shutil
            shutil.rmtree(route_dir, ignore_errors=True)

    def test_stops_on_materializer_failure(self, monkeypatch):
        """Materializer failure 鈫?MATERIALIZATION_FAILED, no executor called."""
        adapter, route, yaml_text = _make_candidate_yaml()
        route_dir = _make_route_dir([
            (f"{route.canonical_id.replace(':', '-')}.yaml", yaml_text),
        ])
        confirmed = _make_confirmed_dict(exploitation="POST")
        target = _mock_target()
        settings = _mock_settings()

        executor_called = {"hit": False}

        def _track_executor(**kw):
            executor_called["hit"] = True
            return _MOCK_EXEC_OUT

        monkeypatch.setattr("agents.executor.run_executor", _track_executor)

        # Missing method 鈫?materializer fails
        result = run_manual_route(
            route_dir=route_dir,
            route_id=route.canonical_id,
            confirmed=confirmed,
            target=target,
            settings=settings,
            workspace_dir=Path(tempfile.mkdtemp()),
            cli_method=None,  # no method 鈫?fail
            cli_location="form",
        )
        import shutil
        shutil.rmtree(route_dir, ignore_errors=True)

        assert not result.success
        assert result.error_code == ManualRouteErrorCode.RUNTIME_FACT_MISSING
        assert not executor_called["hit"], "Executor should not be called after materializer failure"



    def test_materialization_failure_records_stage_and_reason(self, monkeypatch):
        """Materializer contract failure is structured for candidate-loop continuation."""
        adapter, route, yaml_text = _make_candidate_yaml()
        route_dir = _make_route_dir([
            (f"{route.canonical_id.replace(':', '-')}.yaml", yaml_text),
        ])
        confirmed = _make_confirmed_dict(exploitation="POST")
        target = _mock_target()
        settings = _mock_settings()

        def _fail_materializer(*args, **kwargs):
            return MaterializationResult(
                success=False,
                route_id=route.canonical_id,
                plan_path=None,
                payload_template_ref=route.payload_template_ref,
                resolved_endpoint=None,
                resolved_parameter=None,
                resolved_method=None,
                request_location=None,
                diagnostics=(
                    MaterializationDiagnostic(
                        MaterializationErrorCode.PLAN_CONTRACT_INVALID,
                        "materialization",
                        "contract unavailable for this route",
                    ),
                ),
            )

        monkeypatch.setattr("routes.manual_bridge.materialize_route_plan", _fail_materializer)
        monkeypatch.setattr("agents.executor.run_executor", lambda **kw: pytest.fail("executor should not run"))

        try:
            result = run_manual_route(
                route_dir=route_dir,
                route_id=route.canonical_id,
                confirmed=confirmed,
                target=target,
                settings=settings,
                workspace_dir=Path(tempfile.mkdtemp()),
                cli_method="POST",
                cli_location="form",
            )
            assert not result.success
            assert result.error_code == ManualRouteErrorCode.MATERIALIZATION_FAILED
            assert result.failure_record == {
                "route_id": route.canonical_id,
                "stage": "materialization",
                "reason": "contract_unavailable",
                "error_code": "PLAN_CONTRACT_INVALID",
                "diagnostics": ["contract unavailable for this route"],
            }
        finally:
            import shutil
            shutil.rmtree(route_dir, ignore_errors=True)


    def test_candidate_loop_continues_after_materialization_failure(self, monkeypatch):
        """A materialization-only failure is recorded, then the next candidate runs."""
        adapter, first_route, first_yaml = _make_candidate_yaml(technique="arithmetic_probe")
        _, second_route, second_yaml = _make_candidate_yaml(adapter=adapter, technique="syntax_probe")
        route_dir = _make_route_dir([
            (f"{first_route.canonical_id.replace(':', '-')}.yaml", first_yaml),
            (f"{second_route.canonical_id.replace(':', '-')}.yaml", second_yaml),
        ])
        confirmed = _make_confirmed_dict(exploitation="POST")
        target = _mock_target()
        settings = _mock_settings()
        original_materializer = materialize_route_plan

        def _fail_first(route, *args, **kwargs):
            if route.canonical_id == first_route.canonical_id:
                return MaterializationResult(
                    success=False,
                    route_id=route.canonical_id,
                    plan_path=None,
                    payload_template_ref=route.payload_template_ref,
                    resolved_endpoint=None,
                    resolved_parameter=None,
                    resolved_method=None,
                    request_location=None,
                    diagnostics=(
                        MaterializationDiagnostic(
                            MaterializationErrorCode.PLAN_CONTRACT_INVALID,
                            "materialization",
                            "contract unavailable for this route",
                        ),
                    ),
                )
            return original_materializer(route, *args, **kwargs)

        monkeypatch.setattr("routes.manual_bridge.materialize_route_plan", _fail_first)
        monkeypatch.setattr("agents.executor.run_executor", lambda **kw: {
            "version": 1,
            "executed": True,
            "step_results": [{
                "step_id": 1,
                "result": {"ok": True, "exit_code": 0, "stdout": "49", "stderr": ""},
            }],
        })
        monkeypatch.setattr("agents.evaluator.run_evaluator", lambda **kw: _MOCK_EVALUATION_SUCCESS)

        try:
            result = run_manual_route_candidates(
                route_dir=route_dir,
                route_ids=(first_route.canonical_id, second_route.canonical_id),
                confirmed=confirmed,
                target=target,
                settings=settings,
                workspace_dir=Path(tempfile.mkdtemp()),
                adapter=adapter,
                cli_method="POST",
                cli_location="form",
            )
            assert result.success
            assert result.selected_result is not None
            assert result.selected_result.route_id == second_route.canonical_id
            assert result.attempted_route_ids == (first_route.canonical_id, second_route.canonical_id)
            assert result.failure_records == (
                {
                    "route_id": first_route.canonical_id,
                    "stage": "materialization",
                    "reason": "contract_unavailable",
                    "error_code": "PLAN_CONTRACT_INVALID",
                    "diagnostics": ["contract unavailable for this route"],
                },
            )
        finally:
            import shutil
            shutil.rmtree(route_dir, ignore_errors=True)

# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?
# 6. Executor
# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?

class TestExecutor:
    def test_calls_executor_once(self, monkeypatch):
        """Executor called exactly once for manual route."""
        adapter, route, yaml_text = _make_candidate_yaml()
        route_dir = _make_route_dir([
            (f"{route.canonical_id.replace(':', '-')}.yaml", yaml_text),
        ])
        confirmed = _make_confirmed_dict(exploitation="POST")
        target = _mock_target()
        settings = _mock_settings()

        exec_count = {"count": 0}

        def _counting_executor(**kw):
            exec_count["count"] += 1
            return _MOCK_EXEC_OUT

        monkeypatch.setattr("agents.executor.run_executor", _counting_executor)
        monkeypatch.setattr(
            "agents.evaluator.run_evaluator",
            lambda **kw: _MOCK_EVALUATION_SUCCESS,
        )

        try:
            result = run_manual_route(
                route_dir=route_dir,
                route_id=route.canonical_id,
                confirmed=confirmed,
                target=target,
                settings=settings,
                workspace_dir=Path(tempfile.mkdtemp()),
                cli_method="POST",
                cli_location="form",
            )
            assert result.success
            assert exec_count["count"] == 1, f"Executor called {exec_count['count']} times, expected 1"
        finally:
            import shutil
            shutil.rmtree(route_dir, ignore_errors=True)

    def test_does_not_retry(self, monkeypatch):
        """Manual route never retries after failure."""
        adapter, route, yaml_text = _make_candidate_yaml()
        route_dir = _make_route_dir([
            (f"{route.canonical_id.replace(':', '-')}.yaml", yaml_text),
        ])
        confirmed = _make_confirmed_dict(exploitation="POST")
        target = _mock_target()
        settings = _mock_settings()

        exec_count = {"count": 0}

        def _failing_executor(**kw):
            exec_count["count"] += 1
            raise RuntimeError("Executor failure")

        monkeypatch.setattr("agents.executor.run_executor", _failing_executor)

        try:
            result = run_manual_route(
                route_dir=route_dir,
                route_id=route.canonical_id,
                confirmed=confirmed,
                target=target,
                settings=settings,
                workspace_dir=Path(tempfile.mkdtemp()),
                cli_method="POST",
                cli_location="form",
            )
            assert not result.success
            assert result.error_code == ManualRouteErrorCode.EXECUTION_FAILED
            assert exec_count["count"] == 1, "Executor must be called exactly once, no retry"
        finally:
            import shutil
            shutil.rmtree(route_dir, ignore_errors=True)

    def test_does_not_fallback_to_planner(self, monkeypatch):
        """Manual route never imports or calls Planner."""
        adapter, route, yaml_text = _make_candidate_yaml()
        route_dir = _make_route_dir([
            (f"{route.canonical_id.replace(':', '-')}.yaml", yaml_text),
        ])
        confirmed = _make_confirmed_dict(exploitation="POST")
        target = _mock_target()
        settings = _mock_settings()

        planner_called = {"hit": False}

        # Patch run_planner to track calls
        monkeypatch.setattr(
            "agents.planner.run_planner",
            lambda **kw: planner_called.update({"hit": True}) or {},
        )
        monkeypatch.setattr(
            "agents.executor.run_executor",
            lambda **kw: _MOCK_EXEC_OUT,
        )
        monkeypatch.setattr(
            "agents.evaluator.run_evaluator",
            lambda **kw: _MOCK_EVALUATION_SUCCESS,
        )

        try:
            result = run_manual_route(
                route_dir=route_dir,
                route_id=route.canonical_id,
                confirmed=confirmed,
                target=target,
                settings=settings,
                workspace_dir=Path(tempfile.mkdtemp()),
                cli_method="POST",
                cli_location="form",
            )
            assert result.success
            assert not planner_called["hit"], "Planner must never be called in manual route mode"
        finally:
            import shutil
            shutil.rmtree(route_dir, ignore_errors=True)


# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?
# 7. Evaluator and Signals
# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?

class TestEvaluatorSignals:
    def test_passes_execution_result_to_evaluator(self, monkeypatch):
        """Execution result is forwarded to evaluator."""
        adapter, route, yaml_text = _make_candidate_yaml()
        route_dir = _make_route_dir([
            (f"{route.canonical_id.replace(':', '-')}.yaml", yaml_text),
        ])
        confirmed = _make_confirmed_dict(exploitation="POST")
        target = _mock_target()
        settings = _mock_settings()

        captured_exec = {}

        def _capture_evaluator(exec_out=None, **kw):
            captured_exec["data"] = exec_out
            return _MOCK_EVALUATION_SUCCESS

        monkeypatch.setattr("agents.executor.run_executor", lambda **kw: _MOCK_EXEC_OUT)
        monkeypatch.setattr("agents.evaluator.run_evaluator", _capture_evaluator)

        try:
            result = run_manual_route(
                route_dir=route_dir,
                route_id=route.canonical_id,
                confirmed=confirmed,
                target=target,
                settings=settings,
                workspace_dir=Path(tempfile.mkdtemp()),
                cli_method="POST",
                cli_location="form",
            )
            assert result.success
            assert "data" in captured_exec
            assert captured_exec["data"].get("executed") is True
        finally:
            import shutil
            shutil.rmtree(route_dir, ignore_errors=True)

    def test_succeeds_when_expected_signal_observed(self, monkeypatch):
        """Success when evaluator detects expected signals."""
        adapter, route, yaml_text = _make_candidate_yaml()
        route_dir = _make_route_dir([
            (f"{route.canonical_id.replace(':', '-')}.yaml", yaml_text),
        ])
        confirmed = _make_confirmed_dict(exploitation="POST")
        target = _mock_target()
        settings = _mock_settings()

        monkeypatch.setattr("agents.executor.run_executor", lambda **kw: _MOCK_EXEC_OUT)
        monkeypatch.setattr("agents.evaluator.run_evaluator", lambda **kw: _MOCK_EVALUATION_SUCCESS)

        try:
            result = run_manual_route(
                route_dir=route_dir,
                route_id=route.canonical_id,
                confirmed=confirmed,
                target=target,
                settings=settings,
                workspace_dir=Path(tempfile.mkdtemp()),
                cli_method="POST",
                cli_location="form",
            )
            assert result.success
            assert result.evaluation is not None
            assert result.evaluation.get("repro_success") is True
        finally:
            import shutil
            shutil.rmtree(route_dir, ignore_errors=True)

    def test_rejects_http_200_without_expected_signal(self, monkeypatch):
        """HTTP 200 without expected signal 鈫?EXPECTED_SIGNAL_NOT_OBSERVED."""
        adapter, route, yaml_text = _make_candidate_yaml()
        route_dir = _make_route_dir([
            (f"{route.canonical_id.replace(':', '-')}.yaml", yaml_text),
        ])
        confirmed = _make_confirmed_dict(exploitation="POST")
        target = _mock_target()
        settings = _mock_settings()

        monkeypatch.setattr("agents.executor.run_executor", lambda **kw: _MOCK_EXEC_OUT)
        monkeypatch.setattr("agents.evaluator.run_evaluator", lambda **kw: _MOCK_EVALUATION_NO_SIGNAL)

        try:
            result = run_manual_route(
                route_dir=route_dir,
                route_id=route.canonical_id,
                confirmed=confirmed,
                target=target,
                settings=settings,
                workspace_dir=Path(tempfile.mkdtemp()),
                cli_method="POST",
                cli_location="form",
            )
            assert not result.success
            assert result.error_code == ManualRouteErrorCode.EXPECTED_SIGNAL_NOT_OBSERVED
        finally:
            import shutil
            shutil.rmtree(route_dir, ignore_errors=True)

    def test_does_not_fabricate_observed_signals(self, monkeypatch):
        """Evaluator returning empty primitives doesn't get fabricated into success."""
        adapter, route, yaml_text = _make_candidate_yaml()
        route_dir = _make_route_dir([
            (f"{route.canonical_id.replace(':', '-')}.yaml", yaml_text),
        ])
        confirmed = _make_confirmed_dict(exploitation="POST")
        target = _mock_target()
        settings = _mock_settings()

        empty_eval = {
            "repro_success": False,
            "confidence": 0.0,
            "detected_primitives": [],
            "current_exploit_state": "init",
        }

        monkeypatch.setattr("agents.executor.run_executor", lambda **kw: _MOCK_EXEC_OUT)
        monkeypatch.setattr("agents.evaluator.run_evaluator", lambda **kw: empty_eval)

        try:
            result = run_manual_route(
                route_dir=route_dir,
                route_id=route.canonical_id,
                confirmed=confirmed,
                target=target,
                settings=settings,
                workspace_dir=Path(tempfile.mkdtemp()),
                cli_method="POST",
                cli_location="form",
            )
            assert not result.success
            assert result.error_code == ManualRouteErrorCode.EXPECTED_SIGNAL_NOT_OBSERVED
        finally:
            import shutil
            shutil.rmtree(route_dir, ignore_errors=True)


# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?
# 8. Side Effects
# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?

class TestSideEffects:
    def test_offline_tests_send_no_http(self, monkeypatch):
        """No HTTP calls during manual bridge operation."""
        import socket as _socket

        http_calls = {"count": 0}

        def _fail_connect(self, *a, **kw):
            http_calls["count"] += 1
            raise AssertionError("socket.connect called")

        monkeypatch.setattr(_socket.socket, "connect", _fail_connect)

        adapter, route, yaml_text = _make_candidate_yaml()
        route_dir = _make_route_dir([
            (f"{route.canonical_id.replace(':', '-')}.yaml", yaml_text),
        ])
        confirmed = _make_confirmed_dict(exploitation="POST")
        target = _mock_target()
        settings = _mock_settings()

        monkeypatch.setattr("agents.executor.run_executor", lambda **kw: _MOCK_EXEC_OUT)
        monkeypatch.setattr("agents.evaluator.run_evaluator", lambda **kw: _MOCK_EVALUATION_SUCCESS)

        try:
            result = run_manual_route(
                route_dir=route_dir,
                route_id=route.canonical_id,
                confirmed=confirmed,
                target=target,
                settings=settings,
                workspace_dir=Path(tempfile.mkdtemp()),
                cli_method="POST",
                cli_location="form",
            )
            assert result.success
            assert http_calls["count"] == 0, f"HTTP/network calls detected: {http_calls['count']}"
        finally:
            import shutil
            shutil.rmtree(route_dir, ignore_errors=True)

    def test_offline_tests_do_not_load_llm(self):
        """Subprocess import check: no LLM libraries loaded by manual_bridge."""
        script = f"""
import sys
sys.path.insert(0, {str(B_DIR)!r})
before = set(sys.modules)
from routes.manual_bridge import run_manual_route, ManualRouteErrorCode
after = set(sys.modules)
new = after - before
forbidden = {{'openai', 'anthropic', 'langchain', 'litellm'}}
found = forbidden & {{m.split('.')[0] for m in new}}
if found:
    print(f"FORBIDDEN: {{sorted(found)}}")
else:
    print("OK: no forbidden modules")
"""
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=60,
        )
        assert proc.returncode == 0, f"Subprocess failed:\n{proc.stderr}"
        assert "Traceback" not in proc.stderr, f"Traceback:\n{proc.stderr}"
        assert "FORBIDDEN:" not in proc.stdout, f"Forbidden LLM imports:\n{proc.stdout}"

    def test_non_manual_path_unchanged(self):
        """Non-manual CLI path doesn't import manual bridge."""
        script = f"""
import sys
sys.path.insert(0, {str(B_DIR)!r})
before = set(sys.modules)
from cli import cmd_exploit, _build_parser
after = set(sys.modules)
new = after - before
# manual_bridge should not be loaded just by importing cli
manual_loaded = {{m for m in new if 'manual_bridge' in m}}
if manual_loaded:
    print(f"MANUAL_BRIDGE_LOADED: {{sorted(manual_loaded)}}")
else:
    print("OK: manual_bridge not loaded")
"""
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=60,
        )
        assert proc.returncode == 0, f"Subprocess failed:\n{proc.stderr}"
        assert "MANUAL_BRIDGE_LOADED:" not in proc.stdout, (
            f"manual_bridge should not be loaded on normal CLI import:\n{proc.stdout}"
        )


class TestRuntimeFactExtractorTypeSafety:
    @pytest.mark.parametrize(
        "extractor",
        [
            _extract_endpoint_from_confirmed,
            _extract_parameter_from_confirmed,
            _extract_method_from_confirmed,
            _extract_location_from_confirmed,
        ],
    )
    @pytest.mark.parametrize(
        "value",
        [
            "unstructured text",
            {"source": {"code": None}},
            [{"source": {"code": None}}],
            ({"evidence": [{"description": None}]},),
            None,
            7,
            True,
            {
                "source": [
                    None,
                    3.14,
                    False,
                    {"code": (None, {"description": "unstructured text"})},
                ],
            },
        ],
        ids=[
            "str", "dict", "list-dict", "tuple",
            "none", "int", "bool", "mixed-nested",
        ],
    )
    def test_all_extractors_are_safe_for_confirmed_node_types(
        self,
        extractor,
        value,
    ):
        try:
            extractor(value)
        except (TypeError, AttributeError) as exc:
            pytest.fail(f"{extractor.__name__} used a non-string as text: {exc}")

    def test_shared_collector_is_cycle_safe_ordered_and_field_limited(self):
        cyclic = {}
        cyclic["source"] = cyclic
        value = {
            "source": [
                {"code": "first"},
                cyclic,
                {"code_snippet": "second"},
            ],
            "ignored": {"code": "must-not-be-read"},
        }

        assert _collect_text_nodes(value) == ("first", "second")
        for extractor in (
            _extract_endpoint_from_confirmed,
            _extract_parameter_from_confirmed,
            _extract_method_from_confirmed,
            _extract_location_from_confirmed,
        ):
            try:
                extractor(value)
            except (TypeError, AttributeError) as exc:
                pytest.fail(f"{extractor.__name__} failed on a cycle: {exc}")

    @pytest.mark.parametrize(
        "confirmed",
        [
            {
                "source": (
                    '@GetMapping("/") String index('
                    '@RequestParam(name = "text") String value) // query'
                ),
            },
            {
                "source": {
                    "code": (
                        '@GetMapping("/") String index('
                        '@RequestParam(name = "text") String value) // query'
                    ),
                },
            },
            {
                "source": {
                    "code_snippet": (
                        '@GetMapping("/") String index('
                        '@RequestParam(name = "text") String value) // query'
                    ),
                },
            },
            {
                "flow": [{
                    "code": (
                        '@GetMapping("/") String index('
                        '@RequestParam(name = "text") String value) // query'
                    ),
                }],
            },
            {
                "evidence": [{
                    "description": (
                        '@GetMapping("/") with HTTP parameter "text" in query'
                    ),
                }],
            },
            {"exploit_example": "GET /?text=value HTTP/1.1"},
            {
                "request_facts": {
                    "endpoint": "/",
                    "parameter": "text",
                    "method": "GET",
                    "request_location": "query",
                },
            },
        ],
        ids=[
            "source-string", "source-code", "source-code-snippet",
            "flow-code", "evidence-description", "exploit-example",
            "request-facts",
        ],
    )
    def test_allowed_contract_shapes_feed_all_extractors(self, confirmed):
        assert _extract_endpoint_from_confirmed(confirmed) == "/"
        assert _extract_parameter_from_confirmed(confirmed) == "text"
        assert _extract_method_from_confirmed(confirmed, preferred="GET") == "GET"
        assert _extract_location_from_confirmed(
            confirmed,
            preferred="query",
        ) == "query"

    def test_multiple_consistent_sources_are_accepted(self):
        confirmed = {
            "vulnerabilities": [{
                "request_facts": {
                    "endpoint": "/",
                    "parameter": "text",
                    "method": "GET",
                    "request_location": "query",
                },
                "source": {
                    "code": (
                        '@GetMapping("/") String index('
                        '@RequestParam(name = "text") String value) // query'
                    ),
                },
                "exploit_example": "GET /?text=value HTTP/1.1",
            }],
        }

        assert _extract_endpoint_from_confirmed(confirmed) == "/"
        assert _extract_parameter_from_confirmed(confirmed) == "text"
        assert _extract_method_from_confirmed(confirmed) == "GET"
        assert _extract_location_from_confirmed(
            confirmed,
            preferred="query",
        ) == "query"

    def test_plural_allowed_sets_are_retained_for_cli_selection(self):
        confirmed = {
            "vulnerabilities": [{
                "request_facts": {
                    "methods": ["GET", "POST"],
                    "locations": ["query", "form"],
                },
                "source": {
                    "code": '@RequestParam(name = "text") String value',
                    "description": "HTTP GET or POST request",
                },
                "exploit_example": "GET /?text=value HTTP/1.1",
            }],
        }

        assert _extract_method_from_confirmed(confirmed) is None
        assert _extract_method_from_confirmed(
            confirmed,
            preferred="POST",
        ) == "POST"
        assert _extract_location_from_confirmed(confirmed) is None
        assert _extract_location_from_confirmed(
            confirmed,
            preferred="form",
        ) == "form"

    @pytest.mark.parametrize(
        ("extractor", "confirmed"),
        [
            (
                _extract_method_from_confirmed,
                {
                    "request_facts": {"method": "GET"},
                    "request_example": "POST / HTTP/1.1",
                },
            ),
            (
                _extract_location_from_confirmed,
                {
                    "request_facts": {"request_location": "query"},
                    "request_example": (
                        "POST / HTTP/1.1\r\n"
                        "Content-Type: application/json\r\n\r\n"
                        '{"text": "value"}'
                    ),
                },
            ),
        ],
        ids=["method", "location"],
    )
    def test_explicit_conflicts_fail_closed(self, extractor, confirmed):
        with pytest.raises(Exception) as exc_info:
            extractor(confirmed)

        assert exc_info.value.code == ManualRouteErrorCode.RUNTIME_FACT_CONFLICT

    def test_missing_fields_return_none_without_cwe_inference(self):
        confirmed = {
            "vulnerabilities": [{
                "cwe": "CWE-1336",
                "cwe_id": "CWE-917",
                "source": {"file": "Main.java", "line": 21},
            }],
        }

        assert _extract_endpoint_from_confirmed(confirmed) is None
        assert _extract_parameter_from_confirmed(confirmed) is None
        assert _extract_method_from_confirmed(confirmed) is None
        assert _extract_location_from_confirmed(confirmed) is None

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("GET /?text=value HTTP/1.1", "query"),
            (
                "POST / HTTP/1.1\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
                "text=value",
                "form",
            ),
            (
                "POST / HTTP/1.1\r\n"
                "Content-Type: application/json\r\n\r\n"
                '{"text": "value"}',
                "json",
            ),
            ("POST / HTTP/1.1\r\n\r\n" + '{"text": "value"}', "json"),
            ("@RequestBody String body", None),
            ("POST / HTTP/1.1", None),
        ],
        ids=[
            "get-query", "post-form", "json-content-type",
            "json-body", "framework-insufficient", "post-alone",
        ],
    )
    def test_location_requires_physical_request_evidence(self, text, expected):
        assert _extract_location_from_confirmed(text) == expected

    @pytest.mark.parametrize(
        ("annotation", "expected"),
        [
            ('@GetMapping("/")', "GET"),
            ('@PostMapping("/")', "POST"),
            ('@PutMapping("/")', "PUT"),
            ('@DeleteMapping("/")', "DELETE"),
            ('@PatchMapping("/")', "PATCH"),
            (
                '@RequestMapping(method = RequestMethod.PUT, path = "/items")',
                "PUT",
            ),
        ],
    )
    def test_method_from_framework_annotations(self, annotation, expected):
        assert _extract_method_from_confirmed(annotation) == expected

    def test_request_mapping_path_after_method_is_supported(self):
        annotation = '@RequestMapping(method = RequestMethod.PUT, path = "/items")'
        assert _extract_endpoint_from_confirmed(annotation) == "/items"

    def test_static_string_safety_guards_cover_all_extractors(self):
        source = (B_DIR / "routes" / "manual_bridge.py").read_text(encoding="utf-8")
        runtime_block = source[
            source.index("def _collect_text_nodes"):
            source.index("def _resolve_runtime_facts")
        ]

        assert "source.lower()" not in runtime_block
        assert "re.finditer(" not in runtime_block
        assert "str(" not in runtime_block
        assert "def _iter_strings" not in source
        assert "def _iter_parameter_values" not in source
        assert "def _iter_parameter_texts" not in source
        for extractor in (
            _extract_endpoint_from_confirmed,
            _extract_parameter_from_confirmed,
            _extract_method_from_confirmed,
            _extract_location_from_confirmed,
        ):
            assert "_collect_text_nodes" in inspect.getsource(extractor)

# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?
# 9. Smoke Tests
# 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?

class TestRuntimeFactWiringIntegration:
    def test_cli_runtime_facts_reach_frontier_and_materializer_unchanged(
        self,
        monkeypatch,
        tmp_path,
    ):
        import cli
        import routes.manual_bridge as bridge

        adapter, route, yaml_text = _make_candidate_yaml(
            required_runtime_facts=('endpoint', 'parameter', 'method'),
        )
        route_dir = _make_route_dir([
            (route.canonical_id.replace(':', '-') + '.yaml', yaml_text),
        ])
        confirmed_path = tmp_path / 'confirmed.json'
        confirmed_path.write_text(
            json.dumps(_make_confirmed_dict()),
            encoding='utf-8',
        )
        settings = _mock_settings()
        target = _mock_target()
        captured = {}
        runner_calls = {'count': 0}
        printed = []

        real_context_builder = bridge.build_frontier_context
        real_frontier_builder = bridge.build_frontier
        real_materializer = bridge.materialize_route_plan

        def capture_context(*args, **kwargs):
            captured['frontier_runtime_facts'] = kwargs['runtime_facts_source']
            context = real_context_builder(*args, **kwargs)
            captured['frontier_context'] = context
            return context

        def capture_frontier(*args, **kwargs):
            frontier = real_frontier_builder(*args, **kwargs)
            captured['frontier'] = frontier
            return frontier

        def capture_materializer(*args, **kwargs):
            captured['materializer_runtime_facts'] = kwargs['runtime_facts']
            return real_materializer(*args, **kwargs)

        def mocked_final_runner(**kwargs):
            runner_calls['count'] += 1
            return _MOCK_EXEC_OUT

        monkeypatch.setenv('CO_REDTEAM_MAX_ITER', '1')
        monkeypatch.setenv('CO_REDTEAM_MAX_ITER_CAP', '1')
        monkeypatch.setenv('CO_REDTEAM_MAX_RUNS', '1')
        monkeypatch.setattr('core.settings.get_settings', lambda: settings)
        monkeypatch.setattr(bridge, 'build_frontier_context', capture_context)
        monkeypatch.setattr(bridge, 'build_frontier', capture_frontier)
        monkeypatch.setattr(bridge, 'materialize_route_plan', capture_materializer)
        monkeypatch.setattr('agents.executor.run_executor', mocked_final_runner)
        monkeypatch.setattr(
            'agents.evaluator.run_evaluator',
            lambda **kwargs: _MOCK_EVALUATION_SUCCESS,
        )
        monkeypatch.setattr(cli.console, 'print', lambda *args, **kwargs: printed.extend(args))

        import socket as _socket
        monkeypatch.setattr(
            _socket.socket,
            'connect',
            lambda *args, **kwargs: pytest.fail('network access is forbidden'),
        )

        args = SimpleNamespace(
            route_dir=str(route_dir),
            route_id=route.canonical_id,
            route_method='GET',
            route_location='query',
        )

        try:
            exit_code = cli._cmd_exploit_manual_route(target, confirmed_path, args)
        finally:
            import shutil
            shutil.rmtree(route_dir, ignore_errors=True)

        expected = {
            'endpoint': '/',
            'parameter': 'text',
            'method': 'GET',
            'request_location': 'query',
        }
        frontier_facts = captured['frontier_runtime_facts']
        assert {key: frontier_facts[key] for key in expected} == expected
        assert captured['materializer_runtime_facts'] is frontier_facts
        assert tuple(
            sorted(set(route.requires.runtime_facts) - set(captured['frontier_context'].runtime_facts))
        ) == ()
        assert [entry.route_id for entry in captured['frontier'].eligible_routes] == [
            route.canonical_id,
        ]
        assert runner_calls['count'] == 1
        assert exit_code == 0

        banner = next(item for item in printed if hasattr(item, 'renderable'))
        banner_text = banner.renderable.plain
        assert 'Method   GET' in banner_text
        assert 'Location query' in banner_text
        assert frontier_facts['method'] in banner_text
        assert frontier_facts['request_location'] in banner_text

    def test_method_missing_reports_specific_fact_before_frontier(self):
        adapter, route, yaml_text = _make_candidate_yaml(
            required_runtime_facts=('endpoint', 'parameter', 'method'),
        )
        route_dir = _make_route_dir([
            (route.canonical_id.replace(':', '-') + '.yaml', yaml_text),
        ])

        try:
            result = run_manual_route(
                route_dir=route_dir,
                route_id=route.canonical_id,
                confirmed=_make_confirmed_dict(),
                target=_mock_target(),
                settings=_mock_settings(),
                workspace_dir=Path(tempfile.mkdtemp()),
                cli_method=None,
                cli_location='query',
            )
        finally:
            import shutil
            shutil.rmtree(route_dir, ignore_errors=True)

        assert result.error_code == ManualRouteErrorCode.RUNTIME_FACT_MISSING
        assert result.diagnostics == ('[RUNTIME_FACT_MISSING] method',)

    def test_cli_method_conflicting_with_unique_confirmed_method_is_rejected(self):
        adapter, route, yaml_text = _make_candidate_yaml(
            required_runtime_facts=('endpoint', 'parameter', 'method'),
        )
        route_dir = _make_route_dir([
            (route.canonical_id.replace(':', '-') + '.yaml', yaml_text),
        ])

        try:
            result = run_manual_route(
                route_dir=route_dir,
                route_id=route.canonical_id,
                confirmed=_make_confirmed_dict(
                    source_hint='HTTP parameter `text`',
                    exploitation='Only POST is confirmed',
                ),
                target=_mock_target(),
                settings=_mock_settings(),
                workspace_dir=Path(tempfile.mkdtemp()),
                cli_method='GET',
                cli_location='query',
            )
        finally:
            import shutil
            shutil.rmtree(route_dir, ignore_errors=True)

        assert result.error_code == ManualRouteErrorCode.RUNTIME_FACT_CONFLICT
        assert 'method: CLI says GET, confirmed says POST' in result.diagnostics[0]

    def test_cli_location_conflicting_with_unique_confirmed_location_is_rejected(self):
        with pytest.raises(Exception) as exc_info:
            _resolve_runtime_facts(
                target_url='http://127.0.0.1:1337',
                confirmed=_make_confirmed_dict(
                    source_hint='POST form parameter `text`',
                    exploitation='Only POST is confirmed',
                ),
                cli_method='POST',
                cli_location='query',
            )

        assert exc_info.value.code == ManualRouteErrorCode.RUNTIME_FACT_CONFLICT
        assert 'request_location: CLI says query, confirmed says form' in str(exc_info.value)


class TestRealProductionEntryIntegration:
    def test_real_confirmed_and_route_yaml_reach_mocked_executor_once(
        self,
        monkeypatch,
        tmp_path,
    ):
        import cli
        import requests
        import socket
        import routes.manual_bridge as bridge
        from agents.validator import run_validator

        route_id = "cwe-94:init:ssti-reflection:arithmetic-probe"
        route_dir = B_DIR / "data" / "manual_routes" / "challenge1"
        confirmed_path = B_DIR / "data" / "confirmed_vuln.json"
        settings = _mock_settings()
        object.__setattr__(settings, "workspace_dir", tmp_path / "workspace")
        target = _mock_target()

        executor_calls = {"count": 0}
        planner_calls = {"count": 0}
        http_calls = {"count": 0}
        observed_calls = {}
        observed_returns = {}

        def mocked_executor(**kwargs):
            executor_calls["count"] += 1
            exec_out = json.loads(json.dumps(_MOCK_EXEC_OUT))
            exec_out["step_results"][0]["result"]["stdout"] += (
                "\nflag{offline_manual_route_integration}"
            )
            return exec_out
        def forbidden_planner(**kwargs):
            planner_calls["count"] += 1
            pytest.fail("Planner must not run in manual route mode")

        def forbidden_http(*args, **kwargs):
            http_calls["count"] += 1
            pytest.fail("real HTTP is forbidden in this integration test")

        watched = {
            bridge._resolve_runtime_facts.__code__: "resolver",
            bridge._extract_endpoint_from_confirmed.__code__: "endpoint",
            bridge._extract_parameter_from_confirmed.__code__: "parameter",
            bridge._extract_method_from_confirmed.__code__: "method",
            bridge._extract_location_from_confirmed.__code__: "location",
            bridge.build_frontier_context.__code__: "frontier_context",
            bridge.build_frontier.__code__: "frontier",
            bridge.materialize_route_plan.__code__: "materializer",
            run_validator.__code__: "validator",
            bridge.run_manual_route.__code__: "manual_result",
        }

        def profile(frame, event, arg):
            name = watched.get(frame.f_code)
            if name is None:
                return
            if event == "call":
                observed_calls[name] = observed_calls.get(name, 0) + 1
            elif event == "return":
                observed_returns.setdefault(name, []).append(arg)

        monkeypatch.setenv("CO_REDTEAM_MAX_ITER", "1")
        monkeypatch.setenv("CO_REDTEAM_MAX_ITER_CAP", "1")
        monkeypatch.setenv("CO_REDTEAM_MAX_RUNS", "1")
        monkeypatch.setattr("core.settings.get_settings", lambda: settings)
        monkeypatch.setattr("agents.executor.run_executor", mocked_executor)
        monkeypatch.setattr("agents.planner.run_planner", forbidden_planner)
        monkeypatch.setattr(requests.sessions.Session, "request", forbidden_http)
        monkeypatch.setattr(socket.socket, "connect", forbidden_http)
        monkeypatch.setattr(cli.console, "print", lambda *args, **kwargs: None)

        args = SimpleNamespace(
            route_dir=str(route_dir),
            route_id=route_id,
            route_method="GET",
            route_location="query",
        )

        previous_profile = sys.getprofile()
        sys.setprofile(profile)
        try:
            exit_code = cli._cmd_exploit_manual_route(target, confirmed_path, args)
        finally:
            sys.setprofile(previous_profile)

        assert exit_code == 0
        assert {
            name: observed_calls.get(name, 0)
            for name in ("resolver", "endpoint", "parameter", "method", "location")
        } == {
            "resolver": 1,
            "endpoint": 1,
            "parameter": 1,
            "method": 1,
            "location": 1,
        }

        runtime_facts = observed_returns["resolver"][-1]
        assert {
            key: runtime_facts[key]
            for key in ("endpoint", "parameter", "method", "request_location")
        } == {
            "endpoint": "/",
            "parameter": "text",
            "method": "GET",
            "request_location": "query",
        }

        frontier_context = observed_returns["frontier_context"][-1]
        missing_runtime_facts = tuple(
            sorted(
                {"endpoint", "parameter", "method"}
                - set(frontier_context.runtime_facts)
            )
        )
        assert missing_runtime_facts == ()

        frontier = observed_returns["frontier"][-1]
        eligible_entry = next(
            entry
            for entry in frontier.eligible_routes
            if entry.route_id == route_id
        )
        assert eligible_entry.status == "eligible"
        assert all(
            entry.route_id != route_id
            for entry in frontier.blocked_routes
        )

        materializer = observed_returns["materializer"][-1]
        assert materializer.success is True
        validator = observed_returns["validator"][-1]
        assert validator["validation"]["passed"] is True
        manual_result = observed_returns["manual_result"][-1]
        assert manual_result.success is True

        retry_calls = max(0, executor_calls["count"] - 1)
        assert executor_calls["count"] == 1
        assert http_calls["count"] == 0
        assert planner_calls["count"] == 0
        assert retry_calls == 0

class TestManualBridgeSmoke:
    def test_success_smoke_real_pipeline_mock_executor(self, monkeypatch):
        """Full offline pipeline with mocked executor/evaluator 鈫?success."""
        adapter, route, yaml_text = _make_candidate_yaml()
        route_dir = _make_route_dir([
            (f"{route.canonical_id.replace(':', '-')}.yaml", yaml_text),
        ])
        confirmed = _make_confirmed_dict(exploitation="POST")
        target = _mock_target()
        settings = _mock_settings()

        executor_calls = {"count": 0}
        evaluator_calls = {"count": 0}

        def _track_exec(**kw):
            executor_calls["count"] += 1
            return _MOCK_EXEC_OUT

        def _track_eval(**kw):
            evaluator_calls["count"] += 1
            return _MOCK_EVALUATION_SUCCESS

        monkeypatch.setattr("agents.executor.run_executor", _track_exec)
        monkeypatch.setattr("agents.evaluator.run_evaluator", _track_eval)

        import socket as _socket
        http_calls = {"count": 0}
        monkeypatch.setattr(_socket.socket, "connect", lambda self, *a, **kw: http_calls.__setitem__("count", http_calls["count"] + 1))

        try:
            result = run_manual_route(
                route_dir=route_dir,
                route_id=route.canonical_id,
                confirmed=confirmed,
                target=target,
                settings=settings,
                workspace_dir=Path(tempfile.mkdtemp()),
                cli_method="POST",
                cli_location="form",
            )

            # 鈹€鈹€ Assertions 鈹€鈹€
            assert result.success, f"Smoke failed: {result.error_code} 鈥?{result.diagnostics}"
            assert result.plan is not None
            assert len(result.plan["steps"]) == 1, f"plan steps={len(result.plan['steps'])}, expected 1"
            assert executor_calls["count"] == 1, f"executor calls={executor_calls['count']}, expected 1"
            assert evaluator_calls["count"] == 1, f"evaluator calls={evaluator_calls['count']}, expected 1"
            assert http_calls["count"] == 0, f"HTTP calls={http_calls['count']}, expected 0"
            assert result.evaluation is not None
            assert result.evaluation.get("repro_success") is True
            assert "ssti_reflection" in result.evaluation.get("detected_primitives", [])
        finally:
            import shutil
            shutil.rmtree(route_dir, ignore_errors=True)

    def test_failure_smoke_http200_no_signal(self, monkeypatch):
        """HTTP 200 response but no expected signal 鈫?EXPECTED_SIGNAL_NOT_OBSERVED."""
        adapter, route, yaml_text = _make_candidate_yaml()
        route_dir = _make_route_dir([
            (f"{route.canonical_id.replace(':', '-')}.yaml", yaml_text),
        ])
        confirmed = _make_confirmed_dict(exploitation="POST")
        target = _mock_target()
        settings = _mock_settings()

        http200_exec = {
            "version": 1,
            "executed": True,
            "step_results": [{
                "step_id": 1,
                "result": {
                    "ok": True,
                    "exit_code": 0,
                    "stdout": "HTTP 200: OK\n<html>Normal page</html>",
                    "stderr": "",
                },
            }],
        }

        monkeypatch.setattr("agents.executor.run_executor", lambda **kw: http200_exec)
        monkeypatch.setattr("agents.evaluator.run_evaluator", lambda **kw: _MOCK_EVALUATION_NO_SIGNAL)

        try:
            result = run_manual_route(
                route_dir=route_dir,
                route_id=route.canonical_id,
                confirmed=confirmed,
                target=target,
                settings=settings,
                workspace_dir=Path(tempfile.mkdtemp()),
                cli_method="POST",
                cli_location="form",
            )
            assert not result.success, "Should fail 鈥?HTTP 200 without signal is not success"
            assert result.error_code == ManualRouteErrorCode.EXPECTED_SIGNAL_NOT_OBSERVED, (
                f"Expected EXPECTED_SIGNAL_NOT_OBSERVED, got {result.error_code}"
            )
        finally:
            import shutil
            shutil.rmtree(route_dir, ignore_errors=True)
