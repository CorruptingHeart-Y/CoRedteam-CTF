from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from agents import executor
from core.target_context import TargetContext


@pytest.mark.parametrize(
    ("policy_url", "expected"),
    [
        ("http://127.0.0.1:1337", "http://host.docker.internal:1337"),
        ("http://localhost:1337", "http://host.docker.internal:1337"),
        ("http://[::1]:1337", "http://host.docker.internal:1337"),
    ],
)
def test_docker_loopback_policy_url_maps_to_host_gateway(policy_url, expected):
    context = executor._build_execution_target_context(policy_url)

    assert context.policy_base_url == policy_url
    assert context.execution_base_url == expected
    assert context.execution_host == "host.docker.internal"
    assert context.execution_port == 1337
    assert context.network_mode == "docker-host-gateway"


def test_docker_non_loopback_policy_url_is_not_rewritten():
    context = executor._build_execution_target_context("http://192.0.2.10:8080")

    assert context.policy_base_url == "http://192.0.2.10:8080"
    assert context.execution_base_url == "http://192.0.2.10:8080"
    assert context.execution_host == "192.0.2.10"
    assert context.execution_port == 8080
    assert context.network_mode == "docker-direct"


def test_context_json_preserves_policy_and_execution_urls(tmp_path):
    context = executor._build_execution_target_context("http://127.0.0.1:1337")
    workspace = executor._prepare_exec_workspace(
        tmp_path,
        target_context=context.to_context_dict(),
    )

    stored = json.loads((workspace / "context.json").read_text(encoding="utf-8"))
    target_context = stored["target_context"]
    assert target_context == {
        "base_url": "http://127.0.0.1:1337",
        "host": "127.0.0.1",
        "port": 1337,
        "scheme": "http",
        "policy_base_url": "http://127.0.0.1:1337",
        "execution_base_url": "http://host.docker.internal:1337",
        "execution_host": "host.docker.internal",
        "execution_port": 1337,
        "network_mode": "docker-host-gateway",
        "runtime_targets": [{
            "logical": {"protocol": "http", "port": 1337},
            "runtime": {"host": "host.docker.internal", "port": 1337},
        }],
    }


@pytest.mark.parametrize(
    "primitive_context",
    [
        {"transport": "grpc", "port": 50045},
        {"transport_requirements": {"protocol": "grpc", "port": 50045}},
    ],
)
def test_runtime_context_resolves_multiple_service_ports(primitive_context):
    services = executor._logical_services_from_plan({
        "primitive_context": primitive_context,
    })
    assert services == [{"protocol": "grpc", "port": 50045}]

    context = executor._build_execution_target_context(
        "http://127.0.0.1:1337",
        services,
    )

    assert context.policy_base_url == "http://127.0.0.1:1337"
    assert context.execution_host == "host.docker.internal"
    assert context.execution_port == 1337
    assert [target.to_context_dict() for target in context.runtime_targets] == [
        {
            "logical": {"protocol": "http", "port": 1337},
            "runtime": {"host": "host.docker.internal", "port": 1337},
        },
        {
            "logical": {"protocol": "grpc", "port": 50045},
            "runtime": {"host": "host.docker.internal", "port": 50045},
        },
    ]


def test_ast_inflater_prefers_execution_base_url_with_legacy_fallback():
    code = executor._inflate_ast_to_script({
        "id": 1,
        "type": "python",
        "sdk_calls": [{"primitive": "HttpClient.get", "target": "/"}],
    })

    assert "get('execution_base_url') or" in code
    assert "get('base_url', '')" in code
    assert "s = HttpClient(target_base)" in code


class _CaptureScriptSandbox:
    def __init__(self):
        self.calls = []

    def run_python_script(self, **kwargs):
        self.calls.append(kwargs)
        return {
            "ok": True,
            "exit_code": 0,
            "stdout": "STEP_OK\n",
            "stderr": "",
            "execution_mode": "docker",
        }


# ── Execution priority tests ──────────────────────────────────

def test_priority_A_code_wins_over_sdk_calls(tmp_path):
    """Case A: step has both code + sdk_calls → code must execute, inflater must NOT run."""
    sandbox = _CaptureScriptSandbox()
    result, _ = executor._run_docker(
        {
            "id": 101,
            "type": "python",
            "sdk_calls": [{"primitive": "HttpClient.get", "target": "/health"}],
            "code": "print('CODE_EXECUTED')",
        },
        sandbox,
        tmp_path,
    )

    generated = (tmp_path / "step_101.py").read_text(encoding="utf-8")
    assert result["ok"] is True
    assert len(sandbox.calls) == 1
    assert "CODE_EXECUTED" in generated
    assert 'resp = s.get("/health")' not in generated  # inflater was NOT used


def test_priority_B_sdk_calls_inflater_when_no_code(tmp_path):
    """Case B: only sdk_calls (no code) → inflater executes normally."""
    sandbox = _CaptureScriptSandbox()
    result, _ = executor._run_docker(
        {
            "id": 106,
            "type": "python",
            "sdk_calls": [{"primitive": "HttpClient.get", "target": "/health"}],
        },
        sandbox,
        tmp_path,
    )

    generated = (tmp_path / "step_106.py").read_text(encoding="utf-8")
    assert result["ok"] is True
    assert len(sandbox.calls) == 1
    assert 'resp = s.get("/health")' in generated


def test_priority_C_code_executes_when_no_sdk_calls(tmp_path):
    """Case C: only code (no sdk_calls) → code executes normally."""
    sandbox = _CaptureScriptSandbox()
    result, _ = executor._run_docker(
        {
            "id": 107,
            "type": "python",
            "code": "print('CODE_ONLY')",
        },
        sandbox,
        tmp_path,
    )

    generated = (tmp_path / "step_107.py").read_text(encoding="utf-8")
    assert result["ok"] is True
    assert len(sandbox.calls) == 1
    assert "CODE_ONLY" in generated


def test_complex_sdk_calls_with_code_fall_back_to_code(tmp_path):
    sandbox = _CaptureScriptSandbox()
    result, _ = executor._run_docker(
        {
            "id": 102,
            "type": "python",
            "sdk_calls": [{
                "primitive": "HttpClient.raw_request",
                "method": "POST",
                "path": "/example.Service/Call",
                "headers": {"Content-Type": "application/grpc"},
                "body": {"frame": "encoded-frame"},
                "body_format": "grpc",
            }],
            "code": "print('CODE_FALLBACK_RAN')",
        },
        sandbox,
        tmp_path,
    )

    generated = (tmp_path / "step_102.py").read_text(encoding="utf-8")
    assert result["ok"] is True
    assert len(sandbox.calls) == 1
    assert "CODE_FALLBACK_RAN" in generated
    assert "s.raw_request" not in generated


def test_complex_sdk_calls_without_code_fail_explicitly(tmp_path):
    sandbox = _CaptureScriptSandbox()
    result, chain_output = executor._run_docker(
        {
            "id": 103,
            "type": "python",
            "sdk_calls": [{
                "primitive": "HttpClient.raw_request",
                "method": "POST",
                "path": "/example.Service/Call",
                "headers": {"Content-Type": "application/grpc"},
                "body": {"frame": "encoded-frame"},
                "body_format": "grpc",
            }],
        },
        sandbox,
        tmp_path,
    )

    assert result["ok"] is False
    assert result["error_code"] == "UNSUPPORTED_SDK_CALLS_NO_CODE"
    assert result["execution_mode"] == "unsupported_sdk_calls"
    assert chain_output == {}
    assert sandbox.calls == []
    assert not (tmp_path / "step_103.py").exists()


def test_grpc_localhost_code_targets_rewrite_to_host_gateway(tmp_path):
    sandbox = _CaptureScriptSandbox()
    context = executor._build_execution_target_context(
        "http://127.0.0.1:1337",
        [{"protocol": "grpc", "port": 50045}],
    )
    result, _ = executor._run_docker(
        {
            "id": 104,
            "type": "python",
            "code": (
                "primary = 'http://127.0.0.1:50045/example.Service/Call'\n"
                "secondary = 'http://localhost:50045/example.Service/Call'\n"
                "print(primary, secondary)"
            ),
        },
        sandbox,
        tmp_path,
        runtime_targets=context.runtime_targets,
    )

    generated = (tmp_path / "step_104.py").read_text(encoding="utf-8")
    assert result["ok"] is True
    assert generated.count("host.docker.internal:50045") == 2
    assert "127.0.0.1:50045" not in generated
    assert "localhost:50045" not in generated


def test_http_localhost_code_targets_are_unchanged(tmp_path):
    sandbox = _CaptureScriptSandbox()
    result, _ = executor._run_docker(
        {
            "id": 105,
            "type": "python",
            "code": (
                "primary = 'http://127.0.0.1:1337/'\n"
                "secondary = 'http://localhost:1337/'\n"
                "print(primary, secondary)"
            ),
        },
        sandbox,
        tmp_path,
    )

    generated = (tmp_path / "step_105.py").read_text(encoding="utf-8")
    assert result["ok"] is True
    assert "127.0.0.1:1337" in generated
    assert "localhost:1337" in generated
    assert "host.docker.internal:1337" not in generated


def test_sdk_http_client_connects_to_execution_host(monkeypatch):
    captured = {}

    def fake_request(self, method, url, *args, **kwargs):
        captured.update(method=method, url=url)
        return SimpleNamespace(text="49", status_code=200)

    monkeypatch.setattr("requests.Session.request", fake_request)
    namespace: dict[str, object] = {}
    exec(executor._SDK_SOURCE, namespace)

    client = namespace["HttpClient"]("http://host.docker.internal:1337")
    response = client.get("/?text=7*7")

    assert response.text == "49"
    assert captured == {
        "method": "GET",
        "url": "http://host.docker.internal:1337/?text=7*7",
    }


class _FakeContainer:
    id = "1234567890abcdef"

    def __init__(self, stdout: str = "STEP_OK\n", exit_code: int = 0):
        self._stdout = stdout
        self._exit_code = exit_code

    def start(self):
        return None

    def wait(self, timeout):
        return {"StatusCode": self._exit_code}

    def logs(self, stdout=False, stderr=False):
        return self._stdout.encode() if stdout else b""

    def remove(self, force=True, v=True):
        return None


class _FakeContainers:
    def __init__(self, container):
        self.container = container
        self.create_kwargs = None

    def create(self, **kwargs):
        self.create_kwargs = kwargs
        return self.container

    def list(self):
        pytest.fail("loopback host-gateway routing must not scan target containers")


def _sandbox_with_fake_client(container):
    sandbox = executor.DockerSandbox("test-image")
    containers = _FakeContainers(container)
    sandbox._client = SimpleNamespace(containers=containers)
    return sandbox, containers


def test_docker_transport_uses_host_gateway_mapping(tmp_path):
    script = tmp_path / "step_1.py"
    script.write_text("print('ok')", encoding="utf-8")
    (tmp_path / "tmp").mkdir()
    sandbox, containers = _sandbox_with_fake_client(_FakeContainer())

    result = sandbox.run_python_script(
        script_name=script.name,
        exec_workspace=tmp_path,
        step_id=1,
        target_url="http://host.docker.internal:1337",
        target=None,
    )

    assert containers.create_kwargs["network_mode"] == "bridge"
    assert containers.create_kwargs["extra_hosts"] == {
        "host.docker.internal": "host-gateway",
    }
    assert result["target_host"] == "host.docker.internal"
    assert result["target_port"] == 1337
    assert result["network_mode"] == "docker-host-gateway"


@pytest.mark.parametrize(
    ("marker", "code"),
    [
        ("EXECUTION_TARGET_RESOLUTION_FAILED", "EXECUTION_TARGET_RESOLUTION_FAILED"),
        ("EXECUTION_NETWORK_CONNECT_FAILED", "EXECUTION_NETWORK_CONNECT_FAILED"),
    ],
)
def test_execution_network_failures_are_structured(marker, code, tmp_path):
    script = tmp_path / "step_1.py"
    script.write_text("print('should not matter')", encoding="utf-8")
    (tmp_path / "tmp").mkdir()
    sandbox, _ = _sandbox_with_fake_client(
        _FakeContainer(f"{marker}: unavailable\n", exit_code=86),
    )

    result = sandbox.run_python_script(
        script_name=script.name,
        exec_workspace=tmp_path,
        step_id=1,
        target_url="http://host.docker.internal:1337",
        target=None,
    )

    assert result["ok"] is False
    assert result["error_code"] == code

def test_generated_docker_wrapper_preflights_before_user_step(tmp_path):
    context = executor._build_execution_target_context("http://127.0.0.1:1337")
    workspace = executor._prepare_exec_workspace(
        tmp_path,
        target_context=context.to_context_dict(),
    )

    class CaptureSandbox:
        def run_python_script(self, **kwargs):
            return {
                "ok": True,
                "exit_code": 0,
                "stdout": "STEP_OK\n",
                "stderr": "",
                "execution_mode": "docker",
            }

    executor._run_docker(
        {
            "id": 1,
            "type": "python",
            "sdk_calls": [{"primitive": "HttpClient.get", "target": "/"}],
        },
        CaptureSandbox(),
        workspace,
        target_url=context.execution_base_url,
        target=None,
    )

    generated = (workspace / "step_1.py").read_text(encoding="utf-8")
    compile(generated, "step_1.py", "exec")
    assert generated.index("getaddrinfo") < generated.index("# ── User script ──")



def test_run_executor_keeps_target_lock_and_executes_once(monkeypatch, tmp_path):
    target = TargetContext(
        url="http://127.0.0.1:1337",
        scheme="http",
        hostname="127.0.0.1",
        port=1337,
        ip="127.0.0.1",
    )
    validated_path = tmp_path / "validated.json"
    result_path = tmp_path / "result.json"
    validated_path.write_text(json.dumps({
        "validation": {"passed": True},
        "plan": {
            "plan_id": "one-step",
            "steps": [{
                "id": 1,
                "type": "python",
                "purpose": "observe 49",
                "sdk_calls": [{"primitive": "HttpClient.get", "target": "/"}],
            }],
        },
    }), encoding="utf-8")

    calls = []

    class FakeSandbox:
        _image_verified = True

        def __init__(self, image, timeout):
            pass

        def is_available(self):
            return True

        def run_python_script(self, **kwargs):
            calls.append(kwargs)
            return {
                "ok": True,
                "exit_code": 0,
                "stdout": "HTTP 200: 49\nSTEP_OK\n",
                "stderr": "",
                "execution_mode": "docker",
            }

    monkeypatch.setattr(executor, "DockerSandbox", FakeSandbox)

    output = executor.run_executor(
        validated_path=validated_path,
        result_path=result_path,
        workdir=tmp_path,
        target=target,
    )

    assert len(calls) == 1
    assert calls[0]["target_url"] == "http://host.docker.internal:1337"
    assert calls[0]["target"] is None
    assert target.url == "http://127.0.0.1:1337"
    assert output["step_results"][0]["result"]["stdout"].startswith("HTTP 200: 49")
    stored = json.loads(
        (tmp_path / "co_redteam_exec" / "context.json").read_text(encoding="utf-8")
    )["target_context"]
    assert stored["base_url"] == target.url
    assert stored["policy_base_url"] == target.url
    assert stored["execution_base_url"] == "http://host.docker.internal:1337"


def test_run_executor_executes_step_with_warning_only(monkeypatch, tmp_path):
    validated_path = tmp_path / "validated-warning.json"
    result_path = tmp_path / "result-warning.json"
    validated_path.write_text(json.dumps({
        "validation": {
            "passed": True,
            "errors": [],
            "syntax_warnings": ["step[0]: optional output field is missing"],
        },
        "target_context": {"base_url": "http://192.0.2.10:8080"},
        "plan": {
            "plan_id": "warning-only",
            "steps": [{
                "id": 1,
                "type": "python",
                "purpose": "execute despite warning",
                "sdk_calls": [{"primitive": "HttpClient.get", "target": "/"}],
            }],
        },
    }), encoding="utf-8")

    calls = []

    class FakeSandbox:
        _image_verified = True

        def __init__(self, image, timeout):
            pass

        def is_available(self):
            return True

        def run_python_script(self, **kwargs):
            calls.append(kwargs)
            return {
                "ok": True,
                "exit_code": 0,
                "stdout": "HTTP 200: warning did not block\nSTEP_OK\n",
                "stderr": "",
                "execution_mode": "docker",
            }

    monkeypatch.setattr(executor, "DockerSandbox", FakeSandbox)

    output = executor.run_executor(
        validated_path=validated_path,
        result_path=result_path,
        workdir=tmp_path,
    )

    assert len(calls) == 1
    assert output["executed"] is True
    assert output["step_results"][0]["result"]["execution_mode"] == "docker"


def test_run_executor_skips_plan_with_blocking_validation_error(monkeypatch, tmp_path):
    validated_path = tmp_path / "validated-error.json"
    result_path = tmp_path / "result-error.json"
    validation = {
        "passed": False,
        "errors": ["step[0]: blocked import"],
        "syntax_warnings": ["step[0]: optional output field is missing"],
    }
    validated_path.write_text(json.dumps({
        "validation": validation,
        "plan": {
            "plan_id": "blocking-error",
            "steps": [{"id": 1, "type": "python", "purpose": "must not run"}],
        },
    }), encoding="utf-8")

    class UnexpectedSandbox:
        def __init__(self, *args, **kwargs):
            pytest.fail("blocking validation errors must skip executor startup")

    monkeypatch.setattr(executor, "DockerSandbox", UnexpectedSandbox)

    output = executor.run_executor(
        validated_path=validated_path,
        result_path=result_path,
        workdir=tmp_path,
    )

    assert output == {
        "version": 1,
        "executed": False,
        "reason": "validation failed",
        "validation": validation,
        "step_results": [],
        "execution_mode": "blocked",
    }

def test_run_executor_stops_before_evaluator_on_connect_failure(monkeypatch, tmp_path):
    target = TargetContext(
        url="http://127.0.0.1:1337",
        scheme="http",
        hostname="127.0.0.1",
        port=1337,
        ip="127.0.0.1",
    )
    validated_path = tmp_path / "validated-network-failure.json"
    result_path = tmp_path / "result-network-failure.json"
    validated_path.write_text(json.dumps({
        "validation": {"passed": True},
        "plan": {
            "plan_id": "network-failure",
            "steps": [{
                "id": 1,
                "type": "python",
                "purpose": "connect once",
                "sdk_calls": [{"primitive": "HttpClient.get", "target": "/"}],
            }],
        },
    }), encoding="utf-8")

    class FailingSandbox:
        _image_verified = True

        def __init__(self, image, timeout):
            pass

        def is_available(self):
            return True

        def run_python_script(self, **kwargs):
            return {
                "ok": False,
                "exit_code": 0,
                "stdout": "EXECUTION_NETWORK_CONNECT_FAILED: refused\n",
                "stderr": "",
                "error_code": "EXECUTION_NETWORK_CONNECT_FAILED",
                "execution_mode": "docker",
            }

    monkeypatch.setattr(executor, "DockerSandbox", FailingSandbox)

    output = executor.run_executor(
        validated_path=validated_path,
        result_path=result_path,
        workdir=tmp_path,
        target=target,
    )

    assert output["executed"] is False
    assert output["reason"] == "EXECUTION_NETWORK_CONNECT_FAILED"
    assert output["error_code"] == "EXECUTION_NETWORK_CONNECT_FAILED"
    assert output["step_results"][0]["result"]["error_code"] == (
        "EXECUTION_NETWORK_CONNECT_FAILED"
    )
    assert target.url == "http://127.0.0.1:1337"


def test_invalid_execution_url_fails_closed():
    with pytest.raises(executor.ExecutionNetworkError) as exc:
        executor._build_execution_target_context("not-a-url")

    assert exc.value.code == "EXECUTION_TARGET_RESOLUTION_FAILED"
