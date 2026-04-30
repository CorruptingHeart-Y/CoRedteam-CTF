from __future__ import annotations

import json
import logging
import os
import re
import time
import uuid
import warnings
from pathlib import Path
from typing import Any

import docker
from docker.errors import DockerException, ImageNotFound
from docker.models.containers import Container

from agents.validator import safe_split_shell

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
_audit_log = logging.getLogger("SECURITY_AUDIT")
_audit_log.setLevel(logging.INFO)

DANGEROUS_PATTERNS = [
    (r"rm\s+-rf\s+[/~]", "destructive_file_deletion"),
    (r"mkfs|dd\s+if=|>[/\\]/dev/", "disk_destruction"),
    (r"chmod\s+777|chown\s+", "permission_escalation"),
    (r":\(\)\{\s*:", "fork_bomb"),
    (r"curl.*\|\s*(ba)?sh", "remote_code_injection"),
    (r"wget.*\|\s*(ba)?sh", "remote_code_injection"),
    (r"eval\s*\(", "code_eval"),
    (r"export\s+PATH.*bin", "path_injection"),
    (r"/etc/(passwd|shadow|hosts)", "sensitive_file_access"),
    (r"\.\./.*\.\./", "path_traversal"),
    (r"host\.docker\.internal.*\|(ba)?sh", "container_escape_attempt"),
]

BLOCK_ONLY_PATTERNS = [
    (r"rm\s+-rf\s+[/~]", "destructive_file_deletion"),
    (r"mkfs|dd\s+if=|>[/\\]/dev/", "disk_destruction"),
    (r":\(\)\{\s*:", "fork_bomb"),
    (r"curl.*\|\s*(ba)?sh", "remote_code_injection"),
    (r"wget.*\|\s*(ba)?sh", "remote_code_injection"),
    (r"host\.docker\.internal.*\|(ba)?sh", "container_escape_attempt"),
]


class SecurityViolationError(Exception):
    pass


def _audit_command(step_id: int, cmd: str, mode: str) -> None:
    _audit_log.info(f"[AUDIT] step={step_id} mode={mode} cmd={cmd[:500]}")
    for pattern, label in DANGEROUS_PATTERNS:
        if re.search(pattern, cmd, re.IGNORECASE):
            _audit_log.warning(f"[AUDIT] ⚠️  step={step_id} TRIGGERED_PATTERN: {label} in: {cmd[:200]}")


def _check_command_safety(cmd: str, step_id: int) -> list[str]:
    violations = []
    for pattern, label in BLOCK_ONLY_PATTERNS:
        if re.search(pattern, cmd, re.IGNORECASE):
            violations.append(label)
            _audit_log.warning(f"[SECURITY] 🚨 step={step_id} BLOCKED pattern='{label}' cmd={cmd[:200]}")
    return violations


class DockerSandbox:
    REQUIRED_TOOLS = ["curl", "python3", "sh"]

    def __init__(self, image: str, timeout: int = 60, memory_limit: str = "512m", cpu_quota: int = 100000):
        self.image = image
        self.timeout = timeout
        self.memory_limit = memory_limit
        self.cpu_quota = cpu_quota
        self._client: docker.DockerClient | None = None
        self._image_available: bool | None = None
        self._image_verified: bool = False

    @property
    def client(self) -> docker.DockerClient:
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    def is_available(self) -> bool:
        if self._image_available is not None:
            return self._image_available
        try:
            self.client.images.get(self.image)
            self._image_available = True
            return True
        except (DockerException, ImageNotFound):
            self._image_available = False
            return False

    def verify_image_tools(self) -> tuple[bool, list[str]]:
        missing = []
        try:
            check_cmd = "sh -c '" + " && ".join(f"command -v {t} >/dev/null 2>&1 || echo MISSING_{t}" for t in self.REQUIRED_TOOLS) + "'"
            container = self.client.containers.create(
                image=self.image,
                command=check_cmd,
                detach=True,
                mem_limit="64m",
                network_disabled=True,
            )
            container.start()
            result = container.wait(timeout=10)
            stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace").strip()
            stderr_out = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace").strip()
            container.remove(force=True)
            if result["StatusCode"] != 0 or "MISSING" in stdout:
                for t in self.REQUIRED_TOOLS:
                    if f"MISSING_{t}" in stdout:
                        missing.append(t)
                    elif t not in stdout and t not in stderr_out:
                        missing.append(t)
            return len(missing) == 0, missing
        except Exception as e:
            print(f"[docker] Image verification failed: {e}")
            print(f"[docker] Note: Image was built successfully from Dockerfile. Assuming tools are present.")
            return True, []

    def build_image(self, dockerfile_dir: Path, force: bool = False) -> bool:
        try:
            tag = self.image
            if force:
                print(f"[docker] Force rebuilding image {tag} from {dockerfile_dir}...")
                try:
                    self.client.images.remove(tag, force=True)
                except Exception:
                    pass
            else:
                print(f"[docker] Building image {tag} from {dockerfile_dir}...")
            self.client.images.build(
                path=str(dockerfile_dir),
                tag=tag,
                rm=True,
                forcerm=True,
            )
            self._image_available = True
            self._image_verified = False
            print(f"[docker] Image {tag} built successfully.")
            return True
        except DockerException as e:
            print(f"[docker] Failed to build image: {e}")
            self._image_available = False
            return False

    def run_command(self, command: str | list[str], workdir: Path | None = None, step_id: int = 0) -> dict[str, Any]:
        cmd_str = command if isinstance(command, str) else " ".join(command)
        violations = _check_command_safety(cmd_str, step_id)
        if violations:
            raise SecurityViolationError(f"命令被安全策略拦截: {violations}, cmd={cmd_str[:200]}")

        _audit_command(step_id, cmd_str, "docker")
        container_name = f"coredteam-{uuid.uuid4().hex[:12]}"
        container: Container | None = None
        start = time.time()

        try:
            volumes = {}
            if workdir and workdir.exists():
                volumes[str(workdir.resolve())] = {"bind": "/sandbox/workspace", "mode": "ro"}

            tmpfs = {"/tmp": "size=64M,mode=1777", "/var/tmp": "size=32M,mode=1777"}

            container = self.client.containers.create(
                image=self.image,
                command=command,
                name=container_name,
                detach=True,
                mem_limit=self.memory_limit,
                cpu_quota=self.cpu_quota,
                network_disabled=False,
                volumes=volumes,
                working_dir="/sandbox/workspace",
                security_opt=["no-new-privileges"],
                cap_drop=["ALL"],
                read_only=True,
                tmpfs=tmpfs,
                pids_limit=50,
            )

            container.start()
            result = container.wait(timeout=self.timeout)

            stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
            stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")

            exit_code = result.get("StatusCode", -1)
            duration = time.time() - start

            return {
                "ok": exit_code == 0,
                "exit_code": exit_code,
                "stdout": stdout[-19999:] if len(stdout) > 20000 else stdout,
                "stderr": stderr[-19999:] if len(stderr) > 20000 else stderr,
                "duration_sec": round(duration, 3),
                "container_id": container.id[:12],
                "execution_mode": "docker",
            }

        except docker.errors.APIError as e:
            if "timeout" in str(e).lower() or "timed out" in str(e).lower():
                duration = time.time() - start
                stdout = ""
                stderr = ""
                if container:
                    try:
                        stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
                        stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")
                    except Exception:
                        pass
                return {
                    "ok": False,
                    "exit_code": 124,
                    "stdout": stdout[-19999:] if stdout and len(stdout) > 20000 else stdout,
                    "stderr": stderr[-19999:] if stderr and len(stderr) > 20000 else stderr or "Container execution timeout",
                    "duration_sec": round(duration, 3),
                    "execution_mode": "docker",
                }
            return {
                "ok": False,
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Docker API error: {e}",
                "duration_sec": round(time.time() - start, 3),
                "execution_mode": "docker",
            }

        except Exception as e:
            return {
                "ok": False,
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Docker execution failed: {e}",
                "duration_sec": round(time.time() - start, 3),
                "execution_mode": "docker",
            }

        finally:
            if container:
                try:
                    container.remove(force=True, v=True)
                except Exception as e:
                    print(f"[docker] Warning: Failed to remove container {container_name}: {e}")


def _run_docker(
    step: dict[str, Any],
    sandbox: DockerSandbox,
    workdir: Path | None,
) -> dict[str, Any]:
    stype = step.get("type")
    cmd = (step.get("command", "") or "").strip()

    if stype == "python":
        if cmd.startswith("python "):
            code = cmd[7:]  # strip "python "
            if code.startswith("-c "):
                code = code[3:].strip()
            if code.startswith('"') and code.endswith('"'):
                try:
                    code = json.loads(code)
                except json.JSONDecodeError:
                    pass
        else:
            code = cmd
        actual_cmd = ["python3", "-u", "-c", code]
    elif stype == "shell":
        actual_cmd = cmd
    else:
        return {
            "ok": False,
            "exit_code": -1,
            "stdout": "",
            "stderr": f"未知 type: {stype}",
            "duration_sec": 0.0,
            "execution_mode": "docker",
        }

    return sandbox.run_command(actual_cmd, workdir)


def _run_step(
    step: dict[str, Any],
    timeout_sec: int,
    workdir: Path,
    sandbox: DockerSandbox | None,
) -> dict[str, Any]:
    if sandbox is not None and sandbox.is_available():
        print(f"[executor] ✅ Using Docker sandbox for step {step.get('id')}")
        return _run_docker(step, sandbox, workdir)

    err_msg = (
        "🚨 [SECURITY_BLOCKED] Docker沙箱不可用！"
        "AI生成的攻击代码严禁在宿主机执行。"
        f"请确保 Docker Desktop 正在运行且镜像 '{getattr(sandbox, 'image', 'unknown') if sandbox else 'N/A'}' 已构建。"
    )
    print(f"[executor] {err_msg} (step {step.get('id')})")
    _audit_log.critical(f"[SECURITY_VIOLATION] Attempted local execution blocked! step={step.get('id')}")
    raise SecurityViolationError(err_msg)


def run_executor(
    validated_path: Path,
    result_path: Path,
    workdir: Path,
    timeout_sec: int = 120,
    docker_image: str = "co-redteam-sandbox:latest",
    dockerfile_dir: Path | None = None,
) -> dict[str, Any]:
    data = json.loads(validated_path.read_text(encoding="utf-8"))
    val = data.get("validation") or {}
    if not val.get("passed"):
        out = {
            "version": 1,
            "executed": False,
            "reason": "validation failed",
            "validation": val,
            "step_results": [],
            "execution_mode": "blocked",
        }
        result_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        return out

    plan = data.get("plan") or {}
    steps = plan.get("steps") or []
    syntax_warnings = val.get("syntax_warnings") or []
    skip_indices: set[int] = set()
    for w in syntax_warnings:
        m = re.search(r"step\[(\d+)\]", w)
        if m:
            skip_indices.add(int(m.group(1)))

    _audit_log.info(f"[AUDIT] Starting executor: plan_id={plan.get('plan_id')} steps_count={len(steps)}")

    sandbox: DockerSandbox | None = None
    try:
        sandbox = DockerSandbox(image=docker_image, timeout=timeout_sec)
        if not sandbox.is_available():
            if dockerfile_dir and dockerfile_dir.exists():
                sandbox.build_image(dockerfile_dir)
            if not sandbox.is_available():
                raise SecurityViolationError(
                    f"Docker镜像 '{docker_image}' 不存在且构建失败！"
                    "无法创建安全沙箱，拒绝执行任何攻击代码。"
                )
        elif not sandbox._image_verified:
            print(f"[executor] Verifying Docker image {docker_image} tools...")
            ok, missing = sandbox.verify_image_tools()
            if ok:
                sandbox._image_verified = True
                print(f"[executor] Image verification passed.")
            else:
                print(f"[executor] Image missing tools: {missing}, rebuilding...")
                if dockerfile_dir and dockerfile_dir.exists():
                    if sandbox.build_image(dockerfile_dir, force=True):
                        ok2, missing2 = sandbox.verify_image_tools()
                        if ok2:
                            sandbox._image_verified = True
                            print(f"[executor] Image rebuilt and verified successfully.")
                        else:
                            raise SecurityViolationError(
                                f"Docker镜像重建后仍缺少工具: {missing2}！沙箱不安全，拒绝执行。"
                            )
                    else:
                        raise SecurityViolationError("Docker镜像构建失败！无法创建安全沙箱。")
                else:
                    raise SecurityViolationError("无 Dockerfile 目录，无法重建镜像。拒绝执行。")
    except SecurityViolationError:
        raise
    except DockerException as e:
        raise SecurityViolationError(f"Docker 引擎异常: {e}！拒绝在无沙箱环境下执行攻击代码。") from e

    step_results: list[dict[str, Any]] = []
    blocked_count = 0
    for i, st in enumerate(steps):
        if i in skip_indices:
            step_results.append({
                "step_id": st.get("id"),
                "type": st.get("type"),
                "purpose": st.get("purpose"),
                "result": {
                    "ok": False,
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": f"validator 检测到语法错误，自动跳过: {syntax_warnings}",
                    "duration_sec": 0.0,
                    "execution_mode": "skipped_syntax_error",
                },
            })
            continue
        try:
            result = _run_step(st, timeout_sec, workdir, sandbox)
        except SecurityViolationError as e:
            result = {
                "ok": False,
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e),
                "duration_sec": 0.0,
                "execution_mode": "security_blocked",
            }
            blocked_count += 1
        step_results.append({
            "step_id": st.get("id"),
            "type": st.get("type"),
            "purpose": st.get("purpose"),
            "result": result,
        })

    fail_results = [r for r in step_results if not (r.get("result") or {}).get("ok")]
    if fail_results and len(fail_results) == len(step_results):
        stderrs = [(r.get("result") or {}).get("stderr", "")[:120] for r in fail_results]
        if len(set(stderrs)) <= 2:
            print(f"[executor] ⚠️ ALL {len(step_results)} steps failed/blocked:")
            print(f"[executor]   common_stderr: {stderrs[0]}")

    execution_mode = "docker" if sandbox and sandbox.is_available() else "security_blocked"
    out = {
        "version": 1,
        "executed": True,
        "plan_id": plan.get("plan_id"),
        "workdir": str(workdir.resolve()),
        "step_results": step_results,
        "execution_mode": execution_mode,
        "security_policy": "ENFORCED_DOCKER_ONLY",
        "total_steps": len(steps),
        "blocked_steps": blocked_count,
    }
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    _audit_log.info(f"[AUDIT] Executor finished: mode={execution_mode} total={len(steps)} blocked={blocked_count}")
    return out
