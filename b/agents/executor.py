from __future__ import annotations

import json
import logging
import re
import socket
import time
import uuid
from pathlib import Path
from typing import Any, TYPE_CHECKING
from urllib.parse import urlparse

import docker
from docker.errors import DockerException, ImageNotFound
from docker.models.containers import Container

if TYPE_CHECKING:
    from core.target_context import TargetContext


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
_audit_log = logging.getLogger("SECURITY_AUDIT")
_audit_log.setLevel(logging.INFO)

# ──────────────────────────────────────────────
#  SDK 源码（写入沙箱 /workspace/redteam_sdk.py）
# ──────────────────────────────────────────────
_SDK_SOURCE = """\
\"\"\"Co-RedTeam Tactical SDK -- auto-injected into every Docker sandbox workspace.\"\"\"

import base64
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_WORKSPACE    = "/workspace"
_TMP_DIR      = "/workspace/tmp"
_CONTEXT_PATH = f"{_WORKSPACE}/context.json"
_SESSION_PATH = f"{_TMP_DIR}/session.json"


# ── HttpClient ──────────────────────────────────

class HttpClient(requests.Session):
    \"\"\"Generic red-team HTTP client: SSL-ignore, cookie persistence, CSRF extraction.\"\"\"

    def __init__(self, base_url: str = "", verify_ssl: bool = False):
        super().__init__()
        self.base_url       = base_url.rstrip("/") if base_url else ""
        self._verify_ssl    = verify_ssl
        self._last_response = None
        self._restore_session()

    def request(self, method: str, url: str, *args, **kwargs) -> requests.Response:
        if self.base_url and not url.startswith(("http://", "https://")):
            url = f"{self.base_url}{url}"
        kwargs.setdefault("verify", self._verify_ssl)
        resp = super().request(method.upper(), url, *args, **kwargs)
        self._last_response = resp
        return resp

    def get(self, url, *a, **kw):    return self.request("GET",    url, *a, **kw)
    def post(self, url, *a, **kw):   return self.request("POST",   url, *a, **kw)
    def put(self, url, *a, **kw):    return self.request("PUT",    url, *a, **kw)
    def delete(self, url, *a, **kw): return self.request("DELETE", url, *a, **kw)

    @property
    def last_response(self):
        return self._last_response

    def auto_extract_csrf(self, source=None) -> str:
        candidates = []
        if source is None:
            sc = self.cookies.get("session", "")
            if sc:
                candidates.append(("jwt", sc))
            if self._last_response is not None:
                candidates.append(("html", self._last_response.text))
        elif isinstance(source, str):
            if "." in source and len(source.split(".")) >= 2:
                candidates.append(("jwt", source))
            else:
                candidates.append(("html", source))
        elif hasattr(source, "text") and hasattr(source, "cookies"):
            sc = source.cookies.get("session", "")
            if sc:
                candidates.append(("jwt", sc))
            candidates.append(("html", source.text))
        for kind, data in candidates:
            token = self._csrf_from_jwt(data) if kind == "jwt" else self._csrf_from_html(data)
            if token:
                return token
        return ""

    def _csrf_from_jwt(self, session_cookie: str) -> str:
        try:
            parts = session_cookie.strip().split(".")
            if len(parts) < 2:
                return ""
            payload_b64 = parts[1]
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            token = payload.get("antiCSRFToken", "")
            return token if isinstance(token, str) and token else ""
        except Exception:
            return ""

    def _csrf_from_html(self, html_text: str) -> str:
        patterns = [
            r'name=["\\'?]?antiCSRFToken["\\'?][^>]*value=["\\'"]([^"\\']+)',
            r'value=["\\'"]([^"\\']+)["\\'"][^>]*name=["\\'?]?antiCSRFToken',
            r'antiCSRFToken["\\'?]\\s*[:=]\\s*["\\'"]([^"\\']+)',
        ]
        for pat in patterns:
            m = re.search(pat, html_text, re.IGNORECASE)
            if m:
                return m.group(1).strip()
        return ""

    def _restore_session(self):
        p = Path(_SESSION_PATH)
        if not p.exists():
            return
        try:
            raw = p.read_text(encoding="utf-8").strip()
            if not raw:
                return
            data = json.loads(raw)
            cookies = data.get("cookies", {})
            if isinstance(cookies, dict):
                for name, value in cookies.items():
                    self.cookies.set(name, value)
        except (json.JSONDecodeError, OSError):
            pass

    def persist_session(self):
        try:
            data = {"cookies": dict(self.cookies)}
            p = Path(_SESSION_PATH)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        except OSError:
            pass

    def __del__(self):
        try:
            self.persist_session()
        except Exception:
            pass


# backward-compat alias
AttackerSession = HttpClient


# ── ContextStore ────────────────────────────────

class ContextStore:
    \"\"\"Cross-step KV store backed by /workspace/tmp/context_store.json.\"\"\"

    _PATH = Path(_TMP_DIR) / "context_store.json"

    def _load(self) -> dict:
        if self._PATH.exists():
            try:
                raw = self._PATH.read_text(encoding="utf-8").strip()
                if raw:
                    return json.loads(raw)
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def _dump(self, data: dict) -> None:
        self._PATH.parent.mkdir(parents=True, exist_ok=True)
        self._PATH.write_text(json.dumps(data, ensure_ascii=False, default=str), encoding="utf-8")

    def save(self, key: str, value: Any) -> None:
        data = self._load()
        data[key] = value if not hasattr(value, "__dict__") else str(value)
        self._dump(data)

    def load(self, key: str, default=None) -> Any:
        return self._load().get(key, default)

    def load_all(self) -> dict:
        return self._load()

    def delete(self, key: str) -> None:
        data = self._load()
        data.pop(key, None)
        self._dump(data)


# ── OOBReceiver ─────────────────────────────────

class OOBReceiver:
    \"\"\"Background HTTP listener for SSRF/XSS/SSTI out-of-band callbacks.

    Usage:
        oob = OOBReceiver(port=8765)
        oob.start()
        # ... trigger the vulnerability ...
        hit = oob.wait_for_callback(timeout=30)
        print(hit)   # {"method": "GET", "path": "/...", "body": "...", "headers": {...}}
        oob.stop()
    \"\"\"

    def __init__(self, host: str = "0.0.0.0", port: int = 8765):
        self.host    = host
        self.port    = port
        self._hits: list[dict] = []
        self._lock   = threading.Lock()
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        receiver = self

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self):  self._record("GET")
            def do_POST(self): self._record("POST")
            def do_PUT(self):  self._record("PUT")
            def do_HEAD(self): self._record("HEAD")

            def _record(self, method: str):
                length = int(self.headers.get("Content-Length", 0))
                body   = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
                hit    = {
                    "method":  method,
                    "path":    self.path,
                    "body":    body,
                    "headers": dict(self.headers),
                    "time":    time.time(),
                }
                with receiver._lock:
                    receiver._hits.append(hit)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *_):
                pass  # suppress default stderr logging

        self._server = HTTPServer((self.host, self.port), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def wait_for_callback(self, timeout: float = 30) -> dict | None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                if self._hits:
                    return self._hits[-1]
            time.sleep(0.25)
        return None

    def get_all_hits(self) -> list[dict]:
        with self._lock:
            return list(self._hits)

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"


# ── 步骤间通信（module-level helpers） ──────────

_ctx_store = ContextStore()

def save_context(key: str, value: Any) -> None:
    _ctx_store.save(key, value)
    # also mirror to legacy context.json for chain_output extraction
    ctx = _read_ctx()
    ctx[key] = value if not hasattr(value, "__dict__") else str(value)
    _write_ctx(ctx)


def load_context(key: str, default=None):
    return _ctx_store.load(key, default)


def load_all_context() -> dict:
    return _ctx_store.load_all()


def output_result(data_dict: dict) -> None:
    print("###CHAIN_OUTPUT###" + json.dumps(data_dict, ensure_ascii=False, default=str))


def ensure_session_persisted():
    import gc
    sp = Path(_SESSION_PATH)
    existing = {}
    if sp.exists():
        raw = sp.read_text(encoding="utf-8")
        try:
            existing = json.loads(raw) if raw.strip() else {}
        except (json.JSONDecodeError, OSError):
            pass
    for obj in gc.get_objects():
        if isinstance(obj, HttpClient):
            cookies = dict(obj.cookies)
            if cookies:
                existing["cookies"] = cookies
                break
    sp.parent.mkdir(parents=True, exist_ok=True)
    sp.write_text(json.dumps(existing, ensure_ascii=False), encoding="utf-8")


# ── 内部辅助 ────────────────────────────────────

def _read_ctx() -> dict:
    p = Path(_CONTEXT_PATH)
    if p.exists():
        try:
            raw = p.read_text(encoding="utf-8")
            if raw.strip():
                return json.loads(raw)
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _write_ctx(ctx: dict) -> None:
    Path(_CONTEXT_PATH).write_text(
        json.dumps(ctx, ensure_ascii=False, default=str),
        encoding="utf-8",
    )


def _ser(value: Any) -> Any:
    if isinstance(value, requests.Response):
        return {
            "_type": "response",
            "status_code": value.status_code,
            "text": value.text[:2000],
            "headers": dict(value.headers),
            "cookies": dict(value.cookies),
            "url": value.url,
        }
    if hasattr(value, "__dict__"):
        return str(value)
    return value


def _deser(value: Any) -> Any:
    if isinstance(value, dict) and value.get("_type") == "response":
        return value
    return value
"""

# ──────────────────────────────────────────────
#  安全规则集
# ──────────────────────────────────────────────
PYTHON_BLOCKED_PATTERNS = [
    (r"\bos\.system\s*\(", "os_system_exec"),
    (r"\bos\.popen\s*\(", "os_popen_exec"),
    (r"\bos\.exec[lvp]?\s*\(", "os_exec"),
    (r"\bos\.spawn[lvp]?\s*\(", "os_spawn"),
    (r"\bsubprocess\.(run|call|Popen|check_output|check_call)\s*\(", "subprocess_call"),
    (r"\bctypes\.", "ctypes_raw_call"),
    (r"\bimport\s+ctypes\b", "ctypes_import"),
    (r"\b__import__\s*\(", "dynamic_import"),
    (r"\bcompile\s*\(", "runtime_compile"),
    (r"\bexecfile\s*\(", "exec_file"),
]

SECCOMP_PROFILE = {
    "defaultAction": "SCMP_ACT_ERRNO",
    "defaultErrnoRet": 1,
    "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_AARCH64"],
    "syscalls": [
        {"names": [
            "accept", "accept4", "access", "arch_prctl", "bind", "brk", "capget", "capset",
            "chdir", "chmod", "chown", "close", "connect", "dup", "dup2", "dup3",
            "epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait",
            "eventfd2", "execve", "exit", "exit_group", "faccessat", "faccessat2",
            "fadvise64", "fallocate", "fchmod", "fchmodat", "fchown", "fchownat",
            "fcntl", "fdatasync", "flock", "fork", "fstat", "fstatfs", "fsync",
            "ftruncate", "futex", "getcwd", "getdents", "getdents64", "getegid",
            "geteuid", "getgid", "getgroups", "getpeername", "getpgrp", "getpid",
            "getppid", "getpriority", "getrandom", "getresgid", "getresuid",
            "getrlimit", "getsockname", "getsockopt", "gettid", "gettimeofday",
            "getuid", "inotify_add_watch", "inotify_init1", "inotify_rm_watch",
            "listen",
            "ioctl", "lseek", "lstat", "madvise", "membarrier", "memfd_create",
            "mincore", "mkdir", "mkdirat", "mmap", "mprotect", "mremap", "munmap",
            "nanosleep", "newfstatat", "open", "openat", "pipe", "pipe2",
            "poll", "ppoll", "prctl", "pread64", "preadv", "prlimit64",
            "pwrite64", "pwritev", "read", "readahead", "readlink", "readlinkat",
            "recvfrom", "recvmmsg", "recvmsg", "rename", "renameat", "renameat2",
            "restart_syscall", "rmdir", "rt_sigaction", "rt_sigprocmask",
            "rt_sigreturn", "rt_sigsuspend", "sched_getaffinity", "sched_yield",
            "seccomp", "select", "sendfile", "sendmmsg", "sendmsg", "sendto",
            "set_robust_list", "set_tid_address", "setgid", "setgroups",
            "setsockopt", "setuid", "shutdown", "sigaltstack", "socket",
            "socketpair", "stat", "statfs", "statx", "symlink", "symlinkat",
            "sysinfo", "tgkill", "timer_create", "timer_delete", "timer_gettime",
            "timer_settime", "timerfd_create", "timerfd_gettime", "timerfd_settime",
            "umask", "uname", "unlink", "unlinkat", "wait4", "waitid",
            "write", "writev", "copy_file_range",
        ], "action": "SCMP_ACT_ALLOW"},
    ],
}


class SecurityViolationError(Exception):
    pass


# ──────────────────────────────────────────────
#  网络隔离辅助
# ──────────────────────────────────────────────

def _resolve_target(target_url: str) -> tuple[str, int, str]:
    """Resolve raw target URL → (ip, port, hostname); empty strings on failure.

    Used only when no TargetContext is provided (legacy path). When the CLI
    locks a target, the TargetContext supplies these values directly without
    re-resolving.
    """
    if not target_url:
        return "", 0, ""
    try:
        parsed = urlparse(target_url)
        host = parsed.hostname or ""
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80
        # Windows/Mac: host.docker.internal is not resolvable by the host OS resolver.
        # Return the Docker magic value directly so the container can reach the host.
        if host in ("host.docker.internal", "localhost"):
            return "host-gateway", port, host
        ip = socket.gethostbyname(host)
        return ip, port, host
    except Exception as e:
        _audit_log.warning(f"[NETWORK] 无法解析 target_url={target_url}: {e}")
        return "", 0, ""


def _create_isolated_network(client: docker.DockerClient, target_ip: str, target_port: int) -> str | None:
    """
    创建仅允许访问目标 IP:Port 的自定义 Docker 网络。
    返回网络名称；若 target_ip 为空则返回 None（使用 network_disabled=True）。
    """
    if not target_ip:
        return None
    net_name = f"coredteam-net-{uuid.uuid4().hex[:8]}"
    try:
        client.networks.create(
            net_name,
            driver="bridge",
            options={
                "com.docker.network.bridge.enable_icc": "false",
                "com.docker.network.bridge.enable_ip_masquerade": "true",
            },
            labels={"coredteam": "isolated", "target_ip": target_ip, "target_port": str(target_port)},
        )
        _audit_log.info(f"[NETWORK] 已创建隔离网络 {net_name} -> {target_ip}:{target_port}")
        return net_name
    except Exception as e:
        _audit_log.warning(f"[NETWORK] 创建网络失败: {e}，将使用 network_disabled=True")
        return None


def _remove_network(client: docker.DockerClient, net_name: str) -> None:
    try:
        net = client.networks.get(net_name)
        net.remove()
    except Exception:
        pass


# ──────────────────────────────────────────────
#  Python 安全检查
# ──────────────────────────────────────────────

def _check_python_safety(code: str, step_id: int) -> list[str]:
    violations = []
    for pattern, label in PYTHON_BLOCKED_PATTERNS:
        if re.search(pattern, code):
            violations.append(label)
            _audit_log.warning(f"[SECURITY] PYTHON_BLOCKED pattern='{label}' step={step_id}")
    return violations


# ──────────────────────────────────────────────
#  工作区准备：SDK + context.json + tmp 目录
# ──────────────────────────────────────────────

def _prepare_exec_workspace(base_workdir: Path) -> Path:
    """
    准备执行工作区：
    - exec_workspace/          → 只读挂载到 /workspace
    - exec_workspace/tmp/      → 可写挂载到 /workspace/tmp
    - exec_workspace/redteam_sdk.py  → 注入 SDK
    - exec_workspace/context.json    → 步骤间通信文件
    """
    ws = base_workdir / "co_redteam_exec"
    ws.mkdir(parents=True, exist_ok=True)

    # 写入 SDK
    sdk_path = ws / "redteam_sdk.py"
    sdk_path.write_text(_SDK_SOURCE, encoding="utf-8")

    # 初始化 context
    ctx_file = ws / "context.json"
    if not ctx_file.exists():
        ctx_file.write_text("{}", encoding="utf-8")

    # 创建可写 tmp 目录
    tmp_dir = ws / "tmp"
    tmp_dir.mkdir(exist_ok=True)

    return ws


# ──────────────────────────────────────────────
#  DockerSandbox
# ──────────────────────────────────────────────

class DockerSandbox:
    REQUIRED_TOOLS = ["python3"]

    def __init__(self, image: str, timeout: int = 180, memory_limit: str = "512m", cpu_quota: int = 100000):
        self.image        = image
        self.timeout      = timeout
        self.memory_limit = memory_limit
        self.cpu_quota    = cpu_quota
        self._client: docker.DockerClient | None = None
        self._image_available: bool | None       = None
        self._image_verified: bool               = False

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
        except (DockerException, ImageNotFound):
            self._image_available = False
        return self._image_available

    def verify_image_tools(self) -> tuple[bool, list[str]]:
        missing = []
        try:
            check_cmd = "sh -c '" + " && ".join(
                f"command -v {t} >/dev/null 2>&1 || echo MISSING_{t}"
                for t in self.REQUIRED_TOOLS
            ) + "'"
            container = self.client.containers.create(
                image=self.image,
                command=check_cmd,
                detach=True,
                mem_limit="64m",
                network_disabled=True,
            )
            container.start()
            container.wait(timeout=10)
            stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
            container.remove(force=True)
            for t in self.REQUIRED_TOOLS:
                if f"MISSING_{t}" in stdout:
                    missing.append(t)
        except Exception as e:
            print(f"[docker] 镜像验证失败: {e}，假定工具已存在。")
        return len(missing) == 0, missing

    def build_image(self, dockerfile_dir: Path, force: bool = False) -> bool:
        try:
            tag = self.image
            if force:
                print(f"[docker] 强制重建镜像 {tag} ...")
                try:
                    self.client.images.remove(tag, force=True)
                except Exception:
                    pass
            else:
                print(f"[docker] 构建镜像 {tag} ...")
            self.client.images.build(path=str(dockerfile_dir), tag=tag, rm=True, forcerm=True)
            self._image_available = True
            self._image_verified  = False
            print(f"[docker] 镜像 {tag} 构建成功。")
            return True
        except DockerException as e:
            print(f"[docker] 构建失败: {e}")
            self._image_available = False
            return False

    def run_python_script(
        self,
        script_name: str,
        exec_workspace: Path,
        step_id: int = 0,
        env_vars: dict[str, str] | None = None,
        target_url: str = "",
        target: "TargetContext | None" = None,
    ) -> dict[str, Any]:
        """Run a script inside the sandbox.

        Mount策略：
          exec_workspace  → /workspace       (只读，含 SDK 和脚本)
          exec_workspace/tmp → /workspace/tmp (读写，用于 session、输出等)

        网络策略：
          始终使用默认 bridge 网络，网络始终开启。
          若目标为 host.docker.internal 或 localhost，注入 extra_hosts 使容器能访问宿主机。
        """
        container_name = f"coredteam-{uuid.uuid4().hex[:12]}"
        container: Container | None = None
        start = time.time()

        if target is not None:
            target_ip = target.ip
            target_port = target.port
            target_host = target.hostname
        else:
            target_ip, target_port, target_host = _resolve_target(target_url)

        tmp_host = str((exec_workspace / "tmp").resolve())
        volumes = {
            str(exec_workspace.resolve()): {"bind": "/workspace", "mode": "ro"},
            tmp_host:                      {"bind": "/workspace/tmp", "mode": "rw"},
        }

        # Always use bridge — never disable networking.
        extra_hosts: dict[str, str] = {}
        needs_host_gateway = (
            target_ip == "host-gateway"
            or (target_host and target_host in ("host.docker.internal", "localhost"))
            or (target_url and any(h in target_url for h in ("host.docker.internal", "localhost")))
        )
        if needs_host_gateway:
            extra_hosts["host.docker.internal"] = "host-gateway"
            extra_hosts["localhost"] = "host-gateway"
            _audit_log.info(
                f"[NETWORK] step={step_id} host={target_host} mode=bridge extra_hosts=host-gateway"
            )
        else:
            _audit_log.info(
                f"[NETWORK] step={step_id} host={target_host} ip={target_ip} mode=bridge"
            )

        try:
            create_kwargs: dict[str, Any] = dict(
                image=self.image,
                command=["python3", "-u", f"/workspace/{script_name}"],
                name=container_name,
                detach=True,
                mem_limit=self.memory_limit,
                memswap_limit=self.memory_limit,
                cpu_quota=self.cpu_quota,
                volumes=volumes,
                working_dir="/workspace/tmp",
                security_opt=["no-new-privileges"],
                cap_drop=["ALL"],
                pids_limit=64,
                environment=env_vars or {},
                network_mode="bridge",
            )
            if extra_hosts:
                create_kwargs["extra_hosts"] = extra_hosts

            container = self.client.containers.create(**create_kwargs)
            container.start()
            result = container.wait(timeout=self.timeout)

            stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
            stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")
            exit_code = result.get("StatusCode", -1)

            return {
                "ok": exit_code == 0,
                "exit_code": exit_code,
                "stdout": stdout[-19999:] if len(stdout) > 20000 else stdout,
                "stderr": stderr[-19999:] if len(stderr) > 20000 else stderr,
                "duration_sec": round(time.time() - start, 3),
                "container_id": container.id[:12],
                "execution_mode": "docker",
                "network_mode": "bridge",
                "target_ip": target_ip,
                "target_host": target_host,
            }

        except docker.errors.APIError as e:
            if "timeout" in str(e).lower() or "timed out" in str(e).lower():
                stdout, stderr = "", ""
                if container:
                    try:
                        stdout = container.logs(stdout=True,  stderr=False).decode("utf-8", errors="replace")
                        stderr = container.logs(stdout=False, stderr=True ).decode("utf-8", errors="replace")
                    except Exception:
                        pass
                return {
                    "ok": False, "exit_code": 124,
                    "stdout": stdout[-19999:] if stdout and len(stdout) > 20000 else stdout,
                    "stderr": stderr or "Container execution timeout",
                    "duration_sec": round(time.time() - start, 3),
                    "execution_mode": "docker",
                }
            return {
                "ok": False, "exit_code": -1, "stdout": "",
                "stderr": f"Docker API error: {e}",
                "duration_sec": round(time.time() - start, 3),
                "execution_mode": "docker",
            }

        except Exception as e:
            return {
                "ok": False, "exit_code": -1, "stdout": "",
                "stderr": f"Docker execution failed: {e}",
                "duration_sec": round(time.time() - start, 3),
                "execution_mode": "docker",
            }

        finally:
            if container:
                try:
                    container.remove(force=True, v=True)
                except Exception as ex:
                    print(f"[docker] 警告: 无法移除容器 {container_name}: {ex}")


# ──────────────────────────────────────────────
#  步骤执行
# ──────────────────────────────────────────────

def _run_docker(
    step: dict[str, Any],
    sandbox: DockerSandbox,
    exec_workspace: Path,
    env_vars: dict[str, str] | None = None,
    target_url: str = "",
    target: "TargetContext | None" = None,
) -> tuple[dict[str, Any], dict]:
    stype   = step.get("type")
    code    = (step.get("command", "") or "").strip()
    step_id = step.get("id", 0)

    if stype != "python":
        return {
            "ok": False, "exit_code": -1, "stdout": "", "stderr": f"不支持的 type: {stype}",
            "duration_sec": 0.0, "execution_mode": "docker",
        }, {}

    violations = _check_python_safety(code, step_id)
    if violations:
        _audit_log.critical(f"[SECURITY] Python 代码被拦截 step={step_id}: {violations}")
        return {
            "ok": False, "exit_code": -1, "stdout": "",
            "stderr": f"[SECURITY_BLOCKED] 含禁止模式: {violations}",
            "duration_sec": 0.0, "execution_mode": "security_blocked",
        }, {}

    script_name = f"step_{step_id}.py"
    script_path = exec_workspace / script_name
    wrapped_code = (
        "import sys\n"
        "sys.path.insert(0, '/workspace')\n"
        "from redteam_sdk import *\n\n"
        + code
        + "\n\ntry:\n    ensure_session_persisted()\nexcept Exception:\n    pass\n"
    )
    script_path.write_text(wrapped_code, encoding="utf-8")

    result = sandbox.run_python_script(
        script_name=script_name,
        exec_workspace=exec_workspace,
        step_id=step_id,
        env_vars=env_vars,
        target_url=target_url,
        target=target,
    )

    # 读取 context.json 作为 chain_output
    chain_output: dict = {}
    ctx_path = exec_workspace / "context.json"
    if ctx_path.exists():
        try:
            raw = ctx_path.read_text(encoding="utf-8").strip()
            if raw and raw != "{}":
                chain_output = json.loads(raw)
        except (json.JSONDecodeError, OSError):
            pass

    return result, chain_output


def _run_step(
    step: dict[str, Any],
    timeout_sec: int,
    exec_workspace: Path,
    sandbox: "DockerSandbox | None",
    env_vars: dict[str, str] | None = None,
    target_url: str = "",
    target: "TargetContext | None" = None,
) -> tuple[dict[str, Any], dict]:
    if sandbox is not None and sandbox.is_available():
        print(f"[executor] Docker 沙箱执行 step {step.get('id')}")
        return _run_docker(
            step, sandbox, exec_workspace,
            env_vars=env_vars, target_url=target_url, target=target,
        )

    err_msg = (
        "[SECURITY_BLOCKED] Docker 沙箱不可用！"
        "AI 生成的攻击代码不得在宿主机上运行。"
        f"请确保 Docker Desktop 正在运行且镜像 '{getattr(sandbox, 'image', 'N/A') if sandbox else 'N/A'}' 已构建。"
    )
    print(f"[executor] {err_msg} (step {step.get('id')})")
    _audit_log.critical(f"[SECURITY_VIOLATION] 本地执行被拦截! step={step.get('id')}")
    raise SecurityViolationError(err_msg)


# ──────────────────────────────────────────────
#  主入口
# ──────────────────────────────────────────────

def run_executor(
    validated_path: Path,
    result_path: Path,
    workdir: Path,
    timeout_sec: int = 300,
    docker_image: str = "co-redteam-sandbox:latest",
    dockerfile_dir: Path | None = None,
    target: "TargetContext | None" = None,
) -> dict[str, Any]:
    data = json.loads(validated_path.read_text(encoding="utf-8"))
    val  = data.get("validation") or {}

    if not val.get("passed"):
        out = {
            "version": 1, "executed": False, "reason": "validation failed",
            "validation": val, "step_results": [], "execution_mode": "blocked",
        }
        result_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        return out

    plan   = data.get("plan") or {}
    steps  = plan.get("steps") or []

    if target is not None:
        target_url = target.url
    else:
        target_url = ""
        tc = data.get("target_context") or {}
        if isinstance(tc, dict) and tc.get("base_url"):
            target_url = tc["base_url"]

    sandbox_env: dict[str, str] = {}
    if target is not None:
        sandbox_env.update(target.as_env())

    # 跳过有语法错误的步骤
    syntax_warnings = val.get("syntax_warnings") or []
    skip_indices: set[int] = set()
    for w in syntax_warnings:
        m = re.search(r"step\[(\d+)\]", w)
        if m:
            skip_indices.add(int(m.group(1)))

    _audit_log.info(
        f"[AUDIT] 启动 executor: plan_id={plan.get('plan_id')} steps={len(steps)} target={target_url}"
    )

    # 初始化沙箱
    sandbox: DockerSandbox | None = None
    try:
        sandbox = DockerSandbox(image=docker_image, timeout=timeout_sec)
        if not sandbox.is_available():
            if dockerfile_dir and dockerfile_dir.exists():
                sandbox.build_image(dockerfile_dir)
            if not sandbox.is_available():
                raise SecurityViolationError(
                    f"Docker 镜像 '{docker_image}' 不存在且构建失败！拒绝执行攻击代码。"
                )
        elif not sandbox._image_verified:
            print(f"[executor] 验证 Docker 镜像工具 {docker_image} ...")
            ok, missing = sandbox.verify_image_tools()
            if ok:
                sandbox._image_verified = True
                print("[executor] 镜像验证通过。")
            else:
                print(f"[executor] 镜像缺少工具: {missing}，尝试重建...")
                if dockerfile_dir and dockerfile_dir.exists():
                    if sandbox.build_image(dockerfile_dir, force=True):
                        ok2, missing2 = sandbox.verify_image_tools()
                        if ok2:
                            sandbox._image_verified = True
                        else:
                            raise SecurityViolationError(f"重建后仍缺少工具: {missing2}！")
                    else:
                        raise SecurityViolationError("镜像构建失败！")
                else:
                    raise SecurityViolationError("无 Dockerfile 目录，无法重建镜像。")
    except SecurityViolationError:
        raise
    except DockerException as e:
        raise SecurityViolationError(f"Docker 引擎异常: {e}！") from e

    # 准备执行工作区
    exec_workspace = _prepare_exec_workspace(workdir)
    print(f"[executor] 执行工作区: {exec_workspace}")

    step_results: list[dict[str, Any]] = []
    blocked_count = 0
    chain_context: dict[str, str] = {}

    for i, st in enumerate(steps):
        if i in skip_indices:
            step_results.append({
                "step_id": st.get("id"), "type": st.get("type"), "purpose": st.get("purpose"),
                "result": {
                    "ok": False, "exit_code": -1, "stdout": "", "duration_sec": 0.0,
                    "stderr": f"validator 检测到语法错误，已跳过: {syntax_warnings}",
                    "execution_mode": "skipped_syntax_error",
                },
                "chain_output": {},
            })
            continue

        try:
            result, step_chain_output = _run_step(
                st, timeout_sec, exec_workspace, sandbox,
                env_vars=sandbox_env or None, target_url=target_url, target=target,
            )
        except SecurityViolationError as e:
            result = {
                "ok": False, "exit_code": -1, "stdout": "", "stderr": str(e),
                "duration_sec": 0.0, "execution_mode": "security_blocked",
            }
            step_chain_output = {}
            blocked_count += 1

        if step_chain_output:
            chain_context.update(step_chain_output)

        # 从 stdout 中提取 ###CHAIN_OUTPUT###
        stdout = result.get("stdout", "")
        fallback_chain: dict = {}
        marker = "###CHAIN_OUTPUT###"
        if stdout and marker in stdout:
            idx = stdout.find(marker)
            remaining = stdout[idx + len(marker):].lstrip()
            if remaining.startswith("{"):
                depth, end = 0, 0
                for ci, ch in enumerate(remaining):
                    if ch == "{": depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            end = ci + 1
                            break
                if end:
                    try:
                        fallback_chain = json.loads(remaining[:end])
                        if fallback_chain:
                            chain_context.update(fallback_chain)
                            step_chain_output = {**step_chain_output, **fallback_chain}
                    except json.JSONDecodeError:
                        pass

        if step_chain_output:
            print(
                f"[executor] step {st.get('id')} chain_output: "
                f"{json.dumps(step_chain_output, ensure_ascii=False)[:200]}"
            )

        step_results.append({
            "step_id": st.get("id"),
            "type":    st.get("type"),
            "purpose": st.get("purpose"),
            "result":  result,
            "chain_output": step_chain_output,
        })

    fail_results = [r for r in step_results if not (r.get("result") or {}).get("ok")]
    if fail_results and len(fail_results) == len(step_results):
        stderrs = [(r.get("result") or {}).get("stderr", "")[:120] for r in fail_results]
        if len(set(stderrs)) <= 2:
            print(f"[executor] 所有 {len(step_results)} 个步骤均失败/被拦截:")
            print(f"[executor]   stderr: {stderrs[0]}")

    execution_mode = "docker" if sandbox and sandbox.is_available() else "security_blocked"
    out = {
        "version": 1,
        "executed": True,
        "plan_id":  plan.get("plan_id"),
        "workdir":  str(workdir.resolve()),
        "step_results":    step_results,
        "chain_context":   chain_context,
        "execution_mode":  execution_mode,
        "security_policy": "ENFORCED_DOCKER_ONLY",
        "total_steps":     len(steps),
        "blocked_steps":   blocked_count,
    }
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    _audit_log.info(
        f"[AUDIT] Executor 完成: mode={execution_mode} total={len(steps)} blocked={blocked_count}"
    )
    return out
