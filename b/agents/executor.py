from __future__ import annotations

import json
import hashlib
import logging
import re
import socket
import textwrap
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
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_WORKSPACE    = "/workspace"
_TMP_DIR      = "/workspace/tmp"
_CONTEXT_PATH = f"{_TMP_DIR}/context.json"
_SESSION_PATH = f"{_TMP_DIR}/session.json"

_CRLF = chr(13) + chr(10)
_CRLF2 = _CRLF * 2


# ── RawResponse ──────────────────────────────────

class RawResponse:
    \"\"\"HTTP response parsed from raw socket bytes for raw_request().\"\"\"

    def __init__(self, raw: str):
        self._raw = raw
        parts = raw.split(_CRLF2, 1)
        self._body = parts[1] if len(parts) > 1 else ""
        header_block = parts[0]
        lines = header_block.split(_CRLF)
        status_line = lines[0]
        status_parts = status_line.split(" ", 2)
        self.status_code = int(status_parts[1]) if len(status_parts) > 1 else 0
        self.text = self._body

        self.headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                self.headers[k.strip().lower()] = v.strip()

    def json(self) -> dict:
        import json as _json
        return _json.loads(self._body)


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

    def raw_request(self, method: str, path: str, headers: dict | None = None,
                    body: str = "") -> "RawResponse":
        \"\"\"Send a raw HTTP request via socket, bypassing URL normalization.

        Use this when requests.Session strips characters like '#', '%00', '..;'
        that are essential for HAProxy / WAF bypass. The path is sent verbatim.

        Returns a RawResponse with .status_code, .text, .headers, .json().
        \"\"\"
        parsed = urlparse(self.base_url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_tls = parsed.scheme == "https"

        hdr_lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
        if headers:
            for k, v in headers.items():
                hdr_lines.append(f"{k}: {v}")
        else:
            hdr_lines.append("Connection: close")
        if body:
            if not headers or "Content-Length" not in {k.lower() for k in headers}:
                hdr_lines.append(f"Content-Length: {len(body)}")
        hdr_lines.append("")
        if body:
            hdr_lines.append(body)
        hdr_lines.append("")
        raw = _CRLF.join(hdr_lines)

        # create_connection iterates ALL getaddrinfo results (cf. Docker
        # extra_hosts where localhost resolves to both 127.0.0.1 and the
        # target container IP). Plain socket.connect() only tries the first.
        sock = socket.create_connection((host, port), timeout=15)
        try:
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host, do_handshake_on_connect=False)
                sock.do_handshake()
            sock.sendall(raw.encode())
            resp_data = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    resp_data += chunk
                except socket.timeout:
                    break
        finally:
            sock.close()

        return RawResponse(resp_data.decode("utf-8", errors="replace"))

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

    def get_callbacks(self) -> list[dict]:
        \"\"\"Backward-compat alias for get_all_hits().\"\"\"
        return self.get_all_hits()

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
#  Task 6: AST → code inflater
# ──────────────────────────────────────────────

def _inflate_ast_to_script(step: dict[str, Any]) -> str:
    """Generate a runnable Python script from structured sdk_calls + imports.

    When Planner outputs declarative AST (imports + sdk_calls) without raw
    command code, this inflater generates the executable Python.
    Execution priority (enforced by _run_docker): sdk_calls > code > command.
    """
    imports = step.get("imports") or []
    sdk_calls = step.get("sdk_calls") or []

    # If no sdk_calls, return raw command/code unchanged
    if not sdk_calls:
        return step.get("code") or step.get("command", "")

    # Build from sdk_calls
    lines: list[str] = []

    # Deduplicate imports (wrapper already does "from redteam_sdk import *")
    # json is already inlined below; don't duplicate
    seen_imports: set[str] = {"redteam_sdk", "json"}
    for imp in imports:
        if imp not in seen_imports:
            seen_imports.add(imp)
            lines.append(f"import {imp}")

    # SDK already injected by wrapper, just reference it
    lines.extend([
        "",
        "import json",
        "# Load prior step context (RW tmp copy has save_context() data; RO copy has base_url)",
        "try:",
        "    with open('/workspace/tmp/context.json') as f: _prior_ctx = json.load(f)",
        "except (FileNotFoundError, json.JSONDecodeError):",
        "    with open('/workspace/context.json') as f: _prior_ctx = json.load(f)",
        "target_base = _prior_ctx.get('target_context', {}).get('base_url', '')",
        "s = HttpClient(target_base)",
        "",
    ])

    for call in sdk_calls:
        if isinstance(call, dict):
            primitive = call.get("primitive", "")
            target = call.get("target", "/")
            body = call.get("body")
            raw = call.get("raw", b"")
        else:
            primitive = str(call)
            target = "/"
            body = None
            raw = b""

        if primitive == "HttpClient.get":
            lines.append(f'resp = s.get("{target}")')
            lines.append('print(f"HTTP {resp.status_code}: {resp.text[:2000]}")')
            lines.append('save_context("_last_response_text", resp.text[:2000])')
            lines.append('save_context("_last_status", resp.status_code)')
        elif primitive == "HttpClient.post":
            body_str = json.dumps(body) if body else "{}"
            lines.append(f'resp = s.post("{target}", json={body_str})')
            lines.append('print(f"HTTP {resp.status_code}: {resp.text[:2000]}")')
            lines.append('save_context("_last_response_text", resp.text[:2000])')
            lines.append('save_context("_last_status", resp.status_code)')
        elif primitive == "HttpClient.raw_request":
            raw_val = json.dumps(raw.decode() if isinstance(raw, bytes) else str(raw))
            lines.append(f'resp = s.raw_request("{target}", {raw_val})')
            lines.append('print(resp)')
            lines.append('save_context("_last_raw_response", resp.text[:2000])')
        elif primitive == "HttpClient.last_response":
            lines.append('print(f"Last response: {s.last_response}")')

    lines.append("print('STEP_OK')")
    return "\n".join(lines)


# ──────────────────────────────────────────────
#  物理硬截断（防上下文爆满 / 注意力涣散）
# ──────────────────────────────────────────────

_HARD_TRUNC_THRESHOLD = 8000
_HARD_TRUNC_HEAD      = 2000
_HARD_TRUNC_TAIL      = 4000


def _hard_truncate(text: str, threshold: int = _HARD_TRUNC_THRESHOLD,
                   head: int = _HARD_TRUNC_HEAD, tail: int = _HARD_TRUNC_TAIL) -> str:
    """Physical head+tail truncation — never summarize, always preserve raw bytes.

    When output exceeds *threshold* chars, keep the first *head* chars (usually
    request/command context) and the last *tail* chars (usually error / stack
    trace / flag), replacing the middle with a marker.  The result is always
    raw, verbatim substrings — no LLM summarization, no semantic compression.
    """
    if len(text) <= threshold:
        return text
    omitted = len(text) - head - tail
    return f"{text[:head]}\n...[TRUNCATED {omitted} chars]...\n{text[-tail:]}"
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
    (r"\btime\.sleep\s*\(\s*(\d+(?:\.\d+)?)\s*\)", "time_sleep_long"),
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

def _find_target_container_network(client: docker.DockerClient, host: str, port: int) -> str | None:
    """Auto-detect the Docker network of the target container by its host port binding.

    Returns the network name (e.g. 'shared_net') so sandbox can join it directly,
    or None if no container publishes the given port — fall back to bridge+host-gateway.
    """
    try:
        for c in client.containers.list():
            ports = (c.attrs.get("NetworkSettings", {}) or {}).get("Ports", {}) or {}
            for container_port, bindings in (ports or {}).items():
                if not bindings:
                    continue
                for b in bindings:
                    if b and str(b.get("HostPort")) == str(port):
                        nets = c.attrs.get("NetworkSettings", {}).get("Networks", {})
                        if nets:
                            net_name = next(iter(nets.keys()))
                            target_ip = nets[net_name].get("IPAddress", "")
                            _audit_log.info(
                                f"[NETWORK] 发现目标容器 {c.name} 在 {net_name} (IP={target_ip})"
                            )
                            return net_name
        return None
    except Exception as e:
        _audit_log.warning(f"[NETWORK] 扫描目标网络失败: {e}")
        return None


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
        m = re.search(pattern, code)
        if not m:
            continue
        if label == "time_sleep_long":
            # 仅禁止 sleep > 3s；短 sleep 合法
            try:
                duration = float(m.group(1))
                if duration <= 3:
                    continue
            except (ValueError, IndexError):
                pass
        violations.append(label)
        _audit_log.warning(f"[SECURITY] PYTHON_BLOCKED pattern='{label}' step={step_id}")
    return violations


# ──────────────────────────────────────────────
#  工作区准备：SDK + context.json + tmp 目录
# ──────────────────────────────────────────────


def _stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _build_materialized_execution_record(
    selected_canonical_strategy_id: str,
    method: str,
    endpoint: str,
    parameter: str,
    payload: str,
) -> dict[str, Any]:
    normalized_method = str(method or "").strip().upper()
    normalized_endpoint = str(endpoint or "/").strip() or "/"
    normalized_parameter = str(parameter or "").strip()
    normalized_body = {normalized_parameter: payload}
    parameter_names = sorted(normalized_body.keys())
    normalized_body_json = _stable_json(normalized_body)
    execution_source = _stable_json({
        "method": normalized_method,
        "endpoint": normalized_endpoint,
        "parameters": parameter_names,
        "body": normalized_body,
    })
    return {
        "selected_canonical_strategy_id": selected_canonical_strategy_id,
        "materialized": True,
        "request_method": normalized_method,
        "request_endpoint": normalized_endpoint,
        "request_parameters": parameter_names,
        "normalized_request_body": normalized_body,
        "request_body_fingerprint": _sha256_text(normalized_body_json),
        "execution_fingerprint": _sha256_text(execution_source),
        "request_sent": False,
    }


def _mark_materialized_request_sent(
    record: dict[str, Any],
    http_responses: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    out = dict(record)
    out["request_sent"] = bool(http_responses)
    out["http_responses"] = list(http_responses or [])
    return out


def _materialize_strategy_request(selected_sid: str, target: "TargetContext | None") -> dict | None:
    """Read YAML template + RuntimeTruths → synthesize exact HTTP request step."""
    import sys, yaml
    from pathlib import Path as _Path
    # Ensure b/ is on path for memory.runtime_truths import
    _b_root = _Path(__file__).resolve().parent.parent
    if str(_b_root) not in sys.path:
        sys.path.insert(0, str(_b_root))
    from memory.runtime_truths import get_runtime_truths
    _rtt = get_runtime_truths()
    method = str(_rtt.get("injection_method") or "POST")
    endpoint = str(_rtt.get("injection_endpoint") or "/")
    param = str(_rtt.get("injection_parameter") or "text")
    target_url = target.url.rstrip("/") if target else "http://127.0.0.1:1"
    tmpl_dir = _Path(__file__).resolve().parent.parent / "templates"
    for yf in tmpl_dir.rglob("*.yaml"):
        with open(yf, encoding="utf-8") as f:
            d = yaml.safe_load(f)
        for pt in d.get("payload_templates", []):
            if pt.get("canonical_strategy_id") == selected_sid:
                tpl = pt.get("template", "")
                if not tpl:
                    print(f"[executor] materializer: {selected_sid} has empty template, skipping")
                    return None
                import re as _re
                if _re.search(r'[A-Z_]{4,}', tpl) and not _re.search(r'[a-z0-9]', tpl.split('(')[-1].split(')')[0] if '(' in tpl else ''):
                    print(f"[executor] materializer REJECT: unresolved placeholder in template: {repr(tpl)}")
                    return None
                code = (
                    f"import redteam_sdk\n"
                    f"s = redteam_sdk.HttpClient('{target_url}')\n"
                    f"payload = {repr(tpl)}\n"
                    f"resp = s.{method.lower()}('{endpoint}', data={{'{param}': payload}})\n"
                    f"print(f'HTTP {{resp.status_code}}: {{resp.text[:2000]}}')\n"
                    f"print('STEP_OK')"
                )
                materialized_record = _build_materialized_execution_record(
                    selected_canonical_strategy_id=selected_sid,
                    method=method,
                    endpoint=endpoint,
                    parameter=param,
                    payload=tpl,
                )
                print(f"[executor] materialized {selected_sid}: {method} {endpoint} {param}={repr(tpl)[:50]}")
                return {
                    "id": "materialized-1",
                    "type": "python",
                    "command": code,
                    "purpose": f"materialized {selected_sid} via {method} {endpoint}?{param}=...",
                    "expected_outcome": "STEP_OK",
                    "_materialized_execution_record": materialized_record,
                }
    print(f"[executor] materializer: {selected_sid} not found in any YAML")
    return None


def _prepare_exec_workspace(base_workdir: Path, target_context: dict | None = None) -> Path:
    """
    准备执行工作区：
    - exec_workspace/          → 只读挂载到 /workspace
    - exec_workspace/tmp/      → 可写挂载到 /workspace/tmp
    - exec_workspace/redteam_sdk.py  → 注入 SDK
    - exec_workspace/context.json    → 步骤间通信文件（预注入 target_context）
    """
    ws = base_workdir / "co_redteam_exec"
    ws.mkdir(parents=True, exist_ok=True)

    # 写入 SDK（二进制模式避免 Windows \\n→\\r\\n 转换破坏字符串字面量）
    sdk_path = ws / "redteam_sdk.py"
    sdk_path.write_bytes(_SDK_SOURCE.encode("utf-8"))

    # 初始化 context — 预注入 target_context 以便 LLM 脚本读取 base_url
    # 同时写入 ro 区（供脚本初始读取）和 tmp（供 save_context 写入）
    ctx_file = ws / "context.json"
    initial: dict[str, Any] = {}
    if target_context:
        initial["target_context"] = target_context
    ctx_file.write_text(json.dumps(initial, ensure_ascii=False), encoding="utf-8")

    # 创建可写 tmp 目录
    tmp_dir = ws / "tmp"
    tmp_dir.mkdir(exist_ok=True)
    # 同时写入可写区，让 save_context 有初始数据可以追加
    tmp_ctx = tmp_dir / "context.json"
    tmp_ctx.write_text(json.dumps(initial, ensure_ascii=False), encoding="utf-8")

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
          优先检测目标容器所在的 Docker 网络并直连（容器→容器，不经过宿主机）。
          若无法检测则回退到 bridge + extra_hosts。
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

        # ── 网络策略：优先直连靶机容器网络（不经过宿主机） ──
        target_net: str | None = None
        target_container_ip: str = ""
        extra_hosts: dict[str, str] = {}

        # 尝试通过端口映射找到靶机容器所在的 Docker 网络
        if target_port and self.client:
            target_net = _find_target_container_network(self.client, target_host or "", target_port)

        if target_net:
            # 加入靶机容器所在网络，直接容器间通信，绕过宿主机
            network_mode = target_net
            # 查找目标容器在该网络上的 IP 以构建 extra_hosts
            try:
                for c in self.client.containers.list():
                    nets = c.attrs.get("NetworkSettings", {}).get("Networks", {})
                    if target_net in nets:
                        target_container_ip = nets[target_net].get("IPAddress", "")
                        break
                if target_container_ip:
                    extra_hosts["host.docker.internal"] = target_container_ip
                    extra_hosts["localhost"] = target_container_ip
                    _audit_log.info(
                        f"[NETWORK] step={step_id} target_net={target_net} container_ip={target_container_ip} "
                        f"mode=direct-container-to-container (ZERO host traffic)"
                    )
            except Exception as e:
                _audit_log.warning(f"[NETWORK] 获取目标容器 IP 失败: {e}")
        else:
            # 回退：bridge + host-gateway（仅当目标确实是宿主机端口时）
            network_mode = "bridge"
            needs_host_gateway = (
                target_ip == "host-gateway"
                or (target_host and target_host in ("host.docker.internal", "localhost"))
                or (target_url and any(h in target_url for h in ("host.docker.internal", "localhost")))
            )
            if needs_host_gateway:
                extra_hosts["host.docker.internal"] = "host-gateway"
                extra_hosts["localhost"] = "host-gateway"
                _audit_log.warning(
                    f"[NETWORK] step={step_id} host={target_host} mode=bridge+host-gateway "
                    f"(FALLBACK — traffic may route through Docker host)"
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
                network_mode=network_mode,
            )
            if extra_hosts:
                create_kwargs["extra_hosts"] = extra_hosts

            container = self.client.containers.create(**create_kwargs)
            container.start()
            result = container.wait(timeout=self.timeout)

            stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
            stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")
            exit_code = result.get("StatusCode", -1)

            # Physical hard-truncation: keep head + tail of raw output, no LLM summarization
            stdout = _hard_truncate(stdout)
            stderr = _hard_truncate(stderr, threshold=2000, head=600, tail=800)

            return {
                "ok": exit_code == 0,
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
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
                    "stdout": _hard_truncate(stdout) if stdout else "",
                    "stderr": _hard_truncate(stderr or "Container execution timeout", threshold=2000, head=600, tail=800),
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

_HTTP_LOG_RE = re.compile(
    r"\[HTTP\]\s+(\d{3})\s+(\w+)\s+(\S+?)\s*=>\s*(.*?)(?=\n\[HTTP\]|\nSTEP_OK|\nSTEP_FAIL|\Z)",
    re.DOTALL,
)


def _extract_http_responses_from_stdout(stdout: str) -> list[dict[str, Any]]:
    """Parse [HTTP] markers injected by the auto-logging wrapper and extract structured HTTP response data."""
    responses: list[dict[str, Any]] = []
    for m in _HTTP_LOG_RE.finditer(stdout):
        responses.append({
            "status_code": int(m.group(1)),
            "method": m.group(2),
            "url": m.group(3),
            "response_body": m.group(4)[:2000],
        })
    return responses


def _run_docker(
    step: dict[str, Any],
    sandbox: DockerSandbox,
    exec_workspace: Path,
    env_vars: dict[str, str] | None = None,
    target_url: str = "",
    target: "TargetContext | None" = None,
) -> tuple[dict[str, Any], dict]:
    stype   = step.get("type")
    step_id = step.get("id", 0)

    # ── Protocol Unification: execution priority ──
    # sdk_calls > code > command (no fallback mixing)
    sdk_calls = step.get("sdk_calls") or []
    if sdk_calls:
        code = _inflate_ast_to_script(step)
        print(f"[executor] using AST compiler path step[{step_id}] ({len(code)} chars)")
    elif step.get("code"):
        code = step["code"]
        print(f"[executor] using code field step[{step_id}] ({len(code)} chars)")
    elif step.get("command"):
        code = (step["command"] or "").strip()
        print(f"[executor] using command field step[{step_id}] (LEGACY) ({len(code)} chars)")
    else:
        code = ""
        print(f"[executor] step[{step_id}] no executable payload (no sdk_calls/code/command)")

    if stype != "python":
        return {
            "ok": False, "exit_code": -1, "stdout": "", "stderr": f"不支持的 type: {stype}",
            "duration_sec": 0.0, "execution_mode": "docker",
        }, {}

    if not code or not code.strip():
        return {
            "ok": False, "exit_code": -1, "stdout": "",
            "stderr": "步骤无可执行代码（sdk_calls/code/command 均为空）",
            "duration_sec": 0.0, "execution_mode": "docker",
        }, {}

    # ── RuntimeTruths last-resort: auto-swap GET→POST when override active ──
    runtime_override = step.get("_runtime_override") or {}
    if runtime_override.get("http_method") == "POST":
        inject_param = runtime_override.get("inject_param", "text")
        original_code = code
        # Swap .get() → .post() for bare paths
        code = re.sub(r"\.get\s*\(\s*['\"]/", ".post('/", code)
        code = re.sub(r'\.get\s*\(\s*["\"]/', '.post("/', code)
        # Swap params= → data= (GET query style → POST body style)
        if "params=" in code and "data=" not in code:
            code = code.replace("params=", "data=")
            code = re.sub(
                r"data=\s*\{",
                f"data={{'{inject_param}': ",
                code,
                count=1,
            )
            print(
                f"[executor] last-resort POST override step[{step_id}]: "
                f"params=→data=, inject_param={inject_param}"
            )
        if code != original_code:
            print(
                f"[executor] last-resort POST override step[{step_id}]: "
                f".get(→.post( applied"
            )

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
    import textwrap
    indented_code = textwrap.indent(code, "    ")
    wrapped_code = (
        "import sys, traceback, json as _json\n"
        "sys.path.insert(0, '/workspace')\n"
        "from redteam_sdk import *\n"
        "# ── Cross-step context restore (auto-injected by Executor) ──\n"
        "_prior = load_all_context()\n"
        "# ── HTTP auto-logging instrumentation (injected by Executor) ──\n"
        "_hc_req_orig = HttpClient.request\n"
        "def _hc_req(self, method, url, *a, **kw):\n"
        "    try:\n"
        "        resp = _hc_req_orig(self, method, url, *a, **kw)\n"
        "        body = (resp.text or '')[:500]\n"
        "        print(f'[HTTP] {resp.status_code} {method} {url} => {body}')\n"
        "        return resp\n"
        "    except Exception as _e:\n"
        "        print(f'[HTTP_ERR] {method} {url}: {_e}')\n"
        "        raise\n"
        "HttpClient.request = _hc_req\n"
        "# ── User script ──\n"
        "try:\n"
        + indented_code +
        "\n    print('STEP_OK')\n"
        "except Exception as _exec_e:\n"
        "    _script_err = _json.dumps({'error': str(_exec_e), 'traceback': traceback.format_exc()}, ensure_ascii=False)\n"
        "    print('STEP_FAIL: ' + _script_err)\n"
        "finally:\n"
        "    try:\n"
        "        ensure_session_persisted()\n"
        "    except Exception:\n"
        "        pass\n"
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

    # 读取 context.json 作为 chain_output（优先读 tmp/ 下的可写副本）
    chain_output: dict = {}
    for candidate in (exec_workspace / "tmp" / "context.json", exec_workspace / "context.json"):
        if candidate.exists():
            try:
                raw = candidate.read_text(encoding="utf-8").strip()
                if raw and raw != "{}":
                    chain_output = json.loads(raw)
                    break
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
    materialized_execution_record: dict[str, Any] | None = None

    # ── Materializer: if plan has selected_canonical_strategy_id, use YAML + RuntimeTruths ──
    selected_sid = plan.get("selected_canonical_strategy_id", "")
    if selected_sid:
        materialized_step = _materialize_strategy_request(selected_sid, target)
        if materialized_step:
            steps = [materialized_step]
            materialized_execution_record = materialized_step.get("_materialized_execution_record")
            print(f"[executor] materialized {selected_sid} step cmd={materialized_step['command'][:200]}")
        else:
            print(f"[executor] materializer returned None for {selected_sid}, falling back to plan steps")

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

    # 仅跳过有真实 Python SyntaxError 的步骤（不是 POLYGLOT / exploit_reasoning / trajectory 警告）
    # _check_python_syntax() 产生的 SyntaxError 标记为 "Python 语法错误（Planner 请修正后重新生成此步骤）"
    # POLYGLOT / exploit_reasoning / primitive_context / trajectory 警告不应阻断执行
    _SYNTAX_ERROR_RE = re.compile(r"Python 语法错误（Planner 请修正后重新生成此步骤）")
    syntax_warnings = val.get("syntax_warnings") or []
    skip_indices: set[int] = set()
    for w in syntax_warnings:
        if not _SYNTAX_ERROR_RE.search(w):
            continue  # 非语法错误的 warning，不跳过
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
    tc_dict: dict[str, Any] = {}
    if target is not None:
        tc_dict = {"base_url": target.url, "host": target.hostname, "port": target.port, "scheme": target.scheme}
    elif target_url:
        tc_dict = {"base_url": target_url}
    exec_workspace = _prepare_exec_workspace(workdir, target_context=tc_dict if tc_dict else None)
    print(f"[executor] 执行工作区: {exec_workspace}")

    step_results: list[dict[str, Any]] = []
    blocked_count = 0
    chain_context: dict[str, str] = {}

    for i, st in enumerate(steps):
        # ═══════════════════════════════════════════════════════════
        # 注入点诊断日志：确认 Planner 生成的代码中是否包含注入参数
        # 这是整个流水线最关键的自检点 — ?text= 没有出现 = 注入点信息丢失
        # ═══════════════════════════════════════════════════════════
        raw_code = (
            st.get("command") or st.get("code") or
            ("sdk_calls=" + str(st.get("sdk_calls", [])) if st.get("sdk_calls") else "")
        )
        has_injection_param = bool(
            re.search(r'\?(?:text|param|q|query|search|input|id|name|username)=', raw_code)
            if raw_code else False
        )
        print(
            f"[executor] step[{st.get('id')}] injection_param={'YES' if has_injection_param else 'NO'} "
            f"url_fragment={(raw_code or '')[:180]}"
        )
        if i in skip_indices:
            skipped_entry = {
                "step_id": st.get("id"), "type": st.get("type"), "purpose": st.get("purpose"),
                "result": {
                    "ok": False, "exit_code": -1, "stdout": "", "duration_sec": 0.0,
                    "stderr": f"validator ???????????: {syntax_warnings}",
                    "execution_mode": "skipped_syntax_error",
                },
                "chain_output": {},
            }
            step_record = st.get("_materialized_execution_record")
            if isinstance(step_record, dict):
                materialized_execution_record = _mark_materialized_request_sent(step_record, [])
                skipped_entry["materialized_execution_record"] = materialized_execution_record
            step_results.append(skipped_entry)
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
        stderr = result.get("stderr", "")
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

        # 从 stdout 中提取 HTTP 响应记录
        http_responses = _extract_http_responses_from_stdout(stdout)

        # 将 stdout / stderr / HTTP 响应合并进 chain_output，使 Evaluator/Planner 能读取真实输出
        if stdout:
            step_chain_output["_stdout"] = stdout[-3000:]
        if stderr:
            step_chain_output["_stderr"] = stderr[-1000:]
        if http_responses:
            step_chain_output["_http_responses"] = http_responses

        if step_chain_output:
            print(
                f"[executor] step {st.get('id')} chain_output: "
                f"{json.dumps(step_chain_output, ensure_ascii=False)[:200]}"
            )

        step_entry = {
            "step_id": st.get("id"),
            "type":    st.get("type"),
            "purpose": st.get("purpose"),
            "result":  result,
            "chain_output": step_chain_output,
            "http_responses": http_responses,
        }
        step_record = st.get("_materialized_execution_record")
        if isinstance(step_record, dict):
            materialized_execution_record = _mark_materialized_request_sent(step_record, http_responses)
            step_entry["materialized_execution_record"] = materialized_execution_record
        step_results.append(step_entry)

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
    if materialized_execution_record:
        out["materialized_execution_record"] = materialized_execution_record
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    _audit_log.info(
        f"[AUDIT] Executor 完成: mode={execution_mode} total={len(steps)} blocked={blocked_count}"
    )
    return out
