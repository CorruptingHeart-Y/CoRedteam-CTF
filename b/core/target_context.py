from __future__ import annotations

import socket
from dataclasses import dataclass
from urllib.parse import urlparse


class TargetLockError(ValueError):
    """Raised when the user-supplied target URL cannot be locked."""


@dataclass(frozen=True)
class TargetContext:
    """Single source of truth for the locked exploit target.

    The URL is parsed once at the CLI boundary and threaded down through
    coordinator, planner prompts, executor, and Docker network rules. No
    component is permitted to fabricate a different URL or host.
    """

    url: str
    scheme: str
    hostname: str
    port: int
    ip: str

    @property
    def base_url(self) -> str:
        return self.url

    @property
    def authority(self) -> str:
        return f"{self.hostname}:{self.port}"

    @property
    def is_https(self) -> bool:
        return self.scheme == "https"

    def as_env(self) -> dict[str, str]:
        return {
            "CO_REDTEAM_TARGET_URL": self.url,
            "CO_REDTEAM_TARGET_HOST": self.hostname,
            "CO_REDTEAM_TARGET_PORT": str(self.port),
            "CO_REDTEAM_TARGET_IP": self.ip,
            "CO_REDTEAM_TARGET_SCHEME": self.scheme,
        }


def lock_target(url: str) -> TargetContext:
    """Parse, validate and DNS-resolve the user-supplied URL exactly once."""
    if not url or not url.strip():
        raise TargetLockError("--url 不能为空")
    raw = url.strip()
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise TargetLockError(
            f"--url 必须以 http:// 或 https:// 开头，收到: {raw!r}"
        )
    if not parsed.hostname:
        raise TargetLockError(f"--url 缺少主机名: {raw!r}")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    try:
        ip = socket.gethostbyname(parsed.hostname)
    except OSError as e:
        raise TargetLockError(
            f"无法解析目标主机 {parsed.hostname!r}: {e}"
        ) from e

    canonical = f"{parsed.scheme}://{parsed.hostname}:{port}"
    if parsed.path and parsed.path != "/":
        canonical += parsed.path.rstrip("/")

    return TargetContext(
        url=canonical,
        scheme=parsed.scheme,
        hostname=parsed.hostname,
        port=port,
        ip=ip,
    )
