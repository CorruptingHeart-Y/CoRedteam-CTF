from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any


# ── Payload Fingerprint 算法 ──────────────────────────────────────────


def normalize_template(template: str, lang: str = "text") -> str:
    """规范化 payload 模板，消除空白/缩进/注释/硬编码地址差异。

    用于生成去重指纹，确保语义等价的 payload 产生相同 hash。
    """
    t = template.strip()
    # 统一换行符
    t = t.replace("\r\n", "\n").replace("\r", "\n")
    # 去除尾部空白行
    while t.endswith("\n\n"):
        t = t[:-1]
    # Python 代码：strip 每行空白、移除注释行
    if lang in ("python",):
        lines = []
        for line in t.split("\n"):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            lines.append(stripped)
        t = "\n".join(lines)
    # URL/IP/端口归一化
    t = re.sub(r"https?://[^\s\"')\]]+", "{{TARGET_URL}}", t)
    t = re.sub(r"host\.docker\.internal:\d+", "{{TARGET_URL}}", t)
    t = re.sub(r"localhost:\d+", "{{TARGET_URL}}", t)
    t = re.sub(r"domain=\".+?\"", "domain=\"{{CALLBACK}}\"", t)
    t = re.sub(r"port=\d+", "port={{PORT}}", t)
    # Velocity 变量名归一化
    t = re.sub(r"\$(\w+)", r"$VAR", t)
    t = t.strip()
    return t


def fingerprint(template: str, lang: str = "text") -> str:
    """计算 payload 的唯一指纹。

    Args:
        template: 原始 payload 模板文本
        lang: 语言类型 (python, text, etc.)

    Returns:
        SHA256 前 16 位 hex 字符串
    """
    normalized = normalize_template(template, lang)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def fingerprint_entry(entry: dict[str, Any]) -> str:
    """从 tech.json 条目计算指纹。

    使用 template 或 payload 字段，并考虑 lang 字段。
    """
    template = entry.get("template") or entry.get("payload") or ""
    lang = entry.get("lang", "text")
    return fingerprint(str(template), str(lang))


# ── 全局注册表 — 内存+磁盘双重存储 ───────────────────────────────────


_REGISTRY_FILE = "payload_registry.json"


class PayloadRegistry:
    """全局 payload 指纹注册表，防止重复写入。

    启动时从磁盘加载，所有写入点在 append 前查验。
    每条 payload 被首次接受后自动注册。
    """

    def __init__(self, memory_dir: Path) -> None:
        self._memory_dir = memory_dir
        self._registry_path = memory_dir / _REGISTRY_FILE
        self._fingerprints: dict[str, dict[str, Any]] = {}
        # 为 tech.json 已有条目预加载指纹，防止存量重复被忽略
        self._load_existing_tech_entries()
        self._load_disk_registry()

    # ── 磁盘读写 ──

    def _load_disk_registry(self) -> None:
        if self._registry_path.exists():
            try:
                data = json.loads(self._registry_path.read_text(encoding="utf-8"))
                self._fingerprints.update(data.get("fingerprints", {}))
            except (json.JSONDecodeError, OSError):
                pass

    def _save_disk_registry(self) -> None:
        self._registry_path.parent.mkdir(parents=True, exist_ok=True)
        self._registry_path.write_text(
            json.dumps({"fingerprints": self._fingerprints, "_updated": time.time()},
                       ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def _load_existing_tech_entries(self) -> None:
        """扫描 tech.json 中已有条目并注册指纹，防止存量被忽略。"""
        tech_path = self._memory_dir / "tech.json"
        if not tech_path.exists():
            return
        try:
            data = json.loads(tech_path.read_text(encoding="utf-8"))
            for entry in data.get("payload_templates", []):
                self._register_entry_internal(entry, persist=False)
        except (json.JSONDecodeError, OSError):
            pass

    def _register_entry_internal(self, entry: dict[str, Any], persist: bool = True) -> str:
        """内部注册，返回指纹。"""
        fp = fingerprint_entry(entry)
        if fp not in self._fingerprints:
            self._fingerprints[fp] = {
                "first_seen": time.time(),
                "name": entry.get("name", "")[:80],
                "source": entry.get("source", "unknown"),
                "cwe": entry.get("cwe", ""),
            }
            if persist:
                self._save_disk_registry()
        return fp

    # ── 公开 API ──

    def is_duplicate(self, entry: dict[str, Any]) -> bool:
        """检查一条 payload 是否已存在。"""
        return fingerprint_entry(entry) in self._fingerprints

    def register(self, entry: dict[str, Any]) -> str:
        """注册一条新 payload。返回其指纹。"""
        return self._register_entry_internal(entry, persist=True)

    def register_many(self, entries: list[dict[str, Any]]) -> int:
        """批量注册。返回新增数量。"""
        added = 0
        for entry in entries:
            fp = fingerprint_entry(entry)
            if fp not in self._fingerprints:
                self._register_entry_internal(entry, persist=False)
                added += 1
        if added > 0:
            self._save_disk_registry()
        return added

    @property
    def count(self) -> int:
        return len(self._fingerprints)

    def stats(self) -> dict[str, Any]:
        sources: dict[str, int] = {}
        cwes: dict[str, int] = {}
        for fp, info in self._fingerprints.items():
            src = info.get("source", "unknown")
            sources[src] = sources.get(src, 0) + 1
            cwe = info.get("cwe", "UNKNOWN")
            cwes[cwe] = cwes.get(cwe, 0) + 1
        return {
            "total_fingerprints": self.count,
            "by_source": sources,
            "by_cwe": cwes,
        }


# ── Memory Score ──────────────────────────────────────────────────────

_SCORE_DEFAULTS = {
    "success_count": 0,
    "failure_count": 0,
    "score": 0,
    "last_used": 0.0,
    "last_success": 0.0,
}


def _calc_score(success_count: int, failure_count: int, last_success: float) -> float:
    """计算 payload 质量评分。

    公式: score = success_count * 2 - failure_count + decay_bonus
    其中 decay_bonus = max(0, 30 - days_since_last_success)
    衰减因子确保久未生效的 payload 逐渐降权，但不会变负。
    """
    now = time.time()
    days_since = (now - last_success) / 86400.0 if last_success > 0 else 365.0
    decay = max(0.0, 30.0 - days_since)
    return float(success_count * 2 - failure_count) + decay


def score_entry(entry: dict[str, Any]) -> float:
    """计算单条 entry 的评分（不入库，纯计算）。"""
    sc = entry.get("success_count", 0)
    fc = entry.get("failure_count", 0)
    ls = entry.get("last_success", 0.0)
    return _calc_score(int(sc), int(fc), float(ls))


def update_payload_score(
    memory_dir: Path,
    payload_fingerprint: str,
    success: bool,
    entry_matcher: dict[str, Any] | None = None,
) -> float:
    """根据执行结果更新 tech.json 中对应 payload 的评分。

    Args:
        memory_dir: memory 目录路径
        payload_fingerprint: 目标 payload 的指纹 (16-char hex)
        success: True=成功，False=失败
        entry_matcher: 可选，用于无法精确匹配指纹时的回退匹配（按 template 匹配）

    Returns:
        更新后的 score 值
    """
    tech_path = memory_dir / "tech.json"
    if not tech_path.exists():
        return 0.0

    try:
        data = json.loads(tech_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return 0.0

    entries = data.get("payload_templates") or []
    updated = False
    now = time.time()

    for entry in entries:
        fp = fingerprint_entry(entry)
        matched = fp == payload_fingerprint
        # 回退：按 entry_matcher 的 template 字段匹配
        if not matched and entry_matcher:
            tpl = entry_matcher.get("template") or entry_matcher.get("payload") or ""
            if tpl and (entry.get("template") == tpl or entry.get("payload") == tpl):
                matched = True

        if not matched:
            continue

        # 初始化/补齐分数字段
        for key, default in _SCORE_DEFAULTS.items():
            entry.setdefault(key, default)

        entry["last_used"] = now
        if success:
            entry["success_count"] = int(entry.get("success_count", 0)) + 1
            entry["last_success"] = now
        else:
            entry["failure_count"] = int(entry.get("failure_count", 0)) + 1

        entry["score"] = _calc_score(
            int(entry.get("success_count", 0)),
            int(entry.get("failure_count", 0)),
            float(entry.get("last_success", 0.0)),
        )
        updated = True
        break

    if updated:
        tech_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    return float((entries[0].get("score", 0)) if entries else 0.0) if not updated else float(
        next(
            (e.get("score", 0) for e in entries if fingerprint_entry(e) == payload_fingerprint),
            0.0,
        )
    )


def get_scored_payloads(
    memory_dir: Path,
    min_score: float | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """获取带评分的 payload 列表，可按最低分过滤。

    Args:
        memory_dir: memory 目录路径
        min_score: 最低评分阈值，None 表示不过滤
        limit: 最大返回数量

    Returns:
        按 score 降序排列的 payload 列表（浅拷贝，含分数字段）
    """
    tech_path = memory_dir / "tech.json"
    if not tech_path.exists():
        return []

    try:
        data = json.loads(tech_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []

    entries = data.get("payload_templates") or []
    result: list[dict[str, Any]] = []
    for e in entries:
        # 确保分数字段存在
        scored = dict(e)
        for key, default in _SCORE_DEFAULTS.items():
            scored.setdefault(key, default)
        scored["_fingerprint"] = fingerprint_entry(e)
        result.append(scored)

    if min_score is not None:
        result = [e for e in result if e.get("score", 0) >= min_score]

    result.sort(key=lambda e: e.get("score", 0), reverse=True)
    return result[:limit]


def dedup_tech_json(memory_dir: Path) -> tuple[int, int]:
    """清理 tech.json 中的重复条目。

    Returns:
        (before_count, after_count)
    """
    tech_path = memory_dir / "tech.json"
    if not tech_path.exists():
        return (0, 0)

    try:
        data = json.loads(tech_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return (0, 0)

    entries = data.get("payload_templates") or []
    before = len(entries)

    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for e in entries:
        fp = fingerprint_entry(e)
        if fp in seen:
            continue
        seen.add(fp)
        deduped.append(e)

    if len(deduped) < before:
        data["payload_templates"] = deduped
        tech_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    return (before, len(deduped))


# ── Singleton ──────────────────────────────────────────────────────────

_registry: PayloadRegistry | None = None


def get_registry(memory_dir: Path | None = None) -> PayloadRegistry:
    global _registry
    if _registry is None:
        if memory_dir is None:
            from pathlib import Path as _Path
            memory_dir = _Path(__file__).resolve().parents[1] / "memory"
        _registry = PayloadRegistry(memory_dir)
    return _registry


def reset_registry() -> None:
    global _registry
    _registry = None
