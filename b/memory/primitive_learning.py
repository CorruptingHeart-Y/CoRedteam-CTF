from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from memory.exploit_primitives import (
    ExploitPrimitive,
    PrimitiveRegistry,
    get_primitive_registry,
    CROSS_TARGET_SYNTAX_MAP,
)


# ═══════════════════════════════════════════════════════════════════
# Observation → Primitive 推断规则
# ═══════════════════════════════════════════════════════════════════

@dataclass
class PrimitiveObservation:
    """一条原始观察，将被学习引擎转化为 primitive 推断。"""

    payload: str
    endpoint: str
    method: str
    response_status: int
    response_body_snippet: str
    stdout_snippet: str
    success: bool
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ── 启发式检测规则：payload/evidence → primitive ──

_HEURISTIC_DETECTORS: list[tuple[str, str, re.Pattern, str]] = [
    # (primitive_id, description, pattern, evidence_note)
    # SSTI family
    ("ssti_reflection", "expression reflected as computed value",
     re.compile(r"\{\{7\*7\}\}.*49|\$\{7\*7\}.*49|<%=7\*7%>.*49|#\{7\*7\}.*49", re.DOTALL),
     "expression_evaluated"),
    ("ssti_reflection", "config object accessed",
     re.compile(r"<Config\s|config\[|secret_key|SECRET_KEY", re.IGNORECASE),
     "config_object_reflected"),
    ("ssti_execution", "class traversal output detected",
     re.compile(r"<class\s|__globals__|__subclasses__|__mro__|__builtins__", re.IGNORECASE),
     "object_introspection_succeeded"),
    ("ssti_execution", "os.popen executed via SSTI",
     re.compile(r"uid=\d+|gid=\d+|www-data|root:[x*]:", re.IGNORECASE),
     "command_executed_via_template"),
    ("blind_ssti", "SSTI with no direct output but OOB attempted",
     re.compile(r"OOBReceiver|oob\.url|wait_for_callback", re.IGNORECASE),
     "oob_ssti_attempted"),

    # SQL family
    ("sql_boolean", "boolean-based differentiation",
     re.compile(r"(AND|OR)\s+['\"]?\d['\"]?\s*=\s*['\"]?\d['\"]?|1=1|1=2", re.IGNORECASE),
     "boolean_condition_injected"),
    ("sql_union", "UNION SELECT detected",
     re.compile(r"UNION\s+(ALL\s+)?SELECT\s+\d+", re.IGNORECASE),
     "union_select_injected"),
    ("sql_stacked", "stacked query detected",
     re.compile(r";\s*(INSERT|UPDATE|DELETE|DROP|CREATE)\s+", re.IGNORECASE),
     "stacked_query_injected"),

    # Command injection family
    ("command_separator", "shell separator in payload",
     re.compile(r"[;&|`$]\s*(id|whoami|ls|cat|dir|ping|nslookup)", re.IGNORECASE),
     "command_separator_used"),
    ("command_substitution", "command substitution in payload",
     re.compile(r"\$\([^)]+\)|`[^`]+`", re.IGNORECASE),
     "command_substitution_attempted"),

    # Deserialization
    ("deserialization_object_injection", "pickle/reduce payload",
     re.compile(r"__reduce__|pickle\.(dumps|loads)|cos\nsystem", re.IGNORECASE),
     "deserialization_gadget_constructed"),

    # Post-exploitation
    ("arbitrary_file_read", "file content extracted",
     re.compile(r"root:[x*]:\d+:\d+:|/etc/(passwd|shadow|hosts)|flag\{", re.IGNORECASE),
     "file_content_obtained"),
    ("command_execution", "command output in response",
     re.compile(r"(uid=\d+|gid=\d+|Linux\s+\S+\s+\d+\.\d+|Microsoft\s+Windows)", re.IGNORECASE),
     "command_executed_with_output"),
    ("credential_dump", "credentials found",
     re.compile(r"(password|passwd|secret|api_key|token)\s*[:=]\s*['\"]?\S+['\"]?", re.IGNORECASE),
     "credentials_extracted"),
    ("filesystem_traversal", "path traversal pattern",
     re.compile(r"\.\./\.\./|\.\.\\\.\.\\|%2e%2e%2f", re.IGNORECASE),
     "path_traversal_attempted"),

    # OOB
    ("dns_exfiltration", "DNS exfil via nslookup/dig",
     re.compile(r"nslookup|dig\s+@|\.attacker\.com", re.IGNORECASE),
     "dns_exfil_attempted"),
    ("http_callback", "HTTP callback exfil",
     re.compile(r"curl\s+\S+\$\(|wget\s+\S+\$\(|http.*oob.*url", re.IGNORECASE),
     "http_callback_attempted"),
    ("blind_rce_oob", "blind RCE OOB confirmed",
     re.compile(r"OOBReceiver.*hit\.body|callback.*received|OOB.*hit\s", re.IGNORECASE),
     "blind_rce_oob_confirmed"),
]


def _analyze_ssti_engine(response_text: str, payload: str) -> str:
    """从响应和 payload 推断具体的模板引擎。"""
    text = response_text.lower()
    # Jinja2 signatures
    if "jinja2" in text or "flask" in text or "werkzeug" in text:
        return "jinja2"
    if "{{" in payload and ("49" in response_text or "7777777" in response_text):
        return "jinja2"
    # Freemarker
    if "${" in payload and "freemarker" in text:
        return "freemarker"
    # Twig
    if "twig" in text or "symfony" in text:
        return "twig"
    # Thymeleaf
    if "thymeleaf" in text or "#{" in payload:
        return "thymeleaf"
    # EJS
    if "<%=" in payload:
        return "ejs"
    # Generic fallback based on syntax
    if "{{" in payload:
        return "jinja2"
    if "${" in payload:
        return "freemarker"
    if "#{" in payload:
        return "thymeleaf"
    if "<%=" in payload:
        return "ejs"
    return "unknown"


# ═══════════════════════════════════════════════════════════════════
# PrimitiveLearningEngine
# ═══════════════════════════════════════════════════════════════════

@dataclass
class LearnedPrimitive:
    """引擎从观察中自动学习到的 primitive 实例。"""

    primitive_id: str
    confidence: float
    evidence: str
    engine_hint: str = ""
    payload_instance: str = ""
    endpoint: str = ""
    method: str = ""
    learned_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    observations_count: int = 1
    generalized: bool = False
    cross_target_applicable: list[str] = field(default_factory=list)


class PrimitiveLearningEngine:
    """从 trajectory 观察中自动抽象 exploit primitive。

    核心逻辑：
      观察 "{{7*7}} -> 49" → 抽象 "ssti_execution / jinja2 / expression_evaluated"
      观察 "?id=1 UNION SELECT ..." → 抽象 "sql_union / union_select_reflected"

    持久化到 b/memory/learned_primitives.json
    """

    def __init__(self, path: Path | str = "b/memory/learned_primitives.json") -> None:
        self.path = Path(path)
        self.learned: dict[str, LearnedPrimitive] = {}
        self._registry = get_primitive_registry()
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            for item in data.get("learned_primitives", []):
                lp = LearnedPrimitive(**item)
                self.learned[lp.primitive_id] = lp
        except Exception:
            self.learned = {}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(
                {
                    "learned_primitives": [self._lp_to_dict(lp) for lp in self.learned.values()],
                    "version": 1,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

    @staticmethod
    def _lp_to_dict(lp: LearnedPrimitive) -> dict[str, Any]:
        return {
            "primitive_id": lp.primitive_id,
            "confidence": lp.confidence,
            "evidence": lp.evidence,
            "engine_hint": lp.engine_hint,
            "payload_instance": lp.payload_instance,
            "endpoint": lp.endpoint,
            "method": lp.method,
            "learned_at": lp.learned_at,
            "observations_count": lp.observations_count,
            "generalized": lp.generalized,
            "cross_target_applicable": lp.cross_target_applicable,
        }

    # ── learn API ──

    def learn_from_observation(self, obs: PrimitiveObservation) -> list[LearnedPrimitive]:
        """从单条观测中学习 primitive。返回新学习到的 primitive 列表。"""
        newly_learned: list[LearnedPrimitive] = []

        combined_text = f"{obs.payload} {obs.response_body_snippet} {obs.stdout_snippet}"

        # 1. 启发式匹配
        for pid, desc, pattern, evidence_note in _HEURISTIC_DETECTORS:
            if pattern.search(combined_text):
                confidence = 0.6
                # 如果有成功标记，提升置信度
                if obs.success:
                    confidence += 0.2
                # 如果响应状态码表示成功
                if 200 <= obs.response_status < 300:
                    confidence += 0.1

                engine_hint = ""
                if "ssti" in pid:
                    engine_hint = _analyze_ssti_engine(
                        obs.response_body_snippet + obs.stdout_snippet,
                        obs.payload,
                    )

                cross_target = []
                if pid in CROSS_TARGET_SYNTAX_MAP:
                    cross_target = list(CROSS_TARGET_SYNTAX_MAP[pid].keys())

                lp = LearnedPrimitive(
                    primitive_id=pid,
                    confidence=min(confidence, 0.95),
                    evidence=f"{desc}: {evidence_note}",
                    engine_hint=engine_hint,
                    payload_instance=obs.payload[:300],
                    endpoint=obs.endpoint,
                    method=obs.method,
                    cross_target_applicable=cross_target,
                )

                # 如果更高置信度的版本已存在，只更新
                existing = self.learned.get(pid)
                if existing:
                    existing.observations_count += 1
                    existing.confidence = max(existing.confidence, lp.confidence)
                    existing.evidence = lp.evidence
                    existing.payload_instance = lp.payload_instance
                    existing.generalized = existing.observations_count >= 2
                else:
                    self.learned[pid] = lp
                    newly_learned.append(lp)

        # 2. Registry-based matching (more precise)
        matches = self._registry.match_payload_to_primitive(obs.payload, combined_text)
        for primitive, score in matches:
            pid = primitive.primitive_id
            if pid not in self.learned:
                lp = LearnedPrimitive(
                    primitive_id=pid,
                    confidence=score * 0.9,  # slightly discount registry-only matches
                    evidence=f"Registry match: {primitive.description}",
                    engine_hint=primitive.engine_hint,
                    payload_instance=obs.payload[:300],
                    endpoint=obs.endpoint,
                    method=obs.method,
                    cross_target_applicable=list(primitive.cross_target_syntax.keys()),
                )
                self.learned[pid] = lp
                newly_learned.append(lp)
            else:
                existing = self.learned[pid]
                existing.observations_count += 1
                existing.confidence = max(existing.confidence, score * 0.9)
                existing.generalized = existing.observations_count >= 2

        if newly_learned:
            self._save()

        return newly_learned

    def learn_from_trajectory_nodes(self, nodes: list[Any]) -> list[LearnedPrimitive]:
        """从 trajectory nodes 批量学习。"""
        newly_learned: list[LearnedPrimitive] = []
        for node in nodes:
            obs = PrimitiveObservation(
                payload=getattr(node, "payload", ""),
                endpoint=getattr(node, "endpoint", ""),
                method=getattr(node, "method", "GET"),
                response_status=200,
                response_body_snippet=getattr(node, "evidence", ""),
                stdout_snippet=getattr(node, "evidence", ""),
                success=getattr(node, "success", False),
                timestamp=getattr(node, "timestamp", ""),
            )
            learned = self.learn_from_observation(obs)
            newly_learned.extend(learned)
        return newly_learned

    def generalize_primitive(self, primitive_id: str) -> LearnedPrimitive | None:
        """对一个 primitive 进行跨目标泛化。

        例如 ssti_reflection 成功后：
          - 记录所有已知引擎的 payload 语法
          - 标记 generalized=True
          - 填充 cross_target_applicable
        """
        lp = self.learned.get(primitive_id)
        if not lp:
            return None

        if primitive_id in CROSS_TARGET_SYNTAX_MAP:
            lp.cross_target_applicable = list(CROSS_TARGET_SYNTAX_MAP[primitive_id].keys())
        lp.generalized = True
        self._save()
        return lp

    # ── query API ──

    def get_learned(self, primitive_id: str) -> LearnedPrimitive | None:
        return self.learned.get(primitive_id)

    def get_all_learned(self) -> dict[str, LearnedPrimitive]:
        return dict(self.learned)

    def get_active_primitives(self, min_confidence: float = 0.4) -> list[LearnedPrimitive]:
        """返回置信度高于阈值的所有已学习 primitive。"""
        return [lp for lp in self.learned.values() if lp.confidence >= min_confidence]

    def get_next_upgrade_targets(self) -> list[tuple[str, str, float]]:
        """返回当前已确认 primitive 的可能升级目标（使用 transition graph）。
        返回: [(current_primitive_id, upgrade_target_id, recommendation_score), ...]
        """
        from memory.primitive_transition_graph import get_transition_graph
        graph = get_transition_graph()
        targets: list[tuple[str, str, float]] = []
        for pid, lp in self.learned.items():
            if lp.confidence < 0.5:
                continue
            next_prims = graph.get_next_primitives(pid)
            for up_id in next_prims:
                if up_id not in self.learned:
                    targets.append((pid, up_id, 0.8))
                elif self.learned[up_id].confidence < 0.5:
                    targets.append((pid, up_id, 0.5))
        targets.sort(key=lambda x: x[2], reverse=True)
        return targets

    def get_exploit_chain(self) -> list[str]:
        """构建当前已确认的 exploit chain（使用 transition graph 的 DFS）。"""
        from memory.primitive_transition_graph import get_transition_graph
        graph = get_transition_graph()

        # Find injection primitives (entry points)
        entries = [
            pid for pid, lp in self.learned.items()
            if lp.confidence >= 0.5 and self._registry.get(pid)
            and self._registry.get(pid).primitive_type == "injection"
        ]

        chain: list[str] = []
        visited: set[str] = set()

        def dfs(pid: str) -> None:
            if pid in visited:
                return
            visited.add(pid)
            chain.append(pid)
            for up_id in graph.get_next_primitives(pid):
                if up_id in self.learned and self.learned[up_id].confidence >= 0.4:
                    dfs(up_id)

        for entry in entries[:3]:  # max 3 entry points
            dfs(entry)

        return chain

    def build_planner_context(self) -> str:
        """构建 Planner 需要的已学习 primitive 上下文。"""
        lines: list[str] = []
        lines.append("╔══════════════════════════════════════════════════════════════╗")
        lines.append("║  🧠 Primitive Learning — 自动抽象的 Exploit 原语认知      ║")
        lines.append("╚══════════════════════════════════════════════════════════════╝")
        lines.append("")

        active = self.get_active_primitives(min_confidence=0.4)
        if not active:
            lines.append("  （尚未学习到任何 exploit primitive，处于初始探测阶段）")
            lines.append("")
            return "\n".join(lines)

        # Group by type
        by_type: dict[str, list[LearnedPrimitive]] = {}
        for lp in active:
            p = self._registry.get(lp.primitive_id)
            ptype = p.primitive_type if p else "unknown"
            by_type.setdefault(ptype, []).append(lp)

        for ptype, title in [("injection", "已激活注入原语"), ("post_exploitation", "已激活后利用原语"), ("oob", "已激活OOB原语")]:
            items = by_type.get(ptype, [])
            if not items:
                continue
            lines.append(f"── {title} ──")
            for lp in items:
                lines.append(f"  ▸ {lp.primitive_id} (confidence={lp.confidence:.2f})")
                lines.append(f"    证据: {lp.evidence[:150]}")
                if lp.engine_hint:
                    lines.append(f"    引擎: {lp.engine_hint}")
                if lp.payload_instance:
                    lines.append(f"    实例: {lp.payload_instance[:200]}")
                if lp.cross_target_applicable:
                    lines.append(f"    可迁移: {', '.join(lp.cross_target_applicable[:5])}")
                if lp.generalized:
                    lines.append(f"    ✅ 已泛化 — 可跨目标复用")
                lines.append("")

        # Upgrade targets
        upgrade_targets = self.get_next_upgrade_targets()
        if upgrade_targets:
            lines.append("── 🔼 推荐升级目标 ──")
            for cur, tgt, score in upgrade_targets[:5]:
                lines.append(f"  {cur} → {tgt} (优先级={score:.2f})")
            lines.append("")

        # Exploit chain
        chain = self.get_exploit_chain()
        if chain:
            lines.append(f"── 🔗 当前 Exploit Chain ──")
            lines.append(f"  {' → '.join(chain)}")
            lines.append("")

        lines.append("【使用说明】:")
        lines.append("  - 已学习的 primitive 可以直接复用到新 payload，无需重新探测")
        lines.append("  - 优先沿 upgrade 推荐路径推进，不要随机尝试")
        lines.append("  - 每轮观察到的新证据会继续喂给 PrimitiveLearningEngine 更新认知")
        lines.append("╚══════════════════════════════════════════════════════════════╝")

        return "\n".join(lines)


# ── singleton ──
_engine: PrimitiveLearningEngine | None = None


def get_learning_engine(path: Path | str = "b/memory/learned_primitives.json") -> PrimitiveLearningEngine:
    global _engine
    if _engine is None:
        _engine = PrimitiveLearningEngine(path)
    return _engine


def reset_learning_engine() -> None:
    global _engine
    _engine = None