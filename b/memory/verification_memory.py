from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

# ── Inference markers: evidence containing these signals gets downgraded to hypothesis ──
_INFERENCE_MARKERS: list[str] = [
    "should", "may", "likely", "probably", "therefore",
    "因此", "应可", "应该", "可能", "推断", "说明",
]

# Additional hallucination patterns for evidence quality check
_HALLUCINATION_PATTERNS: list[re.Pattern] = [
    re.compile(r"应可工作"),
    re.compile(r"因此.*应该"),
    re.compile(r"说明.*应可"),
    re.compile(r"Java反射链应可"),
    re.compile(r"should work", re.IGNORECASE),
    re.compile(r"therefore.*should", re.IGNORECASE),
    re.compile(r"proves.*will work", re.IGNORECASE),
]


def _contains_inference(text: str) -> bool:
    """Check if text contains inference/hallucination language that should be downgraded."""
    for marker in _INFERENCE_MARKERS:
        if marker in text.lower():
            return True
    for pat in _HALLUCINATION_PATTERNS:
        if pat.search(text):
            return True
    return False


class VerificationMemory:
    """持久化"已确认事实"（Confirmed Facts）——攻击过程中被反复验证、物理证据确凿的命题。

    与 ExploitTrajectoryMemory 的区别：
      - Trajectory 是每轮的状态快照（时间序列），VerificationMemory 是去重的"知识集合"。
      - Planner 基于 confirmed facts 推理，而不是每轮重新猜测。
      - Validator 检查新 plan 是否与 confirmed facts 矛盾。

    持久化路径：b/memory/verification_memory.json
    """

    def __init__(self, path: Path | str = "b/memory/verification_memory.json") -> None:
        self.path = Path(path)
        self.facts: dict[str, Any] = {
            "confirmed_base_url": "",
            "confirmable_endpoints": [],          # 已确认可达的端点
            "injectable_params": {},              # {"/endpoint": ["param1", "param2"]}
            "injectable_endpoints": [],           # 已确认可注入的端点
            "accepted_fields": [],                # 已接受的字段名列表
            "rejected_fields": [],                # 已拒绝的字段名列表
            "template_engine": "",                # e.g. "jinja2", "twig", "freemarker"
            "reflection_confirmed": False,        # payload 是否被反射
            "payload_blacklist": [],              # 已知被过滤的关键词
            "payload_bypass_techniques": [],      # 已知绕过手法
            "working_primitives": [],             # [{"primitive_id": str, "confidence": float, "evidence": str, "engine": str}]
            "primitive_knowledge": {},             # 结构化 primitive 知识库 (migration target)
            "confirmed_cve": "",                  # 确认存在的 CVE
            "target_app": "",                     # 目标应用名称
            "target_framework": "",               # 框架名称
            "auth_status": "unknown",             # authenticated / unauthenticated / partial
            "csrf_token_required": False,         # 是否需要 CSRF token
            "waf_detected": False,                # 是否检测到 WAF
            "waf_type": "",                       # WAF 类型
            "confirmed_flags": [],                # 已捕获的 flag 列表
            "hypotheses": [],                      # [{type, reasoning, confidence, source, timestamp}]
        }
        self._last_round_new_facts: int = 0       # counter for coordinator progress tracking
        self._load()

    @staticmethod
    def _now() -> float:
        return time.time()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                for k, v in data.items():
                    if k in self.facts:
                        self.facts[k] = v
                # hypotheses are always loaded from disk
                self.facts["hypotheses"] = data.get("hypotheses", [])
        except Exception:
            pass

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # ── P0: Memory Quarantine — respect global write switch ──
        try:
            from core.memory_store import DISABLE_LONG_TERM_WRITE
            if DISABLE_LONG_TERM_WRITE:
                return
        except ImportError:
            pass
        self.path.write_text(json.dumps(self.facts, ensure_ascii=False, indent=2), encoding="utf-8")

    # ── write API ──

    def confirm(self, key: str, value: Any) -> None:
        """确认一个事实。"""
        if key == "confirmable_endpoints" and isinstance(value, str):
            eps = self.facts.setdefault("confirmable_endpoints", [])
            if value not in eps:
                eps.append(value)
        elif key == "injectable_endpoints" and isinstance(value, str):
            eps = self.facts.setdefault("injectable_endpoints", [])
            if value not in eps:
                eps.append(value)
        elif key == "accepted_fields" and isinstance(value, str):
            fields = self.facts.setdefault("accepted_fields", [])
            if value not in fields:
                fields.append(value)
        elif key == "rejected_fields" and isinstance(value, str):
            fields = self.facts.setdefault("rejected_fields", [])
            if value not in fields:
                fields.append(value)
        elif key == "payload_blacklist" and isinstance(value, str):
            bl = self.facts.setdefault("payload_blacklist", [])
            if value not in bl:
                bl.append(value)
        elif key == "payload_bypass_techniques" and isinstance(value, str):
            techs = self.facts.setdefault("payload_bypass_techniques", [])
            if value not in techs:
                techs.append(value)
        elif key == "working_primitives" and isinstance(value, str):
            prims = self.facts.setdefault("working_primitives", [])
            if value not in prims:
                prims.append(value)
        elif key == "confirmed_flags" and isinstance(value, str):
            flags = self.facts.setdefault("confirmed_flags", [])
            if value not in flags:
                flags.append(value)
        elif key == "injectable_params" and isinstance(value, dict):
            existing = self.facts.setdefault("injectable_params", {})
            existing.update(value)
        else:
            self.facts[key] = value
        self._save()

    def confirm_endpoint(self, endpoint: str) -> None:
        self.confirm("confirmable_endpoints", endpoint)

    def confirm_injectable(self, endpoint: str, params: list[str] | None = None) -> None:
        self.confirm("injectable_endpoints", endpoint)
        if params:
            existing = self.facts.setdefault("injectable_params", {})
            ep_params = existing.setdefault(endpoint, [])
            for p in params:
                if p not in ep_params:
                    ep_params.append(p)
            self._save()

    def add_accepted_field(self, field: str) -> None:
        self.confirm("accepted_fields", field)

    def add_rejected_field(self, field: str) -> None:
        self.confirm("rejected_fields", field)

    def add_blacklist(self, keyword: str) -> None:
        self.confirm("payload_blacklist", keyword)

    def add_bypass(self, technique: str) -> None:
        self.confirm("payload_bypass_techniques", technique)

    def add_working_primitive(self, primitive: str | dict) -> None:
        """添加已确认工作的 exploit primitive。支持字符串（旧格式）和字典（新格式）。
        新格式: {"primitive_id": "ssti_execution", "confidence": 0.9, "evidence": "...", "engine": "jinja2"}

        v2: 检测 evidence 中的推断性语言，若存在则降级为 hypothesis。
        """
        if isinstance(primitive, str):
            # Old format: just add as plain dict
            entry = {"primitive_id": primitive, "confidence": 0.7, "evidence": "", "engine": ""}
        else:
            entry = primitive
        pid = entry.get("primitive_id", "")
        evidence = entry.get("evidence", "")

        # ── Inference guard: downgrade hallucinated evidence to hypothesis ──
        if evidence and _contains_inference(evidence):
            entry["confidence"] = min(entry.get("confidence", 0.7) * 0.3, 0.35)
            entry["source"] = "inferred"
            self.add_hypothesis(
                claim_type=pid,
                reasoning=evidence,
                confidence=entry["confidence"],
            )
            print(f"[verification] ⚠️ 推断性 evidence 已降级为 hypothesis: {evidence[:80]}")
            # Still save the downgraded entry so Planner can see it with low confidence
        else:
            entry["source"] = entry.get("source", "observed")

        prims = self.facts.setdefault("working_primitives", [])
        # Dedup by primitive_id
        existing_ids = {p.get("primitive_id", "") if isinstance(p, dict) else p for p in prims}
        if pid not in existing_ids:
            prims.append(entry)
        else:
            # Update confidence if higher
            for i, p in enumerate(prims):
                existing_pid = p.get("primitive_id", "") if isinstance(p, dict) else p
                if existing_pid == pid and isinstance(p, dict):
                    p["confidence"] = max(p.get("confidence", 0), entry.get("confidence", 0))
                    p["evidence"] = entry.get("evidence", "") or p.get("evidence", "")
                    p["source"] = entry.get("source", p.get("source", ""))
        self._last_round_new_facts += 1
        self._save()

    def add_hypothesis(self, claim_type: str, reasoning: str, confidence: float) -> None:
        """存储推断和假设，不进入 verified_facts，只作为 Planner 参考信息，不作为状态转移依据。"""
        hyps = self.facts.setdefault("hypotheses", [])
        hyps.append({
            "type": claim_type,
            "reasoning": reasoning,
            "confidence": confidence,
            "source": "inferred",
            "timestamp": self._now(),
        })
        # Keep only last 50 hypotheses
        if len(hyps) > 50:
            self.facts["hypotheses"] = hyps[-50:]
        self._save()

    def get_hypotheses(self) -> list[dict[str, Any]]:
        return self.facts.get("hypotheses", [])

    def add_flag(self, flag: str) -> None:
        self.confirm("confirmed_flags", flag)

    # ── query API ──

    def get_fact(self, key: str, default: Any = None) -> Any:
        return self.facts.get(key, default)

    def is_field_rejected(self, field: str) -> bool:
        return field in self.facts.get("rejected_fields", [])

    def is_field_accepted(self, field: str) -> bool:
        return field in self.facts.get("accepted_fields", [])

    def is_endpoint_confirmed(self, endpoint: str) -> bool:
        return endpoint in self.facts.get("confirmable_endpoints", [])

    def is_endpoint_injectable(self, endpoint: str) -> bool:
        return endpoint in self.facts.get("injectable_endpoints", [])

    def is_payload_blacklisted(self, keyword: str) -> bool:
        return any(keyword.lower() in bl.lower() for bl in self.facts.get("payload_blacklist", []))

    def get_injectable_params(self, endpoint: str) -> list[str]:
        return self.facts.get("injectable_params", {}).get(endpoint, [])

    def get_working_primitives(self) -> list[str]:
        return self.facts.get("working_primitives", [])

    def get_accepted_fields(self) -> list[str]:
        return self.facts.get("accepted_fields", [])

    # ── planner prompt context ──

    def build_planner_context(self) -> str:
        """构建 Planner 需要的"已确认事实"注入块。"""
        lines: list[str] = []
        lines.append("╔══════════════════════════════════════════════════════════════╗")
        lines.append("║  🔬 Verified Exploit Facts — 已确认的物理事实（必须遵守）  ║")
        lines.append("╚══════════════════════════════════════════════════════════════╝")
        lines.append("")

        if self.facts.get("confirmed_base_url"):
            lines.append(f"  URL: {self.facts['confirmed_base_url']}")

        confirmed_eps = self.facts.get("confirmable_endpoints", [])
        if confirmed_eps:
            lines.append(f"  ✅ 已确认可达端点: {', '.join(confirmed_eps)}")

        injectable_eps = self.facts.get("injectable_endpoints", [])
        if injectable_eps:
            lines.append(f"  💉 已确认可注入端点: {', '.join(injectable_eps)}")

        injectable_params = self.facts.get("injectable_params", {})
        if injectable_params:
            params_str = ", ".join(f"{ep}: [{', '.join(ps)}]" for ep, ps in injectable_params.items())
            lines.append(f"  📌 可注入参数: {params_str}")

        accepted = self.facts.get("accepted_fields", [])
        if accepted:
            lines.append(f"  ✅ 已接受字段名: {', '.join(accepted)}")

        rejected = self.facts.get("rejected_fields", [])
        if rejected:
            lines.append(f"  ❌ 已拒绝字段名: {', '.join(rejected)}")

        if self.facts.get("template_engine"):
            lines.append(f"  🔧 模板引擎: {self.facts['template_engine']}")

        if self.facts.get("reflection_confirmed"):
            lines.append(f"  🔄 Payload 反射已确认")

        blacklist = self.facts.get("payload_blacklist", [])
        if blacklist:
            lines.append(f"  🚫 Payload 黑名单: {', '.join(blacklist)}")

        bypasses = self.facts.get("payload_bypass_techniques", [])
        if bypasses:
            lines.append(f"  🛡️ 已知绕过手法: {'; '.join(bypasses)}")

        primitives = self.facts.get("working_primitives", [])
        if primitives:
            lines.append(f"  ⚡ 已激活利用原语 ({len(primitives)} 个):")
            for p in primitives[-5:]:
                if isinstance(p, dict):
                    pid = p.get("primitive_id", "?")
                    conf = p.get("confidence", 0)
                    engine = p.get("engine", "")
                    ev = p.get("evidence", "")
                    src = p.get("source", "")
                    engine_str = f" | 引擎: {engine}" if engine else ""
                    ev_str = f" | {ev[:80]}" if ev else ""
                    src_str = " [INFERRED]" if src == "inferred" else ""
                    lines.append(f"     ▸ {pid} (conf={conf:.0%}{engine_str}){src_str}{ev_str}")
                else:
                    lines.append(f"     ▸ {p}")

        # Show recent hypotheses
        hyps = self.facts.get("hypotheses", [])
        if hyps:
            recent_hyps = hyps[-3:]
            lines.append(f"  💭 未证实推断假设 ({len(hyps)} 条，仅供参考，不作为状态转移依据):")
            for h in recent_hyps:
                lines.append(f"     ▸ [{h.get('type', '?')}] {h.get('reasoning', '')[:100]} (conf={h.get('confidence', 0):.0%})")

        if self.facts.get("confirmed_cve"):
            lines.append(f"  🎯 确认 CVE: {self.facts['confirmed_cve']}")

        if self.facts.get("target_app"):
            lines.append(f"  📦 目标应用: {self.facts['target_app']}")
        if self.facts.get("target_framework"):
            lines.append(f"  🏗️ 框架: {self.facts['target_framework']}")

        auth = self.facts.get("auth_status", "unknown")
        lines.append(f"  🔑 认证状态: {auth}")

        if self.facts.get("csrf_token_required"):
            lines.append(f"  ⚠️ CSRF Token 需要")

        if self.facts.get("waf_detected"):
            waf = self.facts.get("waf_type", "unknown")
            lines.append(f"  🧱 WAF 检测: {waf}")

        lines.append("")
        lines.append("【使用说明】:")
        lines.append("  - 以上事实已在沙箱执行中被物理证据证实，不得推翻")
        lines.append("  - 已拒绝字段名必须在 payload 中避开，改用已接受字段")
        lines.append("  - Payload 黑名单中的关键词不得出现在新 payload 中")
        lines.append("  - 已确认可注入端点必须作为攻击链的起点，不要重新 fuzz")
        lines.append("  - 如果没有已确认事实，说明初期探测阶段仍需进行")
        lines.append("╚══════════════════════════════════════════════════════════════╝")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "facts_count": sum(1 for v in self.facts.values() if v),
            "confirmed_endpoints": len(self.facts.get("confirmable_endpoints", [])),
            "injectable_endpoints": len(self.facts.get("injectable_endpoints", [])),
            "accepted_fields": len(self.facts.get("accepted_fields", [])),
            "working_primitives": self.facts.get("working_primitives", []),
        }


# ── singleton ──
_verification: VerificationMemory | None = None


def get_verification(path: Path | str = "b/memory/verification_memory.json") -> VerificationMemory:
    global _verification
    if _verification is None:
        _verification = VerificationMemory(path)
    return _verification


def reset_verification() -> None:
    global _verification
    _verification = None