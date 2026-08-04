from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from memory.exploit_primitives import (
    ExploitPrimitive,
    PrimitiveRegistry,
    get_primitive_registry,
)


# ═══════════════════════════════════════════════════════════════════
# Primitive Transition 定义
# ═══════════════════════════════════════════════════════════════════

# 核心 transition graph: primitive_id → [可以升级到的 primitive_ids]
# 这是一个有向图，边表示 "激活后可以自然升级到"

DEFAULT_TRANSITIONS: dict[str, list[str]] = {
    # ── SSTI chain ──
    "ssti_reflection": [
        "ssti_execution",
        "blind_ssti",
        "template_access",
        "configuration_disclosure",
        "file_read",
        "command_execution",
    ],
    "ssti_execution": ["command_execution", "arbitrary_file_read", "blind_ssti"],
    "blind_ssti": ["http_callback", "dns_exfiltration"],

    # ── SQLi chain ──
    "sql_boolean": ["sql_union", "sql_stacked"],
    "sql_union": ["command_execution", "arbitrary_file_read", "credential_dump"],
    "sql_stacked": ["command_execution", "arbitrary_file_read", "privilege_discovery"],

    # ── Command injection chain ──
    "command_separator": ["command_execution", "command_substitution"],
    "command_substitution": ["command_execution", "arbitrary_file_read"],

    # ── Deserialization chain ──
    "deserialization_object_injection": ["command_execution", "arbitrary_file_read"],

    # ── XPath / LDAP chain ──
    "xpath_injection": ["credential_dump", "arbitrary_file_read"],
    "ldap_injection": ["credential_dump"],

    # ── Post-exploitation chain (universal) ──
    "command_execution": ["arbitrary_file_read", "privilege_discovery", "credential_dump", "filesystem_traversal"],
    "arbitrary_file_read": ["credential_dump", "privilege_discovery"],
    "privilege_discovery": ["credential_dump", "command_execution"],
    "credential_dump": ["privilege_discovery", "command_execution"],
    "filesystem_traversal": ["arbitrary_file_read", "credential_dump"],

    # ── OOB chain ──
    "http_callback": ["blind_rce_oob", "dns_exfiltration"],
    "dns_exfiltration": ["http_callback"],
    "blind_rce_oob": ["http_callback", "command_execution"],
    "async_job_trigger": ["http_callback", "dns_exfiltration"],
}

# 定义每个 transition 的 precondition（从源 primitive 到目标 primitive 的条件）
TRANSITION_CONDITIONS: dict[str, dict[str, str]] = {
    "ssti_reflection->ssti_execution": "需确认 template engine 类型（jinja2/twig/freemarker），然后使用对应的 class traversal payload",
    "ssti_reflection->template_access": "Optional objective: access template context or resources; does not require command execution",
    "ssti_reflection->configuration_disclosure": "Optional objective: disclose template-reachable configuration; does not require command execution",
    "ssti_reflection->file_read": "Optional objective: disclose file contents through template or resource access; does not require command execution",
    "ssti_reflection->command_execution": "Optional objective: attempt command execution only when its preconditions hold",
    "ssti_execution->command_execution": "需成功访问 os.popen 或 subprocess 模块（通过 __globals__ 或 __subclasses__ 链）",
    "ssti_execution->arbitrary_file_read": "需成功调用 open() 或 os.popen('cat ...') 并通过响应回显或 OOB 获取内容",
    "sql_boolean->sql_union": "需确定列数（ORDER BY 1,2,3...）和回显位置",
    "sql_union->command_execution": "需数据库支持命令执行（xp_cmdshell / COPY TO PROGRAM / UDF）",
    "sql_union->credential_dump": "需确定数据库名、表名、列名（通过 information_schema）",
    "command_execution->arbitrary_file_read": "任意命令已可执行，直接 cat / read 文件",
    "command_execution->privilege_discovery": "执行 id / sudo -l / find suid 等命令",
    "command_execution->credential_dump": "读取 /etc/shadow、.env、config 文件或数据库凭证",
    "arbitrary_file_read->credential_dump": "已成功读取文件 → 聚焦凭证文件（.env, config.php, shadow, id_rsa）",
}


# ═══════════════════════════════════════════════════════════════════
# PrimitiveTransitionGraph
# ═══════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class ConfirmedCapabilityPrimitive:
    """An evidence-backed capability state."""

    id: str
    description: str
    required_observations: tuple[str, ...]
    success_indicators: tuple[str, ...]
    failure_indicators: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "required_observations": list(self.required_observations),
            "success_indicators": list(self.success_indicators),
            "failure_indicators": list(self.failure_indicators),
        }


@dataclass(frozen=True)
class ConfirmedCapabilityTransition:
    """One observable step between adjacent confirmed capability states."""

    from_state: str
    to_state: str
    prerequisites: tuple[str, ...]
    expected_observations: tuple[str, ...]
    invalid_conditions: tuple[str, ...]
    planner_hint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "from_state": self.from_state,
            "to_state": self.to_state,
            "prerequisites": list(self.prerequisites),
            "expected_observations": list(self.expected_observations),
            "invalid_conditions": list(self.invalid_conditions),
            "planner_hint": self.planner_hint,
        }


TEMPLATE_CAPABILITY_PRIMITIVES: tuple[ConfirmedCapabilityPrimitive, ...] = (
    ConfirmedCapabilityPrimitive(
        id="input_processed",
        description="Controlled input is confirmed to reach template processing.",
        required_observations=("input_reached_template_processing",),
        success_indicators=("input_processed_by_template_layer",),
        failure_indicators=("input_rejected_before_template_processing",),
    ),
    ConfirmedCapabilityPrimitive(
        id="template_evaluation_confirmed",
        description="A controlled template expression is confirmed to be evaluated.",
        required_observations=("controlled_expression_result_observed",),
        success_indicators=("expression_evaluated",),
        failure_indicators=("expression_reflected_verbatim",),
    ),
    ConfirmedCapabilityPrimitive(
        id="object_access_confirmed",
        description="A template-reachable object or member is confirmed observable.",
        required_observations=("template_reachable_object_observed",),
        success_indicators=("object_member_access_confirmed",),
        failure_indicators=("object_access_denied_or_absent",),
    ),
    ConfirmedCapabilityPrimitive(
        id="type_resolution_confirmed",
        description="The type of an accessible object is confirmed resolvable.",
        required_observations=("resolved_type_identity_observed",),
        success_indicators=("stable_type_resolution_confirmed",),
        failure_indicators=("type_resolution_unavailable_or_ambiguous",),
    ),
    ConfirmedCapabilityPrimitive(
        id="method_available",
        description="A method on the resolved type is confirmed available.",
        required_observations=("callable_method_presence_observed",),
        success_indicators=("method_availability_confirmed",),
        failure_indicators=("method_missing_or_inaccessible",),
    ),
    ConfirmedCapabilityPrimitive(
        id="execution_confirmed",
        description="Invocation is confirmed by an observable effect.",
        required_observations=("controlled_invocation_effect_observed",),
        success_indicators=("method_execution_confirmed",),
        failure_indicators=("invocation_blocked_or_no_effect",),
    ),
    ConfirmedCapabilityPrimitive(
        id="output_confirmed",
        description="Observed output is confirmed to originate from execution.",
        required_observations=("execution_result_output_observed",),
        success_indicators=("execution_output_correlated",),
        failure_indicators=("output_absent_or_uncorrelated",),
    ),
)

TEMPLATE_CAPABILITY_STATE_ORDER: tuple[str, ...] = tuple(
    primitive.id for primitive in TEMPLATE_CAPABILITY_PRIMITIVES
)

TEMPLATE_CAPABILITY_TRANSITIONS: tuple[ConfirmedCapabilityTransition, ...] = (
    ConfirmedCapabilityTransition(
        "input_processed",
        "template_evaluation_confirmed",
        ("input_processed_by_template_layer",),
        ("controlled_expression_result_observed",),
        ("input_rejected_before_template_processing",),
        "Confirm template evaluation before reasoning about accessible objects.",
    ),
    ConfirmedCapabilityTransition(
        "template_evaluation_confirmed",
        "object_access_confirmed",
        ("expression_evaluated",),
        ("template_reachable_object_observed",),
        ("expression_reflected_verbatim",),
        "Confirm one reachable object before attempting type resolution.",
    ),
    ConfirmedCapabilityTransition(
        "object_access_confirmed",
        "type_resolution_confirmed",
        ("object_member_access_confirmed",),
        ("resolved_type_identity_observed",),
        ("object_access_denied_or_absent",),
        "Resolve the observed object type before reasoning about methods.",
    ),
    ConfirmedCapabilityTransition(
        "type_resolution_confirmed",
        "method_available",
        ("stable_type_resolution_confirmed",),
        ("callable_method_presence_observed",),
        ("type_resolution_unavailable_or_ambiguous",),
        "Confirm method availability without assuming invocation succeeded.",
    ),
    ConfirmedCapabilityTransition(
        "method_available",
        "execution_confirmed",
        ("method_availability_confirmed",),
        ("controlled_invocation_effect_observed",),
        ("method_missing_or_inaccessible",),
        "Require an observable effect before marking execution confirmed.",
    ),
    ConfirmedCapabilityTransition(
        "execution_confirmed",
        "output_confirmed",
        ("method_execution_confirmed",),
        ("execution_result_output_observed",),
        ("invocation_blocked_or_no_effect",),
        "Correlate returned output with the confirmed execution effect.",
    ),
)


@dataclass
class TransitionPath:
    """一条从源 primitive 到目标 primitive 的完整路径。"""

    path: list[str]
    total_cost: float = 0.0
    conditions_met: list[str] = field(default_factory=list)
    conditions_unmet: list[str] = field(default_factory=list)


class PrimitiveTransitionGraph:
    """管理 exploit primitive 之间的升级路径图。

    Planner 必须沿着此图推进，而不是随机生成 payload。
    核心思想：每个 primitive 都有明确的"下一阶段"目标，
    payload 只是沿着图上边前进的实例化手段。
    """

    def __init__(self, registry: PrimitiveRegistry | None = None) -> None:
        self._registry = registry or get_primitive_registry()
        self._transitions: dict[str, list[str]] = dict(DEFAULT_TRANSITIONS)
        self._transition_conditions: dict[str, str] = dict(TRANSITION_CONDITIONS)

        self._capability_primitives = {
            primitive.id: primitive for primitive in TEMPLATE_CAPABILITY_PRIMITIVES
        }
        self._capability_transitions = {
            (transition.from_state, transition.to_state): transition
            for transition in TEMPLATE_CAPABILITY_TRANSITIONS
        }

    # ── query API ──

    def get_next_primitives(self, current_primitive_id: str) -> list[str]:
        """返回从当前 primitive 可以升级到的所有目标 primitive ids。"""
        return self._transitions.get(current_primitive_id, [])

    def get_transition_condition(self, from_id: str, to_id: str) -> str:
        """返回从 from_id 到 to_id 的 transition 条件。"""
        key = f"{from_id}->{to_id}"
        return self._transition_conditions.get(key, f"需确认 {from_id} 已成功激活，然后尝试升级到 {to_id}")


    def get_capability_primitive(self, state_id: str) -> ConfirmedCapabilityPrimitive | None:
        """Return the evidence contract for a confirmed capability state."""
        return self._capability_primitives.get(state_id)

    def get_capability_primitives(self) -> tuple[ConfirmedCapabilityPrimitive, ...]:
        """Return capability states in required progression order."""
        return TEMPLATE_CAPABILITY_PRIMITIVES

    def get_capability_transitions(self) -> tuple[ConfirmedCapabilityTransition, ...]:
        """Return all fine-grained single-step transitions."""
        return TEMPLATE_CAPABILITY_TRANSITIONS

    def get_transition(
        self,
        from_state: str,
        to_state: str,
    ) -> ConfirmedCapabilityTransition | None:
        """Return the rich contract for one exact capability transition."""
        return self._capability_transitions.get((from_state, to_state))

    def get_next_state(self, current_state: str) -> str | None:
        """Return the next capability state, with legacy first-target fallback."""
        for transition in TEMPLATE_CAPABILITY_TRANSITIONS:
            if transition.from_state == current_state:
                return transition.to_state
        next_primitives = self.get_next_primitives(current_state)
        return next_primitives[0] if next_primitives else None

    def get_all_upgrade_targets(self, active_primitives: list[str]) -> list[tuple[str, str, str]]:
        """给定已激活的 primitive 列表，返回所有可能的升级目标。
        返回: [(from_primitive, to_primitive, condition), ...]
        """
        targets: list[tuple[str, str, str]] = []
        active_set = set(active_primitives)
        for pid in active_set:
            for next_pid in self._transitions.get(pid, []):
                if next_pid not in active_set:  # only suggest targets not yet reached
                    condition = self.get_transition_condition(pid, next_pid)
                    targets.append((pid, next_pid, condition))
        return targets

    def find_shortest_path(self, from_id: str, to_id: str) -> TransitionPath | None:
        """BFS 查找到目标 primitive 的最短路径。"""
        if from_id == to_id:
            return TransitionPath(path=[from_id], total_cost=0)

        visited: set[str] = {from_id}
        queue: list[tuple[str, list[str]]] = [(from_id, [from_id])]

        while queue:
            current, path = queue.pop(0)
            for next_pid in self._transitions.get(current, []):
                if next_pid == to_id:
                    full_path = path + [to_id]
                    conditions_met: list[str] = []
                    conditions_unmet: list[str] = []
                    for i in range(len(full_path) - 1):
                        cond = self.get_transition_condition(full_path[i], full_path[i + 1])
                        conditions_unmet.append(cond)
                    return TransitionPath(
                        path=full_path,
                        total_cost=len(full_path) - 1,
                        conditions_unmet=conditions_unmet,
                    )
                if next_pid not in visited:
                    visited.add(next_pid)
                    queue.append((next_pid, path + [next_pid]))

        return None

    def get_exploit_chain_plan(self, active_primitives: list[str], target_primitive: str = "credential_dump") -> TransitionPath | None:
        """给定当前已激活的 primitive，规划从任一活跃 primitive 到目标 primitive 的路径。"""
        best_path: TransitionPath | None = None

        for pid in active_primitives:
            path = self.find_shortest_path(pid, target_primitive)
            if path and (best_path is None or path.total_cost < best_path.total_cost):
                best_path = path

        return best_path

    def get_entry_primitives(self, cwe_ids: list[str]) -> list[str]:
        """根据 CWE IDs 推荐初始探测 primitive。

        例如 CWE-94 → ssti_reflection, CWE-89 → sql_boolean, CWE-78 → command_separator
        """
        cwe_to_primitive: dict[str, list[str]] = {
            "CWE-94": ["ssti_reflection"],
            "CWE-917": ["ssti_reflection"],
            "CWE-89": ["sql_boolean", "sql_union"],
            "CWE-78": ["command_separator", "command_substitution"],
            "CWE-502": ["deserialization_object_injection"],
            "CWE-918": ["http_callback"],
            "CWE-79": ["command_execution"],  # XSS may chain to cookie steal
            "CWE-643": ["xpath_injection"],
            "CWE-90": ["ldap_injection"],
            "CWE-22": ["filesystem_traversal"],
        }
        results: list[str] = []
        seen: set[str] = set()
        for cwe in cwe_ids:
            for pid in cwe_to_primitive.get(cwe, []):
                if pid not in seen:
                    seen.add(pid)
                    results.append(pid)
        return results

    # ── planner context ──

    def build_planner_context(self, active_primitives: list[str] | None = None) -> str:
        """构建 Planner 需要的 transition graph 注入块。"""
        lines: list[str] = []
        lines.append("╔══════════════════════════════════════════════════════════════╗")
        lines.append("║  📊 Primitive Transition Graph — 攻击原语升级路线图        ║")
        lines.append("╚══════════════════════════════════════════════════════════════╝")
        lines.append("")
        lines.append("【核心规则】你必须沿以下图推进，不要随机尝试 payload：")
        lines.append("")
        lines.append("── 推荐攻击链（按 CWE 类型）──")
        lines.append("")

        # SSTI chain
        ssti_chain = self.find_shortest_path("ssti_reflection", "credential_dump")
        if ssti_chain:
            lines.append(f"  SSTI 路径: {' → '.join(ssti_chain.path)}")
        # SQLi chain
        sqli_chain = self.find_shortest_path("sql_boolean", "credential_dump")
        if sqli_chain:
            lines.append(f"  SQLi 路径: {' → '.join(sqli_chain.path)}")
        # Command injection chain
        cmd_chain = self.find_shortest_path("command_separator", "credential_dump")
        if cmd_chain:
            lines.append(f"  命令注入路径: {' → '.join(cmd_chain.path)}")
        # Deserialization chain
        deser_chain = self.find_shortest_path("deserialization_object_injection", "command_execution")
        if deser_chain:
            lines.append(f"  反序列化路径: {' → '.join(deser_chain.path)}")

        lines.append("")

        if active_primitives:
            lines.append(f"── 当前已激活 Primitive: {', '.join(active_primitives)} ──")
            targets = self.get_all_upgrade_targets(active_primitives)
            if targets:
                lines.append("  🔼 可升级目标（按优先级排列）：")
                for from_p, to_p, cond in targets[:5]:
                    lines.append(f"    {from_p} → {to_p}")
                    lines.append(f"      条件: {cond}")
            else:
                lines.append("  （已到达所有可达 primitive，考虑 OOB 或 credential extraction）")
            lines.append("")

        lines.append("【Primitive 升级规则】：")
        lines.append("  1. 不要在同级 primitive 上反复尝试不同 payload — 那是随机漫游")
        lines.append("  2. 每轮至少尝试一次 primitive 升级（沿图中边向前推进）")
        lines.append("  3. 如果升级失败，记录失败原因（哪个 precondition 未满足），然后调整")
        lines.append("  4. payload 是 primitive 的实例化 — 先确定目标 primitive，再选 payload")
        lines.append("  5. 如果当前路径阻塞，尝试从另一个已激活 primitive 的分支推进")
        lines.append("╚══════════════════════════════════════════════════════════════╝")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "transitions": self._transitions,
            "conditions": self._transition_conditions,
        }


# ── singleton ──
_graph: PrimitiveTransitionGraph | None = None


def get_transition_graph() -> PrimitiveTransitionGraph:
    global _graph
    if _graph is None:
        _graph = PrimitiveTransitionGraph()
    return _graph


def reset_transition_graph() -> None:
    global _graph
    _graph = None