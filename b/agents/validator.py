from __future__ import annotations

import json
import re
import shlex
import copy
import ast
from pathlib import Path
from typing import Any

import yaml

from memory.exploit_trajectory import get_trajectory
from memory.verification_memory import get_verification
from control.anti_regression import AntiRegressionController


# ═══════════════════════════════════════════════════════════════════
# Runtime Manifest — 从 coordinator 导入，Validator 100% 与此对齐
# ═══════════════════════════════════════════════════════════════════

_manifest_imported = False
_MANIFEST_SAFE_MODULES: set[str] = set()
_MANIFEST_BLOCKED_MODULES: set[str] = set()
_MANIFEST_SDK_PRIMITIVES: set[str] = set()


def _load_manifest() -> None:
    """Dynamically import RUNTIME_MANIFEST from coordinator. Cached after first call."""
    global _manifest_imported, _MANIFEST_SAFE_MODULES, _MANIFEST_BLOCKED_MODULES
    global _MANIFEST_SDK_PRIMITIVES
    if _manifest_imported:
        return
    try:
        from coordinator import RUNTIME_MANIFEST
        _MANIFEST_SAFE_MODULES = set(RUNTIME_MANIFEST.get("safe_modules", []))
        _MANIFEST_BLOCKED_MODULES = set(RUNTIME_MANIFEST.get("blocked_modules", []))
        _MANIFEST_SDK_PRIMITIVES = set(RUNTIME_MANIFEST.get("sdk_primitives", []))
        _manifest_imported = True
    except ImportError:
        # Fallback: use hardcoded defaults matching manifest
        _MANIFEST_SAFE_MODULES = {
            "json", "base64", "re", "time", "struct",
            "urllib.parse", "http.cookies",
            "hashlib", "hmac",
            "redteam_sdk",
        }
        _MANIFEST_BLOCKED_MODULES = {
            "os", "subprocess", "socket", "ctypes", "cffi", "pty", "signal",
            "multiprocessing", "importlib", "pickle", "marshal", "builtins",
            "gc", "inspect", "ast", "code", "codeop", "compileall", "dis",
            "types", "weakref", "requests", "urllib3", "urllib",
        }
        _MANIFEST_SDK_PRIMITIVES = set()
        _manifest_imported = True


# ═══════════════════════════════════════════════════════════════════
# Policy loader — reads sandbox_policy.yaml from disk every call
# (no caching) so that Consolidator overrides take effect immediately.
# ═══════════════════════════════════════════════════════════════════

_POLICY_PATH = Path(__file__).resolve().parent.parent / "policies" / "sandbox_policy.yaml"
_policy_load_logged = False


def load_policies() -> dict[str, Any]:
    """Read sandbox security policy from YAML + merge manifest blocks."""
    global _policy_load_logged
    _load_manifest()
    with open(_POLICY_PATH, "r", encoding="utf-8") as fh:
        policies = yaml.safe_load(fh)
    # Runtime Manifest 优先：覆盖 YAML 中的 allowlist/blocklist
    policies["import_rules"]["allowlist"] = sorted(_MANIFEST_SAFE_MODULES)
    policies["import_rules"]["blocklist"] = sorted(_MANIFEST_BLOCKED_MODULES)
    if not _policy_load_logged:
        rule_count = _count_rules(policies)
        print(f"[validator] 策略已加载（{rule_count} 条规则，manifest 对齐）")
        _policy_load_logged = True
    return policies


def get_manifest() -> dict[str, set[str]]:
    """Return validated manifest sets for external consumers (AST checker etc.)."""
    _load_manifest()
    return {
        "safe_modules": _MANIFEST_SAFE_MODULES,
        "blocked_modules": _MANIFEST_BLOCKED_MODULES,
        "sdk_primitives": _MANIFEST_SDK_PRIMITIVES,
    }


def _count_rules(policies: dict[str, Any]) -> int:
    import_rules = policies.get("import_rules", {})
    return (
        len(import_rules.get("allowlist", []))
        + len(import_rules.get("blocklist", []))
        + len(policies.get("text_scan_rules", []))
        + len(policies.get("shell_tool_allowlist", []))
    )


# ═══════════════════════════════════════════════════════════════════
# Text scan — unified regex matching against text_scan_rules
# ═══════════════════════════════════════════════════════════════════

def _scan_text(text: str, step_type: str, policies: dict[str, Any]) -> list[dict[str, str]]:
    """Run all text_scan_rules against *text*.  Returns a list of matching
    rule dicts (name / severity / remediation)."""
    matches: list[dict[str, str]] = []
    for rule in policies.get("text_scan_rules", []):
        rule_types = rule.get("step_types", ["python", "shell"])
        if step_type not in rule_types:
            continue
        if not re.search(rule["pattern"], text, re.IGNORECASE):
            continue
        ctx = rule.get("context_pattern")
        if ctx and not re.search(ctx, text, re.IGNORECASE):
            continue
        matches.append({
            "name": rule["name"],
            "severity": rule.get("severity", "error"),
            "remediation": rule["remediation"],
        })
    return matches


# ═══════════════════════════════════════════════════════════════════
# Import checks (AST-based, default-deny: not-in-allowlist OR in-blocklist → reject)
# ═══════════════════════════════════════════════════════════════════

def _check_python_imports(code: str, policies: dict[str, Any]) -> tuple[bool, str]:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return True, ""

    allowlist: set[str] = set(policies["import_rules"]["allowlist"])
    blocklist: set[str] = set(policies["import_rules"]["blocklist"])

    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                full = alias.name
                if root in blocklist:
                    violations.append(
                        f"  ❌ `import {full}` — `{root}` is blocked (sandbox escape risk)"
                    )
                elif root not in allowlist and full not in allowlist:
                    violations.append(
                        f"  ❌ `import {full}` — `{root}` is not in the allowlist"
                    )
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            full = node.module or ""
            if root in blocklist:
                violations.append(
                    f"  ❌ `from {full} import ...` — `{root}` is blocked (sandbox escape risk)"
                )
            elif root not in allowlist and full not in allowlist:
                violations.append(
                    f"  ❌ `from {full} import ...` — `{root}` is not in the allowlist"
                )

    if violations:
        allowed_sample = ", ".join(sorted(allowlist)[:15]) + ", ..."
        msg = (
            "Python script uses unauthorized modules:\n"
            + "\n".join(violations)
            + f"\n\n  ✅ Allowed: {allowed_sample}\n"
            + "  For HTML parsing use bs4.BeautifulSoup; for JWT use jwt.decode; "
            "for OOB callbacks use redteam_sdk.OOBReceiver"
        )
        return False, msg
    return True, ""


# ═══════════════════════════════════════════════════════════════════
# Shell whitelist
# ═══════════════════════════════════════════════════════════════════

def _check_shell_whitelist(cmd: str, policies: dict[str, Any]) -> tuple[bool, str]:
    whitelist: set[str] = set(policies.get("shell_tool_allowlist", []))
    stripped = cmd.strip().lstrip("$").strip()
    first_token = re.split(r"\s+", stripped)[0].lower() if stripped else ""
    sub_cmds = re.split(r"&&|\|\||;", stripped)
    for sub in sub_cmds:
        sub = sub.strip()
        if not sub:
            continue
        first = re.split(r"\s+", sub)[0].lower()
        first = first.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        if first not in whitelist:
            return False, (
                f"shell command uses unauthorized tool `{first}`.\n"
                f"  ✅ Allowed tools: {', '.join(sorted(whitelist))}\n"
                f"  For HTTP operations use type=\"python\" + HttpClient"
            )
    return True, ""


# ═══════════════════════════════════════════════════════════════════
# Python helpers
# ═══════════════════════════════════════════════════════════════════

def _strip_python_prefix(cmd: str) -> str:
    stripped = cmd.strip()
    m = re.match(r"^(python3?|py)\s+(-u\s+)?(-c\s+)?", stripped, re.IGNORECASE)
    if m:
        tail = stripped[m.end():]
        if (tail.startswith('"') and tail.endswith('"')) or (tail.startswith("'") and tail.endswith("'")):
            tail = tail[1:-1]
        return tail
    return cmd


def _check_python_syntax(cmd: str) -> tuple[bool, str]:
    code = _strip_python_prefix(cmd)
    if not code or not code.strip():
        return False, "Python 代码为空，请提供完整脚本"

    try:
        ast.parse(code)
        return True, ""
    except SyntaxError as e:
        line_content = ""
        if e.lineno and code:
            lines = code.splitlines()
            if 0 < e.lineno <= len(lines):
                line_content = lines[e.lineno - 1]

        pointer = ""
        if e.offset and line_content:
            pointer = " " * (e.offset - 1) + "^"

        msg = (
            f"Python 语法错误（Planner 请修正后重新生成此步骤）：\n"
            f"  错误类型: {e.msg}\n"
            f"  位置: 第 {e.lineno} 行，第 {e.offset} 列\n"
        )
        if line_content:
            msg += f"  问题代码:\n    {line_content}\n"
            if pointer:
                msg += f"    {pointer}\n"

        hint = _syntax_hint(e.msg, line_content)
        if hint:
            msg += f"  ��� 修复建议: {hint}"

        return False, msg


def _syntax_hint(msg: str, line: str) -> str:
    m = msg.lower()
    if "unexpected eof" in m or "unexpected indent" in m:
        return "检查是否有未闭合的括号、引号或缩进错误"
    if "invalid syntax" in m:
        if "f'" in line or 'f"' in line:
            return "f-string 内不能嵌套同类型引号，改用不同引号或转义"
        if line.strip().endswith(":"):
            return "冒号后的代码块不能为空，至少添加 `pass`"
        return "检查运算符、括号是否配对，以及关键字拼写"
    if "eol while scanning" in m:
        return "字符串未闭合，检查引号是否配对"
    if "indentation" in m:
        return "缩进错误，Python 要求一致使用空格（建议4个空格），不能混用 Tab 和空格"
    return ""


# ═══════════════════════════════════════════════════════════════════
# Step validation
# ═══════════════════════════════════════════════════════════════════

def _check_python_output_template(code: str, step_id: int | str) -> list[str]:
    """Checks that Python script has proper output instrumentation for feedback chain.

    Executor auto-injects HTTP logging and STEP_OK/STEP_FAIL markers, but we still
    validate here to catch scripts that are so broken the injected wrapper wouldn't help.
    """
    warnings: list[str] = []
    step_label = f"step[{step_id}]"

    # Check if code makes HTTP requests
    has_http_call = bool(re.search(
        r'(?:requests|HttpClient)\.(?:get|post|put|delete|request)\s*\(',
        code,
    ))

    if has_http_call:
        # Check that HTTP result is printed after calls (at least once)
        has_response_log = bool(re.search(
            r'print\s*\(.*(?:resp|response|r\.)\.(?:status_code|text)\b',
            code,
        ))
        if not has_response_log:
            warnings.append(
                f"{step_label}: HTTP 请求后缺少响应输出语句。"
                f"Executor 会自动注入 HTTP 日志，但脚本自身应至少有一处 "
                f"print(f'HTTP {{resp.status_code}}: {{resp.text[:300]}}')。"
                f"缺失响应日志会导致 Evaluator 看不到 HTTP 响应体，无法判断攻击是否成功。"
            )

        # Check for try/except around HTTP calls (at least some coverage)
        has_try = bool(re.search(r'\btry\s*:', code))
        has_except = bool(re.search(r'\bexcept\s', code))
        if not (has_try and has_except):
            warnings.append(
                f"{step_label}: HTTP 请求调用未包裹在 try/except 中。"
                f"Executor 会自动在外层注入异常捕获，但建议在关键请求处自行捕获: "
                f"try: resp = s.get(...); print(...) \\n"
                f"except Exception as e: print(f'[HTTP_ERR] {{e}}')"
            )

    return warnings


def _validate_step(step: dict[str, Any], policies: dict[str, Any]) -> tuple[bool, list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(step, dict):
        return False, ["step 必须是对象（dict）"], warnings

    step_type = step.get("type")
    if step_type not in ("python", "shell"):
        errors.append(
            f"type 字段值 `{step_type}` 无效，必须是 \"python\" 或 \"shell\"\n"
            "  HTTP 请求/多步逻辑 → type=\"python\"；sqlmap 等 CLI → type=\"shell\""
        )

    cmd = step.get("command")
    alt_code = step.get("code", "")
    alt_sdk = step.get("sdk_calls", [])
    has_command = isinstance(cmd, str) and cmd.strip()
    has_code = isinstance(alt_code, str) and alt_code.strip()
    has_sdk = isinstance(alt_sdk, list) and len(alt_sdk) > 0

    if not has_command and not has_code and not has_sdk:
        errors.append(
            "command 字段为空，且无 code/sdk_calls 替代字段。"
            "旧版请提供 command 字符串，新版请提供 imports + sdk_calls 声明式数组。"
        )
        return False, errors, []

    if has_sdk and not step_type:
        # 声明式步骤默认视为 python 类型
        step["type"] = "python"
        step_type = "python"

    if has_command and len(cmd) > 12000:
        errors.append(f"command 过长（{len(cmd)} 字符），请拆分为多个步骤（建议单步不超过 12000 字符）")

    # ── text_scan_rules: 仅当 command/code 存在时才扫描文本 ──
    text_to_scan = cmd if has_command else alt_code
    if text_to_scan and text_to_scan.strip():
        scan_matches = _scan_text(text_to_scan, step_type, policies)
        error_matches = [m for m in scan_matches if m["severity"] == "error"]
        for match in error_matches:
            errors.append(f"命令包含危险操作，已拒绝：{match['remediation']}")

    # ── shell whitelist (only when no deny-pattern hit) ──
    if step_type == "shell" and not error_matches:
        if has_command:
            ok, reason = _check_shell_whitelist(cmd, policies)
            if not ok:
                errors.append(reason)

    # ── 沙箱输出模板强制检查（仅对旧版 command 文本生效）──
    if step_type == "python" and has_command:
        output_checks = _check_python_output_template(cmd, step.get("id", "?"))
        for check_err in output_checks:
            warnings.append(check_err)
            print(f"[validator] [OUTPUT_TEMPLATE] {check_err}")

    return len(errors) == 0, errors, warnings


# ═══════════════════════════════════════════════════════════════════
# Plan normalisation & dependency-chain checks
# ═══════════════════════════════════════════════════════════════════

def _normalize_plan(plan: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    fixed = copy.deepcopy(plan)
    warnings: list[str] = []
    steps = fixed.get("steps")
    if not isinstance(steps, list):
        return fixed, warnings
    for st in steps:
        if not isinstance(st, dict) or st.get("type") != "python":
            continue
        cmd = st.get("command")
        if not isinstance(cmd, str) or not cmd.strip():
            continue
        stripped = _strip_python_prefix(cmd)
        if stripped != cmd:
            st["command"] = stripped
            warnings.append(f"step[{st.get('id', '?')}]: 已自动移除 `python -c` 前缀")
    return fixed, warnings


def _check_broken_dependency_chain(
    steps: list[dict[str, Any]],
    prior_feedback: dict[str, Any] | None,
) -> tuple[bool, list[str]]:
    if not prior_feedback or not steps:
        return True, []

    failed_step_ids: set[int] = set()
    memory_patch = prior_feedback.get("memory_patch", {})
    strategy_patch = memory_patch.get("strategy", {})
    add_failures = strategy_patch.get("add_failures", [])
    for af in add_failures:
        sid = af.get("step_id")
        if isinstance(sid, int):
            failed_step_ids.add(sid)

    analysis = prior_feedback.get("analysis", {})
    what_happened = analysis.get("what_happened", "")
    for match in re.finditer(
        r"Step (\d+): Failed with FileNotFoundError",
        what_happened,
    ):
        failed_step_ids.add(int(match.group(1)))

    if not failed_step_ids:
        return True, []

    violations: list[str] = []

    id_to_idx: dict[int, int] = {}
    id_to_step: dict[int, dict[str, Any]] = {}
    for i, st in enumerate(steps):
        if isinstance(st, dict):
            sid = st.get("id")
            if isinstance(sid, int):
                id_to_idx[sid] = i
                id_to_step[sid] = st

    file_producer: dict[str, int] = {}
    for st in steps:
        if not isinstance(st, dict):
            continue
        sid = st.get("id")
        cmd = st.get("command", "")
        if not isinstance(cmd, str):
            continue
        for match in re.finditer(
            r"""['\"]?/tmp/(\w+\.(?:txt|json|jwt|jwk|token|secret|pem|key))['\"]?""",
            cmd,
        ):
            fname = match.group(1)
            if isinstance(sid, int):
                file_producer[f"/tmp/{fname}"] = sid

    for st in steps:
        if not isinstance(st, dict):
            continue
        sid = st.get("id")
        if not isinstance(sid, int):
            continue
        step_label = f"step[{sid}]"

        depends_raw = st.get("depends_on")
        if isinstance(depends_raw, (int, float)):
            depends_raw = int(depends_raw)
            if depends_raw in failed_step_ids:
                violations.append(
                    f"{step_label}: 依赖的前置 step[{depends_raw}] 在上轮已失败，"
                    f"本轮若无替代方案则此步骤不可执行。"
                    f"请在 plan 中删除此步骤或增加一个能补齐缺失产物的替代步骤。"
                )

        cmd = st.get("command", "")
        if not isinstance(cmd, str):
            continue
        for match in re.finditer(
            r"""['\"]?/tmp/(\w+\.(?:txt|json|jwt|jwk|token|secret|pem|key))['\"]?""",
            cmd,
        ):
            fname = match.group(1)
            fpath = f"/tmp/{fname}"
            creator = file_producer.get(fpath)
            if creator is not None and creator in failed_step_ids:
                violations.append(
                    f"{step_label}: 需要读取 `{fpath}`，但该文件应由 step[{creator}] 生成，"
                    f"而 step[{creator}] 在上轮已失败。"
                    f"禁止在缺失前置产物的条件下构造后续步骤。"
                )
                break

    early_ids = [
        s.get("id") for s in steps
        if isinstance(s, dict) and isinstance(s.get("id"), int) and s.get("id") <= 4
    ]
    critical_range_ids = [eid for eid in early_ids if 2 <= eid <= 4]
    if early_ids and all(eid in failed_step_ids for eid in early_ids):
        late_steps = [
            s for s in steps
            if isinstance(s, dict) and isinstance(s.get("id"), int) and s.get("id", 0) >= 5
        ]
        if len(late_steps) >= 2:
            late_ids = [s.get("id") for s in late_steps]
            violations.append(
                f"前序步骤{early_ids}已全部失败，但计划仍包含 {len(late_steps)} 个后续步骤 "
                f"（step {late_ids}）。这是典型的'沙滩建城堡'模式。"
                f"Validator 拒绝此计划。请缩减到 3-4 步以内，集中精力攻克前置 bypass/认证问题。"
            )
    elif critical_range_ids and all(eid in failed_step_ids for eid in critical_range_ids):
        late_steps = [
            s for s in steps
            if isinstance(s, dict) and isinstance(s.get("id"), int) and s.get("id", 0) >= 4
        ]
        if len(late_steps) >= 3:
            late_ids = [s.get("id") for s in late_steps]
            violations.append(
                f"关键 bypass/利用步骤 {critical_range_ids} 已全部失败，"
                f"但计划仍包含 {len(late_steps)} 个后续步骤（step {late_ids}）。"
                f"这属于无效的'空中楼阁'计划。"
                f"请将计划缩减到最多 4 步以内，只包含 bypass 探测本身，"
                f"拿到 token 后再考虑后续攻击链。"
            )

    all_cmds = "\n".join(
        st.get("command", "") for st in steps if isinstance(st, dict)
    )
    for st in steps:
        if not isinstance(st, dict):
            continue
        sid = st.get("id")
        cmd = st.get("command", "")
        if not isinstance(cmd, str):
            continue
        for match in re.finditer(
            r"""['\"]?/tmp/(\w+\.(?:txt|json|jwt|jwk|token|secret|pem|key))['\"]?""",
            cmd,
        ):
            fname = match.group(1)
            fpath = f"/tmp/{fname}"
            producer = file_producer.get(fpath)
            if producer is None:
                if fpath not in cmd.replace(fpath, ""):
                    is_reading = any(
                        pattern in cmd.lower()
                        for pattern in ("open(", "with open", "read()", "load(", "json.load")
                    )
                    if is_reading:
                        violations.append(
                            f"step[{sid}]: 尝试读取 `{fpath}`，但没有任何步骤负责生成该文件。"
                            f"这是死依赖——请增加一个前置步骤来创建此文件，或在拿到数据之前删除此步骤。"
                        )
                        break

    return len(violations) == 0, violations


# ═══════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════

def _validate_trajectory_awareness(
    steps: list[dict[str, Any]], prior_feedback: dict[str, Any] | None
) -> tuple[bool, list[str], list[str]]:
    """轨迹感知验证：状态转换合法性 + payload 退化检测 + chain 连续性 + exploit reasoning。

    返回 (通过?, 错误列表, 警告列表)。
    """
    errors: list[str] = []
    warnings: list[str] = []

    if not steps:
        return True, [], []

    traj = get_trajectory()
    verif = get_verification()
    controller = AntiRegressionController(traj, verif)
    current_state = traj.get_current_state()
    chain = traj.get_current_chain()

    # ── 1. 状态退化检查 ──
    state_ok, state_err = controller.validate_state_regression(steps)
    if not state_ok:
        errors.append(f"[state_regression] {state_err}")

    # ── 2. Chain 连续性检查 ──
    chain_ok, chain_err = controller.validate_chain_break(steps, chain)
    if not chain_ok:
        warnings.append(f"[chain_break] {chain_err}")

    # ── 3. Payload 退化检查 ──
    for st in steps:
        if not isinstance(st, dict):
            continue
        cmd = st.get("command", "")
        if cmd:
            payload_ok, payload_err = controller.validate_payload_regression(cmd)
            if not payload_ok:
                errors.append(f"step[{st.get('id', '?')}] [payload_regression]: {payload_err}")

    # ── 4. Exploit reasoning 字段检查（降级为非阻断性 warnings）──
    reasoning_ok, reasoning_errs = controller.validate_exploit_reasoning(steps, current_state)
    if not reasoning_ok:
        warnings.extend(f"[exploit_reasoning] {e}" for e in reasoning_errs)

    # ── 4.5 Primitive-driven reasoning 字段检查（降级为非阻断性 warnings）──
    for st in steps:
        if not isinstance(st, dict):
            continue
        sid = st.get("id", "?")
        target_primitive = st.get("target_primitive", "")
        why_primitive = st.get("why_this_primitive_advances_chain", "")
        if not target_primitive or not isinstance(target_primitive, str) or not target_primitive.strip():
            warnings.append(
                f"step[{sid}]: 缺少 target_primitive 字段。建议从 Primitive Taxonomy "
                f"（ssti_reflection / command_execution / ...）中选择一个目标 primitive。"
            )
        if not why_primitive or not isinstance(why_primitive, str) or not why_primitive.strip():
            warnings.append(
                f"step[{sid}]: 缺少 why_this_primitive_advances_chain 字段。"
            )

    # ── 4.6 Plan-level primitive_context 检查 ──

    # ── 5. 状态跳级检查 ──
    state_order = {"init": 0, "probe_success": 1, "payload_injected": 2,
                   "gadget_triggered": 3, "oob_received": 4}
    current_idx = state_order.get(current_state, 0)
    for st in steps:
        if not isinstance(st, dict):
            continue
        expected_state = st.get("expected_outcome", "")
        for state_name in ("gadget_triggered", "oob_received"):
            if state_name in expected_state.lower():
                target_idx = state_order.get(state_name, 0)
                if target_idx > current_idx + 1:
                    errors.append(
                        f"step[{st.get('id', '?')}] 状态跳级违规: "
                        f"当前状态 '{current_state}'，步骤声称预期 '{state_name}'，"
                        f"中间跳过了至少一个状态。禁止跳级。"
                    )

    return len(errors) == 0, errors, warnings


def _validate_step_ast_against_manifest(
    step: dict[str, Any], step_label: str,
) -> tuple[bool, list[str]]:
    """Validate step imports and SDK calls against RUNTIME_MANIFEST.

    In AST mode (sdk_calls present): uses the *declared* imports/sdk_calls arrays.
    In LEGACY mode: uses the *_ast_imports/_ast_sdk_calls* pre-extracted by Planner.

    Checks:
      1. Every import must be in safe_modules.
      2. No blocked module is imported.
      3. SDK calls must match registered sdk_primitives (if sdk_primitives is populated).
    """
    _load_manifest()
    errors: list[str] = []

    # AST mode: use declared arrays directly (no ast.parse needed)
    declared_imports = step.get("imports")
    declared_sdk_calls = step.get("sdk_calls")
    is_ast_mode = isinstance(declared_sdk_calls, list) and len(declared_sdk_calls) > 0

    if is_ast_mode:
        imports = declared_imports or []
        sdk_calls = declared_sdk_calls
    else:
        # LEGACY mode: use Planner-extracted _ast_* fields
        imports = step.get("_ast_imports")
        sdk_calls = step.get("_ast_sdk_calls")
        valid = step.get("_ast_valid", True)
        if imports is None and sdk_calls is None:
            return True, []  # AST was not extracted (shell step or syntax error)
        if not valid:
            errors.append(f"{step_label}: AST 解析失败，跳过 import/SDK 验证")
            return False, errors

    # Check every import against manifest
    for imp in (imports or []):
        root = imp.split(".")[0]
        if root in _MANIFEST_BLOCKED_MODULES:
            errors.append(
                f"{step_label}: import `{imp}` — root `{root}` 在 Manifest BLOCKED 列表中"
            )
        elif root not in _MANIFEST_SAFE_MODULES and imp not in _MANIFEST_SAFE_MODULES:
            errors.append(
                f"{step_label}: import `{imp}` — 不在 Manifest 允许列表中"
            )

    # Check SDK calls against registered primitives (if manifest has them)
    if sdk_calls and _MANIFEST_SDK_PRIMITIVES:
        for call in sdk_calls:
            # Handle both string and dict forms: "HttpClient.get" or {"primitive": "HttpClient.get", ...}
            if isinstance(call, dict):
                call_str = call.get("primitive", "")
            else:
                call_str = str(call)
            base_call = call_str.rstrip("(")
            matched = any(
                base_call == p or base_call.startswith(p.rstrip("("))
                for p in _MANIFEST_SDK_PRIMITIVES
            )
            if not matched:
                errors.append(
                    f"{step_label}: SDK call `{base_call}` 未在 Manifest sdk_primitives 中注册"
                )

    return len(errors) == 0, errors


def validate_plan(
    plan: dict[str, Any],
    prior_feedback: dict[str, Any] | None = None,
) -> dict[str, Any]:
    policies = load_policies()

    errors: list[str] = []
    syntax_warnings: list[str] = []

    if plan.get("version") != 1:
        errors.append("顶层字段 `version` 应为整数 1")

    steps = plan.get("steps")
    if not isinstance(steps, list) or not steps:
        errors.append("`steps` 必须是非空数组")
    else:
        chain_ok, chain_violations = _check_broken_dependency_chain(steps, prior_feedback)
        if not chain_ok:
            errors.extend(chain_violations)

        # 🔑 轨迹感知验证：状态转换合法性 + payload 退化 + chain 连续性 + exploit reasoning
        traj_ok, traj_errs, traj_warns = _validate_trajectory_awareness(steps, prior_feedback)
        if not traj_ok:
            errors.extend(traj_errs)
        if traj_warns:
            syntax_warnings.extend(traj_warns)
        if traj_errs or traj_warns:
            print(f"[validator] 🛡️ 轨迹感知验证: {len(traj_errs)} 错误, {len(traj_warns)} 警告")

        # 🔑 Primitive context 验证（缺失字段自动推断，不阻断执行）
        primitive_ctx = plan.get("primitive_context")
        if not primitive_ctx or not isinstance(primitive_ctx, dict):
            syntax_warnings.append(
                "plan 缺少 primitive_context 字段。你必须在计划顶层声明 current_primitive、"
                "target_primitive、transition_edge、fallback_primitive。"
                "这是 primitive-driven reasoning 的强制要求。"
            )
            plan["primitive_context"] = {}
            primitive_ctx = plan["primitive_context"]
        if not primitive_ctx.get("current_primitive"):
            syntax_warnings.append("primitive_context.current_primitive 为空 — 请从 trajectory 中确认当前 primitive")
        if not primitive_ctx.get("target_primitive"):
            first_primitive = next(
                (s.get("target_primitive") for s in plan.get("steps", []) if s.get("target_primitive")),
                "information_disclosure"
            )
            primitive_ctx["target_primitive"] = first_primitive
            syntax_warnings.append(
                f"primitive_context.target_primitive 为空，自动从 steps[0].target_primitive 推断为 "
                f"\"{first_primitive}\"。请 Planner 后续回合显式声明。"
            )

        for i, st in enumerate(steps):
            step_label = f"step[{i}]（id={st.get('id', '?')}）" if isinstance(st, dict) else f"step[{i}]"

            # ── Protocol Unification: AST mode vs LEGACY mode ──
            step_sdk = st.get("sdk_calls") if isinstance(st, dict) else None
            is_ast_mode = isinstance(step_sdk, list) and len(step_sdk) > 0
            print(f"[validator] step[{st.get('id', '?')}] mode={'AST' if is_ast_mode else 'LEGACY'}")

            # ── Mixed protocol rejection: sdk_calls + command 不能共存 ──
            if is_ast_mode and isinstance(st, dict):
                cmd = st.get("command", "")
                has_command = isinstance(cmd, str) and cmd.strip()
                if has_command:
                    errors.append(
                        f"{step_label}: 混合协议违规 — sdk_calls 与 command 字段同时存在。"
                        f"AST 纯模式下禁止输出 command 字段（包括占位符）。"
                        f"请删除 command 字段，只保留 imports + sdk_calls。"
                    )
                    continue

            # ── Task 5: 声明式 imports/sdk_calls 结构数组强校验 ──
            if isinstance(st, dict) and st.get("type") == "python":
                step_imports = st.get("imports")
                step_sdk_calls = st.get("sdk_calls")

                # 检查 imports 是否在 Manifest safe_modules 范围内
                if isinstance(step_imports, list) and step_imports:
                    for imp in step_imports:
                        root = imp.split(".")[0]
                        if root in _MANIFEST_BLOCKED_MODULES:
                            errors.append(
                                f"{step_label}: 声明的 import `{imp}` 在 Manifest BLOCKED 列表中，"
                                f"valid:false — 请使用 HttpClient 代替原生通信"
                            )
                        elif root not in _MANIFEST_SAFE_MODULES and imp not in _MANIFEST_SAFE_MODULES:
                            errors.append(
                                f"{step_label}: 声明的 import `{imp}` 不在 Manifest safe_modules 中，"
                                f"valid:false — 仅限: {', '.join(sorted(_MANIFEST_SAFE_MODULES)[:8])}"
                            )

                # 检查 sdk_calls 是否来自 Manifest sdk_primitives
                if isinstance(step_sdk_calls, list) and _MANIFEST_SDK_PRIMITIVES:
                    for call in step_sdk_calls:
                        if isinstance(call, dict):
                            call_str = call.get("primitive", "")
                        else:
                            call_str = str(call)
                        base_call = call_str.rstrip("(")
                        matched = any(
                            base_call == p or base_call.startswith(p.rstrip("("))
                            for p in _MANIFEST_SDK_PRIMITIVES
                        )
                        if not matched:
                            errors.append(
                                f"{step_label}: 声明的 SDK call `{call}` 未在 Manifest sdk_primitives "
                                f"中注册，valid:false"
                            )
                elif isinstance(step_sdk_calls, list) and not step_sdk_calls and _MANIFEST_SDK_PRIMITIVES:
                    # 空数组 → 可能有绕过意图，警告但不阻断
                    syntax_warnings.append(
                        f"{step_label}: sdk_calls 为空数组 — 如果此步骤需要 HTTP 通信，"
                        f"必须声明对应的 HttpClient 原语"
                    )

            if not isinstance(st, dict):
                continue

            # ── Protocol Unification: AST mode → pure JSON schema validation ──
            if is_ast_mode:
                # AST 模式下：禁止调用 ast.parse() / _check_python_syntax() / _check_python_imports()
                # 直接进入 Manifest AST JSON schema 校验路径
                # imports / sdk_calls 声明式结构校验已在上面完成（lines ~750-786）
                # 这里补充 AST vs Manifest 交叉校验
                ast_ok, ast_errs = _validate_step_ast_against_manifest(st, step_label)
                if not ast_ok:
                    errors.extend(ast_errs)
                    print(f"[validator] [AST-MANIFEST] {step_label}: {ast_errs}")
                continue

            # ── LEGACY 模式：command/code 文本解析路径 ──
            ok, errs, step_warnings = _validate_step(st, policies)
            if errs:
                errors.extend([f"{step_label}: {e}" for e in errs])
                continue
            if step_warnings:
                syntax_warnings.extend([f"{step_label}: {w}" for w in step_warnings])

            cmd = st.get("command", "")
            alt_code = st.get("code", "")

            # ── Python 步骤语法 + import 检查 ──
            has_cmd = isinstance(cmd, str) and cmd.strip()
            has_code = isinstance(alt_code, str) and alt_code.strip()

            if st.get("type") == "python":
                if has_cmd or has_code:
                    code_to_check = cmd if has_cmd else alt_code

                    # 1. syntax check
                    py_ok, py_err = _check_python_syntax(code_to_check)
                    if not py_ok:
                        syntax_warnings.append(f"{step_label}: {py_err}")
                        print(f"[validator] [SYNTAX] {step_label}: {py_err}")

                    # 2. import allowlist/blocklist check (AST parse of actual code text)
                    if has_cmd:
                        import_ok, import_err = _check_python_imports(cmd, policies)
                        if not import_ok:
                            errors.append(f"{step_label}: {import_err}")

            # 3. text_scan_rules — polyglot / semantic warnings (severity=warning)
            text_to_scan = cmd if has_cmd else alt_code
            if text_to_scan and text_to_scan.strip():
                scan_matches = _scan_text(text_to_scan, "python", policies)
                for match in scan_matches:
                    if match["severity"] == "warning":
                        msg = f"{step_label}: {match['remediation']}"
                        print(f"[validator] [POLYGLOT] {msg}")
                        syntax_warnings.append(msg)

    passed = len(errors) == 0
    result: dict[str, Any] = {"passed": passed, "errors": errors}
    if syntax_warnings:
        result["syntax_warnings"] = syntax_warnings
        result["syntax_hint"] = (
            "以上步骤存在语法错误，Planner 请逐项修正后重新生成。"
            "语法错误步骤将被跳过执行，不影响其他步骤。"
        )
    return result


def run_validator(
    plan_path: Path,
    validated_path: Path,
    prior_feedback: dict[str, Any] | None = None,
) -> dict[str, Any]:
    raw_plan = json.loads(plan_path.read_text(encoding="utf-8"))
    normalized_plan, norm_warnings = _normalize_plan(raw_plan)
    result = validate_plan(normalized_plan, prior_feedback=prior_feedback)
    payload = {
        "version": 1,
        "validation": result,
        "warnings": norm_warnings,
        "normalization_applied": len(norm_warnings) > 0,
        "plan": normalized_plan if result["passed"] else None,
    }
    validated_path.parent.mkdir(parents=True, exist_ok=True)
    validated_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return payload


def safe_split_shell(cmd: str) -> list[str]:
    try:
        return shlex.split(cmd, posix=True)
    except ValueError:
        return [cmd]
