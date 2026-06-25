from __future__ import annotations

import json
import re
import shlex
import copy
import ast
from pathlib import Path
from typing import Any

from core.strategy_identity import read_trusted_selection, validate_plan_against_trusted_selection

# ────────────────────────────────────────────────────────────────
# AST-based import security policy
#
# ALLOWLIST  — modules explicitly permitted inside the sandbox
# DENYLIST   — modules that must never be imported (escape risk)
#
# Any module not in either list is also denied (default-deny).
# ────────────────────────────────────────────────────────────────
PYTHON_IMPORT_ALLOWLIST: set[str] = {
    # HTTP / network (requests-level only — raw socket blocked separately)
    "requests", "urllib", "urllib3", "httpx",
    # HTTP server (needed by OOBReceiver in redteam_sdk)
    "http",
    # Data parsing — mandatory alternatives to fragile regex
    "json", "re", "base64", "hashlib", "hmac", "struct", "binascii",
    "html", "xml", "xml.etree",
    # HTML parsing
    "bs4", "lxml",
    # JWT / token decoding
    "jwt",
    # Standard utilities
    "time", "datetime", "random", "string", "itertools", "functools",
    "collections", "copy", "io", "pathlib",
    # Concurrency (threading only — multiprocessing blocked)
    "threading",
    # SDK injected by executor
    "redteam_sdk",
    # Type / utility
    "typing", "dataclasses", "enum", "abc",
    # Encoding
    "codecs", "unicodedata",
    # Crypto (stdlib + popular libs, no ctypes/cffi)
    "Crypto", "cryptography",
    # Math
    "math", "decimal", "fractions",
    # Read-only system info
    "sys", "os.path",
}

# Modules that are hard-blocked regardless of context.
# These are the actual sandbox-escape vectors.
PYTHON_IMPORT_DENYLIST: set[str] = {
    "os",             # os.system / os.popen / os.execv
    "subprocess",     # subprocess.run / Popen
    "socket",         # raw socket — use HttpClient / OOBReceiver instead
    "ctypes",         # memory ops / shellcode injection
    "cffi",
    "pty",            # pseudo-terminal
    "signal",
    "multiprocessing",
    "importlib",      # dynamic import bypass
    "pickle",         # deserialization RCE
    "marshal",
    "builtins",       # overwrite built-ins
    "gc",             # object traversal
    "inspect",        # frame / code object access
    "ast",            # code object manipulation
    "code",
    "codeop",
    "compileall",
    "dis",            # bytecode decompilation
    "types",          # dynamic function/class creation
    "weakref",
}

# Shell commands allowed as the leading token
SHELL_COMMAND_WHITELIST: set[str] = {
    "curl", "wget", "sqlmap", "nmap", "nikto",
    "python3", "python", "py",
    "jq", "grep", "awk", "sed", "cut", "sort", "uniq", "tr", "head", "tail",
    "echo", "cat", "ls", "pwd",
    "dig", "nslookup", "host",
    "openssl",
    "wfuzz", "ffuf", "gobuster",
}

# Patterns that are always denied regardless of whitelist
DENY_PATTERNS = [
    r"rm\s+(-[rfFR]+\s*)+/",
    r":\(\)\s*\{",
    r"mkfs\.",
    r"dd\s+if=",
    r"chmod\s+-R\s+777\s*/",
    r">/dev/sd",
    r"\|\s*(sh|bash|zsh|fish)\b",
    r"curl.+\|\s*(sh|bash)",
    r"wget.+\|\s*(sh|bash)",
    r"DROP\s+TABLE",
    r"format\s+[a-z]:",
    r"shutdown\s+/",
    r"Invoke-WebRequest.*-OutFile",
    r"del\s+/f\s+/s\s+/q\s+[a-z]:\\\\windows",
]


def _is_denied_command(cmd: str) -> tuple[bool, str]:
    for p in DENY_PATTERNS:
        if re.search(p, cmd, re.IGNORECASE):
            return True, f"命中高危禁止模式: `{p}`"
    return False, ""


def _check_shell_whitelist(cmd: str) -> tuple[bool, str]:
    """检查 shell 命令是否以白名单工具开头。"""
    stripped = cmd.strip().lstrip("$").strip()
    first_token = re.split(r"\s+", stripped)[0].lower() if stripped else ""
    # 允许以白名单工具开头，或以 && / || 串联的子命令（每段首词都在白名单中）
    sub_cmds = re.split(r"&&|\|\||;", stripped)
    for sub in sub_cmds:
        sub = sub.strip()
        if not sub:
            continue
        first = re.split(r"\s+", sub)[0].lower()
        # 去掉可能的路径前缀（如 /usr/bin/curl）
        first = first.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        if first not in SHELL_COMMAND_WHITELIST:
            return False, (
                f"shell command uses unauthorized tool `{first}`.\n"
                f"  ✅ Allowed tools: {', '.join(sorted(SHELL_COMMAND_WHITELIST))}\n"
                f"  ℹ️  For HTTP operations use type=\"python\" + HttpClient"
            )
    return True, ""


def _check_python_imports(code: str) -> tuple[bool, str]:
    """AST-based import check: denylist takes priority, then allowlist (default-deny)."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return True, ""  # syntax errors reported separately

    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                full = alias.name
                if root in PYTHON_IMPORT_DENYLIST:
                    violations.append(
                        f"  ❌ `import {full}` — `{root}` is blocked (sandbox escape risk)"
                    )
                elif root not in PYTHON_IMPORT_ALLOWLIST and full not in PYTHON_IMPORT_ALLOWLIST:
                    violations.append(
                        f"  ❌ `import {full}` — `{root}` is not in the allowlist"
                    )
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            full = node.module or ""
            if root in PYTHON_IMPORT_DENYLIST:
                violations.append(
                    f"  ❌ `from {full} import ...` — `{root}` is blocked (sandbox escape risk)"
                )
            elif root not in PYTHON_IMPORT_ALLOWLIST and full not in PYTHON_IMPORT_ALLOWLIST:
                violations.append(
                    f"  ❌ `from {full} import ...` — `{root}` is not in the allowlist"
                )

    if violations:
        allowed_sample = "requests, json, re, base64, bs4, jwt, threading, http, redteam_sdk, hashlib, ..."
        msg = (
            "Python script uses unauthorized modules:\n"
            + "\n".join(violations)
            + f"\n\n  ✅ Allowed: {allowed_sample}\n"
            + "  ℹ️  For HTML parsing use bs4.BeautifulSoup; for JWT use jwt.decode; "
            "for OOB callbacks use redteam_sdk.OOBReceiver"
        )
        return False, msg
    return True, ""


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
        # 生成对 Planner 友好的错误报告
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

        # 常见错误给出修复提示
        hint = _syntax_hint(e.msg, line_content)
        if hint:
            msg += f"  �� 修复建议: {hint}"

        return False, msg


def _check_polyglot_correctness(code: str, step_id: int) -> list[str]:
    """Detect common JWT/JSON polyglot construction errors that cause exploit failure.

    These are *semantic* errors that pass syntax checks but are guaranteed to fail
    against python_jwt / jwcrypto due to key ordering requirements.

    Returns a list of warning strings (empty = no issues found).
    """
    warnings: list[str] = []
    step_label = f"step[{step_id}]"

    # Pattern 1: json.dumps() used to construct a polyglot — key order is wrong
    if re.search(r'json\.dumps\s*\(\s*polyglot', code) or re.search(r'json\.dumps\s*\(\s*\{', code):
        if re.search(r'(fake_payload|forged|polyglot|extra_key)', code, re.IGNORECASE):
            warnings.append(
                f"{step_label}: 检测到使用 json.dumps(dict) 构造 JWT/JSON polyglot。"
                f"这会导致注入的 key 被排序到最后，python_jwt 先解析正经字段再解析伪造字段，从而产生 "
                f"'Invalid base64-encoded string' 或 'Invalid JWS Object' 错误。"
                f"【修复】：必须用字符串拼接 (f-string 或 +) 构造 polyglot，并将伪造 key 放在 JSON 对象的【第一个】位置。"
                f"参考格式: '{{\" ' + header + '.' + fake_payload + '.\":\"\",\"protected\":\"' + ... + '\"}}'"
            )

    # Pattern 2: .rstrip('=') on base64url-encoded strings — breaks python_jwt internal decoder
    if re.search(r'\.rstrip\s*\(\s*[\'\"]=\s*[\'\"]\s*\)', code):
        if re.search(r'(base64|urlsafe_b64encode|b64encode)', code, re.IGNORECASE):
            warnings.append(
                f"{step_label}: 检测到 base64 编码后调用了 .rstrip('=')。"
                f"python_jwt 内部的 jwcrypto 解码器要求完整 padding，去掉 '=' 会导致 "
                f"'Incorrect padding' 或 'Invalid base64-encoded string' 错误。"
                f"【修复】：删除 .rstrip('=') 调用，保留 base64url 编码的完整输出。"
            )

    # Pattern 3: alg:none used — python_jwt 3.3.3 explicitly rejects it
    if re.search(r'"alg"\s*:\s*"none"', code, re.IGNORECASE):
        warnings.append(
            f"{step_label}: 检测到使用 alg:none 的 JWT 攻击。"
            f"python_jwt 3.3.3 及更高版本明确拒绝 alg:none 令牌，此攻击无效。"
            f"【修复】：使用 JSON Polyglot 攻击 (CVE-2022-39227) 替代 alg:none。"
        )

    return warnings


def _syntax_hint(msg: str, line: str) -> str:
    """根据常见语法错误给出修复建议。"""
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


def _validate_step(step: dict[str, Any]) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if not isinstance(step, dict):
        return False, ["step 必须是对象（dict）"]

    step_type = step.get("type")
    if step_type not in ("python", "shell"):
        errors.append(
            f"type 字段值 `{step_type}` 无效，必须是 \"python\" 或 \"shell\"\n"
            "  �� HTTP 请求/多步逻辑 → type=\"python\"；sqlmap 等 CLI → type=\"shell\""
        )

    cmd = step.get("command")
    if not isinstance(cmd, str) or not cmd.strip():
        errors.append("command 字段不能为空，请提供完整的脚本或命令")
        return False, errors

    if len(cmd) > 12000:
        errors.append(f"command 过长（{len(cmd)} 字符），请拆分为多个步骤（建议单步不超过 12000 字符）")

    # 危险操作检查（所有类型都要过）
    bad, reason = _is_denied_command(cmd)
    if bad:
        errors.append(f"命令包含危险操作，已拒绝：{reason}")

    # 类型特定白名单检查
    if step_type == "shell" and not bad:
        ok, reason = _check_shell_whitelist(cmd)
        if not ok:
            errors.append(reason)
        # 检查 shell 中的链式高危操作
        if re.search(r"(;|&&|\|\|)\s*(rm|del|format|mkfs|dd)\b", cmd, re.IGNORECASE):
            errors.append("shell 命令包含链式高危操作（rm/del/format/mkfs/dd），已拒绝")

    return len(errors) == 0, errors


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
    """Detect plans that build on steps whose preconditions are already known to have failed.

    Scans for:
    1. Steps whose ``depends_on`` references a step that FAILED in the prior run
    2. Steps whose command reads ``/tmp/`` files that a FAILED step was supposed to create
    3. High-id steps (>=5) when early steps (1-3) all failed — "castle on sand" pattern

    Returns (is_clean, list_of_violations).
    """
    if not prior_feedback or not steps:
        return True, []

    # Gather failed step IDs from the prior feedback
    failed_step_ids: set[int] = set()
    memory_patch = prior_feedback.get("memory_patch", {})
    strategy_patch = memory_patch.get("strategy", {})
    add_failures = strategy_patch.get("add_failures", [])
    for af in add_failures:
        sid = af.get("step_id")
        if isinstance(sid, int):
            failed_step_ids.add(sid)

    # Also check for FileNotFoundError mentions in the feedback analysis
    analysis = prior_feedback.get("analysis", {})
    what_happened = analysis.get("what_happened", "")
    # Extract step IDs that failed due to FileNotFoundError
    import re as _re
    for match in _re.finditer(
        r"Step (\d+): Failed with FileNotFoundError",
        what_happened,
    ):
        failed_step_ids.add(int(match.group(1)))

    if not failed_step_ids:
        return True, []

    violations: list[str] = []

    # Build a map from step id to step index
    id_to_idx: dict[int, int] = {}
    id_to_step: dict[int, dict[str, Any]] = {}
    for i, st in enumerate(steps):
        if isinstance(st, dict):
            sid = st.get("id")
            if isinstance(sid, int):
                id_to_idx[sid] = i
                id_to_step[sid] = st

    # Map of "file → creating step id" for /tmp/ files mentioned in commands
    file_producer: dict[str, int] = {}
    for st in steps:
        if not isinstance(st, dict):
            continue
        sid = st.get("id")
        cmd = st.get("command", "")
        if not isinstance(cmd, str):
            continue
        # Steps that WRITE to /tmp/ files
        for match in _re.finditer(
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

        # Check 1: explicit depends_on
        depends_raw = st.get("depends_on")
        if isinstance(depends_raw, (int, float)):
            depends_raw = int(depends_raw)
            if depends_raw in failed_step_ids:
                violations.append(
                    f"{step_label}: 依赖的前置 step[{depends_raw}] 在上轮已失败，"
                    f"本轮若无替代方案则此步骤不可执行。"
                    f"请在 plan 中删除此步骤或增加一个能补齐缺失产物的替代步骤。"
                )

        # Check 2: command reads /tmp/ files that a FAILED step produced
        cmd = st.get("command", "")
        if not isinstance(cmd, str):
            continue
        for match in _re.finditer(
            r"""['\"]?/tmp/(\w+\.(?:txt|json|jwt|jwk|token|secret|pem|key))['\"]?""",
            cmd,
        ):
            fname = match.group(1)
            fpath = f"/tmp/{fname}"
            # Check if this file was supposed to be created by a FAILED step
            creator = file_producer.get(fpath)
            if creator is not None and creator in failed_step_ids:
                violations.append(
                    f"{step_label}: 需要读取 `{fpath}`，但该文件应由 step[{creator}] 生成，"
                    f"而 step[{creator}] 在上轮已失败。"
                    f"禁止在缺失前置产物的条件下构造后续步骤。"
                )
                break  # One violation per step is enough

    # Check 3: "castle on sand" — multiple early critical steps failed, plan still sprawling
    #    Two variants:
    #    (a) ALL early steps 1-3 failed → plan of 5+ steps rejected
    #    (b) Steps in the 2-4 "bypass/exploit" range all failed AND late steps exist
    early_ids = [
        s.get("id") for s in steps
        if isinstance(s, dict) and isinstance(s.get("id"), int) and s.get("id") <= 4
    ]
    critical_range_ids = [eid for eid in early_ids if 2 <= eid <= 4]  # bypass/exploit phase
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
        # Steps 2-4 (bypass/exploit phase) all failed
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

    # Check 4: "orphan consumer" — step reads a /tmp/ file that NO step produces
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
        for match in _re.finditer(
            r"""['\"]?/tmp/(\w+\.(?:txt|json|jwt|jwk|token|secret|pem|key))['\"]?""",
            cmd,
        ):
            fname = match.group(1)
            fpath = f"/tmp/{fname}"
            producer = file_producer.get(fpath)
            # The file is "open for reading" if the step reads it but doesn't produce it
            if producer is None:
                # Is this step trying to read the file (not create/write it)?
                if fpath not in cmd.replace(fpath, ""):  # crude: the file path appears
                    is_reading = any(
                        pattern in cmd.lower()
                        for pattern in ("open(", "with open", "read()", "load(", "json.load")
                    )
                    if is_reading:
                        violations.append(
                            f"step[{sid}]: 尝试读取 `{fpath}`，但没有任何步骤负责生成该文件。"
                            f"这是死依赖——请增加一个前置步骤来创建此文件，或在拿到数据之前删除此步骤。"
                        )
                        break  # One orphan per step is enough

    return len(violations) == 0, violations


def validate_plan(
    plan: dict[str, Any],
    prior_feedback: dict[str, Any] | None = None,
    trusted_selection: dict[str, Any] | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    syntax_warnings: list[str] = []

    if trusted_selection is not None:
        trusted_ok, trusted_errors = validate_plan_against_trusted_selection(plan, trusted_selection)
        if not trusted_ok:
            errors.extend(trusted_errors)

    if plan.get("version") != 1:
        errors.append("顶层字段 `version` 应为整数 1")

    steps = plan.get("steps")
    if not isinstance(steps, list) or not steps:
        errors.append("`steps` 必须是非空数组")
    else:
        # ── 步数依赖熔断 — 必须先于其他检查 ──
        chain_ok, chain_violations = _check_broken_dependency_chain(steps, prior_feedback)
        if not chain_ok:
            errors.extend(chain_violations)
            # Don't short-circuit; still run other structural checks to give full picture

        for i, st in enumerate(steps):
            step_label = f"step[{i}]（id={st.get('id', '?')}）" if isinstance(st, dict) else f"step[{i}]"

            # 基础结构校验
            ok, errs = _validate_step(st)
            if errs:
                errors.extend([f"{step_label}: {e}" for e in errs])
                continue  # 结构错误时跳过后续检查

            if not isinstance(st, dict):
                continue

            cmd = st.get("command", "")

            # Python 步骤：语法检查 + import 白名单
            if st.get("type") == "python" and isinstance(cmd, str) and cmd.strip():
                # 1. 语法检查
                py_ok, py_err = _check_python_syntax(cmd)
                if not py_ok:
                    syntax_warnings.append(f"{step_label}: {py_err}")
                    print(f"[validator] [SYNTAX] {step_label}: {py_err}")
                    # 语法错误不阻塞整个计划，但记录供 Planner 修正
                    continue

                # 2. import 白名单检查
                import_ok, import_err = _check_python_imports(cmd)
                if not import_ok:
                    errors.append(f"{step_label}: {import_err}")

                # 3. JWT/JSON polyglot 正确性检查（语义级反模式检测）
                polyglot_warnings = _check_polyglot_correctness(cmd, st.get("id", 0))
                for pw in polyglot_warnings:
                    print(f"[validator] [POLYGLOT] {pw}")
                    # Polyglot warnings cause the step to be skipped, not the whole plan rejected
                    syntax_warnings.append(pw)

    passed = len(errors) == 0
    result: dict[str, Any] = {"passed": passed, "errors": errors}
    if syntax_warnings:
        result["syntax_warnings"] = syntax_warnings
        result["syntax_hint"] = (
            "⚠️ 以上步骤存在语法错误，Planner 请逐项修正后重新生成。"
            "语法错误步骤将被跳过执行，不影响其他步骤。"
        )
    return result


def run_validator(
    plan_path: Path,
    validated_path: Path,
    prior_feedback: dict[str, Any] | None = None,
    trusted_selection_path: Path | None = None,
) -> dict[str, Any]:
    raw_plan = json.loads(plan_path.read_text(encoding="utf-8"))
    normalized_plan, norm_warnings = _normalize_plan(raw_plan)
    trusted_selection = read_trusted_selection(trusted_selection_path) if trusted_selection_path else None
    result = validate_plan(
        normalized_plan,
        prior_feedback=prior_feedback,
        trusted_selection=trusted_selection,
    )
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