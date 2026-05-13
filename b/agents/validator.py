from __future__ import annotations

import json
import re
import shlex
import copy
import ast
from pathlib import Path
from typing import Any

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


def validate_plan(plan: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    syntax_warnings: list[str] = []

    if plan.get("version") != 1:
        errors.append("顶层字段 `version` 应为整数 1")

    steps = plan.get("steps")
    if not isinstance(steps, list) or not steps:
        errors.append("`steps` 必须是非空数组")
    else:
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

    passed = len(errors) == 0
    result: dict[str, Any] = {"passed": passed, "errors": errors}
    if syntax_warnings:
        result["syntax_warnings"] = syntax_warnings
        result["syntax_hint"] = (
            "⚠️ 以上步骤存在语法错误，Planner 请逐项修正后重新生成。"
            "语法错误步骤将被跳过执行，不影响其他步骤。"
        )
    return result


def run_validator(plan_path: Path, validated_path: Path) -> dict[str, Any]:
    raw_plan = json.loads(plan_path.read_text(encoding="utf-8"))
    normalized_plan, norm_warnings = _normalize_plan(raw_plan)
    result = validate_plan(normalized_plan)
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
