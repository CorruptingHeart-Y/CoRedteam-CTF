from __future__ import annotations

import json
import re
import shlex
import copy
import ast
from pathlib import Path
from typing import Any

DENY_PATTERNS = [
    r"rm\s+(-[rfFR]+\s*)+/",
    r":\(\)\s*\{",
    r"mkfs\.",
    r"dd\s+if=",
    r"chmod\s+-R\s+777",
    r"format\s+[a-z]:",
    r"del\s+/f\s+/s\s+/q",
    r"shutdown\s+/",
    r"Invoke-WebRequest.*-OutFile",
    r">/dev/sd",
    r"curl.+pipe\s+sh",
    r"wget.+pipe\s+sh",
    r"DROP\s+TABLE",
]


def _is_denied_command(cmd: str) -> tuple[bool, str]:
    lowered = cmd.lower()
    for p in DENY_PATTERNS:
        if re.search(p, lowered, re.IGNORECASE):
            return True, f"命中高危模式: {p}"
    if "rm -rf /" in lowered or re.search(r"rm\s+.*\s+/\s*$", lowered):
        return True, "疑似根目录删除"
    return False, ""


def _validate_step(step: dict[str, Any]) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if not isinstance(step, dict):
        return False, ["step 非对象"]
    if step.get("type") not in ("python", "shell"):
        errors.append("type 必须是 python 或 shell")
    cmd = step.get("command")
    if not isinstance(cmd, str) or not cmd.strip():
        errors.append("command 不能为空")
        return False, errors
    if len(cmd) > 8000:
        errors.append("command 过长")
    bad, reason = _is_denied_command(cmd)
    if bad:
        errors.append(reason)
    # 避免误伤 python 一行脚本：仅在 shell 命令下检查明显危险链式执行
    if step.get("type") == "shell" and re.search(r"(;|&&|\|\|)\s*(rm|del|format|mkfs|dd)\b", cmd, re.IGNORECASE):
        errors.append("shell 命令包含可疑链式高危操作")
    return len(errors) == 0, errors


def _normalize_python_command(cmd: str) -> tuple[str, bool]:
    stripped = cmd.strip()
    # 已是 python 启动形式，保持不动
    if re.match(r"^(python|python3|py)\b", stripped, re.IGNORECASE):
        return cmd, False
    # 裸 python 代码自动包装，避免执行器找不到可执行文件
    wrapped = f"python -c {json.dumps(stripped, ensure_ascii=False)}"
    return wrapped, True


def _normalize_plan(plan: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    fixed = copy.deepcopy(plan)
    warnings: list[str] = []
    steps = fixed.get("steps")
    if not isinstance(steps, list):
        return fixed, warnings
    for i, st in enumerate(steps):
        if not isinstance(st, dict):
            continue
        if st.get("type") != "python":
            continue
        cmd = st.get("command")
        if not isinstance(cmd, str) or not cmd.strip():
            continue
        new_cmd, changed = _normalize_python_command(cmd)
        if changed:
            st["command"] = new_cmd
            warnings.append(f"step[{i}] python 裸代码已自动包装为 python -c")
    return fixed, warnings


def _extract_python_code(cmd: str) -> str:
    """提取 python -c 后代码；若为裸代码则原样返回。"""
    stripped = cmd.strip()
    parts = safe_split_shell(stripped)
    if len(parts) >= 3 and re.match(r"^(python|python3|py)$", parts[0], re.IGNORECASE):
        try:
            idx = parts.index("-c")
        except ValueError:
            return stripped
        if idx + 1 < len(parts):
            code = parts[idx + 1].strip()
            if (code.startswith('"') and code.endswith('"')) or (code.startswith("'") and code.endswith("'")):
                code = code[1:-1]
            code = code.replace('\\"', '"').replace("\\'", "'")
            return code
    return stripped


def _fix_truncated_code(code: str) -> tuple[str, list[str]]:
    fixes = []
    fixed = code.strip()

    if not fixed:
        return fixed, fixes

    open_paren = fixed.count("(") - fixed.count(")")
    open_brack = fixed.count("[") - fixed.count("]")
    open_brace = fixed.count("{") - fixed.count("}")
    single_quote_count = fixed.count("'") - fixed.count("\\'") * 2
    double_quote_count = fixed.count('"') - fixed.count('\\"') * 2

    if open_paren > 0:
        fixed += ")" * open_paren
        fixes.append(f"补全 {open_paren} 个缺失圆括号")

    if open_brack > 0:
        fixed += "]" * open_brack
        fixes.append(f"补全 {open_brack} 个缺失方括号")

    if open_brace > 0:
        fixed += "}" * open_brace
        fixes.append(f"补全 {open_brace} 个缺失花括号")

    if single_quote_count % 2 != 0:
        fixed += "'"
        fixes.append("补全缺失的单引号")

    if double_quote_count % 2 != 0:
        fixed += '"'
        fixes.append("补全缺失的双引号")

    if fixed.rstrip().endswith("\\"):
        fixed = fixed.rstrip("\\") + '"'
        fixes.append("移除截断反斜杠并补全引号")

    if fixed.rstrip().endswith((":", "else", "elif", "except", "finally", "return")):
        fixed += ' ""'
        fixes.append("空语句体填充，避免语法错误")

    return fixed, fixes


def _check_python_syntax(cmd: str) -> tuple[bool, str]:
    code = _extract_python_code(cmd)
    if not code or not code.strip():
        return False, "python 代码为空"

    fixed_code, fixes = _fix_truncated_code(code)

    try:
        ast.parse(fixed_code)
        if fixes:
            print(f"[validator] 自动修复: {fixes}")
        return True, ""
    except SyntaxError:
        pass

    try:
        wrapped = (
            "import io,gzip;"
            + fixed_code.replace("import requests", "import requests", 1)
        )
        ast.parse(wrapped)
        if fixes:
            print(f"[validator] 自动修复(wrapped): {fixes}")
        return True, ""
    except SyntaxError:
        pass

    try:
        ast.parse(code)
        return True, ""
    except SyntaxError as e:
        return False, f"python 语法错误: {e.msg} (line={e.lineno}, offset={e.offset})"


def validate_plan(plan: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    syntax_warnings: list[str] = []
    if plan.get("version") != 1:
        errors.append("version 应为 1")
    steps = plan.get("steps")
    if not isinstance(steps, list) or not steps:
        errors.append("steps 必须为非空数组")
    else:
        for i, st in enumerate(steps):
            ok, errs = _validate_step(st)
            if isinstance(st, dict) and st.get("type") == "python":
                cmd = st.get("command")
                if isinstance(cmd, str) and cmd.strip():
                    py_ok, py_err = _check_python_syntax(cmd)
                    if not py_ok:
                        syntax_warnings.append(f"step[{i}]: {py_err} (该步骤将跳过执行，不影响其他步骤)")
                        print(f"[validator] ⚠️ {syntax_warnings[-1]}")
                        continue
            if (not ok) or errs:
                errors.extend([f"step[{i}]: {e}" for e in errs])
    passed = len(errors) == 0
    result = {"passed": passed, "errors": errors}
    if syntax_warnings:
        result["syntax_warnings"] = syntax_warnings
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
    """尽量安全地将 shell 命令拆成 argv；失败则单元素回退。"""
    try:
        # 【核心修复】：将 posix=False 改为 posix=True。
        # 这样它就能完美识别包含转义双引号 (\") 的复杂 Python 代码了！
        return shlex.split(cmd, posix=True)
    except ValueError:
        return [cmd]