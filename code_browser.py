import os
import sys
from pathlib import Path
from langchain_core.tools import tool

# ============================================================
# Stage 1 Target Scope Enforcement
# ============================================================
# BASE_DIR is set ONCE from CO_REDTEAM_TARGET_ROOT env var at import time.
# All file reads MUST be contained within this directory.
# If not set, falls back to cwd (legacy behavior for backward compat).

def _resolve_target_root() -> Path:
    """Resolve the target root from env var or fall back to cwd."""
    env_root = os.environ.get("CO_REDTEAM_TARGET_ROOT", "")
    if env_root:
        p = Path(env_root).resolve()
        if not p.exists():
            print(f"[code_browser] WARNING: CO_REDTEAM_TARGET_ROOT={env_root} does not exist, falling back to cwd", file=sys.stderr)
            return Path(".").resolve()
        print(f"[code_browser] resolved_target_root={p}")
        return p
    return Path(".").resolve()

BASE_DIR = _resolve_target_root()


def _safe_path(relative_path: str) -> Path:
    """
    Internal helper: containment-locked path resolver.
    ---
    FAILS CLOSED on:
      - absolute paths (must use relative)
      - ../ traversal that escapes BASE_DIR
      - symlinks pointing outside BASE_DIR
      - paths that don't exist

    Returns a resolved Path guaranteed to be within BASE_DIR.
    """
    # ---- Rule: absolute paths are always rejected ----
    if os.path.isabs(relative_path):
        raise ValueError(
            f"安全拦截: 禁止使用绝对路径 '{relative_path}'。"
            f"必须使用相对于 '{BASE_DIR}' 的相对路径。"
        )

    # ---- Resolve and canonicalize ----
    candidate = (BASE_DIR / relative_path).resolve()

    # ---- Containment check (catches ../ escapes and symlink escapes) ----
    try:
        candidate.relative_to(BASE_DIR)
    except ValueError:
        raise ValueError(
            f"安全拦截: 路径越界 '{relative_path}'。"
            f"解析后路径 '{candidate}' 不在允许的根目录 '{BASE_DIR}' 内。"
        )

    # ---- Existence check ----
    if not candidate.exists():
        raise FileNotFoundError(f"未找到文件或目录: '{relative_path}' (解析后: '{candidate}')")

    return candidate


@tool
def get_whole_file_structure_tool(path: str = ".") -> str:
    """
    获取指定目录及其所有子目录的完整文件结构树。
    这是分析代码库的第一步，用来寻找入口点、配置文件等。
    参数 path: 必须使用相对于目标根目录的相对路径（默认为根目录 "."）。
    """
    try:
        target_dir = _safe_path(path)
        tree = []
        for root, dirs, files in os.walk(target_dir):
            level = str(root).replace(str(target_dir), '').count(os.sep)
            indent = ' ' * 4 * level
            tree.append(f"{indent}{os.path.basename(root)}/")
            subindent = ' ' * 4 * (level + 1)
            for f in files:
                tree.append(f"{subindent}{f}")
        result = "\n".join(tree)[:4000]  # 防止目录太大撑爆 Token
        print(f"[code_browser] get_whole_file_structure_tool(path={path!r}) → resolved={target_dir}, output_len={len(result)}")
        return result
    except Exception as e:
        return f"获取文件结构失败: {str(e)}"


@tool
def get_snippet_tool(file_path: str, start_line: int, end_line: int) -> str:
    """
    提取指定文件中的特定行范围（代码片段）。
    用于构建漏洞证据链（Evidence）。
    参数 file_path: 文件相对路径（相对于目标根目录）。
    参数 start_line: 开始行号（从 1 开始）。
    参数 end_line: 结束行号。
    """
    try:
        target_file = _safe_path(file_path)
        with open(target_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        start = max(0, start_line - 1)
        end = min(len(lines), end_line)

        snippet = ""
        for i in range(start, end):
            snippet += f"Line {i+1}: {lines[i]}"
        print(f"[code_browser] get_snippet_tool(file_path={file_path!r}, lines={start_line}-{end_line}) → resolved={target_file}, output_len={len(snippet)}")
        return snippet
    except Exception as e:
        return f"获取代码片段失败: {str(e)}"


CODE_TOOLS = [get_whole_file_structure_tool, get_snippet_tool]
