import os
from pathlib import Path
from langchain_core.tools import tool

# ！！！这就是我们的“黑箱”边界 ！！！
# 锁定目标代码库的绝对路径。大模型绝对无法越过这个目录。
BASE_DIR = Path(".").resolve()

def _safe_path(relative_path: str) -> Path:
    """内部辅助函数：软隔离路径锁，防止目录穿越攻击 (如 ../../../etc/passwd)"""
    # 假设传进来的是绝对路径，先转成相对路径，防止直接绕过
    if os.path.isabs(relative_path):
        # 简单粗暴：不准传绝对路径
        raise ValueError("安全拦截: 必须使用相对路径。")
        
    target_path = (BASE_DIR / relative_path).resolve()
    # 核心黑箱逻辑：判断最终路径是否以 BASE_DIR 开头
    if not str(target_path).startswith(str(BASE_DIR)):
        raise ValueError(f"安全拦截: 尝试访问越权路径 {relative_path}")
    
    if not target_path.exists():
         raise FileNotFoundError(f"未找到文件或目录: {relative_path}")
    return target_path

@tool
def get_whole_file_structure_tool(path: str = ".") -> str:
    """
    获取指定目录及其所有子目录的完整文件结构树。
    这是分析代码库的第一步，用来寻找入口点、配置文件等。
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
        return "\n".join(tree)[:4000] # 防止目录太大撑爆 Token
    except Exception as e:
        return f"获取文件结构失败: {str(e)}"

@tool
def get_snippet_tool(file_path: str, start_line: int, end_line: int) -> str:
    """
    提取指定文件中的特定行范围（代码片段）。
    用于构建漏洞证据链（Evidence）。
    参数 file_path: 文件相对路径。
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
        return snippet
    except Exception as e:
        return f"获取代码片段失败: {str(e)}"

CODE_TOOLS = [get_whole_file_structure_tool, get_snippet_tool]