import chromadb
from langchain_core.tools import tool

# 1. 链接我们刚才初始化好的 ChromaDB 向量数据库
# 注意：这里的 path 必须和你刚才存数据的路径完全一致！
chroma_client = chromadb.PersistentClient(path="./co_redteam_memory")

# 获取已经存在的集合 (Collection)
# 如果提示找不到 collection，说明你前面的初始化脚本没跑成功
collection = chroma_client.get_collection(name="vulnerability_docs")

# 2. 定义静态摘要工具 [cite: 650]
@tool
def get_vulnerability_summary() -> str:
    """
    获取常见代码级漏洞的概述和 CWE 映射表。
    当你不确定从哪里开始分析代码，或者需要整理审计思路时，请首先调用此工具获取灵感。
    """
    # 这里提供一个极简的导航，告诉大模型库里有什么
    summary = """
    # 核心漏洞知识库导航
    你可以使用 `query_vulnerability_docs` 工具，输入以下关键字获取详细的审计策略：
    - 注入类: SQL Injection (CWE-89), OS Command Injection (CWE-78), Code Injection (CWE-94)
    - 越权与认证: Broken Access Control (CWE-284), IDOR (CWE-639), Missing Authorization (CWE-862)
    - 数据与反序列化: Deserialization of Untrusted Data (CWE-502)
    - 跨站与前端: XSS (CWE-79), CSRF (CWE-352)
    - 文件与路径: Path Traversal (CWE-22), Unrestricted File Upload (CWE-434)
    - 配置与凭证: Hard-coded Credentials (CWE-798)
    """
    return summary

# 3. 定义动态检索工具 [cite: 653]
@tool
def query_vulnerability_docs(query: str) -> str:
    """
    查询漏洞知识库，获取特定漏洞的详细描述、代码表象和具体的审计策略。
    参数 query: 漏洞的名称、CWE ID 或相关技术关键词 (例如 "CWE-89", "反序列化", "SQL注入")。
    """
    try:
        # 向 ChromaDB 发起相似度查询
        results = collection.query(
            query_texts=[query],
            n_results=2  # 每次只返回最相关的 2 条，节省 DeepSeek 的 Token
        )
        
        # 检查是否搜到了内容
        if not results['documents'] or not results['documents'][0]:
            return f"知识库中未找到与 '{query}' 相关的漏洞文档，请尝试更换关键词。"
            
        # 将搜到的几段文本拼成一个字符串返回给大模型
        formatted_docs = "\n\n====================\n\n".join(results['documents'][0])
        return f"针对查询 '{query}'，检索到以下权威审计策略：\n\n{formatted_docs}"
        
    except Exception as e:
        return f"查询向量数据库时发生底层错误: {str(e)}"

# 暴露给外部调用的工具列表
# 之后在主程序里，你只需要 from vul_doc import VULN_TOOLS 即可
VULN_TOOLS = [get_vulnerability_summary, query_vulnerability_docs]