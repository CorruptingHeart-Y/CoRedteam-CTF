import json
import os
import re
from datetime import datetime
from typing import TypedDict, List, Dict, Any
from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage, AIMessage
from dotenv import load_dotenv

# 导入工具和数据库客户端
from vul_doc import VULN_TOOLS, chroma_client
from code_browser import CODE_TOOLS

# 加载环境变量
load_dotenv()

# ==========================================
# 1. 颜色定义 (ANSI 转义码)
# ==========================================
BLUE = "\033[94m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"

# ==========================================
# 2. 初始化 LLM (DeepSeek-V3)
# ==========================================
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY")

llm = ChatOpenAI(
    model="deepseek-chat",
    api_key=DEEPSEEK_API_KEY,
    base_url="https://api.deepseek.com",
    temperature=0.1,
)

ALL_TOOLS = CODE_TOOLS + VULN_TOOLS
llm_with_tools = llm.bind_tools(ALL_TOOLS)
TOOL_MAP = {tool.name: tool for tool in ALL_TOOLS}

class CoRedteamState(TypedDict):
    iteration_count: int
    vulnerabilities: str
    critic_feedback: str
    messages: List[Any]

# ==========================================
# 3. 节点逻辑
# ==========================================

def analysis_node(state: CoRedteamState):
    print(f"\n{BOLD}{BLUE}[🚀 Analysis Agent]{RESET} 开始第 {state['iteration_count'] + 1} 轮深度代码审计...")

    # --- 长期记忆检索 (RAG) - 双库查询 + 关键覆盖兜底 ---
    memory_context = ""
    try:
        parts = []

        # [1] 查询 vulnerability_patterns (历史经验)
        pattern_collection = chroma_client.get_collection(name="vulnerability_patterns")
        pat_results = pattern_collection.query(
            query_texts=["越权访问, 逻辑漏洞, 注入攻击, 混淆绕过, 认证缺陷, 业务状态机, CSRF"],
            n_results=5
        )
        if pat_results and pat_results['documents'] and pat_results['documents'][0]:
            pattern_texts = []
            for doc in pat_results['documents'][0]:
                pattern_texts.append(doc)
            parts.append(("历史经验", pattern_texts))

        # [2] 查询 vulnerability_docs (CWE 知识库) - 补充代码型 RAG 可能遗漏的逻辑漏洞
        docs_collection = chroma_client.get_collection(name="vulnerability_docs")
        cwe_results = docs_collection.query(
            query_texts=["CSRF 跨站请求伪造, 认证绕过, 逻辑缺陷, 权限绕过, 业务越权, 状态机篡改"],
            n_results=6
        )
        if cwe_results and cwe_results['documents'] and cwe_results['documents'][0]:
            cwe_texts = []
            for doc in cwe_results['documents'][0]:
                cwe_texts.append(doc)
            parts.append(("CWE知识库", cwe_texts))

        # [3] 组装 memory_context
        if parts:
            memory_context = "\n【你的长期实战经验 & CWE 知识库 (Long-Term Memory + RAG)】：\n"
            memory_context += "请务必结合以下知识和经验进行代码审查，特别注意逻辑型漏洞（如 CSRF、IDOR、认证绕过）：\n"
            for section_name, docs in parts:
                memory_context += f"\n--- {section_name} ---\n"
                for idx, doc in enumerate(docs):
                    memory_context += f"  [{idx+1}] {doc}\n"

    except Exception:
        pass

    # 【核心修复1】：修改系统提示词，要求输出标准 JSON 对象格式
    sys_prompt = f"""你是一个高级安全分析智能体。你必须分析代码并输出漏洞 JSON。
    【核心禁令】：
    1. 严禁想象：禁止虚构任何文件夹、文件名、函数名或代码行。
    2. 证据至上：每一条 'evidence' 必须 100% 复制自真实文本。
    3. 拒绝模板：严禁输出教科书范例，必须针对 target_codebase 里的真实代码。
    4. 警惕混淆：如果在非预期后缀(如.css, .jpg)发现编程逻辑，务必如实报告。

    【输出逻辑】：
    - 必须输出一个合法的 JSON 对象，根节点必须是 "vulnerabilities" 数组（例如：{{"vulnerabilities": [{{...}}]}}）。
    - 提供包含漏洞的完整函数块，明确指出 Source 和 Sink。
    
    {memory_context}
    """

    messages = [SystemMessage(content=sys_prompt)]
    if state["critic_feedback"]:
        messages.append(HumanMessage(content=f"请参考评审意见修正：\n{state['critic_feedback']}"))
    else:
        messages.append(HumanMessage(content="开始分析 target_codebase 目录并检索 CWE 模式。"))

    step_count = 0
    MAX_STEPS = 20 

    while True:
        res = llm_with_tools.invoke(messages)
        messages.append(res)
        if not res.tool_calls or step_count >= MAX_STEPS:
            break
            
        for tool_call in res.tool_calls:
            print(f"  {BLUE}└─ 执行工具:{RESET} {tool_call['name']} | {YELLOW}参数:{RESET} {tool_call['args']}")
            tool_fn = TOOL_MAP[tool_call['name']]
            tool_out = tool_fn.invoke(tool_call['args'])
            print(f"  {YELLOW}└─ 工具返回结果前20字:{RESET} {str(tool_out)[:50]}...")
            messages.append(ToolMessage(content=str(tool_out), tool_call_id=tool_call['id']))
        step_count += 1
    
    # 【核心修复2】：强开底层 JSON_OBJECT 模式，杜绝少标点符号的解析错误
    json_llm = llm.bind(response_format={"type": "json_object"})
    final_res = json_llm.invoke(messages + [HumanMessage(content="请严格输出最终的 JSON 对象，必须包含 'vulnerabilities' 键。")])
    
    print(f"\n{BLUE}--- Analysis Agent 提交的草案 ---{RESET}")
    print(f"{BLUE}{final_res.content}{RESET}")
    print(f"{BLUE}-------------------------------{RESET}")
    
    return {
        "vulnerabilities": final_res.content,
        "iteration_count": state["iteration_count"] + 1,
        "messages": messages
    }

def critique_node(state: CoRedteamState):
    print(f"\n{BOLD}{RED}[🧐 Critique Agent]{RESET} 正在进行极其刻薄的交叉验证...")
    
    sys_prompt = """你现在是全球最顶尖、最挑剔的安全审计专家。
    检查 Analysis Agent 提交的漏洞提议：
    1. 证据核实：如果是教科书范例而无业务特征，直接 REJECTED。
    2. 路径对齐：文件名必须真实存在。
    3. 逻辑闭环：SQL 注入必须有真实的数据库交互代码。
    4. 颗粒度：必须有精准行号。

    输出纯 JSON：{"review_results": [{"id": "...", "status": "...", "feedback": "..."}], "overall_feedback": "..."}
    严禁任何 Markdown 标记。"""

    res = llm.invoke([
        SystemMessage(content=sys_prompt), 
        HumanMessage(content=f"请审查漏洞提议，严防 AI 幻觉：\n{state['vulnerabilities']}")
    ])
    
    print(f"\n{RED}=== Critique Agent 的评审反馈 ==={RESET}")
    print(f"{RED}{res.content}{RESET}")
    print(f"{RED}================================={RESET}")
    
    return {"critic_feedback": res.content}

def evolution_node(state: CoRedteamState):
    print(f"\n{BOLD}{GREEN}[🧠 Evolution]{RESET} 任务总结，写入长期记忆...")
    
    evolution_prompt = f"复盘审计：\n结果：{state['vulnerabilities']}\n反馈：{state['critic_feedback']}\n提取一条通用的漏洞模式经验。"
    experience = llm.invoke(evolution_prompt).content
    
    collection = chroma_client.get_or_create_collection(name="vulnerability_patterns")
    collection.add(
        documents=[experience],
        ids=[f"pattern_{state['iteration_count']}_{hash(experience[:5])}"]
    )
    
    print(f"\n{GREEN}💡 沉淀的新经验:{RESET}")
    print(f"{GREEN}{experience}{RESET}")
    print(f"💡 记忆库已更新。{RESET}")
    
    return {}

# ==========================================
# 4. 路由逻辑
# ==========================================

def should_continue(state: CoRedteamState):
    try:
        raw_output = state.get("critic_feedback", "")
        match = re.search(r'\{.*\}', raw_output, re.DOTALL)
        clean_json = match.group(0) if match else raw_output
        
        feedback = json.loads(clean_json)
        results = feedback.get("review_results", [])
        should_retry = any(r.get("status") in ["NEEDS_REFINEMENT", "REJECTED"] for r in results)
        
        if should_retry and state["iteration_count"] < 3:
            print(f"\n{YELLOW}[🔄 系统] 法官不满意，要求分析员补齐证据链！{RESET}")
            return "analyze"
    except Exception as e:
        print(f"{RED}[⚠️] JSON 解析失败: {e}{RESET}")
    
    print(f"\n{GREEN}[🏁 系统] 流程达成一致，进入进化阶段。{RESET}")
    return "evolve"

# ==========================================
# 5. 工作流组装
# ==========================================

builder = StateGraph(CoRedteamState)
builder.add_node("Analysis", analysis_node)
builder.add_node("Critique", critique_node)
builder.add_node("Evolution", evolution_node)

builder.set_entry_point("Analysis")
builder.add_edge("Analysis", "Critique")
builder.add_conditional_edges("Critique", should_continue, {"analyze": "Analysis", "evolve": "Evolution"})
builder.add_edge("Evolution", END)

app = builder.compile()

# ==========================================
# 6. 主执行流程 (双路保存报告)
# ==========================================

if __name__ == "__main__":
    print(f"{BOLD}{YELLOW}=== CO-REDTEAM Phase 1 (Discovery) 系统启动 ==={RESET}")
    initial_state = {"iteration_count": 0, "vulnerabilities": "", "critic_feedback": "", "messages": []}
    
    final_vulnerabilities = ""

    # 流式执行并捕获最终输出
    for output in app.stream(initial_state):
        if "Analysis" in output:
            final_vulnerabilities = output["Analysis"].get("vulnerabilities", final_vulnerabilities)

    if final_vulnerabilities:
        def _fix_json(raw):
            s = raw
            # 清理 Markdown 标记
            s = re.sub(r'```json\s*', '', s)
            s = re.sub(r'\s*```', '', s)
            
            # 兼容 JSON 对象 {...} 和 JSON 数组 [...]
            m = re.search(r'(\{.*\}|\[.*\])', s, re.DOTALL)
            s = m.group(0) if m else s
            return s

        final_json = None
        clean = _fix_json(final_vulnerabilities)

        try:
            parsed_data = json.loads(clean)
            
            # 如果大模型返回了数组，我们手动把它包成对象，防止后续 .get() 报错
            if isinstance(parsed_data, list):
                final_json = {"vulnerabilities": parsed_data, "status": "ANALYSIS_COMPLETE"}
            else:
                final_json = parsed_data
                
        except json.JSONDecodeError as err:
            print(f"{BOLD}{RED}  [JSON Fix] 解析失败: {str(err)}{RESET}")
            final_json = {"vulnerabilities": [], "status": "JSON_PARSE_ERROR", "error": str(err)}

        if final_json:
            paths = [
                "./reports/vulnerability_proposal_latest.json",
                "b/data/confirmed_vuln.json",
            ]
            os.makedirs("./reports", exist_ok=True)
            os.makedirs("b/data", exist_ok=True)

            for p in paths:
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(final_json, f, ensure_ascii=False, indent=4)

            # 兼容提取漏洞数量
            vulns = final_json.get("vulnerabilities", [])
            vuln_count = len(vulns)
            print(f"\n{BOLD}{GREEN}[OK] 报告已保存 ({vuln_count} 个漏洞):{RESET}")
            for p in paths:
                print(f"       {p}")

    print(f"\n{BOLD}{YELLOW}=== 审计流程结束 ==={RESET}")