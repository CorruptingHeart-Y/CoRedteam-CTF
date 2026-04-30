import json
import os
import re
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
# 2. 初始化 DeepSeek-V3
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
# 3. 节点逻辑 (带可视化输出)
# ==========================================

def analysis_node(state: CoRedteamState):
    print(f"\n{BOLD}{BLUE}[🚀 Analysis Agent]{RESET} 开始第 {state['iteration_count'] + 1} 轮深度代码审计...")

    sys_prompt = """你是一个高级安全分析智能体。你必须分析代码并输出漏洞 JSON。
    【核心禁令 - 违反即视为任务失败】：
    1. 严禁想象：禁止虚构任何文件夹、文件名、函数名或代码行。
    2. 证据至上：每一条 'evidence' 必须 100% 复制自工具返回的真实文本，严禁进行“文学加工”。
    3. 闭环检查：如果你调用工具发现目录为空，或者读取文件返回为空，你必须立即停止分析！
    4. 拒绝模板：严禁输出教科书上的典型案例（如常见的 SQL 注入模板），除非你真的在 target_codebase 的代码里看到了它。

    【输出逻辑】：
    - 如果 target_codebase 为空：直接输出 JSON {"vulnerabilities": [], "status": "ERROR_NO_CODE_FOUND"} 并结束。
    - 如果有代码：仅针对你抓取到的真实片段进行漏洞分析。
    - 格式：必须输出纯 JSON 对象，严禁包含任何 Markdown 符号（如 ```json）。
    
    记住：你不是在写小说，你是在做刑事取证。没有物证，就闭嘴
    
    提交证据时，禁止只给孤立的一行代码！ 你必须提供包含该漏洞的完整函数块，并明确指出输入源（Source）和漏洞汇聚点（Sink）。如果法官拒绝了你，请调用 get_snippet_tool 读取更多上下文来反驳他。
    """

    messages = [SystemMessage(content=sys_prompt)]
    if state["critic_feedback"]:
        messages.append(HumanMessage(content=f"请参考评审意见修正：\n{state['critic_feedback']}"))
    else:
        messages.append(HumanMessage(content="开始分析 target_codebase 目录并检索 CWE 模式。"))

    step_count = 0
    MAX_STEPS = 15 

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
    
    final_res = llm.invoke(messages + [HumanMessage(content="请基于以上分析输出最终漏洞 JSON 列表。")])
    
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
    
    # 强制评审员进入“找茬模式”
    sys_prompt = """你现在是全球最顶尖、最挑剔的安全审计专家。你的任务是审查 Analysis Agent 提交的漏洞提议。
    
    【你的评审准则 - 严于律己，更严于律人】：
    1. 证据核实：检查提议中的 'evidence'。如果代码片段看起来像通用的“教科书范例”而没有具体业务特征，直接 REJECTED。
    2. 路径对齐：检查文件名是否真实存在。如果 Analysis 提到了你没听说过的文件路径，直接质疑其真实性。
    3. 逻辑闭环：如果分析员说有 SQL 注入，但代码里根本没看到数据库连接或查询语句，标记为 REJECTED。
    4. 颗粒度检查：如果提议中没有明确的行号（Line Number），标记为 NEEDS_REFINEMENT。

    【裁决逻辑】：
    - APPROVED: 只有在证据确凿（有真实文件名、精准行号、逻辑清晰且严重）时给出。
    - REJECTED: 只要怀疑是 AI 幻觉、虚构代码、或是低级误报，一律拒绝。
    - NEEDS_REFINEMENT: 思路可能对，但证据链断裂，或者描述太笼统。

    输出纯 JSON：{"review_results": [{"id": "...", "status": "...", "feedback": "..."}], "overall_feedback": "..."}
    严禁输出任何 Markdown 标记或多余废话。"""

    res = llm.invoke([
        SystemMessage(content=sys_prompt), 
        HumanMessage(content=f"请审查以下漏洞提议，如果发现它在瞎编，请狠狠地拆穿它：\n{state['vulnerabilities']}")
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
    print(f"{GREEN}💡 记忆库已更新。{RESET}")
    
    return {}

# ==========================================
# 4. 路由逻辑 (带 Robust JSON 提取)
# ==========================================

def should_continue(state: CoRedteamState):
    try:
        raw_output = state.get("critic_feedback", "")
        # 正则提取 JSON 防止大模型废话
        match = re.search(r'\{.*\}', raw_output, re.DOTALL)
        clean_json = match.group(0) if match else raw_output
        
        feedback = json.loads(clean_json)
        results = feedback.get("review_results", [])
        should_retry = any(r.get("status") in ["NEEDS_REFINEMENT", "REJECTED"] for r in results)
        if should_retry and state["iteration_count"] < 3:
            print(f"\n{YELLOW}[🔄 系统] 法官不满意，分析员滚回去补齐证据链！{RESET}")
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

if __name__ == "__main__":
    print(f"{BOLD}{YELLOW}=== CO-REDTEAM Phase 1 (Discovery) 系统启动 ==={RESET}")
    initial_state = {"iteration_count": 0, "vulnerabilities": "", "critic_feedback": "", "messages": []}
    
    for _ in app.stream(initial_state):
        pass
    
    print(f"\n{BOLD}{YELLOW}=== 审计流程结束 ==={RESET}")