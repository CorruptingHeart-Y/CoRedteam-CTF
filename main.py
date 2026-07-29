import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
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
# 0. CWE 字段归一化（Stage 1 输出边界）
# ==========================================

def _normalize_cwe_field(vuln: dict) -> str:
    """Normalize cwe / cwe_id field. Fail-closed on ambiguity or missing data."""
    has_cwe_id = "cwe_id" in vuln
    has_cwe = "cwe" in vuln
    raw_id = vuln.get("cwe_id")
    raw_cwe = vuln.get("cwe")

    if not has_cwe_id and not has_cwe:
        raise ValueError(f"CWE_NORMALIZE_MISSING: neither cwe_id nor cwe in vuln")

    # Only cwe_id
    if has_cwe_id and not has_cwe:
        if not isinstance(raw_id, str) or not raw_id.strip():
            raise ValueError(f"CWE_NORMALIZE_EMPTY: cwe_id empty: {raw_id!r}")
        return raw_id.strip()

    # Only cwe
    if has_cwe and not has_cwe_id:
        if not isinstance(raw_cwe, str) or not raw_cwe.strip():
            raise ValueError(f"CWE_NORMALIZE_EMPTY: cwe empty: {raw_cwe!r}")
        return raw_cwe.strip()

    # Both present
    id_val = raw_id.strip() if isinstance(raw_id, str) else str(raw_id)
    cwe_val = raw_cwe.strip() if isinstance(raw_cwe, str) else str(raw_cwe)
    if not id_val and not cwe_val:
        raise ValueError("CWE_NORMALIZE_BOTH_EMPTY")
    if not id_val:
        return cwe_val
    if not cwe_val:
        return id_val
    if id_val.upper() == cwe_val.upper():
        return id_val
    raise ValueError(f"CWE_NORMALIZE_CONFLICT: cwe_id={id_val!r} != cwe={cwe_val!r}")


def _apply_cwe_normalization(vulns: list) -> list:
    """Normalize CWE fields: ensure every entry has cwe_id, resolve conflicts."""
    out = []
    for v in vulns:
        canonical = _normalize_cwe_field(v)
        entry = {**v, "cwe_id": canonical}
        out.append(entry)
    return out


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
# 2. 初始化 LLM (OpenAI-compatible, controlled by .env)
# ==========================================
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY")
DEEPSEEK_BASE_URL = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
DEEPSEEK_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")

llm = ChatOpenAI(
    model=DEEPSEEK_MODEL,
    api_key=DEEPSEEK_API_KEY,
    base_url=DEEPSEEK_BASE_URL,
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
    file_cache: Dict[str, Any]  # 文件内容缓存，避免重复读取

# ==========================================
# 3. 节点逻辑
# ==========================================

def _extract_feedback_summary(critic_feedback: str) -> str:
    """从Critique反馈中提取关键信息，用于指导Analysis Agent的后续策略"""
    try:
        match = re.search(r'\{.*\}', critic_feedback, re.DOTALL)
        if match:
            feedback_json = json.loads(match.group(0))
            results = feedback_json.get("review_results", [])
            
            rejected_items = []
            needs_refinement = []
            accepted_count = 0
            
            for r in results:
                status = r.get("status", "")
                item_id = r.get("id", "unknown")
                feedback_text = r.get("feedback", "")
                
                if status == "REJECTED":
                    rejected_items.append(f"- {item_id}: {feedback_text[:100]}")
                elif status == "NEEDS_REFINEMENT":
                    needs_refinement.append(f"- {item_id}: {feedback_text[:100]}")
                elif status == "ACCEPTED":
                    accepted_count += 1
            
            summary = f"已接受: {accepted_count} 项\n"
            
            if rejected_items:
                summary += f"\n被拒绝的漏洞（需要重新验证或撤回）：\n"
                summary += "\n".join(rejected_items[:5])  # 最多显示5个
            
            if needs_refinement:
                summary += f"\n\n需要完善的漏洞（证据不足）：\n"
                summary += "\n".join(needs_refinement[:5])
            
            overall = feedback_json.get("overall_feedback", "")
            if overall:
                summary += f"\n\n总体建议: {overall[:200]}"
            
            return summary
    except Exception as e:
        pass
    return "无法解析反馈，请查看原始评审意见"

def analysis_node(state: CoRedteamState):
    iteration = state['iteration_count']
    print(f"\n{BOLD}{BLUE}[🚀 Analysis Agent]{RESET} 开始第 {iteration + 1} 轮深度代码审计...")

    # --- 长期记忆检索 (RAG) - 双库查询 + 关键覆盖兜底 ---
    memory_context = ""
    try:
        parts = []

        # [1] 查询 vulnerability_patterns (历史经验)
        pattern_collection = chroma_client.get_or_create_collection(name="vulnerability_patterns")
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
        docs_collection = chroma_client.get_or_create_collection(name="vulnerability_docs")
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

    # ===== 动态策略调整（根据审计轮次） =====
    if iteration == 0:
        strategy_section = """
## 审计策略（第1轮 - 全面扫描与发现）

你的任务是全面扫描目标代码库，发现所有潜在的安全漏洞。请按以下优先级进行：

### 🔍 扫描重点
1. **入口点分析**: 
   - 路由定义文件 (routes.py, urls.py, views.py, controllers/)
   - API端点 (api.py, endpoints/, resources/)
   - 主应用入口 (main.py, app.py, server.js)

2. **用户输入处理**:
   - 查询参数 (request.args, request.query_params)
   - 表单数据 (request.form, request.body)
   - 路径参数 (URL路径中的变量)
   - 文件上传 (File upload handlers)
   - HTTP Headers (Cookie, Authorization, X-Forwarded-For)

3. **危险函数调用**:
   - 数据库操作: execute(), query(), raw SQL
   - 命令执行: os.system(), subprocess, eval(), exec()
   - 文件操作: open(), read(), write(), path traversal
   - 重定向: redirect(), HttpResponseRedirect
   - 模板渲染: render_template_string(), innerHTML, dangerouslySetInnerHTML

4. **认证与授权**:
   - Session/Cookie管理
   - JWT Token处理
   - 权限检查装饰器 (@login_required, @permission_required)
   - CSRF Token验证

5. **客户端安全**:
   - JavaScript中的敏感数据暴露
   - Service Worker配置
   - DOM操作和事件处理
   - localStorage/sessionStorage使用

### 📝 输出要求
- **质量优先**: 只报告可直接利用的高风险安全漏洞（估计6-10个）
- **避免噪音**: 不要报告以下低价值问题：
  * 配置类：硬编码密码、Cookie标志、错误信息泄露、缺少安全头
  * 理论风险：需要极端前提条件才能利用的问题
  * 重复项：相同source→sink路径只报告一次
  * 总结性描述：不要把多个漏洞合并成"攻击链"单独报告
- 提供完整的source→sink数据流
- 标注漏洞类型和严重程度（CRITICAL/HIGH/MEDIUM/LOW）
- 如果发现多阶段攻击链，明确标注各环节的关系"""
        
    elif iteration == 1:
        feedback_summary = _extract_feedback_summary(state.get('critic_feedback', ''))
        strategy_section = f"""
## 审计策略（第2轮 - 针对性补强证据）

上一轮评审反馈摘要：
{feedback_summary}

### 🎯 本轮任务
针对 Critique Agent 的反馈进行以下操作：

1. **对于被拒绝的漏洞**：
   - 重新验证文件路径和行号是否正确
   - 使用工具重新读取源代码，确认代码片段准确性
   - 如果确实不存在或错误，主动撤回该漏洞提议

2. **对于需要完善的漏洞**：
   - 补充更详细的代码证据
   - 提供 source → sink 的完整数据流追踪
   - 说明漏洞在真实攻击场景中的利用方式

3. **寻找辅助证据**：
   - 检查目标代码库中是否有测试脚本、solver、exploit等参考文件
   - 这些文件通常包含作者提供的攻击示例，可作为佐证
   - 常见目录：htb/, bot/, tests/, exploits/, solve*, poc/

4. **多阶段攻击说明**：
   - 如果某个漏洞是攻击链的一环，明确说明其作用
   - 解释与其他已发现漏洞的关联性
   - 即使单独看可能不完整，但在组合攻击中仍有价值"""
        
    else:
        feedback_summary = _extract_feedback_summary(state.get('critic_feedback', ''))
        strategy_section = f"""
## 审计策略（第{iteration + 1}轮 - 精准修复与最终确认）

前几轮评审反馈：
{feedback_summary}

### 🎯 本轮任务（最后一轮机会）
1. 只针对 Critique Agent 明确指出的问题进行修改
2. 不要重新扫描已被接受的漏洞（避免浪费资源）
3. 对于反复被拒绝的漏洞，考虑是否真的不存在，可以主动移除
4. 确保所有保留的漏洞都有确凿的证据支持
5. 重点提供精确到行号的代码片段"""

    sys_prompt = f"""你是一个高级安全分析智能体。你必须分析代码并输出漏洞 JSON。

{strategy_section}

## 【核心禁令】
1. 严禁想象：禁止虚构任何文件夹、文件名、函数名或代码行。
2. 证据至上：每一条 'evidence' 必须 100% 复制自真实文本。
3. 拒绝模板：严禁输出教科书范例，必须针对目标目录 '{target_display_name}' 里的真实代码。
4. 警惕混淆：如果在非预期后缀(如.css, .jpg)发现编程逻辑，务必如实报告。
5. 锁定根目录：你的所有文件读取工具只能访问目标根目录 '{target_display_name}' 内的文件。任何越界路径都会被工具拒绝。

## 【输出逻辑】
- 必须输出一个合法的 JSON 对象，根节点必须是 "vulnerabilities" 数组
- 提供包含漏洞的完整函数块，明确指出 Source 和 Sink
- 对于多阶段攻击，标注各环节之间的关系
- source.file 路径必须相对于目标根目录 '{target_display_name}'

{memory_context}
"""

    messages = [SystemMessage(content=sys_prompt)]
    if state["critic_feedback"]:
        messages.append(HumanMessage(content=f"请参考评审意见修正：\n{state['critic_feedback']}"))
    else:
        messages.append(HumanMessage(content=f"开始分析目标目录 '{target_display_name}' 并检索 CWE 模式。"))

    # ===== 初始化/恢复文件缓存 =====
    file_cache = state.get('file_cache', {})
    if iteration == 0:
        file_cache = {}
        print(f"{BLUE}[💾 缓存] 初始化文件缓存（第1轮）{RESET}")
    else:
        cache_size = len(file_cache)
        print(f"{BLUE}[💾 缓存] 复用已有缓存 ({cache_size} 个文件)（第{iteration + 1}轮）{RESET}")

    step_count = 0
    MAX_STEPS = 20 
    cache_hits = 0
    cache_misses = 0

    while True:
        res = llm_with_tools.invoke(messages)
        messages.append(res)
        if not res.tool_calls or step_count >= MAX_STEPS:
            break
            
        for tool_call in res.tool_calls:
            tool_name = tool_call['name']
            tool_args = tool_call['args']
            
            # 生成缓存键
            cache_key = f"{tool_name}:{hash(str(sorted(tool_args.items())))}"
            
            # 检查是否命中缓存
            if cache_key in file_cache:
                cached_result = file_cache[cache_key]
                print(f"  {GREEN}└─ [缓存命中✓]{RESET} {tool_name} | 参数: {str(tool_args)[:60]}")
                messages.append(ToolMessage(content=str(cached_result), tool_call_id=tool_call['id']))
                cache_hits += 1
            else:
                # 安全检查：过滤明显的无效路径
                should_skip = False
                if tool_name == 'get_whole_file_structure_tool':
                    path = tool_args.get('path', '')
                    dangerous_paths = ['/', '..', '/etc', '/root', 'C:\\', '\\', '~', '/usr', '/var']
                    if any(path == dp or path.startswith(dp + '/') or path.startswith(dp + '\\') for dp in dangerous_paths):
                        print(f"  {RED}└─ [安全拦截✗]{RESET} 跳过危险路径: {path}")
                        messages.append(ToolMessage(
                            content=f"错误：不允许访问系统路径 '{path}'，请使用目标根目录内的相对路径。",
                            tool_call_id=tool_call['id']
                        ))
                        step_count += 1
                        should_skip = True
                
                if not should_skip:
                    print(f"  {BLUE}└─ 执行工具:{RESET} {tool_name} | {YELLOW}参数:{RESET} {str(tool_args)[:60]}")
                    tool_fn = TOOL_MAP[tool_name]
                    tool_out = tool_fn.invoke(tool_args)
                    print(f"  {YELLOW}└─ 工具返回结果前20字:{RESET} {str(tool_out)[:50]}...")
                    
                    # 存入缓存
                    file_cache[cache_key] = tool_out
                    
                    messages.append(ToolMessage(content=str(tool_out), tool_call_id=tool_call['id']))
                    cache_misses += 1
        
        step_count += 1
    
    # 输出缓存统计
    total_access = cache_hits + cache_misses
    if total_access > 0:
        hit_rate = (cache_hits / total_access) * 100
        print(f"\n{BLUE}[📊 缓存统计]{RESET} 命中: {cache_hits} | 未命中: {cache_misses} | 命中率: {hit_rate:.1f}%")
    
    # 【核心修复2】：强开底层 JSON_OBJECT 模式，杜绝少标点符号的解析错误
    json_llm = llm.bind(response_format={"type": "json_object"})
    
    # 【核心修复3】：清洗带有未执行 tool_calls 的消息，避免 OpenAI 400 错误
    safe_messages = list(messages)
    if safe_messages and hasattr(safe_messages[-1], 'tool_calls') and safe_messages[-1].tool_calls:
        print(f"{YELLOW}[⚠️ 消息清洗] 移除末尾未闭环的 tool_calls 消息，避免 API 400 错误{RESET}")
        safe_messages.pop()
    
    final_res = json_llm.invoke(safe_messages + [HumanMessage(content="请严格输出最终的 JSON 对象，必须包含 'vulnerabilities' 键。")])
    
    print(f"\n{BLUE}--- Analysis Agent 提交的草案 ---{RESET}")
    print(f"{BLUE}{final_res.content}{RESET}")
    print(f"{BLUE}-------------------------------{RESET}")
    
    return {
        "vulnerabilities": final_res.content,
        "iteration_count": iteration + 1,
        "messages": messages,
        "file_cache": file_cache  # 传递缓存给下一轮
    }

def critique_node(state: CoRedteamState):
    print(f"\n{BOLD}{RED}[🧐 Critique Agent]{RESET} 正在进行极其刻薄的交叉验证...")
    
    sys_prompt = """你是一位资深的安全审计评审专家，负责评估漏洞发现的准确性和实用性。

## 核心评审原则（平衡严格性与实用性）

### ❌ 必须拒绝的情况（硬性标准）
1. **路径不存在**: 文件路径或行号在目标代码库中不存在
2. **代码不匹配**: 引用的代码片段与实际文件内容不符
3. **明显幻觉**: 编造不存在的文件、函数、变量或API端点
4. **数据流断裂**: source和sink之间缺乏明确的数据传递关系

### ⚠️ 应该拒绝的情况（质量控制）
5. **低价值配置问题**:
   - 硬编码密码/密钥（除非是生产环境且可直接利用）
   - 缺少HttpOnly/Secure标志等Cookie配置
   - 错误信息泄露堆栈信息
   - 缺少安全响应头（X-Frame-Options等）
   → 这些属于"安全加固建议"，不是真正的可利用漏洞
   
6. **依赖极端前提条件**:
   - 需要攻击者已有管理员权限才能利用的"漏洞"
   - 需要用户主动执行不现实操作的"漏洞"
   - 理论上可行但实际无法利用的边缘案例
   
7. **重复或不完整的漏洞**:
   - 与已报告漏洞完全相同的source→sink路径
   - 只是对其他漏洞的总结或描述（如"多阶段攻击链"本身不是独立漏洞）
   - 缺少明确利用方式的纯理论分析

### ✅ 应该接受的情况（高质量漏洞）
1. **直接可利用的安全漏洞**:
   - 注入类：SQL注入、XSS、命令注入、SSTI、模板注入
   - 认证/授权：竞态条件、IDOR、权限绕过、认证缺陷
   - 客户端攻击：CSRF、SSRF、开放重定向、CSS注入
   
2. **多阶段攻击链中的关键环节**:
   - 即使单个看需要配合其他漏洞，但确实是攻击链中不可或缺的一环
   - 例如：CSS注入（用于窃取CSRF Token）、Service Worker劫持（用于窃取Cookie）
   
3. **引用辅助验证材料**:
   - 目标代码库中的solver/exploit/bot脚本可作为参考
   - 目录如：htb/, bot/, tests/, exploits/, solve*, *.solver.* 等

4. **业务逻辑漏洞**:
   - 竞态条件、状态机篡改、逻辑缺陷
   - 可能没有明显的危险函数调用，但存在安全隐患

## 评审重点
- **质量 > 数量**: 宁可接受5个高质量漏洞，也不要15个低价值噪音
- **可利用性优先**: 只接受真实攻击者能够利用的漏洞
- **避免误报**: 配置问题和理论风险不应算作漏洞
- **去重合并**: 相同source→sink的漏洞只保留最完整的一个

## ⚠️ 输出格式（极其重要）
你必须输出**纯 JSON 格式**，严禁使用任何 Markdown 标记！

正确的输出示例：
{
  "review_results": [
    {
      "id": "VULN-001",
      "status": "ACCEPTED",
      "confidence": "HIGH",
      "feedback": "详细的评审理由",
      "missing_evidence": ""
    }
  ],
  "overall_feedback": "总体评价",
  "identified_attack_patterns": "注入类, 认证类"
}

错误的输出示例（绝对禁止）：
❌ 使用 ### 或 ## 等标题标记
❌ 使用 **粗体** 或 *斜体*
❌ 使用 --- 分隔线
❌ 使用编号列表或项目符号
❌ 任何非JSON格式的文本内容

记住：你的整个回复必须是一个且仅一个合法的JSON对象，从 { 开始到 } 结束，中间不能有任何其他字符。"""

    res = llm.invoke([
        SystemMessage(content=sys_prompt), 
        HumanMessage(content=f"""请审查以下漏洞提议，严格控制质量，只接受真正可利用的高风险漏洞。

## 评审标准提醒
- 拒绝所有配置类问题（硬编码密码、Cookie标志、错误信息泄露等）
- 拒绝重复漏洞和对其他漏洞的总结描述
- 拒绝需要极端前提条件才能利用的"漏洞"
- 接受所有真实的注入/认证/授权/客户端攻击类漏洞
- 接受多阶段攻击链中的关键环节

## ⚠️ Important Reminder
You must output ONLY JSON format. No explanations, titles, lists, or Markdown markers! Start with open_brace and end with close_brace.

## Vulnerability Report to Review
{state['vulnerabilities']}""")
    ])
    
    print(f"\n{RED}=== Critique Agent 的评审反馈 ==={RESET}")
    print(f"{RED}{res.content}{RESET}")
    print(f"{RED}================================={RESET}")
    
    return {"critic_feedback": res.content}

def evolution_node(state: CoRedteamState):
    print(f"\n{BOLD}{GREEN}[🧠 Evolution]{RESET} 任务总结，写入长期记忆...")

    evolution_prompt = (
        "复盘本次代码审计过程，提取一条通用的漏洞模式经验。"
        "\n【重要禁令】"
        "\n- 禁止写入任何绝对文件路径（如 /home/user/... 或 C:\\... 或 target_codebase/...）"
        "\n- 禁止写入任何 flag 值（如 HTB{...} 或 FLAG{...} 或 CTF{...}）"
        "\n- 禁止写入任何具体的 exploit payload、solver 脚本路径或官方解答引用"
        "\n- 禁止写入任何具体的 URL、IP 地址或目标主机信息"
        "\n- 只能描述通用的漏洞模式、检测方法和防御建议"
        "\n结果简报：" + state['vulnerabilities'][:500] + "\n反馈摘要：" + state['critic_feedback'][:500]
    )
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
# 4. 路由逻辑（智能决策）
# ==========================================

def should_continue(state: CoRedteamState):
    try:
        raw_output = state.get("critic_feedback", "")
        match = re.search(r'\{.*\}', raw_output, re.DOTALL)
        clean_json = match.group(0) if match else raw_output
        
        feedback = json.loads(clean_json)
        results = feedback.get("review_results", [])
        total = len(results)
        
        if total == 0:
            print(f"\n{GREEN}[🏁 系统] 无漏洞提议，流程结束。{RESET}")
            return "evolve"
        
        # 统计各类评审结果
        accepted = sum(1 for r in results if r.get("status") == "ACCEPTED")
        rejected = sum(1 for r in results if r.get("status") == "REJECTED")
        needs_refinement = sum(1 for r in results if r.get("status") == "NEEDS_REFINEMENT")
        
        acceptance_rate = accepted / total
        iteration = state["iteration_count"]
        
        # ===== 智能决策逻辑 =====
        should_retry = False
        reason = ""
        
        # 情况1：存在 NEEDS_REFINEMENT 的项目（必须继续完善）
        if needs_refinement > 0 and iteration < 3:
            should_retry = True
            reason = f"有 {needs_refinement} 项需要完善证据"
        
        # 情况2：通过率过低（<50%）且还有重试机会
        elif acceptance_rate < 0.5 and iteration < 2:
            should_retry = True
            reason = f"通过率仅 {acceptance_rate:.0%} ({accepted}/{total})，建议补强证据"
        
        # 情况3：存在可能的误报（反馈中包含"假设性"、"可能"、"推测"等词汇）
        elif rejected > 0 and iteration < 2:
            false_positive_indicators = ['假设', '可能', '推测', '缺乏业务特征', '教科书']
            potential_false_positives = []
            
            for r in results:
                if r.get("status") == "REJECTED":
                    feedback_text = r.get("feedback", "")
                    if any(indicator in feedback_text for indicator in false_positive_indicators):
                        potential_false_positives.append(r.get("id", "unknown"))
            
            if len(potential_false_positives) > 0:
                should_retry = True
                reason = f"检测到 {len(potential_false_positives)} 个可能误报（{', '.join(potential_false_positives[:3])}）"
        
        # 执行重试判断
        if should_retry and iteration < 3:
            print(f"\n{YELLOW}[🔄 系统] {reason}，要求分析员补齐证据链！（第{iteration + 1}轮 → 第{iteration + 2}轮）{RESET}")
            print(f"{YELLOW}       统计: ✅已接受 {accepted} | ❌被拒绝 {rejected} 🔧需完善 {needs_refinement}{RESET}")
            return "analyze"
        else:
            # 不再重试的原因
            if iteration >= 3:
                stop_reason = f"已达最大轮次限制 ({iteration + 1}轮)"
            else:
                stop_reason = f"通过率可接受 ({acceptance_rate:.0%})"
                
            print(f"\n{GREEN}[🏁 系统] 流程达成一致，进入进化阶段。（共{iteration + 1}轮，{stop_reason}）{RESET}")
            print(f"{GREEN}       最终统计: ✅已接受 {accepted} | ❌被拒绝 {rejected} | 🔧需完善 {needs_refinement}{RESET}")
            return "evolve"
            
    except Exception as e:
        print(f"{RED}[⚠️] JSON 解析失败或异常: {e}{RESET}")
        print(f"{GREEN}[🏁 系统] 发生错误，进入进化阶段。{RESET}")
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
    # Fix Unicode emoji output on Windows (GBK codec can't handle emoji)
    if os.name == "nt":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    # ================================================================
    # Stage 1 Target Scope Enforcement
    # ================================================================
    # CO_REDTEAM_TARGET_ROOT is set by CLI (b/cli.py) before spawning this process.
    # code_browser.py reads it at import time to lock BASE_DIR.
    # We re-read and canonicalize here for logging and prompt injection.
    resolved_target_root = os.environ.get("CO_REDTEAM_TARGET_ROOT", "")
    if resolved_target_root:
        resolved_target_root = str(Path(resolved_target_root).resolve())
        os.environ["CO_REDTEAM_TARGET_ROOT"] = resolved_target_root
        print(f"{BOLD}{YELLOW}[TARGET SCOPE] resolved_target_root={resolved_target_root}{RESET}")
    else:
        # Fallback for backward compatibility: use cwd
        resolved_target_root = str(Path(".").resolve())
        print(f"{BOLD}{YELLOW}[TARGET SCOPE] CO_REDTEAM_TARGET_ROOT not set, defaulting to cwd: {resolved_target_root}{RESET}")

    target_display_name = resolved_target_root

    print(f"{BOLD}{YELLOW}=== CO-REDTEAM Phase 1 (Discovery) 系统启动 ==={RESET}")
    initial_state = {
        "iteration_count": 0,
        "vulnerabilities": "",
        "critic_feedback": "",
        "messages": [],
        "file_cache": {}  # 初始化文件缓存
    }
    
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
            # ── CWE normalization: ensure every vuln has cwe_id ──
            vulns = final_json.get("vulnerabilities", [])
            if vulns:
                try:
                    vulns = _apply_cwe_normalization(vulns)
                    final_json["vulnerabilities"] = vulns
                except ValueError as e:
                    print(f"{BOLD}{RED}[CWE NORMALIZE] {e}{RESET}")
                    # Continue with non-normalized data rather than losing results

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