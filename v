import chromadb
import os

DB_PATH = "./co_redteam_memory"
COLLECTION_NAME = "vulnerability_docs"

def init_vulnerability_database():
    client = chromadb.PersistentClient(path=DB_PATH)
    collection = client.get_or_create_collection(name=COLLECTION_NAME)

    cwe_entries = [
    {
        "id": "CWE-89",
        "content": "名称: SQL Injection (SQL注入)\n描述: 应用程序在未正确清理外部输入的情况下，将其直接拼接到 SQL 语句中。\n影响: 数据泄露、数据库被篡改、潜在的服务器控制。\n代码表象: 字符串拼接构建的 SQL 查询 (如 `\"SELECT * FROM users WHERE name = '\" + username + \"'\"`)。\n审计策略: 追踪 HTTP 请求参数，查看其是否未经预编译 (Prepared Statements) 或 ORM 参数化绑定就直接传入了数据库执行函数 (如 `cursor.execute`, `jdbcTemplate.query`)。"
    },
    {
        "id": "CWE-79",
        "content": "名称: Cross-Site Scripting / XSS (跨站脚本)\n描述: 应用程序将不可信的数据直接输出到网页中，未进行 HTML 实体转义。\n影响: 窃取用户 Session、伪造用户操作。\n代码表象: 模板引擎中禁用了自动转义 (如 Jinja2 的 `|safe`，Thymeleaf 的 `th:utext`)，或者在接口中直接原样返回了用户的 HTML 标签输入。\n审计策略: 寻找数据流的 Sink 点（如直接 `render_template` 或构建前端 DOM），检查在此之前是否有针对 `<script>` 等标签的过滤或转义机制。"
    },
    {
        "id": "CWE-22",
        "content": "名称: Path Traversal (路径穿越)\n描述: 应用程序使用外部输入来构造文件路径，但未对 `../` 等特殊目录符号进行限制。\n影响: 任意系统文件读取 (如 `/etc/passwd`) 或代码覆写。\n代码表象: 文件读取函数 (如 `open()`, `FileInputStream`) 的路径参数中包含了未经校验的请求变量。\n审计策略: 检查所有涉及文件读写、下载的接口。确认是否有 `os.path.abspath` 或类似的安全校验确保最终路径没有逃逸出允许的根目录。"
    },
    {
        "id": "CWE-78",
        "content": "名称: OS Command Injection (操作系统命令注入)\n描述: 程序通过拼接字符串构造系统命令并在底层 shell 中执行。\n影响: 远程代码执行 (RCE)，直接接管服务器。\n代码表象: 使用了高危的系统调用函数，如 Python 的 `os.system()`, `subprocess.Popen(shell=True)`，Java 的 `Runtime.getRuntime().exec()`，且参数包含用户输入。\n审计策略: 强烈警告！只要发现用户输入流入系统命令执行函数，且未进行严格的白名单校验，直接标记为高危漏洞。"
    },
    {
        "id": "CWE-502",
        "content": "名称: Deserialization of Untrusted Data (不安全的反序列化)\n描述: 应用程序反序列化了来自不受信任源的数据，攻击者可以通过构造恶意的序列化对象来控制执行流。\n影响: 远程代码执行 (RCE)、拒绝服务。\n代码表象: Python 中的 `pickle.loads()`, `yaml.load()` (非 SafeLoader)；Java 中的 `ObjectInputStream.readObject()`, `Fastjson.parseObject()`。\n审计策略: 检查是否接受了外部传入的序列化数据 (如 Base64 编码的 Cookie、API 参数)。如果是，确认是否使用了安全的序列化格式 (如纯 JSON) 或开启了严格的类型白名单。"
    },
    {
        "id": "CWE-639",
        "content": "名称: Insecure Direct Object References / IDOR (越权访问 / 不安全的直接对象引用)\n描述: 系统基于用户提供的 ID 访问内部资源，但未验证当前用户是否有权访问该 ID 对应的资源。\n影响: 窃取或篡改其他用户的私人数据。\n代码表象: 接口类似 `/api/user/info?id=123`，后端代码仅 `SELECT * FROM users WHERE id = ?`，而未添加 `AND owner_id = current_user_id` 的校验逻辑。\n审计策略: 重点审查业务逻辑代码。找到所有操作特定对象的接口，验证其中是否包含了基于当前登录会话 (Session/Token) 的权限归属校验。"
    },
    {
        "id": "CWE-352",
        "content": "名称: Cross-Site Request Forgery / CSRF (跨站请求伪造)\n描述: 攻击者诱导已登录用户在不知情的情况下执行敏感操作。\n影响: 资金转账、密码修改等未授权的敏感写操作。\n代码表象: 修改状态的 HTTP 请求 (POST/PUT/DELETE) 仅依赖 Cookie 进行身份验证，且没有要求提供 CSRF Token 或验证 Referer。\n审计策略: 检查修改敏感数据的接口，确认其是否验证了 `X-CSRF-Token` 头部，或者框架层面是否全局启用了 CSRF 防护中间件。"
    },
    {
        "id": "CWE-434",
        "content": "名称: Unrestricted Upload of File with Dangerous Type (不安全的文件上传)\n描述: 允许用户上传文件，但未对文件后缀、类型和内容进行严格限制。\n影响: 上传 WebShell 导致服务器被彻底攻陷 (RCE)。\n代码表象: 仅在前端校验后缀，或者后端仅通过 `Content-Type` 头判断文件类型；上传后的文件被保存在 Web 容器可解析的目录中。\n审计策略: 检查文件上传处理逻辑。必须确认：1. 后端拥有严格的后缀名白名单；2. 文件内容校验 (如魔数)；3. 上传目录禁止脚本执行权限或将文件存入对象存储 (OSS)。"
    },
    {
        "id": "CWE-798",
        "content": "名称: Use of Hard-coded Credentials (硬编码凭证)\n描述: 源代码中直接写死了密码、API Key 或加密密钥。\n影响: 源代码泄露即导致系统被接管。\n代码表象: 代码中存在明文的 `PASSWORD = \"admin123\"`, `SECRET_KEY = \"sk-xxxxx\"`。\n审计策略: 扫描配置文件和常量定义文件，确认敏感凭证是否全部被抽离为环境变量读取 (如 `os.environ.get('DB_PASS')`) 或使用了专门的密钥管理系统。"
    },
    {
        "id": "CWE-862",
        "content": "名称: Missing Authorization (缺失授权校验)\n描述: 接口缺乏权限验证，任何访问者都可以直接调用。\n影响: 敏感数据泄露或恶意篡改。\n代码表象: 在通常需要登录或管理员权限的接口 (如 `/admin/delete_user`) 上，缺失了鉴权装饰器 (如 `@login_required`, `@PreAuthorize`)。\n审计策略: 对比普通接口和敏感接口的路由定义，检查权限拦截器或装饰器是否在关键高危操作上出现了遗漏。"
    },
    {
        "id": "CWE-917",
        "content": "名称: Expression Language Injection / SSTI (表达式语言注入 / 模板注入)\n描述: 外部输入被直接当作模板或表达式语言进行解析。\n影响: 信息泄露，通常可升级为远程代码执行 (RCE)。\n代码表象: Python 的 Jinja2 中使用了 `render_template_string(user_input)`；Java 中的 OGNL 或 SpEL 执行了不可信字符串。\n审计策略: 检查模板引擎的使用方式。绝对禁止将用户输入作为模板字符串本身进行编译和渲染，输入只能作为数据变量传递给固定模板。"
    },
    {
        "id": "CWE-94",
        "content": "名称: Improper Control of Generation of Code / Code Injection (代码注入)\n描述: 应用程序动态拼接生成代码并在运行时执行。\n影响: 完全的应用程序控制 (RCE)。\n代码表象: 代码中直接使用用户输入调用了动态执行函数，如 PHP 的 `eval()`, JavaScript/Node.js 的 `eval()`, Python 的 `exec()`。\n审计策略: 这是最严重的漏洞之一。全局搜索 `eval`, `exec` 等关键字，确认是否有外部参数流入其中。"
    },
    {
        "id": "CWE-918",
        "content": "名称: Server-Side Request Forgery / SSRF (服务端请求伪造)\n描述: 应用程序在未验证目标 URL 的情况下，根据用户提供的 URL 发起网络请求。\n影响: 扫描内网端口、读取云平台元数据 (Metadata)、绕过防火墙或访问内部敏感服务。\n代码表象: 使用了发起请求的库 (如 Python 的 `requests.get/post`, `urllib`, Java 的 `HttpURLConnection`, `URL.openStream()`)，且 URL 的域名或 IP 部分直接来自用户参数。\n审计策略: 追踪发起网络请求的函数。验证是否：1. 建立了目标白名单；2. 禁用了对 127.0.0.1、192.168.x.x 等私有 IP 段的访问；3. 限制了允许的协议 (仅限 http/https)。"
    },
    {
        "id": "CWE-287",
        "content": "名称: Improper Authentication / Broken JWT (不当的身份验证 / JWT绕过)\n描述: 应用程序未能正确验证用户的身份凭证或令牌。\n影响: 攻击者可以伪造其他用户或管理员的身份，完全接管账户。\n代码表象: JWT 解析时未强制指定允许的算法白名单，或者依赖用户传入的 Header (`alg`) 来决定解密算法；或者验证 Token 时 `verify=False`。\n审计策略: 审查 JWT 验证或会话恢复逻辑。确保证书/密钥安全，且 `algorithms` 参数必须在后端硬编码限制 (如 `algorithms=['HS256']`)，绝不能从不可信的头部动态获取。"
    },
    {
        "id": "CWE-327",
        "content": "名称: Use of a Broken or Risky Cryptographic Algorithm (使用被破解或有风险的加密算法)\n描述: 应用程序使用了已知存在漏洞、已被破解或极其脆弱的加密算法。\n影响: 攻击者可轻易破解密文，导致敏感数据泄露、签名伪造（如 JWT 绕过）或身份凭证被窃取。\n代码表象: 使用了 MD5、SHA-1 进行密码哈希，使用 DES 进行加密，或者在 JWT 解析时接受了 `none` 算法或由前端指定的任意算法（如从 Token 头部动态读取 `alg`）。\n审计策略: 审查所有涉及加解密、签名和哈希的代码。确认是否强制使用了现代安全算法（如 AES-GCM, SHA-256, bcrypt）。特别在 JWT 校验中，必须审查是否硬编码了安全的 `algorithms` 白名单（如 `['HS256', 'RS256']`），严禁信任并使用从 Token Header 中解析出的算法类型。"
    },
    {
        "id": "CWE-611",
        "content": "名称: XML External Entity Reference / XXE (XML外部实体注入)\n描述: 应用程序在解析 XML 输入时，未禁用外部实体的解析。\n影响: 任意文件读取、服务端请求伪造 (SSRF)、拒绝服务 (DoS)。\n代码表象: 使用了 XML 解析库 (如 Python 的 `lxml`, `xml.etree`, Java 的 `DocumentBuilder`, `SAXParser`)，且未显式禁用 DTD 和外部实体解析 (如 `resolve_entities=True`)。\n审计策略: 只要发现解析外部传入的 XML 数据，必须检查解析器的配置，确认是否禁用了 DOCTYPE 声明或外部实体引用。"
    },
    {
        "id": "CWE-1321",
        "content": "名称: Prototype Pollution (原型链污染)\n描述: JavaScript/Node.js 应用程序中，攻击者能够修改对象的原型链，影响所有继承该原型的对象。\n影响: 远程代码执行 (RCE)、拒绝服务、权限绕过。\n代码表象: 使用了不安全的对象合并函数 (如 `Object.assign()`, `_.merge()`, `jQuery.extend()`) 且未检查属性名是否为 `__proto__` 或 `constructor`。\n审计策略: 检查所有涉及对象合并、深拷贝的代码。确认是否过滤了 `__proto__`, `constructor`, `prototype` 等危险键名，或使用 `Object.create(null)` 创建无原型对象。"
    },
    {
        "id": "CWE-90",
        "content": "名称: LDAP Injection (LDAP注入)\n描述: 应用程序在构造 LDAP 查询时，未对用户输入进行适当的转义或参数化。\n影响: 绕过身份验证、未授权访问目录数据、信息泄露。\n代码表象: LDAP 查询语句中直接拼接用户输入 (如 `\"(uid=\" + username + \")\"`)，未使用参数化查询或转义特殊字符 (`*`, `(`, `)`, `\\`, `NUL`)。\n审计策略: 检查所有 LDAP 查询构造代码。确认是否使用了参数化查询或 LDAP 转义函数处理用户输入。"
    },
    {
        "id": "CWE-601",
        "content": "名称: URL Redirection to Untrusted Site / Open Redirect (开放重定向)\n描述: 应用程序接受用户输入的 URL 并进行重定向，未对目标 URL 进行验证。\n影响: 钓鱼攻击、绕过安全检查、SSRF 攻击链的一部分。\n代码表象: 重定向 URL 直接来自请求参数 (如 `redirect_uri`, `next`, `url`)，未进行白名单校验或协议限制。\n审计策略: 检查所有重定向逻辑。确认是否：1. 使用白名单验证目标域名；2. 禁止 `javascript:` 等危险协议；3. 使用相对路径重定向。"
    },
    {
        "id": "CWE-200",
        "content": "名称: Exposure of Sensitive Information (敏感信息泄露)\n描述: 应用程序向未授权用户暴露了敏感信息，如错误消息、调试信息、内部路径等。\n影响: 为进一步攻击提供情报、隐私泄露。\n代码表象: 错误页面显示完整堆栈跟踪、API 返回过多字段、日志记录敏感数据、响应头泄露服务器版本。\n审计策略: 检查错误处理机制、API 响应结构、日志配置。确认生产环境禁用详细错误信息，API 仅返回必要字段，日志脱敏处理。"
    },
    {
        "id": "CWE-362",
        "content": "名称: Race Condition (竞态条件)\n描述: 多线程/进程环境下，对共享资源的访问未进行同步控制，导致执行结果依赖于时序。\n影响: 数据不一致、权限绕过、重复操作（如重复提现）。\n代码表象: 检查-执行模式未加锁 (如 `if balance >= amount: balance -= amount`)，使用非原子操作更新共享状态。\n审计策略: 审查涉及并发操作的业务逻辑。确认是否使用了数据库事务、分布式锁或原子操作来保护关键资源。"
    },
    {
        "id": "CWE-338",
        "content": "名称: Use of Cryptographically Weak PRNG (使用弱伪随机数生成器)\n描述: 应用程序使用不安全的随机数生成器生成安全敏感的令牌、密钥或 ID。\n影响: 可预测的会话 ID、CSRF Token、验证码，导致会话劫持或绕过。\n代码表象: 使用 `Math.random()`, `random.random()`, `java.util.Random` 等非密码学安全的 PRNG 生成安全令牌。\n审计策略: 检查所有生成安全敏感随机值的代码。确认是否使用了密码学安全的随机数生成器 (如 Python 的 `secrets`, Java 的 `SecureRandom`)。"
    },
    {
        "id": "CWE-117",
        "content": "名称: Improper Output Neutralization for Logs (日志注入)\n描述: 应用程序将未净化的用户输入写入日志文件，攻击者可注入恶意内容。\n影响: 日志伪造、日志注入攻击、SIEM 系统污染。\n代码表象: 直接将用户输入拼接到日志消息中 (如 `log.info(\"User input: \" + userInput)`)，未进行转义或编码。\n审计策略: 检查所有日志记录点。确认是否对用户输入进行了净化处理，移除或转义换行符 (`\\n`, `\\r`) 等特殊字符。"
    },
    {
        "id": "CWE-915",
        "content": "名称: Improperly Controlled Modification of Dynamically-Determined Object Attributes (批量赋值漏洞)\n描述: 框架自动将用户输入绑定到对象属性，未限制可修改的字段。\n影响: 权限提升（修改 `is_admin`）、绕过业务逻辑、数据篡改。\n代码表象: ORM 框架中直接使用 `request.data` 更新模型 (如 `User.objects.update(**request.json)`)，未使用白名单限制字段。\n审计策略: 检查所有模型更新操作。确认是否使用了字段白名单或 DTO 模式，禁止直接绑定用户输入到模型。"
    },
    {
        "id": "CWE-1333",
        "content": "名称: Inefficient Regular Expression Complexity / ReDoS (正则表达式拒绝服务)\n描述: 使用了存在回溯爆炸的正则表达式，攻击者可构造恶意输入导致 CPU 耗尽。\n影响: 拒绝服务、服务不可用。\n代码表象: 正则表达式中包含重叠量词或嵌套重复 (如 `(a+)+`, `(a|a?)+`)，且匹配用户输入。\n审计策略: 审查所有正则表达式。使用工具检测危险模式，或设置匹配超时限制。优先使用非回溯引擎或简化正则。"
    },
    {
        "id": "CWE-377",
        "content": "名称: Insecure Temporary File (不安全的临时文件)\n描述: 应用程序以不安全的方式创建临时文件，可被攻击者预测或篡改。\n影响: 符号链接攻击、权限提升、数据泄露。\n代码表象: 使用固定文件名创建临时文件 (如 `/tmp/myapp.tmp`)，或未设置适当的文件权限。\n审计策略: 检查临时文件创建逻辑。确认是否使用了安全的临时文件 API (如 Python 的 `tempfile.mkstemp()`)，并设置了适当的权限。"
    },
    {
        "id": "CWE-306",
        "content": "名称: Missing Authentication for Critical Function (关键功能缺失认证)\n描述: 敏感功能或接口未实施身份验证，任何人都可以访问。\n影响: 未授权访问敏感功能、数据泄露、系统被控制。\n代码表象: 敏感接口（如管理后台、API 端点）没有身份验证中间件或装饰器。\n审计策略: 审查所有敏感功能的路由定义。确认是否强制要求身份验证，检查是否有遗漏的认证绕过路径。"
    },
    {
        "id": "CWE-120",
        "content": "名称: Buffer Overflow (缓冲区溢出)\n描述: 程序在向缓冲区写入数据时，未检查数据大小，导致数据溢出到相邻内存区域。\n影响: 远程代码执行 (RCE)、拒绝服务、数据损坏。\n代码表象: C/C++ 中使用 `strcpy()`, `gets()`, `sprintf()` 等不检查边界的函数；或使用固定大小缓冲区处理用户输入。\n审计策略: 审查所有内存操作代码。确认是否使用了安全的替代函数 (如 `strncpy()`, `snprintf()`)，并进行边界检查。"
    },
    {
        "id": "CWE-190",
        "content": "名称: Integer Overflow or Wraparound (整数溢出)\n描述: 算术运算结果超出了整数类型的表示范围，导致意外行为。\n影响: 逻辑绕过、内存分配问题、安全检查失效。\n代码表象: 未检查乘法、加法结果是否溢出；使用有符号整数进行大小计算；用户输入直接用于内存分配大小。\n审计策略: 检查所有涉及用户输入的算术运算。确认是否进行了溢出检查，或使用大整数类型。"
    },
    {
        "id": "CWE-74",
        "content": "名称: Second-Order Injection (二次注入)\n描述: 用户输入先被存储到数据库，后续被取出并用于构造命令或查询，此时触发注入。\n影响: SQL 注入、命令注入、XSS 等各类注入攻击。\n代码表象: 数据存储时进行了转义，但读取后直接用于构造 SQL/命令/HTML，未再次转义。\n审计策略: 追踪数据从存储到使用的完整流程。确认在最终使用点是否进行了适当的净化或参数化处理。"
    },
    {
        "id": "CWE-346",
        "content": "名称: Origin Validation Error / CORS Misconfiguration (CORS 配置错误)\n描述: 服务器未正确验证请求来源，允许任意域访问敏感资源。\n影响: 跨域数据窃取、CSRF 攻击增强、敏感信息泄露。\n代码表象: `Access-Control-Allow-Origin` 设置为 `*` 或动态反射请求的 `Origin` 头，且 `Access-Control-Allow-Credentials` 为 `true`。\n审计策略: 检查 CORS 配置。确认是否使用白名单验证 Origin，避免同时使用通配符和凭证模式。"
    },
    {
        "id": "CWE-441",
        "content": "名称: Unintended Proxy/Intermediary (意外的代理行为)\n描述: 应用程序被配置为代理或转发请求，可被利用访问内部资源。\n影响: SSRF、绕过访问控制、数据泄露。\n代码表象: 服务器配置了反向代理或转发规则，未限制目标范围；或存在开放的重定向端点。\n审计策略: 审查服务器配置和路由规则。确认是否限制了代理目标范围，禁用不必要的转发功能。"
    },
    {
        "id": "CWE-1021",
        "content": "名称: Improper Restriction of Rendered UI Layers / Clickjacking (点击劫持)\n描述: 应用程序未阻止页面被嵌入到 iframe 中，可被用于点击劫持攻击。\n影响: 诱导用户执行非预期操作、钓鱼攻击。\n代码表象: 响应头缺少 `X-Frame-Options` 或 `Content-Security-Policy: frame-ancestors`。\n审计策略: 检查 HTTP 响应头。确认是否设置了适当的 Frame 限制策略 (如 `X-Frame-Options: DENY` 或 `SAMEORIGIN`)。"
    },
    {
        "id": "CWE-522",
        "content": "名称: Insufficiently Protected Credentials (凭证保护不足)\n描述: 敏感凭证在传输或存储时未进行适当的保护。\n影响: 凭证泄露、中间人攻击、账户接管。\n代码表象: 明文存储密码、使用 HTTP 传输凭证、密码在日志中可见、使用弱哈希算法存储密码。\n审计策略: 检查凭证处理流程。确认密码使用强哈希算法 (bcrypt, Argon2) 存储，传输使用 HTTPS，日志脱敏处理。"
    },
    {
        "id": "CWE-312",
        "content": "名称: Cleartext Storage of Sensitive Information (明文存储敏感信息)\n描述: 敏感数据以明文形式存储在数据库、文件或配置中。\n影响: 数据泄露导致直接的信息暴露。\n代码表象: 数据库中存储明文密码、信用卡号、个人身份信息；配置文件中明文存储密钥。\n审计策略: 审查数据存储逻辑。确认敏感数据是否进行了加密存储，密钥管理是否安全。"
    },
    {
        "id": "CWE-319",
        "content": "名称: Cleartext Transmission of Sensitive Information (明文传输敏感信息)\n描述: 敏感数据通过网络以明文形式传输，未使用加密。\n影响: 中间人攻击、数据窃听、会话劫持。\n代码表象: 使用 HTTP 而非 HTTPS 传输登录凭证、会话 Cookie、API 密钥；Cookie 未设置 Secure 标志。\n审计策略: 检查网络通信配置。确认是否强制使用 HTTPS，Cookie 设置 Secure 和 HttpOnly 标志。"
    },
    {
        "id": "CWE-307",
        "content": "名称: Improper Restriction of Excessive Authentication Attempts (暴力破解防护不足)\n描述: 应用程序未限制失败的登录尝试次数。\n影响: 账户暴力破解、密码猜测攻击。\n代码表象: 登录接口无速率限制、无账户锁定机制、无验证码保护。\n审计策略: 检查认证接口。确认是否实施了登录失败次数限制、账户锁定、验证码或速率限制机制。"
    },
    {
        "id": "CWE-613",
        "content": "名称: Insufficient Session Expiration (会话过期不足)\n描述: 用户会话在长时间不活动后未正确过期，或注销后会话未失效。\n影响: 会话劫持、账户被盗用。\n代码表象: 会话超时时间过长或无超时、注销功能仅清除客户端 Cookie 而未使服务端会话失效。\n审计策略: 审查会话管理配置。确认会话超时设置合理，注销功能正确使服务端会话失效。"
    },
    {
        "id": "CWE-384",
        "content": "名称: Session Fixation (会话固定)\n描述: 应用程序在用户认证后未重新生成会话 ID。\n影响: 攻击者可预先设置受害者的会话 ID，实现会话劫持。\n代码表象: 登录成功后会话 ID 不变，允许 URL 中传递会话 ID。\n审计策略: 检查登录流程。确认认证成功后是否调用会话重新生成方法 (如 `session_regenerate_id()`)。"
    },
    {
        "id": "CWE-256",
        "content": "名称: Unprotected Storage of Credentials (凭证存储未保护)\n描述: 密码或其他凭证以可逆形式存储，或存储位置不安全。\n影响: 凭证泄露导致账户接管。\n代码表象: 密码使用可逆加密而非哈希存储；凭证存储在代码库、配置文件或可访问的文件中。\n审计策略: 审查凭证存储方式。确认使用不可逆哈希算法存储密码，凭证存储位置安全且访问受限。"
    },
    {
        "id": "CWE-295",
        "content": "名称: Improper Certificate Validation (证书验证不当)\n描述: 应用程序未正确验证 SSL/TLS 证书，导致中间人攻击。\n影响: 中间人攻击、数据窃听、凭证窃取。\n代码表象: 代码中设置 `verify=False` 或 `CERT_NONE`；忽略证书验证错误；未检查证书主机名。\n审计策略: 检查所有 HTTPS 请求代码。确认证书验证未被禁用，且正确验证证书链和主机名。"
    },
    {
        "id": "CWE-311",
        "content": "名称: Missing Encryption of Sensitive Data (敏感数据缺失加密)\n描述: 敏感数据在存储或传输过程中未进行加密保护。\n影响: 数据泄露、隐私侵犯。\n代码表象: 敏感字段（如身份证号、银行卡号）明文存储；API 响应包含明文敏感数据。\n审计策略: 识别所有敏感数据字段。确认是否实施了适当的加密措施，加密算法是否安全。"
    },
    {
        "id": "CWE-602",
        "content": "名称: Client-Side Enforcement of Server-Side Security (客户端安全校验)\n描述: 安全检查仅在客户端执行，服务端未进行验证。\n影响: 绕过安全限制、权限提升。\n代码表象: 仅通过 JavaScript 验证输入、隐藏字段控制权限、前端禁用按钮控制操作。\n审计策略: 审查所有安全相关逻辑。确认服务端是否独立执行了相同的验证，不信任任何客户端输入。"
    },
    {
        "id": "CWE-807",
        "content": "名称: Reliance on Untrusted Inputs in a Security Decision (安全决策依赖不可信输入)\n描述: 应用程序根据用户可控的输入做出安全决策。\n影响: 权限绕过、认证绕过。\n代码表象: 根据 HTTP 头 (如 `X-Forwarded-For`, `Referer`) 判断权限；根据隐藏字段判断用户角色。\n审计策略: 审查所有安全决策逻辑。确认是否仅依赖服务端可信数据（如会话状态）进行授权判断。"
    },
    {
        "id": "CWE-250",
        "content": "名称: Execution with Unnecessary Privileges (以不必要权限执行)\n描述: 应用程序以过高权限运行，超出功能需求。\n影响: 权限提升、系统被完全控制。\n代码表象: Web 服务以 root/Administrator 运行；数据库连接使用超级用户账户。\n审计策略: 审查服务配置和账户权限。确认遵循最小权限原则，使用专用低权限账户运行服务。"
    },
    {
        "id": "CWE-668",
        "content": "名称: Exposure of Resource to Wrong Sphere (资源暴露给错误范围)\n描述: 资源可被预期范围之外的用户访问。\n影响: 信息泄露、未授权访问。\n代码表象: 内部管理接口暴露在公网；测试/调试接口未禁用；敏感文件存放在 Web 根目录。\n审计策略: 审查网络配置和访问控制。确认内部接口仅在内网可访问，生产环境禁用调试功能。"
    },
    {
        "id": "CWE-732",
        "content": "名称: Incorrect Permission Assignment for Critical Resource (关键资源权限分配错误)\n描述: 关键文件或目录的权限设置过于宽松。\n影响: 数据篡改、权限提升、信息泄露。\n代码表象: 配置文件权限为 777 或 666；敏感文件可被任意用户读取/写入。\n审计策略: 检查关键文件和目录的权限设置。确认遵循最小权限原则，仅授权必要的用户访问。"
    },
    {
        "id": "CWE-749",
        "content": "名称: Exposed Dangerous Method or Function (暴露危险方法)\n描述: 应用程序暴露了不应被外部访问的危险方法或 API。\n影响: 未授权执行敏感操作、系统被控制。\n代码表象: RPC/SOAP 接口暴露内部方法；调试 API 可从外部访问；序列化对象暴露敏感方法。\n审计策略: 审查所有公开的 API 和方法。确认是否限制了危险方法的访问，或移除了不必要的暴露。"
    },
    {
        "id": "CWE-942",
        "content": "名称: Permissive Cross-domain Policy (过度宽松的跨域策略)\n描述: Flash/Silverlight 等跨域策略文件允许任意域访问。\n影响: 跨域数据窃取、CSRF 攻击。\n代码表象: `crossdomain.xml` 设置 `<allow-access-from domain=\"*\"/>`；Silverlight 策略文件过于宽松。\n审计策略: 检查跨域策略文件。确认仅允许可信域访问，避免使用通配符。"
    },
    {
        "id": "CWE-1004",
        "content": "名称: Sensitive Cookie Without 'HttpOnly' Flag (敏感 Cookie 缺少 HttpOnly 标志)\n描述: 敏感 Cookie 未设置 HttpOnly 标志，可被 JavaScript 访问。\n影响: XSS 攻击窃取会话 Cookie。\n代码表象: 设置 Cookie 时未指定 `HttpOnly` 属性。\n审计策略: 检查所有 Cookie 设置代码。确认敏感 Cookie（如会话 ID）设置了 `HttpOnly` 和 `Secure` 标志。"
    },
    {
        "id": "CWE-129",
        "content": "名称: Improper Validation of Array Index (数组索引验证不当)\n描述: 使用用户输入作为数组索引时未进行边界检查。\n影响: 越界读写、信息泄露、程序崩溃。\n代码表象: 直接使用用户输入作为数组索引 (如 `array[userInput]`)，未检查索引范围。\n审计策略: 检查所有数组访问代码。确认对用户输入的索引进行了边界验证。"
    },
    {
        "id": "CWE-476",
        "content": "名称: NULL Pointer Dereference (空指针解引用)\n描述: 程序解引用了可能为 NULL 的指针。\n影响: 程序崩溃、拒绝服务、潜在的代码执行。\n代码表象: 使用指针前未检查是否为 NULL；函数返回值未检查即使用。\n审计策略: 审查所有指针使用代码。确认在使用指针前进行了 NULL 检查。"
    },
    {
        "id": "CWE-416",
        "content": "名称: Use After Free (释放后使用)\n描述: 程序在释放内存后继续使用指向该内存的指针。\n影响: 代码执行、数据损坏、拒绝服务。\n代码表象: 释放内存后未将指针置空；返回指向已释放内存的指针。\n审计策略: 审查内存管理代码。确认释放内存后指针被置空，避免悬空指针。"
    },
    {
        "id": "CWE-400",
        "content": "名称: Uncontrolled Resource Consumption (资源消耗不受控)\n描述: 应用程序未限制资源消耗，可被攻击者利用耗尽系统资源。\n影响: 拒绝服务、服务不可用。\n代码表象: 无限制的文件上传大小、无超时的网络请求、无限制的循环或递归。\n审计策略: 检查资源使用限制。确认设置了请求大小限制、超时时间、递归深度限制等。"
    },
    {
        "id": "CWE-407",
        "content": "名称: Inefficient Algorithmic Complexity (算法复杂度攻击)\n描述: 使用了高复杂度算法处理用户输入，可被利用进行 DoS 攻击。\n影响: 拒绝服务、CPU 资源耗尽。\n代码表象: 对用户输入进行 O(n²) 或更高复杂度的处理；未限制输入大小。\n审计策略: 审查算法复杂度。确认对用户输入进行了大小限制，或使用更高效的算法。"
    },
    {
        "id": "CWE-208",
        "content": "名称: Observable Timing Discrepancy (时序攻击)\n描述: 应用程序的执行时间差异可泄露敏感信息。\n影响: 绕过认证、密钥泄露。\n代码表象: 字符串比较使用 `==` 而非常量时间比较；密码验证存在提前返回。\n审计策略: 检查敏感比较操作。确认使用常量时间比较函数 (如 `hmac.compare_digest()`)。"
    },
    {
        "id": "CWE-213",
        "content": "名称: Exposure of Sensitive Information Due to Incompatible Policies (策略不兼容导致信息泄露)\n描述: 不同安全策略之间的差异导致敏感信息泄露。\n影响: 信息泄露、隐私侵犯。\n代码表象: 错误消息在不同环境下显示不同详细程度；调试信息在生产环境泄露。\n审计策略: 审查错误处理和日志策略。确认生产环境禁用详细错误信息，统一安全策略。"
    },
    {
        "id": "CWE-215",
        "content": "名称: Insertion of Sensitive Information Into Debugging Code (敏感信息插入调试代码)\n描述: 调试代码中包含敏感信息。\n影响: 信息泄露。\n代码表象: 调试日志打印密码、密钥等敏感数据；断言消息包含敏感信息。\n审计策略: 审查调试代码和日志。确认敏感信息不被记录，生产环境禁用调试输出。"
    },
    {
        "id": "CWE-532",
        "content": "名称: Insertion of Sensitive Information into Log File (敏感信息写入日志)\n描述: 敏感信息被写入日志文件。\n影响: 凭证泄露、隐私侵犯。\n代码表象: 日志记录密码、会话 ID、信用卡号等敏感数据。\n审计策略: 审查日志内容。确认敏感字段被脱敏或排除在日志之外。"
    },
    {
        "id": "CWE-538",
        "content": "名称: Insertion of Sensitive Information into Externally-Accessible File or Directory (敏感信息写入外部可访问文件)\n描述: 敏感信息被写入可从外部访问的文件或目录。\n影响: 信息泄露。\n代码表象: 将敏感配置写入 Web 根目录；备份文件存放在公开目录。\n审计策略: 检查文件写入位置。确认敏感文件存放在 Web 根目录之外，或设置了适当的访问控制。"
    },
    {
        "id": "CWE-540",
        "content": "名称: Inclusion of Sensitive Information in Source Code (源代码包含敏感信息)\n描述: 源代码中包含敏感信息如密码、密钥。\n影响: 源代码泄露导致系统被入侵。\n代码表象: 代码中硬编码密码、API 密钥、私钥等。\n审计策略: 扫描源代码中的敏感信息模式。确认敏感信息通过环境变量或密钥管理系统获取。"
    },
    {
        "id": "CWE-541",
        "content": "名称: Inclusion of Sensitive Information in Include File (包含文件中包含敏感信息)\n描述: 被包含的文件（如配置文件）包含敏感信息且可能被泄露。\n影响: 信息泄露、系统被入侵。\n代码表象: 配置文件使用 `.inc` 扩展名且位于 Web 目录；配置文件权限过于宽松。\n审计策略: 检查包含文件的位置和权限。确认配置文件位于 Web 根目录之外，或使用 PHP 等语言的特定扩展名。"
    },
    {
        "id": "CWE-124",
        "content": "名称: Buffer Underflow (缓冲区下溢)\n描述: 程序从缓冲区起始位置之前读取数据。\n影响: 信息泄露、代码执行、程序崩溃。\n代码表象: 数组索引为负数；指针运算导致访问缓冲区之前的内存。\n审计策略: 检查所有数组索引和指针运算。确认索引值非负且在有效范围内。"
    },
    {
        "id": "CWE-126",
        "content": "名称: Buffer Over-read (缓冲区过度读取)\n描述: 程序读取缓冲区边界之外的数据。\n影响: 信息泄露、程序崩溃。\n代码表象: 使用 `strlen()` 等函数处理非空终止字符串；未检查读取长度。\n审计策略: 审查缓冲区读取操作。确认正确处理字符串终止符，检查读取边界。"
    },
    {
        "id": "CWE-127",
        "content": "名称: Buffer Over-write (缓冲区过度写入)\n描述: 程序向缓冲区边界之外写入数据。\n影响: 代码执行、数据损坏、拒绝服务。\n代码表象: 使用 `strcpy()`, `memcpy()` 等函数未检查目标缓冲区大小。\n审计策略: 检查所有缓冲区写入操作。确认使用安全的替代函数并进行边界检查。"
    },
    {
        "id": "CWE-131",
        "content": "名称: Incorrect Calculation of Buffer Size (缓冲区大小计算错误)\n描述: 程序错误计算缓冲区所需大小。\n影响: 缓冲区溢出、内存损坏。\n代码表象: 分配内存时未考虑字符串终止符；整数运算错误导致缓冲区大小不足。\n审计策略: 审查内存分配代码。确认正确计算所需大小，包括终止符等额外空间。"
    },
    {
        "id": "CWE-134",
        "content": "名称: Use of Externally-Controlled Format String (格式化字符串漏洞)\n描述: 用户输入被用作格式化字符串。\n影响: 信息泄露、代码执行、拒绝服务。\n代码表象: `printf(userInput)`, `sprintf(buffer, userInput)` 等直接使用用户输入作为格式化字符串。\n审计策略: 检查所有格式化函数调用。确认使用固定格式化字符串，用户输入作为参数传入。"
    },
    {
        "id": "CWE-170",
        "content": "名称: Improper Null Termination (空终止符处理不当)\n描述: 字符串未正确以空字符终止。\n影响: 缓冲区过度读取、信息泄露、程序崩溃。\n代码表象: 手动构造字符串时忘记添加终止符；使用不安全的字符串函数。\n审计策略: 审查字符串处理代码。确认所有字符串正确终止，使用安全的字符串函数。"
    },
    {
        "id": "CWE-188",
        "content": "名称: Reliance on Data/Memory Layout (依赖数据/内存布局)\n描述: 程序依赖特定的数据或内存布局。\n影响: 可移植性问题、安全机制绕过。\n代码表象: 假设结构体成员顺序；依赖特定字节序；假设指针大小。\n审计策略: 审查数据布局相关代码。确认不依赖编译器特定的布局，使用标准接口访问数据。"
    },
    {
        "id": "CWE-415",
        "content": "名称: Double Free (双重释放)\n描述: 同一块内存被释放两次。\n影响: 代码执行、内存损坏、拒绝服务。\n代码表象: 释放内存后未将指针置空，导致再次释放。\n审计策略: 审查内存释放代码。确认释放后指针被置空，避免重复释放。"
    },
    {
        "id": "CWE-426",
        "content": "名称: Untrusted Search Path (不可信搜索路径)\n描述: 应用程序在搜索资源时使用不可信的路径。\n影响: 执行恶意代码、权限提升。\n代码表象: 使用相对路径加载库或配置文件；依赖 PATH 环境变量查找可执行文件。\n审计策略: 检查资源加载逻辑。确认使用绝对路径，或验证搜索路径的安全性。"
    },
    {
        "id": "CWE-456",
        "content": "名称: Missing Initialization of a Variable (变量未初始化)\n描述: 变量在使用前未被初始化。\n影响: 信息泄露、不可预测行为、安全检查绕过。\n代码表象: 声明变量后未赋值即使用；依赖默认初始化值。\n审计策略: 审查变量使用。确认所有变量在使用前被正确初始化。"
    },
    {
        "id": "CWE-457",
        "content": "名称: Use of Uninitialized Variable (使用未初始化变量)\n描述: 程序使用了未初始化的变量。\n影响: 信息泄露、不可预测行为。\n代码表象: 读取未初始化的变量值；依赖栈或堆上的随机值。\n审计策略: 检查变量使用流程。确认所有变量在首次使用前被赋值。"
    },
    {
        "id": "CWE-467",
        "content": "名称: Use of sizeof() on a Pointer Type (对指针类型使用 sizeof)\n描述: 对指针而非实际对象使用 sizeof 运算符。\n影响: 缓冲区大小计算错误、溢出。\n代码表象: `sizeof(pointer)` 而非 `sizeof(*pointer)` 或 `sizeof(array)`。\n审计策略: 审查 sizeof 使用。确认对实际对象而非指针使用 sizeof。"
    },
    {
        "id": "CWE-468",
        "content": "名称: Incorrect Pointer Scaling (指针缩放错误)\n描述: 指针运算时使用了错误的缩放因子。\n影响: 内存访问错误、信息泄露、代码执行。\n代码表象: 对字节指针进行整数运算时未考虑指针类型大小。\n审计策略: 检查指针运算代码。确认正确处理指针类型大小。"
    },
    {
        "id": "CWE-469",
        "content": "名称: Use of Pointer Subtraction to Determine Size (使用指针减法确定大小)\n描述: 使用指针减法计算缓冲区大小，可能得到错误结果。\n影响: 缓冲区大小计算错误、溢出。\n代码表象: 使用 `ptr2 - ptr1` 计算字节数而非元素数。\n审计策略: 审查指针运算。确认正确处理指针减法的结果类型。"
    },
    {
        "id": "CWE-479",
        "content": "名称: Signal Handler Use of a Non-reentrant Function (信号处理程序使用非可重入函数)\n描述: 信号处理程序中调用了非可重入函数。\n影响: 竞态条件、死锁、程序崩溃。\n代码表象: 在信号处理程序中调用 `printf()`, `malloc()`, `free()` 等非可重入函数。\n审计策略: 审查信号处理程序。确认仅调用可重入函数，或使用其他同步机制。"
    },
    {
        "id": "CWE-480",
        "content": "名称: Use of Incorrect Operator (使用错误的运算符)\n描述: 程序中使用了错误的运算符（如 `=` 替代 `==`）。\n影响: 逻辑错误、安全检查绕过。\n代码表象: 条件语句中使用赋值运算符 `=` 而非比较运算符 `==`。\n审计策略: 审查条件表达式。确认使用正确的比较运算符。"
    },
    {
        "id": "CWE-481",
        "content": "名称: Assigning instead of Comparing (赋值而非比较)\n描述: 在条件语句中使用赋值而非比较。\n影响: 逻辑错误、安全检查绕过。\n代码表象: `if (x = y)` 而非 `if (x == y)`。\n审计策略: 检查条件语句。确认使用比较运算符，或使用 Yoda 条件式避免错误。"
    },
    {
        "id": "CWE-482",
        "content": "名称: Comparing instead of Assigning (比较而非赋值)\n描述: 在应该赋值的地方使用了比较运算符。\n影响: 变量值未正确设置、逻辑错误。\n代码表象: `x == y` 而非 `x = y`。\n审计策略: 审查赋值语句。确认使用正确的赋值运算符。"
    },
    {
        "id": "CWE-483",
        "content": "名称: Incorrect Block Delimitation (代码块界定错误)\n描述: 代码块界定不当，如缺少大括号。\n影响: 逻辑错误、安全检查绕过。\n代码表象: if/while 等语句后缺少大括号，缩进误导。\n审计策略: 审查代码结构。确认使用大括号明确界定代码块。"
    },
    {
        "id": "CWE-484",
        "content": "名称: Omitted Break Statement in Switch (Switch 语句缺少 break)\n描述: switch 语句中缺少 break 语句，导致 case 穿透。\n影响: 执行非预期代码、逻辑错误。\n代码表象: switch case 块末尾缺少 break 或 return。\n审计策略: 检查 switch 语句。确认每个 case 块有适当的终止语句。"
    },
    {
        "id": "CWE-567",
        "content": "名称: Unbounded Serialization (无界序列化)\n描述: 应用程序序列化数据时未限制大小或深度。\n影响: 拒绝服务、资源耗尽。\n代码表象: 递归序列化深度嵌套对象；序列化大型数据结构无大小限制。\n审计策略: 审查序列化逻辑。确认设置了深度和大小限制。"
    },
    {
        "id": "CWE-575",
        "content": "名称: Emission of Security-Critical Data to Log (安全关键数据输出到日志)\n描述: 安全关键数据被写入日志。\n影响: 凭证泄露、安全机制绕过。\n代码表象: 日志记录认证 Token、加密密钥、密码等。\n审计策略: 审查日志内容。确认安全关键数据不被记录。"
    },
    {
        "id": "CWE-587",
        "content": "名称: Assignment of a Fixed Address to a Pointer (指针赋值固定地址)\n描述: 将固定内存地址赋给指针。\n影响: 内存访问错误、可移植性问题。\n代码表象: `ptr = (void*)0x12345678` 等硬编码地址。\n审计策略: 审查指针赋值。确认不使用硬编码内存地址。"
    },
    {
        "id": "CWE-588",
        "content": "名称: Attempt to Access Child of a Non-structure Pointer (尝试访问非结构体指针的子元素)\n描述: 通过非结构体类型的指针访问结构体成员。\n影响: 内存访问错误、信息泄露。\n代码表象: 类型转换错误后访问结构体成员。\n审计策略: 审查指针类型转换。确认正确的类型使用。"
    },
    {
        "id": "CWE-589",
        "content": "名称: Call to Non-variadic Function with Variadic Arguments (用可变参数调用非可变参数函数)\n描述: 向非可变参数函数传递可变数量的参数。\n影响: 栈损坏、程序崩溃、代码执行。\n代码表象: 函数声明与调用参数数量不匹配。\n审计策略: 检查函数声明和调用。确认参数数量和类型匹配。"
    },
    {
        "id": "CWE-591",
        "content": "名称: Sensitive Data Storage in Improperly Locked Memory (敏感数据存储在未正确锁定的内存)\n描述: 敏感数据存储在可被交换到磁盘的内存中。\n影响: 敏感数据泄露到磁盘。\n代码表象: 存储密码或密钥时未使用 `mlock()` 锁定内存。\n审计策略: 审查敏感数据处理。确认使用内存锁定机制防止交换。"
    },
    {
        "id": "CWE-592",
        "content": "名称: Authentication Bypass Issues (认证绕过问题)\n描述: 认证机制存在可被绕过的缺陷。\n影响: 未授权访问、账户接管。\n代码表象: 认证检查存在逻辑漏洞；存在认证绕过路径。\n审计策略: 审查认证逻辑。确认所有路径都经过认证检查，无绕过可能。"
    },
    {
        "id": "CWE-593",
        "content": "名称: Authentication Issues: Client-Side (客户端认证问题)\n描述: 认证逻辑在客户端执行，可被绕过。\n影响: 认证绕过、未授权访问。\n代码表象: 使用 JavaScript 进行认证检查；依赖客户端状态判断登录。\n审计策略: 审查认证流程。确认所有认证检查在服务端执行。"
    },
    {
        "id": "CWE-597",
        "content": "名称: Use of Incorrect Operator on Strings (字符串使用错误运算符)\n描述: 对字符串使用了错误的运算符（如 `==` 比较而非 `strcmp`）。\n影响: 认证绕过、逻辑错误。\n代码表象: 使用 `==` 比较字符串而非 `strcmp()` 或 `equals()`。\n审计策略: 检查字符串比较代码。确认使用正确的字符串比较函数。"
    },
    {
        "id": "CWE-598",
        "content": "名称: Use of GET Request Method With Sensitive Query Strings (敏感查询字符串使用 GET 请求)\n描述: 敏感数据通过 GET 请求的查询字符串传递。\n影响: 敏感数据泄露到日志、浏览器历史、Referer 头。\n代码表象: 登录表单使用 GET 方法；密码在 URL 参数中传递。\n审计策略: 审查表单和请求方法。确认敏感数据使用 POST 请求传递。"
    },
    {
        "id": "CWE-599",
        "content": "名称: Missing Validation of OpenSSL Certificate (缺少 OpenSSL 证书验证)\n描述: 使用 OpenSSL 时未验证证书。\n影响: 中间人攻击、数据窃听。\n代码表象: 调用 OpenSSL 函数时未设置验证回调或忽略验证结果。\n审计策略: 检查 OpenSSL 使用代码。确认正确设置证书验证。"
    },
    {
        "id": "CWE-600",
        "content": "名称: Uncaught Exception in Servlet (Servlet 未捕获异常)\n描述: Servlet 中异常未被捕获，导致信息泄露。\n影响: 信息泄露、堆栈跟踪暴露。\n代码表象: Servlet 代码未使用 try-catch 处理异常。\n审计策略: 审查 Servlet 异常处理。确认所有异常被适当捕获和处理。"
    },
    {
        "id": "CWE-603",
        "content": "名称: Use of Client-Side Storage for Sensitive Information (敏感信息存储在客户端)\n描述: 敏感信息存储在客户端可访问的位置。\n影响: 信息泄露、凭证窃取。\n代码表象: 将密码或密钥存储在 Cookie、LocalStorage、隐藏字段中。\n审计策略: 审查客户端存储使用。确认敏感信息不存储在客户端。"
    },
    {
        "id": "CWE-605",
        "content": "名称: Multiple Binds to the Same Port (同一端口多重绑定)\n描述: 多个服务绑定到同一端口，可能导致安全策略绕过。\n影响: 服务混淆、安全策略绕过。\n代码表象: 多个进程绑定同一端口；端口重用配置不当。\n审计策略: 审查端口绑定配置。确认每个服务使用独立端口。"
    },
    {
        "id": "CWE-606",
        "content": "名称: Unchecked Input for Loop Condition (循环条件输入未检查)\n描述: 循环条件使用用户输入且未进行验证。\n影响: 拒绝服务、无限循环。\n代码表象: 循环次数由用户输入控制且无上限。\n审计策略: 检查循环条件。确认对循环次数设置了合理上限。"
    },
    {
        "id": "CWE-609",
        "content": "名称: Double-Checked Locking (双重检查锁定)\n描述: 双重检查锁定模式实现不正确。\n影响: 竞态条件、单例模式失效。\n代码表象: 未使用 volatile 或内存屏障实现双重检查锁定。\n审计策略: 审查并发代码。确认正确实现了双重检查锁定或使用替代方案。"
    },
    {
        "id": "CWE-610",
        "content": "名称: Externally Controlled Reference to a Resource in Another Sphere (外部控制的跨域资源引用)\n描述: 应用程序允许外部控制对其他域资源的引用。\n影响: SSRF、信息泄露。\n代码表象: 用户输入用于构造对其他系统或服务的请求。\n审计策略: 审查跨系统请求。确认对目标资源进行了白名单验证。"
    },
    {
        "id": "CWE-614",
        "content": "名称: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute (HTTPS 会话中敏感 Cookie 缺少 Secure 属性)\n描述: HTTPS 应用中的 Cookie 未设置 Secure 标志。\n影响: Cookie 在 HTTP 连接中被泄露。\n代码表象: HTTPS 应用设置 Cookie 时未指定 Secure 属性。\n审计策略: 检查 Cookie 设置。确认 HTTPS 应用中的 Cookie 设置了 Secure 属性。"
    },
    {
        "id": "CWE-617",
        "content": "名称: Reachable Assertion (可达的断言)\n描述: 程序中的断言可被外部输入触发。\n影响: 拒绝服务、程序崩溃。\n代码表象: 断言条件依赖用户输入；生产环境未禁用断言。\n审计策略: 审查断言使用。确认断言不依赖用户输入，生产环境禁用断言。"
    },
    {
        "id": "CWE-618",
        "content": "名称: Exposed Unsafe ActiveX Method (暴露不安全的 ActiveX 方法)\n描述: ActiveX 控件暴露了不安全的方法。\n影响: 远程代码执行、系统被控制。\n代码表象: ActiveX 控件标记为安全初始化但包含危险方法。\n审计策略: 审查 ActiveX 控件。确认仅暴露安全的方法，或移除 ActiveX。"
    },
    {
        "id": "CWE-619",
        "content": "名称: Dangling Pointer (悬空指针)\n描述: 指针指向已释放或无效的内存。\n影响: 内存访问错误、信息泄露、代码执行。\n代码表象: 释放内存后指针未被置空；返回局部变量的指针。\n审计策略: 审查指针生命周期。确认指针在内存释放后被置空或不再使用。"
    },
    {
        "id": "CWE-621",
        "content": "名称: Variable Extraction Error (变量提取错误)\n描述: 用户输入被错误地提取为变量。\n影响: 变量覆盖、安全检查绕过。\n代码表象: PHP 的 `extract()` 函数处理用户输入；类似的不安全变量注册。\n审计策略: 审查变量提取逻辑。确认不使用不安全的变量提取函数处理用户输入。"
    },
    {
        "id": "CWE-622",
        "content": "名称: Improper Validation of Function Hook Arguments (函数钩子参数验证不当)\n描述: 函数钩子或回调的参数未正确验证。\n影响: 代码执行、权限绕过。\n代码表象: 钩子函数接受并处理未验证的用户输入。\n审计策略: 审查钩子和回调函数。确认对输入参数进行了验证。"
    },
    {
        "id": "CWE-623",
        "content": "名称: Improper Assertion Use (断言使用不当)\n描述: 断言被用于安全检查。\n影响: 生产环境中安全检查被绕过。\n代码表象: 使用 assert() 进行权限检查或输入验证。\n审计策略: 审查断言使用。确认安全检查使用常规条件语句而非断言。"
    },
    {
        "id": "CWE-624",
        "content": "名称: Executable Regular Expression Error (可执行正则表达式错误)\n描述: 正则表达式包含可执行代码。\n影响: 代码执行、拒绝服务。\n代码表象: 使用支持代码执行的正则表达式特性（如 Perl 的 `e` 修饰符）。\n审计策略: 审查正则表达式。确认不使用可执行正则特性。"
    },
    {
        "id": "CWE-625",
        "content": "名称: Permissive Regular Expression (过度宽松的正则表达式)\n描述: 正则表达式过于宽松，匹配了非预期的内容。\n影响: 输入验证绕过、注入攻击。\n代码表象: 正则表达式缺少边界锚定；使用 `.*` 过于宽松。\n审计策略: 审查正则表达式。确认使用严格的模式匹配和边界锚定。"
    },
    {
        "id": "CWE-626",
        "content": "名称: Null Byte Interaction Error (空字节交互错误)\n描述: 空字节被错误处理，导致安全检查绕过。\n影响: 文件类型绕过、路径穿越。\n代码表象: 文件名处理时未过滤空字节；C 字符串与系统调用交互问题。\n审计策略: 审查字符串处理。确认正确处理空字节，使用二进制安全函数。"
    },
    {
        "id": "CWE-627",
        "content": "名称: Dynamic Variable Evaluation (动态变量评估)\n描述: 变量名动态构造且包含用户输入。\n影响: 变量覆盖、信息泄露。\n代码表象: PHP 的可变变量 (`$$var`)；类似的动态变量引用。\n审计策略: 审查动态变量使用。确认不使用用户输入构造变量名。"
    },
    {
        "id": "CWE-628",
        "content": "名称: Function Call with Incorrectly Specified Arguments Value (函数调用参数值指定错误)\n描述: 函数调用时参数值不正确。\n影响: 功能异常、安全检查失效。\n代码表象: 参数顺序错误；使用错误的常量值。\n审计策略: 审查函数调用。确认参数值正确无误。"
    },
    {
        "id": "CWE-636",
        "content": "名称: Not Failing Securely ('Failing Open') (未安全失败)\n描述: 错误或异常情况下系统未安全失败。\n影响: 安全检查被绕过。\n代码表象: 异常处理时默认允许访问；错误时跳过安全检查。\n审计策略: 审查错误处理逻辑。确认错误时默认拒绝访问。"
    },
    {
        "id": "CWE-637",
        "content": "名称: Unnecessary Complexity (不必要的复杂性)\n描述: 安全机制实现过于复杂，增加了漏洞风险。\n影响: 安全机制失效、维护困难。\n代码表象: 复杂的自定义加密算法；多层安全检查存在漏洞。\n审计策略: 审查安全机制设计。确认使用简单、经过验证的安全方案。"
    },
    {
        "id": "CWE-638",
        "content": "名称: Improper Privilege Preservation (权限保存不当)\n描述: 程序在执行期间未正确保存或恢复权限。\n影响: 权限提升。\n代码表象: 临时提升权限后未恢复；权限切换逻辑错误。\n审计策略: 审查权限管理代码。确认权限正确保存和恢复。"
    },
    {
        "id": "CWE-640",
        "content": "名称: Weak Password Recovery Mechanism for Forgotten Password (弱密码恢复机制)\n描述: 密码恢复机制存在安全缺陷。\n影响: 账户接管、信息泄露。\n代码表象: 密码提示过于明显；恢复链接可预测；安全问题答案可猜测。\n审计策略: 审查密码恢复流程。确认使用安全的恢复机制（如随机令牌、多因素验证）。"
    },
    {
        "id": "CWE-641",
        "content": "名称: Improper Restriction of Names for Files and Other Resources (文件和资源名称限制不当)\n描述: 文件或资源名称未正确限制。\n影响: 文件覆盖、路径穿越。\n代码表象: 文件名未过滤特殊字符；允许用户控制完整路径。\n审计策略: 审查文件名处理。确认对文件名进行白名单过滤或安全编码。"
    },
    {
        "id": "CWE-642",
        "content": "名称: External Control of Critical State Data (关键状态数据外部控制)\n描述: 关键状态数据可被外部控制。\n影响: 业务逻辑绕过、权限提升。\n代码表象: 会话状态存储在客户端；关键标志可被用户修改。\n审计策略: 审查状态管理。确认关键状态数据存储在服务端。"
    },
    {
        "id": "CWE-643",
        "content": "名称: Improper Neutralization of Data within XPath Expressions (XPath 注入)\n描述: XPath 查询中未正确净化用户输入。\n影响: 信息泄露、认证绕过。\n代码表象: XPath 查询直接拼接用户输入。\n审计策略: 审查 XPath 查询构造。确认使用参数化查询或输入转义。"
    },
    {
        "id": "CWE-644",
        "content": "名称: Improper Neutralization of HTTP Headers for Script Injection (HTTP 头脚本注入)\n描述: HTTP 头中未正确净化用户输入。\n影响: HTTP 响应分割、缓存投毒、XSS。\n代码表象: HTTP 头值直接包含用户输入。\n审计策略: 审查 HTTP 头设置。确认对头值进行净化，移除换行符等特殊字符。"
    },
    {
        "id": "CWE-645",
        "content": "名称: Overly Restrictive Account Lockout Mechanism (过度限制的账户锁定机制)\n描述: 账户锁定机制过于严格，可被用于拒绝服务。\n影响: 拒绝服务、账户锁定攻击。\n代码表象: 少量失败尝试即永久锁定；无解锁机制。\n审计策略: 审查账户锁定策略。确认锁定时间合理，提供解锁机制。"
    },
    {
        "id": "CWE-646",
        "content": "名称: Reliance on File Name or Extension of Externally-Supplied File (依赖外部文件的名称或扩展名)\n描述: 程序依赖外部提供的文件名或扩展名进行安全决策。\n影响: 文件类型绕过、恶意文件执行。\n代码表象: 仅根据扩展名判断文件类型；信任用户提供的文件名。\n审计策略: 审查文件处理逻辑。确认通过文件内容（魔数）验证文件类型。"
    },
    {
        "id": "CWE-647",
        "content": "名称: Use of Non-Canonical URL Paths for Authorization Decisions (非规范 URL 路径用于授权决策)\n描述: 授权检查使用非规范化的 URL 路径。\n影响: 授权绕过。\n代码表象: URL 路径比较前未规范化；路径中包含 `..` 或编码字符绕过检查。\n审计策略: 审查 URL 授权逻辑。确认路径规范化后再进行比较。"
    },
    {
        "id": "CWE-648",
        "content": "名称: Incorrect Use of Privileged APIs (特权 API 使用不当)\n描述: 特权 API 被不正确地使用。\n影响: 权限提升、安全机制绕过。\n代码表象: 在非必要情况下使用特权 API；特权 API 参数不正确。\n审计策略: 审查特权 API 使用。确认仅在必要时使用，参数正确。"
    },
    {
        "id": "CWE-649",
        "content": "名称: Reliance on Obfuscation or Encryption of Security-Sensitive Inputs without Integrity Check (安全敏感输入仅依赖混淆或加密而无完整性检查)\n描述: 安全敏感数据仅进行混淆或加密，未验证完整性。\n影响: 数据篡改、安全检查绕过。\n代码表象: 使用编码或加密保护数据但无签名或 MAC。\n审计策略: 审查敏感数据处理。确认使用完整性检查（如 HMAC）保护数据。"
    },
    {
        "id": "CWE-650",
        "content": "名称: Trusting HTTP Permission Methods on the Server Side (服务端信任 HTTP 权限方法)\n描述: 服务端信任客户端的 HTTP 方法（如 X-HTTP-Method-Override）。\n影响: 授权绕过。\n代码表象: 根据 X-HTTP-Method-Override 头覆盖请求方法。\n审计策略: 审查 HTTP 方法处理。确认不信任客户端的方法覆盖头。"
    },
    {
        "id": "CWE-651",
        "content": "名称: Exposure of WSDL File Containing Sensitive Information (暴露包含敏感信息的 WSDL 文件)\n描述: WSDL 文件暴露了敏感信息。\n影响: 信息泄露、服务接口暴露。\n代码表象: WSDL 文件可公开访问；包含内部服务地址或敏感操作。\n审计策略: 审查 WSDL 暴露情况。确认限制 WSDL 访问或移除敏感信息。"
    },
    {
        "id": "CWE-652",
        "content": "名称: Improper Neutralization of Data within XQuery Expressions (XQuery 注入)\n描述: XQuery 查询中未正确净化用户输入。\n影响: 信息泄露、数据篡改。\n代码表象: XQuery 查询直接拼接用户输入。\n审计策略: 审查 XQuery 查询构造。确认使用参数化查询或输入转义。"
    },
    {
        "id": "CWE-653",
        "content": "名称: Improper Isolation or Compartmentalization (隔离或分隔不当)\n描述: 系统组件之间隔离不当。\n影响: 权限提升、横向移动。\n代码表象: 不同安全级别的组件共享资源；缺少沙箱隔离。\n审计策略: 审查系统架构。确认不同安全级别的组件适当隔离。"
    },
    {
        "id": "CWE-654",
        "content": "名称: Reliance on a Single Factor in a Security Decision (安全决策仅依赖单一因素)\n描述: 安全决策仅依赖单一因素，缺乏纵深防御。\n影响: 安全机制绕过。\n代码表象: 仅依赖密码认证；仅依赖 IP 地址授权。\n审计策略: 审查安全决策。确认实施多层安全措施。"
    },
    {
        "id": "CWE-655",
        "content": "名称: Insufficient Psychological Acceptability (心理可接受性不足)\n描述: 安全机制过于复杂或繁琐，用户可能绕过。\n影响: 安全机制被绕过。\n代码表象: 复杂的密码策略；繁琐的认证流程。\n审计策略: 审查用户体验。确认安全措施平衡安全性和可用性。"
    },
    {
        "id": "CWE-656",
        "content": "名称: Reliance on Security Through Obscurity (依赖隐蔽式安全)\n描述: 安全依赖于系统的隐蔽性而非实际的安全措施。\n影响: 安全机制被轻易绕过。\n代码表象: 依赖隐藏的管理接口；使用不公开的协议。\n审计策略: 审查安全设计。确认不依赖隐蔽性，实施实际的安全措施。"
    },
    {
        "id": "CWE-657",
        "content": "名称: Violation of Secure Design Principles (违反安全设计原则)\n描述: 系统设计违反了基本的安全设计原则。\n影响: 多种安全漏洞。\n代码表象: 最小权限原则违反；纵深防御缺失；失败开放。\n审计策略: 审查系统设计。确认遵循安全设计原则。"
    },
    ]

    collection.upsert(
        documents=[item["content"] for item in cwe_entries],
        metadatas=[{"cwe_id": item["id"]} for item in cwe_entries],
        ids=[item["id"] for item in cwe_entries]
    )

    print(f"✅ 成功初始化漏洞知识库！")
    print(f"📍 存储位置: {os.path.abspath(DB_PATH)}")
    print(f"📚 当前记录数: {collection.count()}")

if __name__ == "__main__":
    init_vulnerability_database()
