import chromadb
import os

# 1. 配置本地持久化路径 (与后续工具调用路径保持一致)
DB_PATH = "./co_redteam_memory"
COLLECTION_NAME = "vulnerability_docs"

def init_vulnerability_database():
    # 初始化 ChromaDB 客户端
    client = chromadb.PersistentClient(path=DB_PATH)
    
    # 创建或获取集合
    # 论文提到使用向量相似度检索来辅助漏洞发现 [cite: 204, 222]
    collection = client.get_or_create_collection(name=COLLECTION_NAME)

    # 2. 核心漏洞数据 (Top 25 CWE 与审计策略) [cite: 14, 646, 654-678]
    # 我们为 LLM 优化了内容，包含：名称、描述、影响、代码表象、审计策略
    cwe_entries = [
    {
        "id": "CWE-89",
        "content": "CWE-89 SQL Injection (SQL注入) SQLi 数据库注入\n名称: SQL Injection (SQL注入)\n描述: 应用程序在未正确清理外部输入的情况下，将其直接拼接到 SQL 语句中。\n影响: 数据泄露、数据库被篡改、潜在的服务器控制。\n代码表象: 字符串拼接构建的 SQL 查询 (如 `\"SELECT * FROM users WHERE name = '\" + username + \"'\"`)。\n审计策略: 追踪 HTTP 请求参数，查看其是否未经预编译 (Prepared Statements) 或 ORM 参数化绑定就直接传入了数据库执行函数 (如 `cursor.execute`, `jdbcTemplate.query`)。"
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
        "id": "CWE-295",
        "content": "名称: Improper Certificate Validation (证书验证不当)\n描述: 应用程序未正确验证 SSL/TLS 证书，导致中间人攻击。\n影响: 中间人攻击、数据窃听、凭证窃取。\n代码表象: 代码中设置 `verify=False` 或 `CERT_NONE`；忽略证书验证错误；未检查证书主机名。\n审计策略: 检查所有 HTTPS 请求代码。确认证书验证未被禁用，且正确验证证书链和主机名。"
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
        "id": "CWE-732",
        "content": "名称: Incorrect Permission Assignment for Critical Resource (关键资源权限分配错误)\n描述: 关键文件或目录的权限设置过于宽松。\n影响: 数据篡改、权限提升、信息泄露。\n代码表象: 配置文件权限为 777 或 666；敏感文件可被任意用户读取/写入。\n审计策略: 检查关键文件和目录的权限设置。确认遵循最小权限原则，仅授权必要的用户访问。"
    },
    {
        "id": "CWE-1004",
        "content": "名称: Sensitive Cookie Without 'HttpOnly' Flag (敏感 Cookie 缺少 HttpOnly 标志)\n描述: 敏感 Cookie 未设置 HttpOnly 标志，可被 JavaScript 访问。\n影响: XSS 攻击窃取会话 Cookie。\n代码表象: 设置 Cookie 时未指定 `HttpOnly` 属性。\n审计策略: 检查所有 Cookie 设置代码。确认敏感 Cookie（如会话 ID）设置了 `HttpOnly` 和 `Secure` 标志。"
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
        "id": "CWE-208",
        "content": "名称: Observable Timing Discrepancy (时序攻击)\n描述: 应用程序的执行时间差异可泄露敏感信息。\n影响: 绕过认证、密钥泄露。\n代码表象: 字符串比较使用 `==` 而非常量时间比较；密码验证存在提前返回。\n审计策略: 检查敏感比较操作。确认使用常量时间比较函数 (如 `hmac.compare_digest()`)。"
    },
    {
        "id": "CWE-532",
        "content": "名称: Insertion of Sensitive Information into Log File (敏感信息写入日志)\n描述: 敏感信息被写入日志文件。\n影响: 凭证泄露、隐私侵犯。\n代码表象: 日志记录密码、会话 ID、信用卡号等敏感数据。\n审计策略: 审查日志内容。确认敏感字段被脱敏或排除在日志之外。"
    },
    {
        "id": "CWE-134",
        "content": "名称: Use of Externally-Controlled Format String (格式化字符串漏洞)\n描述: 用户输入被用作格式化字符串。\n影响: 信息泄露、代码执行、拒绝服务。\n代码表象: `printf(userInput)`, `sprintf(buffer, userInput)` 等直接使用用户输入作为格式化字符串。\n审计策略: 检查所有格式化函数调用。确认使用固定格式化字符串，用户输入作为参数传入。"
    },
    {
        "id": "CWE-415",
        "content": "名称: Double Free (双重释放)\n描述: 同一块内存被释放两次。\n影响: 代码执行、内存损坏、拒绝服务。\n代码表象: 释放内存后未将指针置空，导致再次释放。\n审计策略: 审查内存释放代码。确认释放后指针被置空，避免重复释放。"
    },
    {
        "id": "CWE-456",
        "content": "名称: Missing Initialization of a Variable (变量未初始化)\n描述: 变量在使用前未被初始化。\n影响: 信息泄露、不可预测行为、安全检查绕过。\n代码表象: 声明变量后未赋值即使用；依赖默认初始化值。\n审计策略: 审查变量使用。确认所有变量在使用前被正确初始化。"
    },
    {
        "id": "CWE-643",
        "content": "名称: Improper Neutralization of Data within XPath Expressions (XPath 注入)\n描述: XPath 查询中未正确净化用户输入。\n影响: 信息泄露、认证绕过。\n代码表象: XPath 查询直接拼接用户输入。\n审计策略: 审查 XPath 查询构造。确认使用参数化查询或输入转义。"
    },
    {
        "id": "CWE-636",
        "content": "名称: Not Failing Securely ('Failing Open') (未安全失败)\n描述: 错误或异常情况下系统未安全失败。\n影响: 安全检查被绕过。\n代码表象: 异常处理时默认允许访问；错误时跳过安全检查。\n审计策略: 审查错误处理逻辑。确认错误时默认拒绝访问。"
    },
    {
        "id": "CWE-640",
        "content": "名称: Weak Password Recovery Mechanism for Forgotten Password (弱密码恢复机制)\n描述: 密码恢复机制存在安全缺陷。\n影响: 账户接管、信息泄露。\n代码表象: 密码提示过于明显；恢复链接可预测；安全问题答案可猜测。\n审计策略: 审查密码恢复流程。确认使用安全的恢复机制（如随机令牌、多因素验证）。"
    },
    {
        "id": "CWE-642",
        "content": "名称: External Control of Critical State Data (关键状态数据外部控制)\n描述: 关键状态数据可被外部控制。\n影响: 业务逻辑绕过、权限提升。\n代码表象: 会话状态存储在客户端；关键标志可被用户修改。\n审计策略: 审查状态管理。确认关键状态数据存储在服务端。"
    },
    {
        "id": "CWE-654",
        "content": "名称: Reliance on a Single Factor in a Security Decision (安全决策仅依赖单一因素)\n描述: 安全决策仅依赖单一因素，缺乏纵深防御。\n影响: 安全机制绕过。\n代码表象: 仅依赖密码认证；仅依赖 IP 地址授权。\n审计策略: 审查安全决策。确认实施多层安全措施。"
    },
    {
        "id": "CWE-656",
        "content": "名称: Reliance on Security Through Obscurity (依赖隐蔽式安全)\n描述: 安全依赖于系统的隐蔽性而非实际的安全措施。\n影响: 安全机制被轻易绕过。\n代码表象: 依赖隐藏的管理接口；使用不公开的协议。\n审计策略: 审查安全设计。确认不依赖隐蔽性，实施实际的安全措施。"
    },
    ]
    # 3. 批量写入数据
    # ChromaDB 会自动处理 Embedding 向量化过程 
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