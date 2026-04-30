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
    }
    ]
    # 3. 批量写入数据
    # ChromaDB 会自动处理 Embedding 向量化过程 
    collection.add(
        documents=[item["content"] for item in cwe_entries],
        metadatas=[{"cwe_id": item["id"]} for item in cwe_entries],
        ids=[item["id"] for item in cwe_entries]
    )

    print(f"✅ 成功初始化漏洞知识库！")
    print(f"📍 存储位置: {os.path.abspath(DB_PATH)}")
    print(f"📚 当前记录数: {collection.count()}")

if __name__ == "__main__":
    init_vulnerability_database()