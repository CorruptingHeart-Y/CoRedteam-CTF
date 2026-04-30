================================================================================
  Co-RedTeam — 多智能体红队自动化漏洞发现与复现系统
  版本: 2.0 / 日期: 2026-04-27
================================================================================

=== 项目简介 ===

Co-RedTeam 是一个两阶段多智能体红队自动化框架：

  Stage 1 (漏洞发现)  — LangGraph 驱动的代码审计，自动生成漏洞报告
  Stage 2 (动态复现)  — 在 Docker 沙箱中自动生成并执行攻击计划，验证漏洞

两个阶段可独立运行，也可通过 run_pipeline.py 串联全自动执行。

=== 完整文件结构 ===

  Co-RedTeam/
  │
  ├── Stage 1 ─── 漏洞发现引擎 (根目录)
  │   ├── main.py                    # ★ Stage1 主入口 (LangGraph 多智能体)
  │   ├── run_pipeline.py            # ★ 全局总控 (Stage1 → Stage2 桥接)
  │   ├── vul_doc.py                 # 漏洞工具集 + ChromaDB 客户端
  │   ├── vul_doc_ini.py             # 漏洞文档初始化
  │   ├── code_browser.py            # 代码浏览工具 (文件读取/搜索)
  │   ├── demo_securepay.py          # SecurePay 完整演示脚本
  │   ├── demo_docker.py             # Docker 隔离演示
  │   ├── benchmark_evaluator.py     # 基准测试评估器
  │   ├── benchmark_dataset.jsonl    # 基准测试数据集
  │   ├── manage_memory.py           # 记忆管理 (查看/清理 ChromaDB)
  │   ├── check_memory.py            # 记忆检查 (详细查看所有集合)
  │   ├── peek_memory.py             # 记忆快查 (快速查看指定集合)
  │   ├── requirements.txt           # Stage1 Python 依赖
  │   └── .env.template              # 环境变量模板
  │
  ├── Stage 2 ─── 动态复现引擎 (b/)
  │   ├── coordinator.py             # ★ Stage2 主入口 (多智能体协调器)
  │   ├── README.txt                 # 本说明文件
  │   ├── requirements.txt           # Stage2 Python 依赖
  │   ├── Dockerfile                 # Docker 沙箱镜像
  │   ├── .env.example               # Stage2 环境变量模板
  │   ├── agents/                    # 四个智能体
  │   │   ├── __init__.py
  │   │   ├── planner.py             # 规划智能体 (LLM 生成攻击计划)
  │   │   ├── validator.py           # 校验智能体 (语法+安全检查)
  │   │   ├── executor.py            # 执行智能体 (Docker 沙箱)
  │   │   └── evaluator.py           # 评估智能体 (LLM 评估+记忆更新)
  │   ├── core/                      # 核心基础设施
  │   │   ├── __init__.py
  │   │   ├── settings.py            # 环境变量配置读取
  │   │   ├── llm_client.py          # DeepSeek/OpenAI 兼容 LLM 客户端
  │   │   └── memory_store.py        # ChromaDB 三层长期记忆
  │   ├── memory/                    # 初始记忆种子数据
  │   │   ├── pattern.json           # 漏洞模式
  │   │   ├── strategy.json          # 攻击策略+失败教训
  │   │   └── tech.json              # 技术命令+payload 模板
  │   └── data/
  │       └── confirmed_vuln.json    # 漏洞输入 (Stage1 产出/手工编写)
  │
  ├── target_codebase/               # 目标靶机 (Flask 漏洞应用)
  │   └── secure_pay_platform/
  │       ├── app.py                 # 主应用 (含所有漏洞)
  │       ├── config.py              # 配置文件 (含硬编码凭据)
  │       ├── ground_truth.json      # 漏洞真值 (用于评估)
  │       ├── requirements.txt
  │       ├── models/
  │       │   ├── user.py
  │       │   ├── transaction.py
  │       │   └── payment.py
  │       ├── middleware/
  │       │   ├── cors.py
  │       │   └── csrf.py
  │       └── utils/
  │           ├── serializer.py
  │           └── template_engine.py
  │
  └── reports/                       # 漏洞报告输出
      └── vulnerability_proposal_latest.json

=== 系统架构 ===

Stage 1 (漏洞发现):
  target_codebase/ ──→ [CodeBrowser] ──→ [Analysis Agent] ──→ [Critique Agent]
                                                    ↓
                                            ChromaDB 长期记忆
                                                    ↓
                                         [Evolution Agent]
                                                    ↓
                                   reports/vulnerability_proposal_latest.json

Stage 2 (动态复现):
  confirmed_vuln.json ──→ [coordinator] ──→ [planner → validator → executor → evaluator]
                                                     ↕                        ↓
                                              ChromaDB 长期记忆        feedback.json

=== 环境准备 ===

1. Python 3.10+ 虚拟环境

   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # Linux/macOS:
   source .venv/bin/activate

   # 安装 Stage 1 依赖 (根目录)
   pip install -r requirements.txt

   # 安装 Stage 2 依赖 (b/ 目录)
   pip install -r b/requirements.txt

2. Docker Desktop (仅 Stage 2 需要)

   安装 Docker Desktop 并保持运行。
   首次使用前构建沙箱镜像：

   cd b
   docker build -t co-redteam-sandbox:latest .

3. 配置 API Key

   根目录 .env 或 b/.env 中设置：

   DEEPSEEK_API_KEY=sk-your-real-key
   DEEPSEEK_BASE_URL=https://api.deepseek.com
   DEEPSEEK_MODEL=deepseek-chat

=== 使用方法 ===

【方式一：全自动流水线 (推荐)】

   从漏洞发现到动态复现一气呵成：

   python run_pipeline.py

   可选参数：
     --target PATH    指定目标代码库路径 (默认: target_codebase)
     --skip-phase1    跳过 Stage1，使用已有 report 直接跑 Stage2
     --mock           使用 Mock 模式

【方式二：仅 Stage1 漏洞发现】

   python main.py

   输出在 reports/vulnerability_proposal_latest.json

【方式三：仅 Stage2 动态复现】

   # 先将漏洞报告转为 confirmed_vuln.json 格式放到 b/data/
   cd b
   python coordinator.py

   或用 run_pipeline.py 自动桥接：
   python run_pipeline.py --skip-phase1

【其他工具脚本】

   python demo_securepay.py --all       # SecurePay 完整演示
   python demo_docker.py --full         # Docker 隔离演示
   python benchmark_evaluator.py        # 基准测试评估
   python check_memory.py               # 查看所有长期记忆
   python manage_memory.py              # 管理/清理记忆
   python peek_memory.py                # 快速查看指定记忆集合

=== 核心安全设计 (Stage 2) ===

  - 所有攻击代码强制在 Docker 容器中执行
  - 容器配置: read_only=True, no-new-privileges, cap_drop=["ALL"]
  - 绝对不允许在宿主机执行任何攻击代码
  - Validator 拦截高危模式，Executor 拦截真正危险命令

=== FAQ ===

Q: Stage1 和 Stage2 的关系？
A: Stage1 扫描代码生成漏洞报告 (vulnerability_proposal_latest.json)，
   Stage2 读取 confirmed_vuln.json 自动化验证。
   run_pipeline.py 会自动把 Stage1 的输出转为 Stage2 的输入。

Q: 可以只用其中一个吗？
A: 可以。python main.py 只跑 Stage1，cd b && python coordinator.py 只跑 Stage2。

Q: ChromaDB 报错？
A: 删除 co_redteam_memory/ 目录重新运行即可。
