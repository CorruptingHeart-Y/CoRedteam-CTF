# Co-RedTeam: LLM-Driven Autonomous Red Team Framework

> 基于大模型强化学习驱动的自动化红队渗透测试与自适应进化框架
>
> 论文实现：[Co-RedTeam: Orchestrated Security Discovery and Exploitation with LLM Agents](https://arxiv.org/abs/2602.02164) (arXiv:2602.02164)

---

## 项目简介

Co-RedTeam 是一个**全自动的 LLM 多智能体协作框架**，输入一个 CTF Web 挑战的源代码目录或漏洞报告，输出 **Flag**，全程无需人工介入。

```
源码目录 → [Phase 1: 静态审计] → 漏洞报告 JSON
                                    ↓
                    [Phase 2: 双模型攻击流水线] → Flag
```

核心思路来自论文 §3：将安全测试拆分为**审计（Audit）**和**利用（Exploit）**两个阶段，通过多智能体协作 + 长期记忆实现从漏洞发现到武器化利用的端到端自动化。

---

## 核心亮点：双模型自适应进化架构 (Dual-Model Reflexion)

这是项目最重要的架构创新。我们采用两层智能体分级协作设计，模拟顶级红队团队的运作模式：

### 微观战术层 — "四大金刚"（高性价比工作模型）

四个专用智能体在一个闭环中实时协作，使用性价比最高的模型（如 DeepSeek-V4-Pro）快速迭代攻击链：

| 智能体 | 职责 | 核心能力 |
|--------|------|----------|
| **Planner** | 攻击计划生成 | 读取漏洞报告 + CWE 模板 + RAG 记忆，生成多步攻击计划 JSON |
| **Validator** | 安全策略校验 | AST 级导入白名单 + 危险命令拦截 + 语法检查 + Polyglot 反模式检测 |
| **Executor** | 沙箱隔离执行 | Docker 容器中逐步执行，自动注入 redteam_sdk（HttpClient/OOBReceiver） |
| **Evaluator** | 零信任评估 | 物理铁证检测（S/A/F 三级）+ Blind RCE 识别 + 自动失败教训记录 |

```
Planner → Validator → Executor → Evaluator
    ↑                                  │
    └────── feedback 闭环修正 ─────────┘
```

内置**熔断器**（连续 3 次失败→硬中断+策略切换）、**攻击面轮换器**（一个漏洞被封堵后自动切换下一个）、**衰减式迭代预算**（初始 8 轮，每次里程碑突破自动延长，硬上限 20 轮），确保不会陷入死循环。

### 宏观复盘层 — "导师智能体"（顶级推理模型）

当微观战术层的迭代预算耗尽后，唤醒使用**独立高级大模型**的 **Consolidator（全局复盘导师）**：

1. 审阅整个打靶轨迹（所有 plan → execution → feedback 完整链）
2. 诊断死因（是 WAF 拦截？依赖库底层解析机制？陈旧无效 payload？）
3. 提炼"思想钢印"级战略经验，**直接写入永久记忆库**（`b/memory/pattern.json` + `b/memory/tech.json` + ChromaDB 向量索引）

这形成了**跨任务的自我进化闭环**：上次打靶失败的经验 → 自动变成下次打靶的"禁止事项"和"推荐战术"。

```
微观战术层 (8-20轮) → 耗尽预算 → 唤醒 Consolidator → 提炼战略经验 → 写入永久记忆
                                                                    ↓
                                            下次任务 → RAG 检索到 → Planner 直接使用高阶打法
```

论文对齐：Reflexion / Voyager / ExpeL — LLM-Driven Experiential Learning

---

## 鲁棒性保障

### 网络层容错

`core/llm_client.py` 实现了完整的 OpenAI 兼容 API 客户端，具备：

- **HTTP 超时控制**（`timeout=120s`），防止 API 无响应时永久挂起
- **指数退避重试**：`APITimeoutError` / `APIConnectionError` / `RateLimitError` / `InternalServerError` 自动重试（1s → 2s → 4s）
- **JSON 解析三层容错**：去除 markdown fence → 直接 `json.loads` → 正则提取再解析
- **多提供商兼容**：任何 OpenAI-compatible API 均可直接接入（DeepSeek / vLLM / Ollama / OpenRouter / 各类中转站）

### 安全边界

| 机制 | 层次 | 实现 |
|------|------|------|
| **URL 白名单锁定** | CLI → Coordinator → Executor | `TargetContext` 不可变对象，强制全局唯一目标 |
| **Docker 沙箱** | Executor | 独立容器，内存/CPU/网络配额，执行完自动销毁 |
| **AST 导入白名单** | Validator | 静态扫描 import 语句，default-deny（只允许 requests/json/re/base64 等安全模块） |
| **禁止高危命令** | Validator | 拦截 `rm -rf /`、`subprocess`、`os.system`、ShellShock、进程替换等 |
| **防死循环熔断** | Coordinator | 连续失败 + 无进展检测 + AI 主动熔断（suggest_abort） |

---

## 核心模块架构

```
b/
├── cli.py                          # 统一 CLI 入口：audit / exploit / memory 子命令
├── coordinator.py                  # ★核心★ Phase 2 主控循环 + 熔断器 + 轮换器
├── Dockerfile                      # Alpine 沙箱镜像
├── requirements.txt                # Python 依赖
│
├── agents/                         # 智能体模块
│   ├── planner.py                  # 攻击计划生成（LLM + RAG + 模板）
│   ├── validator.py                # 安全校验（AST 白名单 + 反模式检测）
│   ├── executor.py                 # Docker 沙箱执行 + SDK 注入
│   ├── evaluator.py                # 零信任评估 + 铁证检测
│   └── consolidator.py             # 全局复盘导师（双模型架构核心）
│
├── core/                           # 基础设施
│   ├── llm_client.py               # OpenAI 兼容客户端（超时 + 指数退避重试）
│   ├── memory_store.py             # ChromaDB 三层记忆（patterns/strategies/techniques）
│   ├── settings.py                 # 配置管理（.env → Settings @dataclass）
│   ├── target_context.py           # 目标白名单锁定
│   ├── template_manager.py         # YAML 攻击模板管理
│   ├── challenge_adapter.py        # 可插拔挑战适配器基类
│   ├── ui.py                       # Rich 终端美化
│   └── adapters/                   # 挑战适配器实现
│       └── apexsurvive.py          # ApexSurvive 专项适配器示例
│
├── templates/builtin/              # YAML 攻击模板库
│   └── cve-2022-39227-jwt-polyglot.yaml
│
├── memory/                         # 长期记忆种子数据
│   ├── pattern.json                # 漏洞模式
│   ├── strategy.json               # 策略知识
│   └── tech.json                   # 可复用 payload / 命令 / 脚本
│
├── data/                           # 数据文件
│   └── confirmed_vuln.json         # Phase 1 → Phase 2 桥接文件
│
└── workspace/                      # 运行时产出（plan / execution / feedback）
```

---

## 数据流向

```
[User Input]
    │
    │  python b/cli.py exploit --url http://localhost:1337
    ▼
┌──────────────────────────────────────────────────────────┐
│ coordinator.run_pipeline()                               │
│                                                          │
│  confirmed = json.load("data/confirmed_vuln.json")       │
│  adapter   = get_adapter(challenge_name)   ← 可插拔     │
│  memory    = LayeredMemory(memory_dir)     ← ChromaDB   │
│                                                          │
│  FOR iteration IN 1..max_iterations (上限20):            │
│    plan        = run_planner(adapter, memory, feedback)  │
│    validated   = run_validator(plan, prior_feedback)     │
│    exec_result = run_executor(validated, target)         │
│    feedback    = run_evaluator(exec_result, memory, ...) │
│                                                          │
│    IF feedback["flag_found"]: EXIT(0)                   │
│    IF breaker.triggered(): rotate_strategy()            │
│    IF plan.fully_blocked(): vuln_rotator.rotate()       │
│                                                          │
│  ── 迭代结束后 ──                                       │
│  Consolidator: 全局复盘 → 提炼经验 → 写入永久记忆        │
└──────────────────────────────────────────────────────────┘
```

---

## 快速开始

### 环境要求

- Python 3.10+
- Docker Desktop
- LLM API Key（DeepSeek 或任意 OpenAI 兼容提供商）

### 1. 安装依赖

```bash
cd b
pip install -r requirements.txt
```

### 2. 配置环境变量

```bash
cp .env.example .env
# 编辑 .env 填入你的 API Key
```

`.env` 核心配置项：

```ini
# 主模型（Planner / Validator / Evaluator 共用）
DEEPSEEK_API_KEY=sk-your-key-here
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat

# 复盘导师模型（独立配置，可选更高等级模型）
CONSOLIDATOR_API_KEY=sk-your-key-here
CONSOLIDATOR_BASE_URL=https://api.deepseek.com
CONSOLIDATOR_MODEL=deepseek-chat
```

### 3. 构建 Docker 沙箱镜像（仅一次）

```bash
docker build -t co-redteam-sandbox:latest .
```

### 4. 运行打靶

```bash
# Phase 2 直攻模式（需要已有 confirmed_vuln.json）
python b/cli.py exploit --url http://localhost:1337

# 指定挑战适配器和漏洞文件
python b/cli.py exploit --url http://host.docker.internal:1337 --vuln data/confirmed_vuln.json

# Phase 1 审计模式
python b/cli.py audit --target ./target_codebase/some_challenge/
```

### 5. 管理攻击模板

```bash
# 列出所有可用模板
python b/cli.py memory --list

# 添加新模板
python b/cli.py memory --add templates/builtin/my_template.yaml
```

---

## 已解决挑战

| 挑战 | 难度 | 漏洞类型 | 状态 |
|------|------|------|------|
| TimeKORP | Very Easy | CWE-78 OS Command Injection (PHP) | Solved |
| LockTalk | Medium | CVE-2022-39227 JWT Polyglot + HAProxy Bypass | Solved |

---

## 关键设计决策

### 为什么用两层模型架构？

- **微观层**需要快速迭代（每轮 ~30s），使用高性价比模型控制成本，8-20 轮总调用量可控
- **宏观层**只在迭代结束后执行一次，需要顶级推理能力来诊断深层次死因，值得使用最强模型
- 两层分工模拟了"一线渗透工程师 + 事后复盘技术总监"的真实团队结构

### 为什么 Executor SDK 是动态注入的？

运行时动态写入 `redteam_sdk.py` 到容器 workspace，提供标准化工具（HttpClient、OOBReceiver、ContextStore），版本更新无需重新 build Docker 镜像。

### 三层记忆系统的作用

- **L1 Patterns**："这个错误模式以前见过吗？" → 快速分类
- **L2 Strategies**："这种情况下什么策略有效？" → 决策支持
- **L3 Techniques**："这个 CWE 有什么现成 payload？" → 代码复用

---

## Citation

```bibtex
@misc{co-redteam2026,
  title        = {Co-RedTeam: Orchestrated Security Discovery and Exploitation with LLM Agents},
  year         = {2026},
  eprint       = {2602.02164},
  archiveprefix = {arXiv},
  primaryclass = {cs.CR}
}
```

## License

Academic research reproduction. For security research and educational purposes only.