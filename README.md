# Co-RedTeam: Orchestrated Security Discovery and Exploitation with LLM Agents

> **论文复现项目** — [Co-RedTeam: Orchestrated Security Discovery and Exploitation with LLM Agents](https://arxiv.org/abs/2602.02164) (arXiv:2602.02164)
>
> 基于 LLM 多智能体的全自动化漏洞发现与利用框架，支持 CTF Web 挑战从代码审计到 Flag 提取的端到端攻击链。

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Sandbox-green.svg)](https://www.docker.com/)
[![LLM](https://img.shields.io/badge/LLM-DeepSeek-orange.svg)](https://platform.deepseek.com/)
[![ArXiv](https://img.shields.io/badge/Paper-2602.02164-red.svg)](https://arxiv.org/abs/2602.02164)

---

## 目录

- [项目简介](#项目简介)
- [核心特性](#核心特性)
- [架构设计](#架构设计)
- [快速开始](#快速开始)
- [使用指南](#使用指南)
  - [Phase 1: 代码审计](#phase-1-代码审计)
  - [Phase 2: 攻击利用](#phase-2-攻击利用)
  - [CLI 工具](#cli-工具)
- [安全机制](#安全机制)
- [项目结构](#项目结构)
- [实战案例](#实战案例)
- [配置说明](#配置说明)
- [论文引用](#论文引用)

---

## 项目简介

Co-RedTeam 是一个基于大语言模型的多智能体协作框架，实现了论文 *Co-RedTeam: Orchestrated Security Discovery and Exploitation with LLM Agents* 中提出的双阶段攻击流水线：

### 双阶段架构

```
┌──────────────────────────────────────────────────────────────────┐
│                     Phase 1: 漏洞发现 (Audit)                      │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌────────────┐  │
│  │ 目标源码  │ →  │ 静态分析  │ →  │ LLM 理解  │ →  │ 漏洞报告   │  │
│  │ (PHP/..) │    │ (AST/正则)│    │ (DeepSeek)│    │ (JSON)     │  │
│  └──────────┘    └──────────┘    └──────────┘    └────────────┘  │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│                   Phase 2: 攻击利用 (Exploit)                      │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐      │
│  │ Planner  │ → │Validator │ → │ Executor │ → │Evaluator │      │
│  │ (规划器)  │   │ (验证器)  │   │ (执行器)  │   │ (评估器)  │      │
│  └──────────┘   └──────────┘   └──────────┘   └──────────┘      │
│       ↑              ↑              ↑              ↑             │
│   记忆系统       安全检查        Docker沙箱      反馈迭代          │
│   熔断保护       语法校验        超时控制        结果评估          │
└──────────────────────────────────────────────────────────────────┘
                              ↓
                        🚩 Flag 获取！
```

---

## 核心特性

| 特性 | 描述 |
|------|------|
| 🤖 **LLM 驱动** | 使用 DeepSeek API 进行漏洞理解和攻击链规划 |
| 🔗 **多步攻击链** | Planner 自动设计 5-10 步复杂攻击序列 |
| 🛡️ **Docker 沙箱** | 所有攻击代码在隔离容器中执行，保护宿主机 |
| 🔒 **URL 白名单锁定** | 严格限制网络访问仅指向目标 URL |
| ⚡ **防死循环熔断器** | 连续 3 次评估失败自动切换攻击策略 |
| 🧠 **长期记忆注入** | ChromaDB 向量数据库存储历史经验，跨任务复用 |
| 📋 **CLI 统一路由** | `argparse` 实现 `audit`/`exploit`/`memory` 子命令 |
| 🎨 **终端日志美化** | 基于 `rich` 的彩色阶段性日志输出 |
| 🔌 **可插拔适配器** | 挑战适配器模式，支持不同 Web 挑战格式 |
| 📐 **迭代上限保护** | 严格遵守 20 次迭代上限，超时安全退出并清理沙箱 |

---

## 架构设计

### 多智能体协作

```
                    Coordinator（主协调器）
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                 ▼
   ┌─────────┐    ┌──────────┐    ┌──────────────┐
   │ Planner │◄───│ Evaluator│    │ LayeredMemory │
   │ (LLM)   │    │ (LLM)    │    │ (ChromaDB)    │
   └────┬────┘    └────▲─────┘    └──────────────┘
        │              │
        ▼              │
   ┌──────────┐        │
   │ Validator│        │
   │ (静态)    │        │
   └────┬─────┘        │
        │              │
        ▼              │
   ┌──────────┐        │
   │ Executor │────────┘
   │ (Docker) │
   └──────────┘
```

### 三层记忆架构

| 层级 | 内容 | 用途 |
|------|------|------|
| **L1: 攻击模式** | 类似漏洞的成功利用路径 | 快速匹配已知模式 |
| **L2: 策略知识** | 通用的漏洞利用策略和方法论 | 跨题目知识迁移 |
| **L3: 技术细节** | 具体的 payload 构造和绕过技巧 | 精细化攻击微调 |

---

## 快速开始

### 环境要求

- **Python** 3.10+
- **Docker Desktop**（用于沙箱执行）
- **DeepSeek API Key**（可使用 Mock 模式跳过）
- **Windows** / Linux / macOS

### 安装

```bash
# 1. 进入项目目录
cd CoRedteam-CTF/b

# 2. 安装 Python 依赖
pip install -r requirements.txt

# 3. 配置环境变量
cp .env.example .env
# 编辑 .env 文件，填入你的 DEEPSEEK_API_KEY

# 4. 构建 Docker 沙箱镜像
docker build -t co-redteam-sandbox:latest .
```

### 验证安装

```bash
# 检查 CLI 是否正常
python cli.py -h

# 查看可用挑战适配器
python coordinator.py --list-adapters
```

---

## 使用指南

### Phase 1: 代码审计

对目标 Web 应用的源代码进行静态分析和 LLM 辅助理解，生成结构化漏洞报告。

```bash
# 审计指定目录下的代码
python cli.py audit --target target_codebase/cybench_web_challenges/"[Very Easy] TimeKORP"

# 或者直接运行全局流水线
python run_pipeline.py --target "target_codebase/cybench_web_challenges/[Very Easy] TimeKORP"
```

**输出**: `reports/vulnerability_proposal_latest.json` — 结构化漏洞报告，自动桥接至 `b/data/confirmed_vuln.json`

### Phase 2: 攻击利用

基于 Phase 1 的漏洞报告，启动多智能体攻击流水线。

```bash
# 完整流水线（Phase 1 + Phase 2）
python run_pipeline.py --target "target_codebase/cybench_web_challenges/[Very Easy] TimeKORP"

# 仅运行 Phase 2（已有 confirmed_vuln.json）
python run_pipeline.py --skip-phase1

# 使用 CLI 直接启动 Phase 2
python b/cli.py exploit --url http://localhost:1337

# 指定自定义漏洞报告
python b/cli.py exploit --url http://localhost:1337 --confirmed b/data/confirmed_vuln.json
```

**关键参数**:
- `--url`: 目标 URL（**必填**，严格白名单锁定）
- `--confirmed`: 漏洞报告 JSON 文件路径

### CLI 工具

统一的命令行路由，支持三大子命令：

```bash
# 审计子命令
python cli.py audit --target TARGET_DIR          # Phase 1 漏洞发现

# 利用子命令（URL 白名单锁定）
python cli.py exploit --url URL [--confirmed PATH]  # Phase 2 攻击利用

# 记忆管理子命令
python cli.py memory list                        # 查看攻击模板
python cli.py memory show TEMPLATE_ID            # 查看模板详情
python cli.py memory add FILE.yaml               # 添加模板
python cli.py memory remove TEMPLATE_ID          # 删除模板
python cli.py memory query --cwe CWE-79          # 按 CWE 查询模板
python cli.py memory stats                       # 统计信息
python cli.py memory init-builtin               # 初始化内置模板
```

### Mock 模式

不需要 LLM API Key 时的调试模式：

```bash
# 设置环境变量
set CO_REDTEAM_MOCK_LLM=true    # Windows
export CO_REDTEAM_MOCK_LLM=true # Linux/Mac

# 运行流水线
python run_pipeline.py --mock
```

---

## 安全机制

### URL 白名单锁定

Phase 2 启动后，所有网络访问被严格限制为仅目标 URL。系统在以下层面实施：

1. **CLI 层**: `--url` 为必填参数，不可省略
2. **Coordinator 层**: 全局 TargetContext 向下穿透
3. **Executor 层**: Docker 网络配置仅允许访问目标 IP:Port
4. **Planner 层**: 强制注入目标 URL 修正指令，禁止硬编码域名

### 防死循环熔断器

当连续 3 次 Evaluator 报告失败时：
- 触发硬中断，强制切换攻击策略
- 向 Planner 注入策略切换指令
- 从长期记忆中检索类似漏洞的替代利用路径

### Docker 沙箱隔离

- 每个攻击步骤在独立容器中执行
- 超时控制（默认 300 秒/步）
- 内存和 CPU 配额限制
- 容器执行完成后自动清理

### 迭代上限保护

- 严格遵循 20 次迭代上限
- 超时自动安全退出
- 清理所有 Docker 容器和临时工作空间

---

## 项目结构

```
CoRedteam-CTF/
├── b/                              # Phase 2: 攻击利用引擎
│   ├── coordinator.py              # 主协调器（Pipeline 编排）
│   ├── cli.py                      # 统一 CLI 入口
│   ├── Dockerfile                  # Docker 沙箱镜像定义
│   ├── requirements.txt            # Python 依赖
│   ├── agents/
│   │   ├── planner.py              # 攻击规划器（LLM 驱动）
│   │   ├── validator.py            # 计划验证器（语法 + 安全）
│   │   ├── executor.py             # 执行器（Docker 沙箱）
│   │   └── evaluator.py            # 结果评估器（反馈循环）
│   ├── core/
│   │   ├── llm_client.py           # LLM 客户端（DeepSeek API）
│   │   ├── memory_store.py         # 长期记忆（ChromaDB 三层架构）
│   │   ├── settings.py             # 配置管理
│   │   ├── target_context.py       # 目标上下文 + URL 白名单锁定
│   │   ├── template_manager.py     # 攻击模板管理器
│   │   ├── challenge_adapter.py    # 挑战适配器（可插拔）
│   │   └── ui.py                   # 终端 UI 美化（rich）
│   ├── templates/                  # 攻击模板库（YAML）
│   ├── data/
│   │   └── confirmed_vuln.json     # Stage 1 输出 → Stage 2 输入
│   └── workspace/                  # 运行时代码产出（gitignore 保护）
├── main.py                         # Phase 1: 代码审计入口
├── run_pipeline.py                 # 全局流水线总控脚本
├── .env.template                   # 环境变量模板
└── target_codebase/                # 待审计的目标代码库
    └── cybench_web_challenges/     # CyBench CTF 挑战集
```

---

## 实战案例

### TimeKORP (CyBench [Very Easy])

**漏洞类型**: CWE-78 OS Command Injection

**攻击流程**:
1. Phase 1 审计 `TimeController.php` 和 `TimeModel.php`，发现 `$_GET['format']` 参数直接拼接到 `exec()` 命令中
2. Phase 2 Planner 生成多步攻击链：探测 → 命令注入 → Flag 提取
3. Executor 在 Docker 沙箱中执行 PoC
4. 成功提取 Flag

**PoC**:
```bash
curl "http://target:1337/?format=%27%3B+cat+/flag*+%23"
```

---

## 配置说明

编辑 `b/.env` 或项目根目录的 `.env` 文件：

```ini
# DeepSeek API
DEEPSEEK_API_KEY=sk-your-key-here
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat

# Mock 模式（无需 API Key）
CO_REDTEAM_MOCK_LLM=false

# Docker 沙箱
CO_REDTEAM_DOCKER_ENABLED=true
CO_REDTEAM_DOCKER_IMAGE=co-redteam-sandbox:latest
CO_REDTEAM_DOCKER_TIMEOUT=300
CO_REDTEAM_DOCKER_MEMORY=512m
CO_REDTEAM_DOCKER_CPU_QUOTA=100000

# 目标覆盖（覆盖 confirmed_vuln.json 中的 base_url）
CO_REDTEAM_TARGET_BASE=http://localhost:1337

# 最大迭代次数
CO_REDTEAM_MAX_ITER=20
```

---

## 论文引用

```bibtex
@misc{co-redteam2026,
  title        = {Co-RedTeam: Orchestrated Security Discovery and Exploitation with LLM Agents},
  author       = {Anonymous},
  year         = {2026},
  eprint       = {2602.02164},
  archiveprefix = {arXiv},
  primaryclass = {cs.CR},
  url          = {https://arxiv.org/abs/2602.02164}
}
```

---

## License

本项目为学术研究用途的论文复现，仅供安全研究和教育目的使用。请勿用于未授权的渗透测试或攻击行为。
