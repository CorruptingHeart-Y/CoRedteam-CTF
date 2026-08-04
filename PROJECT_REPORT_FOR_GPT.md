# Co-RedTeam 项目报告 — 当前状态与待决策问题

## 1. 项目概述

Co-RedTeam 是一个多智能体协作的自动化漏洞利用框架。架构采用五层流水线：

```
Planner → Validator → Executor → GoalVerifier → Evaluator → 迭代循环
```

- **Planner**: 基于 LLM (DeepSeek) 根据 confirmed_vuln.json（Phase 1 静态审计输出）生成攻击计划 plan.json
- **Validator**: 对 plan 做 AST 安全检查、Manifest 对齐、策略合规校验
- **Executor**: Docker 沙箱内执行 Python 攻击脚本，自动注入 HTTP 日志
- **GoalVerifier**: 确定性 flag 扫描（正则匹配），若命中直接 return 0，跳过 Evaluator
- **Evaluator**: LLM 评估攻击结果，输出 feedback（repro_success, confidence, primitive 信号等）
- **Coordinator**: 管理迭代循环、熔断器、衰减式动态预算、攻击面轮换、FSM 状态推进

历史截图证明，旧版曾通过上述完整五层链路在单次 plan、单个 step 中直接获取 challenge1 flag（Planner → TemplateManager → Validator → Executor → Evaluator → confidence=1.0 → flag → 停止迭代）。

## 2. 当前架构变更

在最新版本中引入了 **Manual Route Bridge** (`b/routes/manual_bridge.py`)，这是一套全新的代码路径：

```
CLI --manual-route → Admission → Registry → Frontier → Materializer → Validator → Executor → Evaluator(llm=None)
```

目的：允许用户指定一个 YAML 路由文件，绕过 Planner 的 LLM 生成和策略选择，直接进入执行链。

**当前使用的命令**：
```bash
python b/cli.py exploit --url https://TARGET:1337 \
    --confirmed b/data/confirmed_vuln.json \
    --manual-route \
    --route-dir b/data/manual_routes/challenge1 \
    --route-id cwe-94:init:ssti-reflection:arithmetic-probe \
    --max-iter 1 --max-runs 1
```

**当前结果**：只执行了算术探针（`#set($x=7*7)$x`），Manual Route Bridge 检测到输出中的 "49" 即判定 signal_match=True（`b/routes/manual_bridge.py:894` 存在无条件覆盖 `signal_match = True`），然后退出。

## 3. Manual Route 绕过的模块（完整清单）

| 组件 | 状态 | 影响 |
|---|---|---|
| **Planner** | 绕过 | 不调用 LLM，不从模板库选策略，不构建攻击链 |
| **TemplateManager** | 绕过 | 不检索 CWE 模板库，不使用历史经验 |
| **Consolidator** | 绕过 | 迭代结束后不提炼战略经验到永久记忆 |
| **FSM / state update** | 绕过 | 不记录 trajectory、不更新 primitive learning、不写 verification memory |
| **迭代终止逻辑** | 绕过 | 无熔断器、无衰减式扩展、无进展检测、无攻击面轮换 |
| **GoalVerifier** | 绕过 | 不做 flag 确定性扫描 |
| **Coordinator 主循环** | 绕过 | 完全跳过 `while iteration < budget` |
| **Evaluator (LLM)** | 半绕过 | 仍调用 `run_evaluator()` 但传入 `llm=None` |

**ManualRouteBridge 执行了的部分**：
- Admission (YAML 安全加载)
- Registry (路由注册)
- Frontier (路由准入判断)
- Materializer (YAML→plan.json 转换)
- Validator ✅ (安全检查仍在)
- Executor ✅ (Docker 沙箱仍在)
- Evaluator 本地判定 ✅ (正则检测仍在，但无 LLM)

## 4. YAML 路由文件内容

当前 `b/data/manual_routes/challenge1/cwe-94-init-ssti-reflection-arithmetic-probe.yaml`:

```yaml
schema_version: 1.1.0
canonical_id: cwe-94:init:ssti-reflection:arithmetic-probe
cwe_id: CWE-94
current_state: init
technique: arithmetic_probe
generation_status: candidate_only   # ← 仅候选，非生产
activation:
  state: draft
requires:
  runtime_facts: [endpoint, parameter, method]
target_primitive: ssti_reflection
expected_signals: [arithmetic_result_in_response]
```

**关键问题**：这个 YAML 的 `generation_status: candidate_only` 和 `activation.state: draft` 表明它是由 `route_factory` 自动生成的候选路由，不是人工审核后的完整攻击链。它只包含一个**算术探针**作为第一步探测，不包含从 SSTI 升级到 RCE 的完整 exploit chain。

## 5. 代码库关键文件清单

```
b/
├── cli.py                    # CLI 入口 — cmd_exploit() 分支点
├── coordinator.py            # run_pipeline() — 完整五层链 + FSM
├── agents/
│   ├── planner.py            # run_planner() — LLM 生成攻击计划
│   ├── validator.py          # run_validator() — 安全策略校验
│   ├── executor.py           # run_executor() — Docker 沙箱执行
│   ├── evaluator.py          # run_evaluator() — LLM 评估 + 本地检测
│   └── consolidator.py       # run_global_consolidation() — 复盘提炼
├── core/
│   ├── template_manager.py   # 攻击模板库管理
│   ├── goal_verifier.py      # 确定性 flag 扫描
│   ├── plan_contract.py      # plan 结构合同验证
│   └── ...
├── routes/
│   ├── manual_bridge.py      # Manual Route Bridge — 新路径入口
│   ├── admission.py          # YAML 安全加载 + 准入
│   ├── registry.py           # 路由注册表
│   ├── frontier.py           # 路由准入过滤
│   ├── materializer.py       # YAML → plan.json 物化
│   └── ...
└── data/
    ├── manual_routes/
    │   └── challenge1/
    │       └── cwe-94-init-ssti-reflection-arithmetic-probe.yaml
    └── confirmed_vuln.json
```

## 6. 两个环境对比

| 维度 | 历史成功环境 | 当前环境 |
|---|---|---|
| 代码目录 | `C:\Users\ADMIN\redteam\b` | `C:\Users\ADMIN\red\redteam\b` |
| 目标端口 | 9443 | 1337 |
| Manual Route 功能 | 不存在 | 存在（新增） |
| TemplateManager 策略选择器 | `select_templates_for_target()` (完整) | `get_templates_for_target()` (简化) |
| b/routes/ 模块 | 不存在 | 存在（全新） |
| b/data/manual_routes/ | 不存在 | 存在（全新） |

## 7. 核心诊断

**为什么 Manual Route 只能执行到算术探针就退出？**

因为 YAML 文件本身只是一个 "step 0" 探测路由（`technique: arithmetic_probe`, `target_primitive: ssti_reflection`），它不包含后续的 RCE payload 升级步骤。Manual Route Bridge 没有 Planner 的 LLM 来基于探测结果生成下一步攻击计划，也没有 Coordinator 的迭代循环来多轮推进。它执行一步 → Evaluator 本地判定 → `signal_match=True`（因为检测到 49）→ 返回 success 然后退出。

**完整的五层链仍然存在于 `run_pipeline()` 中**，但被 `--manual-route` 分支完全跳过。

## 8. 可选的前进方向（请 GPT 评估）

### 方案 A：放弃 Manual Route，使用标准 exploit 命令

```bash
python b/cli.py exploit --url https://TARGET:1337 \
    --confirmed b/data/confirmed_vuln.json \
    --challenge generic \
    --max-iter 5 --max-runs 5
```

- 优点：立即恢复完整五层链，无需改代码
- 风险：Planner LLM 可能不走 SSTI 路径，需要 confirmed_vuln.json 中有准确的 CWE-94 SSTI 标注

### 方案 B：增强 Manual Route YAML，使其包含完整 exploit chain

在 YAML 中新增后续步骤（probe → RCE → flag read），让 Materializer 生成多步 plan.json。

- 优点：保留 Manual Route 的精确控制
- 工作量：需要手写完整的 exploit chain YAML（payload template refs、expected signals、state transitions）

### 方案 C：让 Manual Route 回落到 Planner（混合模式）

当 Manual Route 执行探测步骤后，检测到 primitive 信号但未达到 flag → 将信号 + YAML 上下文注入 Planner → 回到完整的 run_pipeline 循环。

- 优点：兼顾精确控制和 LLM 自适应
- 工作量：需要在 manual_bridge.py 和 coordinator.py 之间增加桥接逻辑

### 方案 D：在 Planner 中增加对 YAML 路由的感知（不通过 Manual Route Bridge）

修改 `b/agents/planner.py:963 _build_cwe_templates()`，在 TemplateManager 模板检索之后，追加扫描 `b/data/manual_routes/` 中匹配当前 CWE 的 YAML 路由，将其 payload 信息作为额外模板注入 Planner 的 system prompt。然后使用标准 exploit 命令。

- 优点：新版 YAML 接入完整五层链，不绕过任何组件
- 工作量：只改一个函数（~20 行代码）
- 风险：需确认 Planner LLM 能正确理解 YAML 路由中的 payload 语义

---

**请评估以上方案，给出推荐方向及具体实施步骤。特别关注：**
1. 哪种方案能最快验证"完整五层链仍然能单步获取 flag"
2. Manual Route Bridge 是否应该保留还是废弃
3. YAML 路由文件应该何时、由谁生成完整 exploit chain（人工 vs route_factory vs Planner LLM）
