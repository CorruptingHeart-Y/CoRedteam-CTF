# Co-RedTeam "极简五层版本" 严格只读审计报告

**审计日期**: 2026-07-23
**审计分支**: `competition-standard` (commit `c8cebec`)
**审计范围**: `b/` 目录下的完整五层流水线
**审计方法**: 纯只读静态分析 + 59 项离线单元测试验证
**测试结果**: 59/59 PASSED (2.31s)

---

## A. 极简版准确目录与入口

### 重要前置结论：不存在独立的"极简版"目录

代码库中**没有**名为 `minimal/`、`simple/`、`v3/`、`v1/` 的目录。当前 `competition-standard` 分支上的 `b/` 目录就是唯一的生产版本。所谓"极简五层版本"需要从该版本中**提取子集**，而非切换到另一个已存在的目录。

### 极简五层版本的物理位置

```
C:\Users\ADMIN\red\redteam\b\           ← 唯一的生产根目录
├── cli.py                              ← Phase 2 入口（exploit 子命令）
├── coordinator.py                      ← 核心编排器（五层闭环 + 所有复杂机制）
├── agents/
│   ├── planner.py          (2285行)    ← 第1层
│   ├── validator.py        (1088行)    ← 第2层
│   ├── executor.py         (1387行)    ← 第3层
│   ├── evaluator.py        (1319行)    ← 第4层
│   └── consolidator.py     (1214行)    ← 第5层
├── core/
│   ├── settings.py                     ← 配置数据类
│   ├── llm_client.py                   ← DeepSeekClient
│   ├── memory_store.py                 ← ChromaDB LayeredMemory
│   ├── template_manager.py             ← YAML 武器库 CRUD
│   ├── goal_verifier.py                ← 确定性 flag 扫描器
│   ├── challenge_adapter.py            ← 挑战适配器基类
│   └── target_context.py               ← URL 白名单锁
├── memory/                             ← 内存子系统（competition-standard 新增）
├── control/                            ← 反退化控制（competition-standard 新增）
├── policies/sandbox_policy.yaml        ← 沙箱安全策略
├── templates/builtin/                  ← 17 个 YAML 武器模板
└── workspace/                          ← 运行时 artifact 目录
```

### 入口调用链

```
用户 → cli.py exploit --url URL [--vuln PATH]
     → cmd_exploit()
       → lock_target(url)              # URL 白名单锁
       → run_seed_warmup()             # Consolidator 预热（可选）
       → coordinator.run_pipeline()    # 核心五层闭环
         → for iteration in 1..max_runs:
             Planner → Validator → Executor → GoalVerifier → Evaluator → (loop)
           → Consolidator (循环结束后)
```

---

## B. 五层真实调用链

### 完整生产调用链（从 `coordinator.py:run_pipeline()` 追溯）

```
run_pipeline() @ coordinator.py:992
│
├─[1] run_planner() @ coordinator.py:1080
│   输入: settings, memory(LayeredMemory), confirmed(dict), feedback(dict|None),
│         out_path(Path), llm(DeepSeekClient|None), adapter(ChallengeAdapter|None)
│   输出: plan(dict) → 写入 workspace/plan.json
│   调用: llm.complete_json(system_prompt_with_memory, user_json)
│
├─[2] run_validator() @ coordinator.py:1105
│   输入: plan_path(Path), validated_path(Path), prior_feedback(dict|None),
│         parameter_contract(dict|None)
│   输出: payload(dict) → 写入 workspace/validated_plan.json
│   调用: validate_plan(normalized_plan) — 纯确定性逻辑，无 LLM 调用
│   失败出口: feedback={"from":"validator", ...} → continue (回到 Planner)
│
├─[3] run_executor() @ coordinator.py:1130
│   输入: validated_path(Path), result_path(Path), workdir(Path),
│         timeout_sec, docker_image, dockerfile_dir, target(TargetContext|None)
│   输出: exec_out(dict) → 写入 workspace/execution_result.json
│   调用: DockerSandbox.run_python_script() — 纯确定性执行，无 LLM 调用
│
├─[4a] verify_goal() @ coordinator.py:1168  ← 确定性 flag 扫描（Evaluator 之前）
│   输入: exec_out(dict), plan(dict|None)
│   输出: goal_verification(dict) — verified: bool, artifact: str, ...
│   如果 verified=True → 跳过 Evaluator → 直接 return 0 (IMMEDIATE STOP)
│
├─[4b] run_evaluator() @ coordinator.py:1238  ← 仅在 GoalVerifier 未命中时执行
│   输入: settings, memory, confirmed, plan, exec_out, feedback_path, llm, adapter
│   输出: fb(dict) → 写入 workspace/feedback.json
│   调用: 本地启发式预判定 + llm.complete_json()（如果非 mock）
│
├─[5] 内部循环逻辑 @ coordinator.py:1073-1565
│   - 滑动窗口上下文管理
│   - 多维进度信号检测 (_compute_progress_signals)
│   - 熔断器逻辑 (breaker/circuit breaker)
│   - 攻击面轮换 (_VulnRotator)
│   - 衰减式动态迭代预算
│   - EPE 动量反退化 (exploit_momentum)
│   - HTTP 语义错误自动诊断
│   - 长期记忆失败教训自动记录
│   - 轨迹记录 (_record_trajectory_entry)
│   - Primitive 学习 (_record_primitive_learning)
│   - 验证事实记录 (_record_verified_facts)
│   - feedback 注入 feedback_for_planner → 下一轮 Planner
│
└─[6] run_global_consolidation() @ coordinator.py:1574  ← 循环完全结束后
   输入: workdir(Path), max_iter_reached(bool), is_success(bool)
   输出: result(dict|None)
   调用: _ConsolidatorClient().complete_json() — 使用独立的 CONSOLIDATOR_ LLM
```

---

## C. 每层数据契约

### C.1 Planner

**文件**: `b/agents/planner.py` (2285行)
**入口函数**: `run_planner(settings, memory, confirmed, feedback, out_path, llm, adapter) → plan`

| 维度 | 详情 |
|------|------|
| **权威输入** | `confirmed` dict (来自 Phase 1 审计结果，含 vulnerabilities 列表 + target_context)；`feedback` dict (上一轮 Evaluator/Validator 反馈，首轮为 None)；`memory` (ChromaDB LayeredMemory 三层向量存储) |
| **生成的 artifact** | `workspace/plan.json` — 包含 version, plan_id, vuln_summary, rationale, chain_design, steps[], history_state, primitive_context |
| **状态修改** | 无副作用（纯函数式，仅写入 plan.json） |
| **LLM 调用** | **是** — `llm.complete_json(system_prompt_with_memory, user_json)` — 使用 DeepSeekClient，单次调用 |
| **确定性逻辑** | 六层注意力拓扑组装 (L1-L6 + RETRY)；物理内存预算硬截断 (5000 chars cap)；CWE 模板注入；blueprint 前缀发现；端点提取；target_tags 元数据过滤；`_extract_plan_ast()` AST 元数据提取 |
| **失败出口** | `error="config"` (base_url 为空时)；mock 模式下返回 `_mock_plan()` |
| **关键约束** | 单次 LLM 调用生成一个 plan；不产生多个候选 |

### C.2 Validator

**文件**: `b/agents/validator.py` (1088行)
**入口函数**: `run_validator(plan_path, validated_path, prior_feedback, parameter_contract) → payload`

| 维度 | 详情 |
|------|------|
| **权威输入** | `plan.json` 文件内容；`sandbox_policy.yaml` (每次重新读取，无缓存)；`RUNTIME_MANIFEST` (从 coordinator 动态导入)；`prior_feedback` 中的失败步骤 ID；`parameter_contract` (从 confirmed_vuln 提取的已知参数) |
| **生成的 artifact** | `workspace/validated_plan.json` — 包含 version, validation{pased, errors[], syntax_warnings[]}, warnings[], normalization_applied, plan |
| **状态修改** | 无副作用 |
| **LLM 调用** | **否** — 100% 确定性逻辑 |
| **确定性逻辑** | 9 大类校验：(1) version==1 检查 (2) steps 非空数组 (3) 依赖链断裂检查 `_check_broken_dependency_chain` (4) 轨迹感知验证 `_validate_trajectory_awareness` (状态退化/payload退化/chain连续性/exploit reasoning字段/状态跳级) (5) AST vs Manifest 交叉校验 `_validate_step_ast_against_manifest` (6) Request Contract Gate `_check_request_contract` (参数位置契约) (7) 混合协议违规检测 (sdk_calls+command 共存) (8) Python 语法检查 `_check_python_syntax` (9) 文本扫描规则 `_scan_text` (10) import allowlist/blocklist 检查 `_check_python_imports` (11) shell 工具白名单 `_check_shell_whitelist` |
| **失败出口** | `payload.validation.passed=False` → coordinator 中 `continue` 返回 Planner（携带 errors 和 warnings） |

### C.3 Executor

**文件**: `b/agents/executor.py` (1387行)
**入口函数**: `run_executor(validated_path, result_path, workdir, timeout_sec, docker_image, dockerfile_dir, target) → exec_out`

| 维度 | 详情 |
|------|------|
| **权威输入** | `workspace/validated_plan.json` (仅当 validation.passed=True)；`TargetContext` (URL/IP/Port 白名单)；`Dockerfile` (镜像构建) |
| **生成的 artifact** | `workspace/execution_result.json` — 包含 version, executed, plan_id, workdir, step_results[], chain_context, execution_mode, security_policy, total_steps, blocked_steps |
| **状态修改** | Docker 容器创建/销毁 (每次 step 一个容器)；工作区文件系统 (`co_redteam_exec/` 下的 SDK、context.json、tmp/)；session 持久化 (`/workspace/tmp/session.json`) |
| **LLM 调用** | **否** — 100% 确定性执行引擎 |
| **确定性逻辑** | AST→代码膨胀器 `_inflate_ast_to_script()` (sdk_calls→Python)；代码安全扫描 `_check_python_safety()` (9 种 PYTHON_BLOCKED 正则)；代码包装器 (HTTP 自动日志注入 + STEP_OK/STEP_FAIL + 异常捕获 + session 持久化)；Docker 容器创建 (seccomp + 256MB 内存 + 50% CPU + 30s 超时 + cap_drop=ALL + pids_limit=64)；网络自动检测 (目标容器网络直连 vs bridge+host-gateway 回退)；输出物理硬截断 (8000 chars threshold, head+tail) |
| **失败出口** | `SecurityViolationError` (Docker 不可用/镜像构建失败)；`validation.passed=False` (跳过执行)；`security_blocked` (代码文本包含被拦截模式)；`skipped_syntax_error` (Validator 标记的语法错误步骤) |
| **关键结论** | Executor **不修改** Planner 的计划 — 它只是编译执行。`_inflate_ast_to_script()` 是纯编译，不做语义变更 |

### C.4 Evaluator

**文件**: `b/agents/evaluator.py` (1319行)
**入口函数**: `run_evaluator(settings, memory, confirmed, plan, exec_out, feedback_path, llm, adapter) → fb`

| 维度 | 详情 |
|------|------|
| **权威输入** | `exec_out` (Executor 物理执行结果，**这是唯一权威数据源**)；`plan` (用于 expected_outcome 注入和 sent payload 采集)；`confirmed` |
| **生成的 artifact** | `workspace/feedback.json` — 包含 repro_success, confidence, evidence_level, hard_evidence_found, error_fingerprint, current_exploit_state, milestones_achieved, state_transition_blocker, next_required_action, analysis{what_happened, vs_expectation, guidance}, summary, feedback_for_planner, should_continue, suggest_abort, is_milestone, memory_patch, detected_primitives, primitive_confidence, primitive_evidence, progress_score, exploit_momentum, state_transition_probability, suggested_next_action |
| **状态修改** | `memory.apply_evaluator_patch()` — 写入 ChromaDB 三层向量存储 |
| **LLM 调用** | **是** (mock 模式下跳过) — `llm.complete_json(system_prompt, user_msg)` |
| **确定性逻辑** | 本地预判定（在 LLM 之前执行，结果注入 prompt）：flag 正则检测 `_detect_flag()`、成功信号检测 `_detect_success_signal()`、Blind RCE 检测 `_detect_blind_rce()`、Primitive 启发式检测 `_detect_primitives()`、EPE 进度评分 `_compute_progress_score()` (4 层语义评分)、本地状态判定 `_local_evidence_state()` (6 状态机状态)；零信任覆写（在 LLM 之后执行）：flag 强制成功覆写、Blind RCE 强制降级、无 stdout 强制失败、无 S 级铁证强制降级、unknown_error 自动修正 |
| **失败出口** | Mock 模式下 `_mock_evaluate()` 完全本地评估；LLM 返回结果始终经过 3 层确定性覆写 |

### C.5 Consolidator

**文件**: `b/agents/consolidator.py` (1214行)
**入口函数**: `run_global_consolidation(workdir, max_iter_reached, is_success) → result`
**预热入口**: `run_seed_warmup(confirmed_path) → dict[cwe_id, template_code]`

| 维度 | 详情 |
|------|------|
| **权威输入** | `workdir` 中的 plan.json、execution_result.json、feedback.json (循环结束后的最终状态)；`data/confirmed_vuln.json` |
| **生成的 artifact** | patterns → `b/memory/pattern.json`；techs → `b/memory/tech.json`；YAML → `b/templates/builtin/*.yaml`；ChromaDB 同步写入 |
| **状态修改** | **持久化写入** — JSON 文件追加 + YAML 文件创建/更新 + ChromaDB 写入 |
| **LLM 调用** | **是** — 使用独立的 `CONSOLIDATOR_API_KEY/BASE_URL/MODEL` 配置（不同于 Planner/Evaluator 的 DeepSeek）；支持重试 3 次 + 指数退避 |
| **确定性逻辑** | 战报收集 `_collect_reports()`、上下文脱水 `_dehydrate_context()` (切除冗余日志)、YAML 去重写入、pattern 去重 (error_type 相同则跳过)、ChromaDB 同步 |
| **调用时机** | **仅在战术循环完全结束后** — 位于 `coordinator.py:1571-1579`，在所有迭代 break/return 之后 |
| **风险点** | 读取 `workdir/plan.json` 等文件 — 这些是上一轮（最后一轮）的 artifact。如果循环提前退出（GoalVerifier 命中），Consolidator 读取的是退出前那轮的 artifact，**不会读取到"未来的 run"的 artifact**，但会读取到**当前 run 最后一轮的 artifact**。这是正确的设计 |

---

## D. 当前闭环是否可运行

### 判定：闭环可运行，但存在过度耦合

**闭环路径已验证完整：**

```
Planner → plan.json
  → Validator → validated_plan.json
    → (if not passed: feedback.from="validator" → continue → Planner)
    → Executor → execution_result.json
      → GoalVerifier → (if verified: return 0, STOP)
      → Evaluator → feedback.json
        → feedback 注入 feedback_for_planner + last_execution_raw
        → continue → Planner (下一轮)
```

**多轮证据：**
- `coordinator.py:1073`: `while iteration < _iter_budget` — 显式多轮循环
- `coordinator.py:1278`: `_iter_history` 滑动窗口 — 跨轮上下文维持
- `coordinator.py:1070`: `_prev_round_state` — 跨轮状态对比
- `coordinator.py:1085`: `feedback=feedback` — 上一轮 fb 传给下一轮 Planner
- `planner.py:1952`: `run_planner(..., feedback=feedback, ...)` — Planner 接收 feedback
- `planner.py:2193`: `if feedback: fb_block = _build_feedback_block(feedback)` — feedback 注入 prompt

**闭环终止条件 (8 种)：**
1. GoalVerifier 捕获 flag → return 0
2. Evaluator `repro_success=True` 且 `confidence >= 0.65` → break
3. Evaluator `suggest_abort=True` 且 `iteration >= 4` → break
4. `should_continue=False` 且 `iteration >= 4` → break
5. 连续 `_NO_PROGRESS_ABORT=4` 轮无进展 → break
6. `iteration >= _iter_budget` (衰减式动态预算) → 结束
7. `iteration >= _MAX_HARD_LIMIT` (20) → 结束
8. 用户 CLI 层 `max_runs` 耗尽 (默认 5 次 outer runs) → 结束

---

## E. YAML 多路径选择的最小插入位置

### 当前状态：单路径，无 route_id 概念

当前 Planner **每次只生成一个 plan**（`llm.complete_json()` 单次调用 → 单个 plan dict）。
不存在"从多个候选动作中选择"的机制。YAML 模板仅作为**参考文本注入 prompt**，不作为可选 route。

### 最小插入位置（3 个精确点）

#### E.1 插入点 1：在 Planner 之前 — 加载并过滤 YAML routes

**位置**: `coordinator.py:1077-1088`（Planner 调用之前）
**现状**: 直接调用 `run_planner(...)`，不传递 routes
**最小改动**:
```python
# 在 run_planner 调用之前插入
eligible_routes = _load_and_filter_routes(confirmed, memory)
# eligible_routes: list[dict] — 每个 dict 包含 route_id, requires, steps_template, ...
# 注入到 Planner 的输入中（作为 confirmed 的附加字段或独立参数）
```

**需要的 YAML schema 扩展**（不修改现有模板）:
```yaml
# 新增文件: b/routes/ssti_probe.yaml (示例)
route_id: "ssti_probe_v1"
requires:
  cwe_ids: ["CWE-94", "CWE-1336"]
  min_exploit_state: "init"
  max_exploit_state: "gadget_triggered"
  confirmed_signals: []          # 空 = 无前置条件
steps:
  - description: "SSTI probe with {{7*7}}"
    sdk_calls:
      - primitive: "HttpClient.post"
        target: "/"
        body: {"text": "{{7*7}}"}
        body_format: "form"
expected_outcome: "ssti_reflection"
on_success:
  confirmed_signals: ["ssti_reflection"]
  next_route_hint: "ssti_rce_v1"
on_failure:
  confirmed_signals: []
  next_route_hint: "sql_injection_probe_v1"
```

#### E.2 插入点 2：在 Planner prompt 中 — route_id 选择指令

**位置**: `planner.py` 的 `_extract_user_goal_dense()` 函数（或 `run_planner()` 的 system prompt 组装）
**现状**: 不传递 route 选择指令
**最小改动**:
```
在 L6 User Goal 块末尾添加:
"""
【可用攻击路线 (YAML Routes)】
以下是从攻击模板库中筛选出的与当前目标匹配的攻击路线。
你必须在 plan 的 route_id 字段中声明你选择的路线。
如果当前路线失败，下一轮必须选择另一条路线。

{eligible_routes_text}

【路线选择规则】
- 每条路线包含 requires 条件（CWE/exploit_state/confirmed_signals）
- 只有满足 requires 的路线才出现在此列表中
- 如果本轮未取得进展，下一轮必须切换到不同的 route_id
- 如果 reached success signals，该路线标记为 completed，不再重复尝试
"""
```

#### E.3 插入点 3：在 Evaluator 反馈中 — route outcome 更新

**位置**: `coordinator.py:1248-1251`（Evaluator 调用之后，feedback 组装时）
**现状**: 不追踪 route 级别的 outcome
**最小改动**:
```python
# 在 feedback 组装后添加
route_outcome = _evaluate_route_outcome(fb, exec_out, plan.get("route_id"))
fb["route_outcome"] = route_outcome
# route_outcome: {
#   "route_id": "ssti_probe_v1",
#   "confirmed_signals": ["ssti_reflection"],  # 本轮确认的信号
#   "outcome": "partial_success" | "failed" | "completed",
#   "no_progress": True/False
# }
```

### 完整数据流（最小扩充后）

```
[新] 加载 YAML routes → 按 requires 过滤
  → eligible_routes 注入 Planner prompt
  → Planner 选择 route_id，生成 plan
  → Validator 校验 plan 与 requires 条件
  → Executor 执行
  → Evaluator 更新 confirmed_signals + route outcome
  → 下一轮：无推进 → Planner 选择另一条 route
  → 达到成功信号 → 停止
```

---

## F. 应保留的现有代码

以下代码是极简五层版本的核心，**必须保留**：

| 文件 | 函数/组件 | 保留理由 |
|------|----------|---------|
| `coordinator.py` | `run_pipeline()` 循环骨架 (L1073-1565) | 五层调度核心 |
| `coordinator.py` | `RUNTIME_MANIFEST` (L29-57) | 能力注册清单，Validator/Planner 对齐基准 |
| `planner.py` | `_extract_user_goal_dense()` | 高密度目标摘要提取 |
| `planner.py` | `_build_hard_constraints_block()` | 静态 L2 绝对禁令（不可截断） |
| `planner.py` | `_build_runtime_manifest_block()` | L1 Manifest |
| `planner.py` | `_build_sdk_contract_block()` | L3 SDK 契约 |
| `planner.py` | `_build_feedback_block()` | 上轮反馈注入 |
| `planner.py` | `_enforce_section_budget()` | 六层注意力预算控制（已验证收敛） |
| `validator.py` | `validate_plan()` | 9 类确定性校验 |
| `validator.py` | `_check_request_contract()` | Request Contract Gate |
| `validator.py` | `_validate_trajectory_awareness()` | 状态退化/payload退化检测 |
| `validator.py` | `_extract_parameter_contract()` | 从 confirmed_vuln 提取参数契约 |
| `executor.py` | `_inflate_ast_to_script()` | AST→代码膨胀器 |
| `executor.py` | `_check_python_safety()` | 9 种 PYTHON_BLOCKED 正则 |
| `executor.py` | `DockerSandbox.run_python_script()` | Docker 沙箱执行 |
| `executor.py` | 代码包装器 (L1098-1128) | HTTP 日志注入 + STEP_OK/STEP_FAIL |
| `evaluator.py` | `_sanitize_exec_output()` | 脏数据清洗 |
| `evaluator.py` | `_detect_flag()` / `_detect_success_signal()` | 本地 flag 检测 |
| `evaluator.py` | `_local_evidence_state()` | 本地状态机判定 |
| `evaluator.py` | `_adjudicate_feedback_state()` | LLM 声称 vs 本地证据裁决 |
| `evaluator.py` | 零信任覆写逻辑 (L1271-1297) | 防 LLM 幻觉 |
| `evaluator.py` | `_compute_progress_score()` | EPE 语义进度评分 |
| `core/goal_verifier.py` | `verify_goal()` | **关键** — 确定性 flag 扫描 + 防回声 + Evaluator 之前执行 |
| `core/settings.py` | `get_settings()` | 环境变量配置 |
| `core/llm_client.py` | `DeepSeekClient` | LLM 客户端 |
| `core/template_manager.py` | `TemplateManager.get_templates_for_target()` | YAML 模板匹配（需扩展为 route 加载） |
| `core/target_context.py` | `lock_target()` | URL 白名单锁 |
| `policies/sandbox_policy.yaml` | 完整策略文件 | Validator/Executor 共用安全规则 |

---

## G. 应避免移植的复杂版机制

以下机制属于 `competition-standard` 分支的复杂功能，**不应移植到极简版**：

| 机制 | 位置 | 不移植理由 |
|------|------|-----------|
| `memory/exploit_trajectory.py` + JSON 持久化 | `coordinator.py:_record_trajectory_entry()` → 5 层调用链 | 轨迹记录是辅助分析功能，非核心闭环所需 |
| `memory/verification_memory.py` + write-through | `coordinator.py:_record_verified_facts()` → 多源事实采集 | 验证事实跨轮持久化引入非确定性状态 |
| `memory/exploit_primitives.py` — 20+ 原语定义 | `planner.py:_build_primitive_context()` → prompt 膨胀 | 极简版只需 CWE 模板，不需完整 primitive taxonomy |
| `memory/primitive_learning.py` — 启发式原语学习 | `coordinator.py:_record_primitive_learning()` | 学习引擎是优化层 |
| `memory/primitive_transition_graph.py` — 30+ 有向边 | `planner.py` L6 中注入 | 全局 capability graph 明确禁止 |
| `control/anti_regression.py` — AntiRegressionController + PayloadEvolutionEngine | `validator.py` 导入 + `planner.py` 导入 | 反退化控制是防御层，极简版靠 Evaluator 的自然选择即可 |
| `consolidator.py:run_seed_warmup()` | `cli.py:cmd_exploit()` → Planner 循环前 | 预热是优化，极简版从冷启动开始即可 |
| 衰减式动态迭代预算 (`_iter_budget`, `_milestone_count`, `extension`) | `coordinator.py:1059-1061, 1320-1331` | 极简版用固定迭代次数 |
| 多维进度信号检测 (`_compute_progress_signals` 12 维) | `coordinator.py:507-631` | 极简版只需 binary repro_success |
| 滑动窗口上下文折叠 (`_iter_history`, `_CONTEXT_WINDOW`) | `coordinator.py:1064-1067, 1278-1293` | 极简版每轮独立，只传上一轮 feedback |
| EPE 动量锁定 (exploit_momentum) | `coordinator.py:1454-1475` | 强制路径锁定阻碍 route 切换 |
| 熔断器硬中断 + CWE 专项记忆检索 | `coordinator.py:1395-1450` | 复杂 FSM 状态转换 |
| HTTP 语义错误自动诊断 (9 种模式) | `coordinator.py:202-232, 1211-1222, 1491-1502` | 极简版依赖 LLM 自身分析 HTTP 响应 |
| 攻击面轮换器 (`_VulnRotator`) | `coordinator.py:454-504, 1373-1393` | 漏洞级别轮换，与 route 级别轮换语义重叠 |
| ChromaDB LayeredMemory (三层向量存储) | `core/memory_store.py` | 极简版不需要长期记忆，每轮独立 |
| JWT/JSON Polyglot 构造错误识别 | `coordinator.py:1224-1236` | 特定 CVE 优化 |

---

## H. 分阶段实现计划

### Phase 0: 提取极简骨架（不改代码，仅裁剪引用）

**目标**: 得到一个可运行的、只包含五层闭环的最小 `run_pipeline_minimal()` 函数。

**改动范围**:
- 在 `coordinator.py` 中新增 `run_pipeline_minimal()` 函数，复制 `run_pipeline()` 骨架
- 移除上述 G 节列出的所有机制引用
- 保留: Planner → Validator → Executor → GoalVerifier → Evaluator → feedback → 下一轮 Planner
- 固定迭代次数 (如 5 次)
- 移除: ChromaDB 调用、轨迹记录、反退化、熔断器、攻击面轮换、动态预算、EPE 动量

### Phase 1: YAML Route Schema 定义

**目标**: 定义 route YAML 的 schema，创建 2-3 条示例 route。

**新增文件**:
- `b/routes/schema.py` — Route dataclass + 验证函数
- `b/routes/builtin/ssti_probe.yaml` — SSTI 探测 route
- `b/routes/builtin/ssti_rce.yaml` — SSTI RCE route
- `b/routes/builtin/sqli_probe.yaml` — SQL 注入探测 route

**Route YAML schema**:
```yaml
route_id: str
description: str
requires:
  cwe_ids: [str]        # 需要的 CWE 类型
  min_state: str         # 最低 exploit state
  confirmed_signals: [str]  # 需要的前置信号
steps:
  - description: str
    sdk_calls: [...]
    expected_outcome: str
on_success:
  confirmed_signals: [str]
on_failure:
  fallback_route: str | null
```

### Phase 2: Route 加载 + 过滤

**目标**: 从 `b/routes/` 目录加载所有 YAML，按 `requires` 过滤。

**新增函数**:
- `load_all_routes(routes_dir: Path) → list[Route]`
- `filter_eligible_routes(routes, confirmed, current_state, confirmed_signals) → list[Route]`

**插入位置**: `run_pipeline_minimal()` 中 Planner 调用之前。

### Phase 3: Planner route_id 选择

**目标**: Planner 从 eligible_routes 中选择一条 route_id，融入 plan。

**改动**:
- `planner.py` 中 `_extract_user_goal_dense()` 追加 eligible_routes 文本
- Plan JSON schema 新增 `route_id` 字段（可选，向后兼容）
- Planner system prompt 追加 route 选择指令

### Phase 4: Evaluator route outcome

**目标**: Evaluator 更新 confirmed_signals + route outcome。

**改动**:
- `evaluator.py` 中 `run_evaluator()` 返回的 feedback 新增 `route_outcome` 字段
- 添加 `_evaluate_route_outcome()` 确定性函数（不依赖 LLM）

### Phase 5: 无推进时 route 切换

**目标**: 连续 N 轮无推进时，强制 Planner 选择另一条 route。

**改动**:
- `run_pipeline_minimal()` 中追踪 `current_route_id` 和 `route_attempts`
- 无推进检测：基于 `route_outcome.no_progress`
- 下一轮 Planner 调用前，将排除列表注入 prompt

### Phase 6: 成功信号达到后停止

**目标**: confirmed_signals 匹配 route.on_success.confirmed_signals 时，标记 route 完成，尝试下一个漏洞或停止。

**改动**:
- `run_pipeline_minimal()` 中维护 `completed_routes: set[str]`
- 每次 Evaluator 后检查 `route_outcome.confirmed_signals >= route.on_success.confirmed_signals`

---

## I. 必须新增的离线 golden-path 测试

所有测试必须不触网、不启动 Docker、不使用真实 LLM。

### I.1 Route 加载测试

```python
# test_routes.py

def test_load_all_routes_from_yaml_dir():
    """从 b/routes/ 目录加载所有 YAML → list[Route]"""

def test_route_yaml_schema_validation():
    """缺少 route_id / steps 的 YAML → raise ValidationError"""

def test_filter_routes_by_cwe():
    """confirmed with CWE-94 → only CWE-94 routes returned"""

def test_filter_routes_by_exploit_state():
    """current_state=probe_success → 过滤掉 requires min_state=gadget_triggered 的 route"""

def test_filter_routes_by_confirmed_signals():
    """已有 ssti_reflection → 过滤掉 requires confirmed_signals=[ssti_reflection] 的 route"""

def test_filter_empty_when_no_match():
    """confirmed with CWE-79, no matching routes → []"""
```

### I.2 Route 选择测试

```python
def test_planner_prompt_contains_eligible_routes():
    """eligible_routes 文本出现在 Planner system prompt 中"""

def test_plan_json_has_route_id_field():
    """Plan JSON 包含 route_id 字段"""

def test_planner_selects_different_route_when_previous_failed():
    """feedback 表明上一轮 route 失败 → Planner 选择不同 route_id"""
```

### I.3 Route outcome 测试

```python
def test_route_outcome_partial_success():
    """Evaluator 检测到 ssti_reflection → route_outcome.outcome=partial_success,
       confirmed_signals=[ssti_reflection]"""

def test_route_outcome_failed():
    """所有步骤失败 → route_outcome.outcome=failed, confirmed_signals=[]"""

def test_route_outcome_completed():
    """所有 on_success.confirmed_signals 满足 → route_outcome.outcome=completed"""

def test_route_outcome_no_progress_flag():
    """连续 2 轮同一 route 无新信号 → route_outcome.no_progress=True"""
```

### I.4 闭环集成测试

```python
def test_full_loop_two_routes_second_succeeds():
    """Mock Planner/Executor/Evaluator:
       Round 1: route=ssti_probe → Evaluator: no progress
       Round 2: route=sqli_probe → Evaluator: flag found
       → pipeline returns 0, 2 rounds consumed"""

def test_loop_stops_when_all_routes_exhausted():
    """3 routes, all attempted, all failed → pipeline returns 3"""

def test_loop_stops_when_success_signals_reached():
    """route.on_success.confirmed_signals all detected → route marked complete,
       pipeline checks if any remaining routes, none → returns 0"""

def test_goal_verifier_early_exit_with_route_tracking():
    """GoalVerifier finds flag → returns 0, route tracking records success"""

def test_validator_does_not_block_route_id_field():
    """Plan with route_id field → Validator passes (不拒绝新字段)"""
```

### I.5 回归测试

```python
def test_existing_plan_without_route_id_still_valid():
    """向后兼容：route_id 为可选字段"""

def test_existing_validator_tests_still_pass():
    """b/test_run_isolation_evidence_guard.py 全部 59 项仍通过"""

def test_existing_evaluator_zero_trust_still_works():
    """零信任覆写逻辑不因 route_outcome 新增而改变行为"""
```

---

## J. 推荐修改文件和函数（本轮不得修改）

### 核心修改清单

| 优先级 | 文件 | 函数/位置 | 改动类型 | 描述 |
|--------|------|----------|---------|------|
| **P0** | `coordinator.py` | 新增 `run_pipeline_minimal()` | 新增函数 | 极简五层闭环骨架，移除所有 G 节列出的复杂机制 |
| **P0** | `b/routes/` 目录 | 新建 | 新增目录 | YAML route 定义存放位置 |
| **P0** | `b/routes/schema.py` | 新建 | 新增文件 | Route dataclass + `load_all_routes()` + `filter_eligible_routes()` |
| **P0** | `planner.py` | `_extract_user_goal_dense()` (L982-1091) | 修改 | 在 L6 末尾追加 eligible_routes 文本块 |
| **P0** | `planner.py` | `run_planner()` 签名 (L1952-1960) | 修改 | 新增 `eligible_routes: list[Route] | None` 参数 |
| **P0** | `evaluator.py** | `run_evaluator()` / 新增 `_evaluate_route_outcome()` | 新增函数 | 从 exec_out + plan.route_id 计算 route outcome |
| **P1** | `validator.py` | `validate_plan()` (L867-1058) | 修改 | 新增 route_id 字段存在性检查（warning，不阻断） |
| **P1** | `coordinator.py` | `run_pipeline_minimal()` 内部 | 修改 | 追踪 `current_route_id`、`route_attempts`、`completed_routes`，无推进时切换 route |
| **P1** | `core/template_manager.py` | 新增 `load_routes_for_target()` | 新增方法 | 扩展 TemplateManager 支持 route 加载（或新建 RouteManager） |
| **P2** | `b/routes/builtin/` | 新建 3 个 YAML | 新增文件 | ssti_probe.yaml, ssti_rce.yaml, sqli_probe.yaml |
| **P2** | `b/tests/test_routes.py` | 新建 | 新增文件 | I 节列出的所有离线测试 |
| **P3** | `core/goal_verifier.py` | `verify_goal()` | 修改 | 新增 `route_id` 字段到返回结果 |
| **P3** | `cli.py` | `cmd_exploit()` (L103-163) | 修改 | 新增 `--routes-dir` 参数 |

### 不修改清单（本轮严格禁止）

| 文件 | 理由 |
|------|------|
| `memory/exploit_trajectory.py` | 复杂机制，不移植 |
| `memory/verification_memory.py` | 长期记忆，极简版不需要 |
| `memory/exploit_primitives.py` | primitive taxonomy，极简版不需要 |
| `memory/primitive_learning.py` | 学习引擎，极简版不需要 |
| `memory/primitive_transition_graph.py` | 全局 capability graph，明确禁止 |
| `control/anti_regression.py` | 反退化控制，极简版靠 Evaluator 自然选择 |
| `agents/consolidator.py` | 全局复盘，极简版暂不需要 |
| `core/memory_store.py` | ChromaDB，极简版不需要长期记忆 |
| `policies/sandbox_policy.yaml` | 安全策略，保持不变 |
| `b/Dockerfile` | 沙箱镜像，保持不变 |
| `b/data/confirmed_vuln.json` | 输入数据格式，保持不变 |
| `b/templates/builtin/*.yaml` | 现有武器模板，作为参考文本保留 |

---

## 附录：关键发现汇总

### 关于问题 4: 多轮闭环
**答案**: 是。当前系统已支持 `Evaluator feedback → 下一轮 Planner`。feedback 通过 `feedback_for_planner`、`last_execution_raw`、`current_exploit_state`、`state_transition_blocker` 等字段传递给下一轮 Planner。

### 关于问题 5: Planner 多候选选择
**答案**: 否。当前 Planner 每次只生成**一个** plan。不存在"从多个候选动作中选择"的机制。YAML 模板仅作为参考文本注入 prompt，不提供结构化的可选 route。

### 关于问题 6: Validator 不必要的语义拦截
**答案**: **存在**。`_validate_trajectory_awareness()` 中的 exploit_reasoning 字段检查 (`why_this_step_advances_state` 等 5 个强制字段) 在极简场景下过于严格。当 Planner 不需要理解 primitive 概念时，这些字段的缺失会导致 warnings 或 errors。此外，`_check_request_contract()` 中的 `parameter_contract_unverifiable` 错误会对旧版字符串形式 sdk_calls 产生阻断性拒绝 — 这在极简版中可能过于严格。

### 关于问题 7: Executor 是否修改计划
**答案**: **否**。Executor 是纯确定性编译执行引擎。`_inflate_ast_to_script()` 将声明式 AST 编译为可执行 Python 代码，不做语义变更。代码包装器（HTTP 日志注入 + STEP_OK/STEP_FAIL + 异常捕获 + session 持久化）是增量的、不影响原计划语义的包装。

### 关于问题 8: Evaluator 是否以物理执行结果为权威
**答案**: **是**。Evaluator 设计遵循"零信任"原则：
1. 本地预判定（正则 flag 检测、成功信号检测、Blind RCE 检测）在 LLM 之前执行
2. LLM 结果经过 3 层确定性覆写（flag 强制成功、Blind RCE 强制降级、无 S 级铁证强制降级）
3. `_adjudicate_feedback_state()` 确保 LLM 声称的状态不超过本地证据支持的最高状态
4. `raw_evidence` 字段必须引用 `[HTTP]` 日志、STEP_OK/STEP_FAIL 标记等物理证据

### 关于问题 9: Consolidator 调用时机与旧 artifact
**答案**: Consolidator **仅在战术循环完全结束后**运行（`coordinator.py:1571-1579`）。它读取 `workdir/` 下的 plan.json、execution_result.json、feedback.json — 这些都是最后一轮的 artifact。**风险**: 如果多次 outer run（`cli.py:147` 的 `max_runs` 循环），Consolidator 在每次 `run_pipeline()` 结束时独立运行，读取的是那一次 `run_pipeline()` 最后一轮的 artifact，不会跨 outer run 累积。这是正确的行为。

### 关于 YAML 模板当前结构
当前 17 个 YAML 模板是**纯文档/参考文本**，结构为 `metadata + content + payload_templates[]`。它们**不是** route — 没有 `requires`、`steps`、`on_success`/`on_failure` 等路由语义字段。极简版的 YAML route 需要新增独立的 schema。

---

**审计完成。所有发现基于静态代码分析 + 59 项离线测试验证。无代码修改、无 Docker 运行、无 HTTP 请求。**
