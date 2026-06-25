# Co-RedTeam 深度工程审计报告

> 生成日期：2026-06-10 | 审计范围：完整代码仓库 (HEAD: 0bb7cb4) | 审计人：首席架构师

---

## 1. 核心数据流与模块拓扑

### 1.1 主循环调用链（Coordinator → 五智能体管线）

```
CLI (b/cli.py:exploit)
  └─ lock_target() → TargetContext (b/core/target_context.py:49)
  └─ coordinator.run_pipeline() (b/coordinator.py:1051)
       │
       ├─ [1] Planner (b/agents/planner.py:2257)
       │   Input:  confirmed_vuln (dict), feedback (dict|None), LayeredMemory, DeepSeekClient
       │   Output: plan.json → {"version":1, "plan_id":str, "steps":[...], "vuln_summary":str, ...}
       │
       ├─ [2] Validator (b/agents/validator.py:1052)
       │   Input:  plan.json (Path), prior_feedback (dict|None)
       │   Output: validated_plan.json → {"validation":{passed,errors}, "plan":{...}, "warnings":[...]}
       │
       ├─ [2.5] RuntimeTruths method override (b/memory/runtime_truths.py:73)
       │   Input:  steps list, RuntimeTruths singleton
       │   Output: 修改后的 steps (注入 _runtime_override)
       │
       ├─ [3] Executor (b/agents/executor.py:1190)
       │   Input:  validated_plan.json (Path), TargetContext, DockerSandbox
       │   Output: execution_result.json → {"version":1, "executed":bool, "step_results":[...], "chain_context":{...}}
       │
       ├─ [3.5] ResponseDistiller (b/control/response_distiller.py:596)
       │   Input:  step_results list, chain_output dict
       │   Output: {"capabilities":{...}, "failure_fingerprints":[...], "failure_semantics":[...],
       │            "primitive_telemetry":{...}, "execution_topology":{...}, "meaningful_output":str}
       │
       ├─ [3.6] RuntimeTruths HTML form extraction (b/control/response_distiller.py:471)
       │   Side-effect: 写入 RuntimeTruths (form_method, form_param, confirmed_render_method)
       │
       ├─ [3.7] ExploitFSM update (b/control/exploit_state_machine.py:135)
       │   Input:  distilled dict → 更新 ExploitCapabilityState
       │   Side-effect: 产生 fsm_constraints 注入 feedback
       │
       ├─ [4] Evaluator (b/agents/evaluator.py:1114)
       │   Input:  confirmed_vuln, plan, cleaned exec_out, ExploitFSM state (via feedback)
       │   Output: feedback.json → {"repro_success":bool, "confidence":float, "feedback_for_planner":str, ...}
       │
       └─ [Post-loop] Consolidator (b/agents/consolidator.py:884)
           Input:  workspace/ (plan.json, execution_result.json, feedback.json, confirmed_vuln.json)
           Output: 写入 pattern.json / strategy.json / tech.json + YAML 武器库增量
```

### 1.2 各模块输入/输出数据结构

| 模块 | 输入类型 | 输出类型 | 关键字段 |
|------|---------|---------|---------|
| **Planner** | `confirmed: dict`, `feedback: dict\|None` | `plan: dict` | `steps: list[dict]`, 每个 step 含 `id, type, mode, command/code` |
| **Validator** | `plan.json (Path)` | `validated_plan.json` | `validation.passed: bool`, `validation.errors: list[str]`, `plan.steps` |
| **Executor** | `validated_plan.json (Path)`, `TargetContext` | `execution_result.json` | `step_results: [{step_id, result: {ok, stdout, stderr, exit_code}, chain_output}]` |
| **ResponseDistiller** | `step_results: list[dict]`, `chain_output: dict\|None` | `distilled: dict` | `capabilities: {10个bool}`, `failure_fingerprints: list[str]`, `execution_topology: {10个bool}` |
| **Evaluator** | `confirmed, plan, exec_out` | `feedback: dict` | `repro_success, confidence, error_fingerprint, current_exploit_state, milestones_achieved, state_transition_blocker, next_required_action` |
| **Consolidator** | workspace 目录下全部 JSON | 写入 3 个 memory JSON + YAML 模板 | `memory_patch.patterns/strategies/techs`, `yaml_operations` |

### 1.3 断点与死路径 [CRITICAL]

#### [BROKEN] 模块导入失败
- **`b/coordinator.py:23`**: `from memory.primitive_learning import get_learning_engine, PrimitiveObservation` — **目标文件不存在于磁盘**。`b/memory/primeval_learning.py` 不存在，`b/memory/primitive_learning.py` 也不存在。此 import 在每次 `run_pipeline()` 启动时都会触发 `ImportError`，但由于 coordinator 的 import 在函数体内（非顶层），异常在 `_record_primitive_learning()` 被调用时才会暴露。
- **`b/coordinator.py:24`**: `from memory.primitive_transition_graph import get_transition_graph` — 同样，**文件不存在**。`b/memory/primeval_transition_graph.py` 和 `b/memory/primitive_transition_graph.py` 均不存在。

实际调用点 `_record_primitive_learning()` (coordinator.py 约第 1423 行) 和 `_record_verified_facts()` 使用了 try/except 包裹，因此不会导致主循环崩溃，但功能完全静默失效。

#### [BROKEN] LIGHTWEIGHT_MODE 永久激活
- **`b/coordinator.py:1137`**: `LIGHTWEIGHT_MODE = True` — 这是硬编码常量，无环境变量或配置开关。
- 导致以下功能被完全禁用（代码存在于磁盘但永不执行）：
  - `_distilled_history` 注入 Planner L4 (coordinator.py:1476)
  - EPE Momentum Anti-Regression (coordinator.py:1669-1691)
  - Multi-dimensional progress detection `_compute_progress_signals()` (coordinator.py:1530-1534)

#### [BROKEN] 长期记忆写入全局禁用
- **`b/core/memory_store.py:21`**: `DISABLE_LONG_TERM_WRITE = True` — 硬编码为 True，无配置开关。
- 所有 `upsert_pattern()`, `upsert_strategy()`, `upsert_tech()` 调用均被 `_quarantine_check()` 拒绝。
- **`b/memory/verification_memory.py:99-101`**: `VerificationMemory._save()` 也检查此标志，同样被阻断。
- 即使某条写入满足 `confidence >= 0.95 AND source == "observed"`，`DISABLE_LONG_TERM_WRITE` 在 quarantine 检查的第一行就返回 False。

**后果**: 整个记忆系统的长期写入路径完全切断。Consolidator 在循环结束后仍会写入 JSON 文件（不受 quarantine 限制），但运行中的 ChromaDB 增量写入全部静默丢弃。

---

## 2. Prompt 工程现状审计

### 2.1 System Prompt 层级结构

Planner 的 system prompt 在 `b/agents/planner.py:2304-2401` 组装，共 6+1 层：

| 层 | 名称 | 来源 | 硬上限 (chars) | 实际典型大小 |
|----|------|------|---------------|------------|
| L0 | HIGH_PRIORITY_LESSONS | `_build_high_priority_lessons()` (planner.py:165) | 无单独上限 | ~300-600 |
| L1 | Runtime Manifest | `RUNTIME_MANIFEST` (coordinator.py:33) + `_build_runtime_manifest_block()` (planner.py:265) | 800 | ~500 |
| L2 | Hard Constraints & Bans | `_build_hard_constraints_block()` (planner.py) + `_build_forbidden_techniques_block()` (planner.py:2067) | 600 | ~400-700 |
| L2.5 | Exploit FSM State | `_fsm_constraints` from feedback → `get_hard_constraints_for_prompt()` (exploit_state_machine.py:322) | 600 | ~400-600 |
| L3 | SDK API Contract | `_build_sdk_contract_block()` (planner.py) | 500 | ~400 |
| L4 | Verified Facts & Memory | RuntimeTruths + VerificationMemory + RAG context + distilled trace | 800 | ~500-800 |
| L5 | Trajectory State | `_build_trajectory_context()` (planner.py:2140) | 300 | ~150-250 |
| L6 | Structured Observation | `_build_l6_structured_observation()` (planner.py:2588) | 800 | ~200-400 |

**最终双保险截断**: `_FINAL_PAYLOAD_HARD_CAP = 5000` chars (planner.py:42)

**总 Token 估算** (假设 1 token ≈ 3 chars 中文, ≈ 4 chars 英文): 约 1200-1700 tokens system prompt + user payload。

### 2.2 硬编码 Prompt 模板清单

| 位置 | 内容 | 类型 |
|------|------|------|
| `b/agents/planner.py:573` | `_COMMON_RULES` — redteam_sdk 合法用法 + API 幻觉防火墙 | System Prompt 片段 |
| `b/agents/planner.py:139-162` | `_VELOCITY_KNOWN_LESSONS` — Velocity 模板引擎已知教训 | L0 注入 |
| `b/agents/planner.py:165-263` | `_build_high_priority_lessons()` — 失败指纹→教训映射 | L0 注入 |
| `b/agents/planner.py:814-949` | `_build_cwe_templates_generic()` — 10 个 CWE 类型的硬编码攻击模板 | User Prompt 片段 |
| `b/agents/planner.py:2395-2400` | `_output_schema_directive` — JSON 输出格式指令 | System Prompt 尾缀 |
| `b/agents/evaluator.py:186-432` | `EVAL_SYSTEM` — 评估智能体完整 System Prompt (~250行) | System Prompt |
| `b/agents/consolidator.py:33-106` | `CONSOLIDATOR_SYSTEM_PROMPT` — 复盘导师 System Prompt | System Prompt |
| `b/agents/consolidator.py:1011-1030` | `_WARMUP_USER_TEMPLATE` — Seed warmup 模板 | User Prompt |
| `b/agents/executor.py:27-459` | `_SDK_SOURCE` — 注入 Docker 的完整 SDK 源码 (433行) | 代码生成 |
| `b/agents/validator.py:279-305` | `FORBIDDEN_ARTIFACTS` — 框架噪声黑名单 | 校验规则 |

### 2.3 core_logic 和 runtime_truths 注入评估

**core_logic** (`_extract_user_goal_dense()`, planner.py:1294):
- 在 L6 注入路径中，`core_logic` 被传递给 `_build_l6_structured_observation()` (planner.py:2381) 作为 fallback，但 L6 的主体内容来自 feedback 中的 `detected_primitives` / `milestones_achieved` / `state_transition_blocker`。
- **问题**: `core_logic` 仅在 `feedback is None` 的初始轮次才会作为主要内容出现在 L6。后续轮次中，L6 完全由结构化观察字段驱动，`core_logic` 仅作为 fallback 使用。

**runtime_truths**:
- 通过 `feedback["target_facts"]` 注入 (coordinator.py:1280)，在 Planner L4 中以最高优先级展示 (planner.py:2342-2344)。
- `to_method_override_message()` 注入 `feedback_for_planner` (coordinator.py:1284-1290)。
- **确认**: runtime_truths（form_method, form_param, confirmed_render_method）确实注入到了 L4，且优先级最高 (`l4_parts.insert(0, ...)`)。
- **缺失**: runtime_truths 的内容未注入到 Evaluator 的 system prompt。Evaluator 只收到 `confirmed_vuln` + `plan` + `execution_result`，不知道 RuntimeTruths 已确认了哪些事实。

---

## 3. 记忆系统（Memory）真实状态

### 3.1 ChromaDB 初始化参数

**`b/core/memory_store.py:242-252`**:
```python
class LayeredMemory:
    def __init__(self, memory_dir: Path) -> None:
        self._client = chromadb.PersistentClient(path=str(db_path))
```
- 使用 ChromaDB `PersistentClient`，持久化路径 `co_redteam_memory/`
- 3 个 Collection: `vulnerability_patterns`, `exploit_strategies`, `exploit_techniques`
- **未指定 embedding function** — 使用 ChromaDB 默认的 `all-MiniLM-L6-v2` (ONNX)
- **未指定 distance metric** — 使用默认的 `l2` (Euclidean distance)
- **无 HNSW 参数调优** (M, ef_construction, ef_search 均为默认值)

### 3.2 写入逻辑

**初始化加载** (`_load_initial_memory()`, memory_store.py:267-314):
- 从 `b/memory/pattern.json`, `strategy.json`, `tech.json` 加载初始数据
- 每次 `_ensure_collections()` 都会重新加载，意味着如果磁盘 JSON 已经存在，每次服务重启都会重复 add（可能产生重复条目）
- `_make_unique_id()` 使用 MD5(content) 前缀 + 碰撞计数器，防止同内容重复

**运行时写入** (upsert 系列方法):
- `upsert_pattern()` (line 556), `upsert_strategy()` (line 570), `upsert_tech()` (line 585)
- 全部被 `_quarantine_check()` 阻断（`DISABLE_LONG_TERM_WRITE = True`）
- `apply_evaluator_patch()` (line 666) 同样调用 upsert 方法，同样被阻断

**JSON 文件直接写入**:
- Consolidator 直接写入 `pattern.json`, `strategy.json`, `tech.json` (consolidator.py:415-522)
- PayloadRegistry 写入 `payload_registry.json` (core/payload_registry.py:101-107)
- 这些不经过 ChromaDB upsert，不受 quarantine 限制

### 3.3 检索逻辑

**基础查询** (memory_store.py:502-554):
- `query_patterns()`, `query_strategies()`, `query_tech()` — 语义向量搜索
- 返回 `documents`, `metadatas`, `distances` — **但 distance 未被用于 score 过滤**
- `n_results` 固定为 5（patterns/strategies）或 10（tech）

**标签过滤查询** (memory_store.py:706-871):
- `query_tech_payloads_filtered()` → 使用 `$or` boolean metadata filter
- 当 filter 无结果时，回退到无过滤查询（`_fallback_printed` 防止重复日志）
- 从 metadata 中提取 `_payload_text`, `_full_command`, `_script_content`

**Planner 端 RAG** (`_build_memory_context()`, planner.py:1736-2020):
- 调用 `memory.query_tech_payloads_filtered()` 按 CWE + 标签检索
- 构建 `memory_context` 字符串注入 L4

### 3.4 "SSTI 偏置"和"重复率 85%"的代码级根因

**根因 1 — 初始种子数据偏向**:
`b/memory/tech.json` 中的 `payload_templates` 在项目初始化时被填充。如果种子数据以 SSTI 载荷为主，则 ChromaDB 向量空间会向 SSTI 相关 embedding 偏移。`_load_existing_tech_entries()` (payload_registry.py:109-118) 扫描所有已有条目但不做类别均衡。

**根因 2 — 无 score/confidence 过滤**:
query 方法不根据 score 或 confidence 阈值过滤结果。`distance` 在返回值中可用但从未被用于排除低质量匹配。CWE-keyed 精准检索 (`query_tech_payloads_filtered`) 依赖 boolean metadata filter 而非 semantic relevance。

**根因 3 — 重复写入未被 ChromaDB 层面阻止**:
虽然 `_make_unique_id()` 在加载阶段去重，但运行时 upsert 被 `DISABLE_LONG_TERM_WRITE` 阻断。如果未来启用写入，upsert 使用 MD5 hash 做 key，同一内容不会重复。但 `apply_evaluator_patch()` 的 content 构造逻辑 (`p.get("content") or json.dumps(p, ensure_ascii=False)`) 可能导致语义相同但字节不同的 content 生成不同 ID。

**根因 4 — 无去重查询后处理**:
查询结果直接返回，不经过应用层的语义去重或 diversity reranking。

---

## 4. 关键亮点与设计意图

### 4.1 失败归因结构

**实现完成度: ✅ 已完成**

- `response_distiller.py` 的 `_extract_failure_semantics()` + `_build_failure_semantics_from_topology()` 提供了 4 级失败语义分类: `silent_strip`, `reflected_not_executed`, `invocation_blocked`, `method_invoked_no_output`
- `execution_topology` 细粒度到 10 个布尔语义层 (parsed, rendered, arithmetic_eval, method_invocation, reflection_resolution 等)
- `primitive_telemetry` 跟踪每个 primitive 的 4 种状态 (untried, failed_silent, failed_error, success)
- `failure_fingerprints` 跨轮持久化 (coordinator.py:1486-1488)

### 4.2 Runtime Truth Layer

**实现完成度: ⚠️ 部分实现**

- `b/memory/runtime_truths.py` 已完整实现 singleton + CRUD + persist
- 确定性 HTML form 提取 (`_extract_html_form_facts()`, response_distiller.py:471-593) 使用纯正则，不依赖 LLM
- POST 确认使用 probe-correlated 验证（算术探测 + 49 结果 + POST HTTP 日志三方校验）
- **缺失**: RuntimeTruths 未注入 Evaluator context。Evaluator 不知道 POST 已被确认。

### 4.3 Exploit State Machine (FSM)

**实现完成度: ✅ 已完成**

- `b/control/exploit_state_machine.py`: 10 级能力门控 (payload_delivery → reflection → template_eval → breakout → object_access → method_call → classloader → exec → file_read → flag_exfil)
- N-of-M 滑动窗口稳定性 (需 2/3 次确认)
- 4 个 exploitation surface 置信度衰减 + 阻塞
- 环境失败 vs exploit 失败分离
- FSM 硬约束每轮注入 Planner L2.5

### 4.4 Agentic RL 雏形

**实现完成度: ⚠️ 部分实现**

- `b/core/payload_registry.py`: Payload 指纹 + score 系统 (success_count * 2 - failure_count + decay)
- `b/control/anti_regression.py`: PayloadEvolutionEngine 基于成功/失败历史的渐进变异
- `b/memory/exploit_trajectory.py`: 每轮轨迹记录 + `get_dehydrated_state()` 压缩
- **缺失**: 无 A/B 测试或 bandit 选择机制。无真正的 RL 策略梯度或 reward 传播。Score 更新仅影响 tech.json，不影响 Planner 的 prompt 构造逻辑。

### 4.5 Semantic Sliding Window

**实现完成度: ⚠️ 部分实现（被禁用）**

- `_distilled_history` 和 `_DISTILL_WINDOW = 5` 已实现 (coordinator.py:1134)
- `format_distilled_for_prompt()` (response_distiller.py:828) 将蒸馏结果压缩为 ~400 char 文本
- **被 LIGHTWEIGHT_MODE = True 禁用** (coordinator.py:1476)

### 4.6 认知论守卫（Inference vs Fact）

**实现完成度: ✅ 已完成**

- Evaluator 的 `_sanitize_verified_facts()` (evaluator.py:45-84) 检测推断性语言并降级
- VerificationMemory 的 `add_working_primitive()` (verification_memory.py:174-216) 包含推断检测
- EVAL_SYSTEM 包含完整的 verified_facts vs hypothesis 分离规则 (evaluator.py:248-278)

---

## 5. 已知技术债与当前卡点

### 5.1 未解决的 Bug (基于代码分析)

| 严重度 | 位置 | 描述 |
|--------|------|------|
| **P0** | `b/core/memory_store.py:21` | `DISABLE_LONG_TERM_WRITE = True` 硬编码阻断所有 ChromaDB 写入。Consolidator 学到的经验无法在下一轮 Planner 检索中使用。 |
| **P0** | `b/coordinator.py:23-24` | `primitive_learning` 和 `primitive_transition_graph` 模块导入目标不存在。相关功能静默失效。 |
| **P1** | `b/coordinator.py:1137` | `LIGHTWEIGHT_MODE = True` 禁用蒸馏历史、EPE 动量、多维进展。coordinators 的最大设计投入被关闭。 |
| **P1** | `b/agents/planner.py:42` | `_FINAL_PAYLOAD_HARD_CAP = 5000` chars — 在中文 prompt 场景下约 1200-1700 tokens，剩余 ~2300 tokens 留给 LLM 输出。对于复杂攻击链，5000 chars 可能截断关键约束。 |
| **P2** | `b/core/memory_store.py:267` | `_load_initial_memory()` 每次 `_ensure_collections()` 调用都会重新加载，无幂等性保证。重复初始化可能导致 duplicate IDs。 |
| **P2** | `b/agents/planner.py:2390-2392` | L0-L6 拼接使用 `"\n\n".join(p for p in [...] if p)` — 当某层为空字符串 `""` 时仍会拼接，产生多余空行但不影响功能。 |
| **P3** | `b/agents/consolidator.py:283-413` | `_ConsolidatorClient` 使用独立的 `CONSOLIDATOR_` 环境变量配置，不与主 LLM 配置共享，容易配置遗漏。 |
| **P3** | `b/core/settings.py:47` | `memory_dir` 指向 `ROOT`（即 `b/` 目录），但 `LayeredMemory.__init__` 又将其父目录作为 ChromaDB 路径，两层 parent 计算导致路径依赖调用上下文。 |

### 5.2 Planner 生成 steps=[] 的根因分析

**路径 1 — JSON 解析失败** (`b/core/llm_client.py:19-37`):
- `_extract_json_object()` 的 fallback 正则 `r"(\{[\s\S]*\}|\[[\s\S]*\])"` 是贪婪匹配。如果 LLM 输出多个 JSON 块，可能匹配到不包含 `steps` 的对象。
- 3 次重试后若仍失败，抛出 `SchemaValidationError` 并终止。

**路径 2 — Prompt 截断** (`b/agents/planner.py:2404-2406`):
- `_FINAL_PAYLOAD_HARD_CAP = 5000` 可能截断 `_output_schema_directive`（位于 system prompt 最开头）或 L6 Observation（位于最末尾），导致 LLM 不知道需要输出 `steps` 数组。

**路径 3 — Normalize 逻辑** (`b/agents/planner.py:45-100`):
- `normalize_plan()` 在 step 的 code 和 command 均为空时，填充 `"# EMPTY_STEP: no exploit code was provided for this step"`。这是占位符，Executor 执行时会产生 STEP_OK 但无实际行为。
- normalize 强制将所有 `mode` 设为 `"LEGACY"` 并删除 `sdk_calls` 和 `imports` 字段，可能丢失有效 AST 模式步骤。

**路径 4 — 自动解包后的清理** (`b/agents/planner.py:2532-2560`):
- 4 种嵌套格式的解包逻辑正确，但解包后清理 `plan` 和 `attack_plan` key 的条件 `if _k in plan and _k != "steps"` 可能在边角情况下误删有效的 `plan` 字段。

**路径 5 — Empty Steps Retry** (`b/agents/planner.py:2490-2575`):
- `MAX_STEPS_RETRIES = 2` 提供了有限的自动重试。温度随尝试递增 (0.2 + attempt * 0.1)。
- 最终 guard (line 2574) 在 2 次重试后仍为空时抛出 `SchemaValidationError`，导致整个 pipeline 迭代失败。

### 5.3 临时方案/Hack 代码清单

| 位置 | 描述 |
|------|------|
| `b/coordinator.py:1137` | `LIGHTWEIGHT_MODE = True` — 注释标记为 "Lightweight: only basic success/fail check"，实为永久禁用高级功能 |
| `b/core/memory_store.py:21` | `DISABLE_LONG_TERM_WRITE = True` — 注释标记为 "P0: Memory Quarantine"，旨在防幻觉污染但也阻断所有有效写入 |
| `b/agents/planner.py:79` | `"# EMPTY_STEP: no exploit code was provided for this step"` — 占位符解决空 step 导致的崩溃，但不解决为何生成空 step 的根因 |
| `b/agents/planner.py:2532-2560` | 4 种自动解包模式 — 模型输出格式不稳定导致的防御性代码 |
| `b/agents/validator.py:64-69` | `_strip_python_prefix()` — 处理 LLM 在 command 字段前加 `python` 前缀的常见错误 |
| `b/agents/executor.py:539-610` | `_hard_truncate()` + Python blocked patterns — 正则扫描代码文本并手动拦截危险模式 |
| `b/agents/evaluator.py:1194-1196` | `if fb is None: fb = _mock_evaluate(...)` — LLM complete_json 返回 None 时的降级方案 |

---

## 6. 测试与可观测性现状

### 6.1 自动化回归测试

**[MISSING] 无自动化测试框架**

- `b/test_infer.py` — 0 字节，空文件
- `b/vuln_test_simulated.py` — 3 字节，空文件（仅含换行）
- `b/Co-RedTeam/pwn_feasibility_test.py` — 实际包含测试代码，但仅测试漏洞利用可行性，非回归测试
- 无 `pytest`, `unittest`, `tox`, `nox` 配置
- 无 CI/CD 配置文件 (`.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile` 均不存在)
- 唯一可执行的自测代码在 `if __name__ == "__main__"` 块中:
  - `b/control/response_distiller.py:886-929` — 包含 silent_strip 和 template_eval 场景测试
  - `b/control/exploit_state_machine.py:499-554` — FSM progression 模拟测试

### 6.2 日志系统

**结构化程度: 半结构化**

- 使用 `rich.console` (b/core/ui.py) 输出带颜色主题的终端日志
- 日志级别: `stage()` (阶段), `ok()` (成功), `fail()` (失败), `warn()` (警告), `muted()` (次要), `detail()` (详细)
- `detail()` 仅在 `CO_REDTEAM_VERBOSE=true` 时输出 (b/core/ui.py:33)
- **无结构化日志格式** (无 JSON 日志、无时间戳、无 trace ID、无 span ID)
- **无文件日志输出** — 所有日志仅输出到 stdout/stderr
- `b/agents/executor.py:22-25` 设置了 `SECURITY_AUDIT` logger，但未配置 handler

### 6.3 WebSocket 实时推送

**[MISSING]**

- 项目中无任何 WebSocket 相关代码
- `requirements.txt` 中未包含 websocket 库（虽然 `.venv` 中有安装）
- `rich.console` 输出无法直接桥接到 WebSocket

### 6.4 诊断工具

| 工具 | 位置 | 功能 |
|------|------|------|
| RAW Response 打印 | `b/core/llm_client.py:81-86` | 每次 LLM 调用打印原始响应（前 3000 chars） |
| Planner 诊断 | `b/agents/planner.py:2496-2522` | 打印 system_prompt/user_payload 长度、steps 类型、plan 样本 |
| Distiller 日志 | `b/coordinator.py:1250-1270` | 打印 capabilities, fingerprints, failure_semantics, execution_topology |
| FSM 状态日志 | `b/coordinator.py:1338-1344` | 打印 level, next_target, blocked, surface_confidence |
| 内存预算日志 | `b/agents/planner.py:2408-2411` | 打印每层实际字符数 |
| 记忆检查 | `check_memory.py`, `peek_memory.py`, `manage_memory.py`, `clean_memory.py` | CLI 工具用于检查和维护 ChromaDB |
| 基准评估 | `benchmark_evaluator.py` | 独立脚本，用于评估 pipeline 在基准数据集上的表现 |

### 6.5 总体可观测性评估

- **优势**: Planner/Evaluator/Executor 的关键路径有充足的诊断输出；RAW response 打印对于调试 LLM 行为至关重要
- **劣势**: 无分布式 tracing；无持久化日志文件；无指标采集 (Prometheus/StatsD)；LIGHTWEIGHT_MODE 禁用后大部分 coordinator 日志不会触发

---

## 附录 A: 模块依赖关系图

```
b/agents/planner.py
  ├── core/llm_client.py (DeepSeekClient)
  ├── core/memory_store.py (LayeredMemory)
  ├── core/settings.py (Settings)
  ├── core/template_manager.py (TemplateManager)
  ├── core/challenge_adapter.py (ChallengeAdapter)
  ├── memory/exploit_trajectory.py (ExploitTrajectoryMemory)
  ├── memory/verification_memory.py (VerificationMemory)
  ├── memory/exploit_primitives.py (get_primitive_registry)
  ├── memory/primitive_learning.py [MISSING - ImportError]
  ├── memory/primitive_transition_graph.py [MISSING - ImportError]
  └── control/anti_regression.py (PayloadEvolutionEngine, AntiRegressionController)

b/agents/validator.py
  ├── control/anti_regression.py (AntiRegressionController)
  ├── memory/verification_memory.py (VerificationMemory)
  ├── memory/exploit_trajectory.py (ExploitTrajectoryMemory)
  └── memory/runtime_truths.py (get_runtime_truths)

b/agents/executor.py
  ├── core/target_context.py (TargetContext)
  └── built-in SDK source (_SDK_SOURCE, 433 lines)

b/agents/evaluator.py
  ├── core/llm_client.py (DeepSeekClient)
  ├── core/memory_store.py (LayeredMemory)
  ├── core/settings.py (Settings)
  └── memory/exploit_primitives.py

b/agents/consolidator.py
  ├── core/llm_client.py (_ConsolidatorClient - 独立 LLM)
  └── core/payload_registry.py (PayloadRegistry, dedup)

b/coordinator.py
  ├── agents/planner.py (run_planner)
  ├── agents/validator.py (run_validator)
  ├── agents/executor.py (run_executor)
  ├── agents/evaluator.py (run_evaluator)
  ├── agents/consolidator.py (run_global_consolidation)
  ├── control/exploit_state_machine.py (ExploitCapabilityState)
  ├── control/response_distiller.py (distill_response)
  ├── memory/exploit_trajectory.py (get_trajectory)
  ├── memory/verification_memory.py (get_verification)
  ├── memory/primitive_learning.py [MISSING]
  ├── memory/primitive_transition_graph.py [MISSING]
  └── memory/runtime_truths.py (get_runtime_truths)
```

## 附录 B: P0-P6 修复优先级建议

| 优先级 | 问题 | 建议修复 |
|--------|------|---------|
| **P0** | `DISABLE_LONG_TERM_WRITE = True` | 改为环境变量控制 `CO_REDTEAM_MEMORY_WRITE_ENABLED`，默认 false，验证后开启 |
| **P0** | `primitive_learning`/`primitive_transition_graph` 模块缺失 | 创建 stub 文件或从 import 中移除 |
| **P1** | `LIGHTWEIGHT_MODE = True` | 改为环境变量 `CO_REDTEAM_LIGHTWEIGHT=false` 默认启用完整功能 |
| **P1** | Evaluator 不感知 RuntimeTruths | 在 Evaluator user prompt 中注入 target_facts |
| **P2** | `_load_initial_memory()` 无幂等性 | 在加载前检查 collection count，非空时跳过 |
| **P2** | 无自动化测试 | 为 distiller、FSM、normalize_plan 添加 pytest 测试 |
| **P3** | Consolidator LLM 配置独立 | 统一到 Settings dataclass |
| **P3** | 日志无持久化 | 添加 Python logging file handler 配置 |
| **P4** | Query 结果无 score 过滤 | 在 query 方法中添加 min_distance/max_distance 参数 |
| **P5** | Payload diversity 无保证 | 在 RAG 检索后添加 diversity reranking |
| **P6** | WebSocket 实时推送 | 添加 rich.live 或 websockets 库支持 |

---

*审计完成。所有结论基于代码静态分析，未进行运行时验证。*
