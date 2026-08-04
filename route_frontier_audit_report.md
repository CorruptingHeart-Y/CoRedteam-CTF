# Route Frontier v1 — 运行时事实源审计与最小设计报告

**日期:** 2026-07-25  
**分支:** competition-standard  
**基线:** 261 tests passed  
**范围:** 只读审计，不修改生产代码

---

## 1. Git and Current Baseline

```text
branch: competition-standard
261 passed in 1.92s (confirmed via pytest --collect-only)
```

工作树状态:
- `b/routes/`, `b/test_routes.py`: untracked (Route Factory v1.0–v1.3)
- `target_codebase/cybench_web_challenges/2/`: 23 files deleted (untouched, per constraints)
- `.codex_pytest_registry_*`: 5 ACL-denied temp dirs (environment residue, not touched)
- No commits, no push, no Docker, no HTTP, no LLM.

---

## 2. Current Upgrade Progress

已完成:

| 阶段 | 组件 | 状态 |
|------|------|------|
| v1.0 | `RouteProposal` → `Normalizer` → candidate YAML | ✅ 96 tests |
| v1.2 | Route Admission (offline deterministic gate) | ✅ 212 tests cumulative |
| v1.3 | Route Registry (load, dedup, conflict, snapshot, static query) | ✅ 261 tests cumulative |
| v1.4 | Route Frontier (eligibility from dynamic preconditions) | **本轮设计** |

---

## 3. Current-State Source

### 3.1 权威状态定义

**文件:** `b/memory/exploit_trajectory.py:11`

```python
VALID_STATES = ("init", "probe_success", "payload_injected", "gadget_triggered", "oob_received")
```

另有一个非标准状态 `"objective_verified"`（`b/coordinator.py:1176`），仅在 goal_verifier 确认 flag 后设置，不在 `VALID_STATES` 元组中。

### 3.2 当前状态存储位置

| 位置 | 文件:行号 | 角色 |
|------|-----------|------|
| **Trajectory singleton** | `b/memory/exploit_trajectory.py:107-122` | **权威来源** — `get_current_state()` 逆向遍历 nodes，取最高成功状态 |
| Trajectory node 字段 | `b/memory/exploit_trajectory.py:21` | 每轮快照的 `current_state` |
| Evaluator feedback | `b/agents/evaluator.py:654` | `fb["current_exploit_state"]` — Evaluator 裁定后写入 |
| Coordinator 局部变量 | `b/coordinator.py:524,655,727,896` | 从 feedback 读取 `current_exploit_state` |
| Planner 上下文 | `b/agents/planner.py:1769` | `traj.get_current_state()` 注入 Planner prompt |

### 3.3 Evaluator 如何产生新状态

**文件:** `b/agents/evaluator.py:583-665`

- `_local_evidence_state()` (line 583): 从 stdout、detected_primitives、http_responses 判定本地证据等级
- `_adjudicate_feedback_state()` (line 634): 将 LLM requested state 与 local evidence state 比较，取较低者，防止 LLM 虚报
- 写入 `fb["current_exploit_state"]` = 裁定后状态

### 3.4 Coordinator 如何读取和传递

**文件:** `b/coordinator.py`

- `line 524`: `cur_state = fb.get("current_exploit_state", "init")` — 状态推进检测
- `line 655`: `"exploit_state": fb.get("current_exploit_state", "init")` — 写入 prior_state
- `line 727`: `current_state = fb.get("current_exploit_state", "init")` — trajectory 记录
- `line 896`: `state = fb.get("current_exploit_state", "init")` — 事实记录

### 3.5 Trajectory Memory 中的 current_state

**文件:** `b/memory/exploit_trajectory.py`

- `ExploitTrajectoryNode.current_state` (line 21): 每轮节点记录
- `get_current_state()` (line 107-122): 遍历所有 nodes，找最高成功状态，优先看 `state_transition` 中的目标状态，再看 `current_state` 字段
- 持久化到 `b/memory/exploit_trajectory.json`

### 3.6 是否存在多处 current_state

**存在。** 但这是设计如此而非重复：
- `ExploitTrajectoryNode.current_state` = 该轮快照
- `ExploitTrajectoryMemory.get_current_state()` = 跨轮聚合（权威）
- `fb["current_exploit_state"]` = Evaluator 当轮裁定（临时，同一轮内流转）

### 3.7 结论

```text
Authoritative current-state source:
  get_trajectory().get_current_state()
  → b/memory/exploit_trajectory.py:107-122

Frontier input representation:
  FrontierContext.current_state: str
  — 从 get_trajectory().get_current_state() 读取，传入 Frontier
  — Frontier 不持有 trajectory 引用，不推进状态

备用方案（当 trajectory 不可用时）:
  fb["current_exploit_state"] 从 Evaluator feedback
  — 仅当 trajectory singleton 未初始化时使用
  — 同样只读传入 FrontierContext
```

Frontier **不得**推进或修改状态。

---

## 4. Confirmed-Signal Source

### 4.1 PrimitiveRegistry 中的 observable_signals

**文件:** `b/memory/exploit_primitives.py:14-19`

对于 `ssti_reflection`:
```python
"observable_signals": ["arithmetic_result_in_response", "expression_reflected_verbatim"],
"confirmation": "expression_evaluated",
```

`confirmation` 映射到 `ExploitPrimitive.evidence_requirements` (`exploit_primitives.py:218`):
```python
evidence_requirements=definition.get("confirmation", ""),
```

### 4.2 PrimitiveLearning _HEURISTIC_DETECTORS 输出

**文件:** `b/memory/primitive_learning.py:38-105`

检测到 `ssti_reflection` 时:
- Pattern (line 42-43): `r"\{\{7\*7\}\}.*49|\$\{7\*7\}.*49|<%=7\*7%>.*49|#\{7\*7\}.*49"`
- evidence_note: `"expression_evaluated"`
- 置信度: 0.6 (base) + 0.2 (if success) + 0.1 (if 2xx) = max 0.9

输出写入 `b/memory/learned_primitives.json`

### 4.3 Evaluator 的 primitive detection

**文件:** `b/agents/evaluator.py:386-414`

```python
if re.search(r'\{\{7\*7\}\}.*49|\$\{7\*7\}.*49', all_stdouts, re.DOTALL):
    detected.append("ssti_reflection")
    confidence["ssti_reflection"] = 0.92
    evidence["ssti_reflection"] = "{{7*7}} reflected as 49 — template expression evaluated"
```

输出写入 `fb["detected_primitives"]`, `fb["primitive_confidence"]`, `fb["primitive_evidence"]`

### 4.4 Verification Memory 如何记录已确认事实

**文件:** `b/memory/verification_memory.py`

- `add_working_primitive()` (line 133-155): 记录 `{primitive_id, confidence, evidence, engine}`
- `working_primitives` 字段 (line 20): `[]` 默认
- 去重依据 `primitive_id`
- Coordinator `_record_verified_facts()` (`coordinator.py:888-949`) 每轮写入:
  - `reflection_confirmed: True` + `template_engine: "jinja2"` (line 918-919, 当 stdout 包含 49 和 7*7)
  - `add_working_primitive({primitive_id, confidence, evidence, engine})` (line 928-933)

### 4.5 是否存在统一的 confirmed signal 集合

**不存在。** 项目中有以下分散的 signal/evidence 概念:

| 概念 | 位置 | 类型 | 示例 |
|------|------|------|------|
| `observable_signals` | `exploit_primitives.py:17` | 静态定义（per primitive） | `arithmetic_result_in_response` |
| `confirmation` / `evidence_requirements` | `exploit_primitives.py:19,218` | 静态定义（per primitive） | `expression_evaluated` |
| `_HEURISTIC_DETECTORS` evidence_note | `primitive_learning.py:38-105` | 检测输出 | `"expression_evaluated"` |
| Evaluator `primitive_evidence` | `evaluator.py:402` | Per-round feedback | `"{{7*7}} reflected as 49..."` |
| Trajectory `primitive_evidence` | `exploit_trajectory.py:36` | Per-node record | 同上 |
| Verification `working_primitives` | `verification_memory.py:20,133-155` | 持久化确认 | `{primitive_id, confidence, evidence}` |
| Verification `reflection_confirmed` | `verification_memory.py:17` | Boolean flag | `True` / `False` |
| Coordinator `milestones_achieved` | `coordinator.py:895` | Feedback list | `["init: no trusted local evidence"]` |

### 4.6 同一信号是否存在多个名称

**同一概念使用不同名称:**
- `expression_evaluated` 在 `INJECTION_PRIMITIVES` 中叫 `confirmation` → 在 `ExploitPrimitive` 中叫 `evidence_requirements` (dataclass field name 变化)
- `expression_evaluated` 在 `_HEURISTIC_DETECTORS` 中叫 `evidence_note` (第4个 tuple 元素)
- Primitive detection 证据文本使用自然语言描述而非信号名称: `"{{7*7}} reflected as 49 — template expression evaluated"`
- `observable_signals` 中的 `arithmetic_result_in_response` 和 `expression_reflected_verbatim` 在运行时从不以这些确切名称出现——它们只在 PrimitiveRegistry 定义中使用

### 4.7 三个信号的分析

| 信号 | 归属 | 在 Runtime 中出现形式 |
|------|------|----------------------|
| `expression_evaluated` | `evidence_requirements` (confirmation) | `_HEURISTIC_DETECTORS[0][3]` evidence_note; Evaluator evidence string; Verification `reflection_confirmed: True` |
| `arithmetic_result_in_response` | `observable_signals[0]` | 从不以该名称出现在 runtime；对应 behavior: `{{7*7}} → 49` |
| `expression_reflected_verbatim` | `observable_signals[1]` | 从不以该名称出现在 runtime；对应 behavior: payload 原样反射 |

### 4.8 结论

```text
Frontier 中 confirmed_signals 应从哪里构造:
  从 VerificationMemory 的 working_primitives + reflection_confirmed 字段推断。
  
  具体规则:
  - verification.facts["reflection_confirmed"] == True
    → confirmed_signals 包含 "expression_evaluated"
  - verification.facts["working_primitives"] 中包含 confidence >= 0.5 的
    "ssti_reflection" 条目
    → confirmed_signals 包含 "arithmetic_result_in_response",
      "expression_reflected_verbatim"

允许使用哪些 signal 名称:
  当前 observable_signals 列表中的名称 + evidence_requirements 名称
  = ["arithmetic_result_in_response", "expression_reflected_verbatim",
     "expression_evaluated"]

哪些名称当前不能作为 requires.signals:
  - "command_output_in_response" — 属于 command_separator, 非 ssti_reflection
  - 任何不在当前 target_primitive 的 observable_signals
    或 evidence_requirements 中的名称
```

**重要:** `expression_evaluated` 当前不在 `observable_signals` 中（在 `evidence_requirements` / `confirmation` 中）。如需 Frontier 检查 `requires.signals` 中包含 `expression_evaluated`，必须扩展 Adapter 的 signal 获取接口，或在 Route 的 signal 定义中将 `evidence_requirements` 纳入可检查范围。详见 §8 Schema Gaps。

---

## 5. Runtime-Fact Sources

### 5.1 当前 Route YAML 中的声明

**文件:** `b/routes/admission.py:42`

```python
ROUTE_FACTORY_V1_RUNTIME_FACTS = frozenset(("endpoint", "parameter", "method"))
```

这是一个**局部临时 allowlist**，不是全局 RuntimeTruths 来源。Admission 报告明确记载其为 temporary contract。

### 5.2 真实项目中的运行时数据

| 概念 | Route 名称 | 真实项目存储位置 | 字段名 |
|------|-----------|-----------------|--------|
| 目标 URL | — | `confirmed_vuln.json` → `target_context.base_url` | `base_url` |
| 目标 URL | — | `VerificationMemory.facts["confirmed_base_url"]` | `confirmed_base_url` |
| 可达端点 | `endpoint` | `VerificationMemory.facts["confirmable_endpoints"]` (list of URL strings) | `confirmable_endpoints` |
| 可注入端点 | `endpoint` | `VerificationMemory.facts["injectable_endpoints"]` (list of URL strings) | `injectable_endpoints` |
| 可注入参数 | `parameter` | `VerificationMemory.facts["injectable_params"]` (dict: endpoint→[param_name]) | `injectable_params` |
| HTTP 方法 | `method` | 不存储为确认事实 | — |
| 已接受字段 | — | `VerificationMemory.facts["accepted_fields"]` | `accepted_fields` |
| 模板引擎 | — | `VerificationMemory.facts["template_engine"]` | `template_engine` |
| 认证状态 | — | `VerificationMemory.facts["auth_status"]` | `auth_status` |

### 5.3 详细追踪

#### base_url
- **来源:** `confirmed_vuln.json` 的 `target_context.base_url` → Planner `build_dynamic_prompt()` line 1100
- **环境变量 fallback:** `CO_REDTEAM_TARGET_BASE` (planner.py:1100)
- **VerificationMemory:** `confirmed_base_url` (verification_memory.py:10,199-200)
- **分类:** 目标级已验证事实

#### endpoint / method / http_method
- **来源:** Planner 从 `confirmed_vuln.json` 的 `vulnerabilities[].source` / `data_flow` 字段提取
- **Planner 使用:** `_extract_endpoints_from_vulns()` (planner.py:996) → 注入 Planner prompt
- **VerificationMemory:** `confirmable_endpoints` (可达), `injectable_endpoints` (可注入)
- **Coordinator:** 从 HTTP response URL 提取 `verif.confirm_endpoint(url)` (coordinator.py:913)
- **分类:** endpoint 级已验证事实
- **注意:** HTTP method 不作为独立确认事实存储——它在 attack plan 的每个 step 中由 LLM 指定

#### parameter / injectable_param
- **来源:** VerificationMemory `injectable_params` dict (verification_memory.py:12,101-105,114-118,180-181)
- **格式:** `{endpoint_url: [param_name, ...]}`
- **Coordinator 写入:** `verif.confirm_injectable(endpoint, params)` (verification_memory.py:111-118)
- **分类:** endpoint 级已验证事实

#### template_engine
- **来源:** VerificationMemory `template_engine: "jinja2"` (verification_memory.py:16,919)
- **Coordinator 写入:** 当 stdout 包含 "49" 和 "7*7" 时 (coordinator.py:917-919)
- **分类:** 目标级已验证事实

### 5.4 回答

**1. 哪些是已验证事实:**
- `confirmed_base_url`, `confirmable_endpoints`, `injectable_endpoints`, `injectable_params`, `template_engine`, `reflection_confirmed`, `accepted_fields` — 全部由 VerificationMemory 持久化，Coordinator 在每轮基于物理证据写入

**2. 哪些只是 Planner 推测:**
- `base_url` 从 `target_context` 提取（由 challenge adapter 或 confirmed_vuln.json 预先配置）
- Planner 从 `data_flow` description 文本中提取 endpoint — 这是代码审计结论，不是运行时确认
- HTTP method — Planner 根据漏洞类型推测，不是运行时验证

**3. 哪些是目标级事实:**
- `confirmed_base_url`, `template_engine`, `reflection_confirmed`, `auth_status`, `waf_detected`, `target_app`, `target_framework`

**4. 哪些是 endpoint 级事实:**
- `confirmable_endpoints`, `injectable_endpoints`, `injectable_params`, `accepted_fields`

**5. 哪些可以作为 Frontier v1 的 runtime facts:**
- `base_url` (目标级, 来自 confirmed_vuln.json `target_context` 或 VerificationMemory)
- `endpoint` (endpoint 级, 来自 VerificationMemory `injectable_endpoints`)
- `parameter` (endpoint 级, 来自 VerificationMemory `injectable_params[endpoint]`)
- `template_engine` (目标级, 来自 VerificationMemory)

**6. 当前 `endpoint`、`parameter`、`method` 名称是否和真实代码一致:**

**不一致。** 具体问题:

| Route schema 名称 | 真实项目名称 | 差异 |
|-------------------|-------------|------|
| `endpoint` | `confirmable_endpoints` / `injectable_endpoints` | Route 用单数 `endpoint`，项目用复数列表。Route 需单值 endpoint，项目存储多值列表。 |
| `parameter` | `injectable_params` (dict keyed by endpoint) | Route 用单数 `parameter`，项目用 dict `{endpoint: [params]}`。匹配 endpoint → 取对应 params。 |
| `method` | 不存储 | HTTP method 不作为确认事实存在于 VerificationMemory 或 trajectory 中。Planner 在 plan step 中指定 method，但无运行时持久化。 |

**`method` 字段问题:** `method` 在 Admission allowlist 中但无法从 VerificationMemory 读取——它不是已确认事实。Executor 执行 plan step 时使用 step 中声明的 method (POST/GET)，但 Coordinator 不记录 executed method 到 VerificationMemory。

**7. 是否需要一个只读 RuntimeFactAdapter:**

**需要。** 原因:
- Route schema 使用简化名称 (`endpoint`, `parameter`, `method`)，真实项目使用不同结构 (`injectable_endpoints` list, `injectable_params` dict)
- 必须做名称映射和结构适配
- 必须区分"事实名称存在"和"事实值已确认"
- 必须处理 endpoint → parameter 的层级关系
- 必须是只读单向适配: VerificationMemory → FrontierContext，不反向写入

**8. 是否需要修改现有 Route schema:**

**需要最小修改。** 详见 §8。

---

## 6. Replay and Execution-History Sources

### 6.1 现有系统中与执行历史相关的结构

| 概念 | 位置 | 类型 | 内容 |
|------|------|------|------|
| `tried_payloads` | Planner history_state (LLM-managed) | list of strings | Payload 文本列表 |
| `failed_reasons` | Planner history_state (LLM-managed) | list of strings | 失败原因文本 |
| `consecutive_failures_per_category` | Planner history_state (LLM-managed) | dict | 每类漏洞连续失败计数 |
| `payload_blacklist` | VerificationMemory | list of strings | 被禁 payload 关键词 |
| `failed_payloads` | Trajectory `get_failed_patterns()` | list of strings (last 20) | 失败 payload 文本片段 |
| `successful_payloads` | Trajectory `get_success_paths()` | list of strings (last 10) | 成功 payload 文本片段 |

### 6.2 不存在的能力

- ❌ Route canonical ID 执行历史
- ❌ Execution fingerprint (payload + endpoint + method 的结构化哈希)
- ❌ `tried_route_ids` 或类似列表
- ❌ Replay suppression by route fingerprint
- ❌ AntiRegression payload similarity by route ID
- ❌ Route 级别的失败计数

### 6.3 当前 replay 字段状态

**文件:** `b/routes/schema.py:166-168`

```python
@dataclass(frozen=True)
class ReplayPolicy:
    enabled: bool = False
```

Admission v1 要求 `replay.enabled` 必须为 `False` (`admission.py:652-659`)，且只接受 `{"enabled": bool}` 精确 schema，拒绝任何额外字段 (`admission.py:307-321`)。

### 6.4 判断

**方案 A：本轮暂不实现 replay**

理由:
1. 项目没有 route 级别的结构化执行历史
2. `tried_payloads` 是 LLM-managed free-text，不可靠
3. 没有 execution fingerprint 基础结构
4. `payload_blacklist` 存储关键词字符串，不是 route ID
5. Trajectory 存储 payload 文本（每轮），但没有 route ID 关联
6. 没有 `tried_route_fingerprints` 可以检查

即使实现 "exact route fingerprint replay"，也需要先实现:
- 执行时将 route canonical ID / fingerprint 写入 trajectory
- 持久化已执行的 route fingerprint 集合
这超出了 Frontier v1 的范围。

### 6.5 结论

```text
REPLAY_DEFERRED

Frontier v1 不检查 replay。
FrontierContext.executed_route_fingerprints 默认为空 tuple。
ReplayPolicy 保持 enabled=false，Admission 继续保持拒绝 enabled=true。

延后到 v1.5+:
- 在 Executor 层记录每次执行对应的 route canonical ID / fingerprint
- 在 Trajectory 或 VerificationMemory 新增 executed_route_fingerprints
- Frontier 增加 exact route fingerprint replay gate
```

---

## 7. Current Route `requires` Schema

### 7.1 RouteRequirements 定义

**文件:** `b/routes/schema.py:140-142`

```python
@dataclass(frozen=True)
class RouteRequirements:
    current_state: str
    runtime_facts: tuple[str, ...]
```

### 7.2 Normalizer 如何填充

**文件:** `b/routes/normalizer.py:185-188`

```python
requires=RouteRequirements(
    current_state=current_state,
    runtime_facts=runtime_facts,
),
```

`current_state` = proposal.current_state (规范化后)
`runtime_facts` = proposal.required_runtime_facts (去重去空后)

### 7.3 Admission 如何验证

**文件:** `b/routes/admission.py:624-649`

- `requires.runtime_facts` 非空检查 (`MISSING_RUNTIME_FACTS`)
- `requires.runtime_facts` 每个 fact 必须在 `ROUTE_FACTORY_V1_RUNTIME_FACTS` 中 (`UNKNOWN_RUNTIME_FACT`)
- `requires.current_state` 必须等于 `current_state` (`REQUIRES_STATE_MISMATCH`)

### 7.4 Route 是否支持 `requires.signals`

**不支持。** `RouteRequirements` 没有 `signals` 字段。这是当前 schema 的明确空白。

### 7.5 Route 是否只支持单个 current_state

**是。** `RouteRequirements.current_state` 是单个 `str`，不是 `tuple[str, ...]`。Route 只能声明一个静态 current_state 要求。

### 7.6 Route 是否支持多个合法 state

**不支持。** 一个 Route 只能匹配一个 state。如果需要在多个 state 下都有效，需要多条 Route（不同 canonical ID）。

### 7.7 Route 是否能表达"缺少某 signal 时 blocked"

**当前不能。** 因为 `RouteRequirements` 没有 `signals` 字段。即使添加了 `signals`，也需要定义语义——是 `requires.signals`（执行前必须已确认）还是 `forbidden_signals`（执行前必须不存在）。

### 7.8 Route 是否能表达 endpoint/parameter 级 runtime fact

**部分能，但名称不匹配。** Route 声明 `requires.runtime_facts: ["endpoint", "parameter"]`，但:
- `endpoint` 在真实项目中是 list（`injectable_endpoints`），Route 需要单个值
- `parameter` 在真实项目中是 dict keyed by endpoint，需要 endpoint 上下文才能取值
- Route 无法声明具体需要哪个 endpoint 的哪个 parameter

### 7.9 Admission 是否已经验证这些字段

**部分验证。** Admission 验证:
- `requires.current_state` 等于 `current_state`（静态一致性）
- `requires.runtime_facts` 非空且在 allowlist 中（名称级别）

Admission **不验证**:
- state 值是否合法（由 Normalizer 负责）
- runtime fact 值是否已确认（由 Frontier 负责）

### 7.10 Writer 是否稳定输出

**是。** `render_candidate_route_yaml()` (`writer.py:89-116`) 使用 `yaml.safe_dump` with `sort_keys=False`，按 `to_plain()` 返回的 dict 插入顺序输出。

### 7.11 Registry fingerprint 是否包含这些字段

**是。** `route_fingerprint()` (`registry.py:22-29`) 对 `route.to_plain()` 的完整 JSON 计算 SHA-256，包含所有字段。

---

## 8. Schema Gaps

### 8.1 确认的 Gaps

#### Gap 1: RouteRequirements 缺少 `signals` 字段

**当前:**
```python
@dataclass(frozen=True)
class RouteRequirements:
    current_state: str
    runtime_facts: tuple[str, ...]
```

**需要:**
```python
@dataclass(frozen=True)
class RouteRequirements:
    current_state: str
    runtime_facts: tuple[str, ...]
    signals: tuple[str, ...] = ()  # NEW
```

**影响范围:**
- `b/routes/schema.py`: RouteRequirements 增加 signals 字段
- `b/routes/normalizer.py`: Normalizer 填充 `requires.signals`（当前正常填充空 tuple 或从 proposal 复制）
- `b/routes/admission.py`: `_mapping_with_keys` 的 required fields 需要更新；YAML schema 需要增加 `signals` 字段
- `b/test_routes.py`: 测试需要更新以包含 signals

**理由:** 没有 `requires.signals`，Frontier 无法检查 "required signals ⊆ confirmed signals"。

#### Gap 2: runtime fact 名称与项目不匹配

| Route schema | 真实项目 | 问题 |
|-------------|---------|------|
| `endpoint` | `injectable_endpoints` (list) | 名称不一致；项目存储 list，route 需要单个值 |
| `parameter` | `injectable_params` (dict) | 名称不一致；需要 endpoint 上下文 |
| `method` | 不存在 | 项目不存储 HTTP method 为确认事实 |

**建议:** 需要 RuntimeFactAdapter 做名称映射和结构适配，而不是修改真实项目的字段名。

#### Gap 3: `expression_evaluated` 不在 observable_signals 中

Normalizer 通过 `adapter.get_observable_signals()` 校验 expected_signals，而 `expression_evaluated` 在 `evidence_requirements` 中。当前 Normalizer 和 Admission 都将其拒绝为 expected_signal。

**建议:** Frontier 的 `requires.signals` 检查应同时接受 `observable_signals` 和 `evidence_requirements`。需要：
- `PrimitiveAdapter` 增加 `get_confirmation_signal(primitive_id) -> str` 方法
- 或 Normalizer/Admission 合并两个来源到 signal 校验中

### 8.2 最小 Schema Patch（Frontier 前必须）

```text
SCHEMA_PATCH_REQUIRED_BEFORE_FRONTIER

范围:
1. b/routes/schema.py:
   - RouteRequirements 增加 signals: tuple[str, ...] = ()

2. b/routes/normalizer.py:
   - normalize_route_proposal() 中 requires.signals 初始化为空 tuple
   - （后续可通过 proposal 或 adapter 填充）

3. b/routes/admission.py:
   - _TOP_LEVEL_FIELDS 不变（requires 本身已在其中）
   - _mapping_with_keys(data, "requires", frozenset(("current_state", "runtime_facts", "signals")))
   - YAML load 时接受 signals 为空 list 或 string list
   - 新增 AdmissionErrorCode: UNKNOWN_REQUIRED_SIGNAL (如需验证 signal 名称)

4. b/routes/primitive_adapter.py:
   - 增加 get_confirmation_signal(primitive_id) -> str | None
   - 返回 ExploitPrimitive.evidence_requirements 值

5. b/test_routes.py:
   - 更新 requires 相关测试适应新字段
   - 确保所有 261 tests 仍然通过

不得修改:
  - PrimitiveRegistry
  - INJECTION_PRIMITIVES
  - 任何生产代码
```

### 8.3 expected_signals vs requires.signals

必须严格区分:

```text
expected_signals = 执行此 Route 后，期望观察到什么信号
  → 用于 Validator / Evaluator 判断 exploit 是否成功
  → 来自 ExploitPrimitive.observable_signals
  → 当前 Route schema 已支持（top-level expected_signals + success.expected_signals）

requires.signals = 执行此 Route 前，必须已经确认什么信号
  → 用于 Frontier 判断 Route 是否 eligible
  → 来自 VerificationMemory 的已确认事实
  → 当前 Route schema 不支持（需要 schema patch）
```

两者**不得**混用。`expected_signals` 是"执行后期望"，`requires.signals` 是"执行前必须"。Frontier 只检查 `requires.signals`。

---

## 9. Minimal Frontier v1 Boundary

### 9.1 建议输入结构

```python
@dataclass(frozen=True)
class FrontierContext:
    current_state: str
    confirmed_signals: tuple[str, ...]
    runtime_facts: Mapping[str, object]
    executed_route_fingerprints: tuple[str, ...] = ()
```

**字段依据（基于真实代码审计）:**

| 字段 | 来源 | 读取方式 |
|------|------|---------|
| `current_state` | `get_trajectory().get_current_state()` | Trajectory singleton，只读 |
| `confirmed_signals` | VerificationMemory + PrimitiveRegistry | Adapter 适配（见 §4.8） |
| `runtime_facts` | VerificationMemory facts dict | `get_verification().facts` 子集适配 |
| `executed_route_fingerprints` | (deferred) | 空 tuple |

### 9.2 建议输出结构

```python
@dataclass(frozen=True)
class FrontierDiagnostic:
    code: FrontierDiagnosticCode  # str Enum
    canonical_id: str
    message: str

@dataclass(frozen=True)
class FrontierEntry:
    registered_route: RegisteredRoute
    eligibility: str  # "eligible" | "blocked"
    diagnostics: tuple[FrontierDiagnostic, ...]

@dataclass(frozen=True)
class RouteFrontier:
    eligible: tuple[FrontierEntry, ...]
    blocked: tuple[FrontierEntry, ...]
    context_fingerprint: str
```

### 9.3 Frontier 允许的操作

- ✅ 读取 Registry snapshot (`RouteRegistry.snapshot()`)
- ✅ 检查每个 route 的动态前置条件
- ✅ 生成 eligible / blocked 分类
- ✅ 提供稳定 diagnostics
- ✅ 确定性排序 (by canonical ID)

### 9.4 Frontier 禁止的操作

- ❌ 打分、排名、选择最佳 route
- ❌ 修改 Registry（不增删 route）
- ❌ 修改 Route（不修改任何字段）
- ❌ 修改 Verification Memory
- ❌ 修改 Trajectory Memory
- ❌ 推进状态
- ❌ 执行 fallback
- ❌ 执行 unlock
- ❌ 生成 payload
- ❌ 调用 Planner
- ❌ 调用 LLM
- ❌ 发送 HTTP
- ❌ 新建第二份事实源

---

## 10. FrontierContext Contract

### 10.1 Context Adapter 设计

需要 `context_adapter.py`（只读、单向）:

```text
VerificationMemory + Trajectory + PrimitiveRegistry
  → RuntimeFactAdapter (只读适配)
  → FrontierContext (frozen input)
```

**Adapter 职责:**
1. 从 `get_trajectory().get_current_state()` 读取当前状态
2. 从 `get_verification().facts` 读取运行时事实
3. 从 VerificationMemory `working_primitives` + `reflection_confirmed` 推断 confirmed_signals
4. 做名称映射: `injectable_endpoints` → `endpoint`, `injectable_params` → `parameter`
5. 不写入任何持久化存储

**Adapter 不负责:**
- 状态推进
- 信号检测
- Payload 生成
- 新建事实

### 10.2 runtime_facts 映射表

```python
# RuntimeFactAdapter 内部映射 (只读)
_RUNTIME_FACT_SOURCES = {
    "base_url": lambda verif: verif.facts.get("confirmed_base_url", ""),
    "endpoint": lambda verif: verif.facts.get("injectable_endpoints", []),
    # 返回 list; Frontier 检查时需适配:
    # 如果 route 需要 endpoint，取 injectable_endpoints 中任意非空值
    "parameter": lambda verif: verif.facts.get("injectable_params", {}),
    # 返回 dict; Frontier 检查时需 endpoint 上下文
    "method": lambda verif: None,
    # 项目不存储 method 为确认事实 — 返回 None
    "template_engine": lambda verif: verif.facts.get("template_engine", ""),
}
```

### 10.3 context_fingerprint 算法

```python
def context_fingerprint(context: FrontierContext) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "current_state": context.current_state,
                "confirmed_signals": sorted(context.confirmed_signals),
                "runtime_facts": dict(sorted(context.runtime_facts.items())),
                "executed_route_fingerprints": sorted(context.executed_route_fingerprints),
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
```

---

## 11. Eligibility Rules

### Rule 1: State Requirement

```text
IF route.requires.current_state != context.current_state:
    → STATE_REQUIREMENT_UNSATISFIED → blocked
```

精确字符串比较。不做模糊匹配、不回退、不推测。Frontier 不允许状态回退。

### Rule 2: Signal Requirements

```text
IF route.requires.signals is not empty:
    IF NOT (set(route.requires.signals) ⊆ set(context.confirmed_signals)):
        → MISSING_REQUIRED_SIGNALS → blocked
```

`requires.signals` 为空时跳过此检查（向后兼容尚无 signals 的 route）。

**前提:** 需要 §8.2 的 schema patch（RouteRequirements 增加 signals 字段）。

### Rule 3: Runtime Fact Requirements

必须区分三个层面:

```text
A. Fact 名称存在: fact name in route.requires.runtime_facts
   → 已由 Admission 验证 (UNKNOWN_RUNTIME_FACT)

B. Fact 值已确认: context.runtime_facts[fact_name] is not None/non-empty
   → Frontier 检查

C. Fact 值适用于当前 route: 值类型和上下文匹配
   → Frontier 检查 (endpoint/parameter 层级关系)
```

**第一版可行规则:**

```text
For each fact_name in route.requires.runtime_facts:

  1. 名称检查:
     fact_name 必须在 ROUTE_FACTORY_V1_RUNTIME_FACTS 中
     → 已由 Admission 保证，Frontier 不重复

  2. 值存在检查:
     fact_value = context.runtime_facts.get(fact_name)
     IF fact_value is None or fact_value is empty:
         → RUNTIME_FACT_NOT_CONFIRMED → blocked

  3. 值适配检查:
     - endpoint:
         fact_value 是 list[str]; 非空即满足
         (Frontier v1 不强制匹配具体 endpoint name)
     - parameter:
         fact_value 是 dict[str, list[str]]; 非空 dict 即满足
         (Frontier v1 不强制检查 endpoint-parameter 层级关系)
     - method:
         fact_value 可能为 None (项目不存储); → RUNTIME_FACT_NOT_CONFIRMED
         (实际效果: 声明 requires method 的 route 总是 blocked)
     - base_url:
         fact_value 是 str; 非空即满足
     - template_engine:
         fact_value 是 str; 非空即满足
```

**注意:** `method` 作为 runtime fact 在当前项目中总是返回 NOT_CONFIRMED，因为 HTTP method 不作为确认事实存储。这需要后续在 Coordinator 中记录执行的 method，或从 route schema 中移除 `method` 的 allowlist 条目。

### Rule 4: Replay Requirement

```text
DEFERRED — Frontier v1 不检查
context.executed_route_fingerprints 默认为空 tuple
所有 route 跳过 replay 检查
```

### Rule 5: Candidate Integrity

```text
Frontier 只接收 Registry snapshot 中的 RegisteredRoute
snapshot 中的 route 已通过 Admission
Frontier 验证 snapshot 类型为 RouteRegistrySnapshot
不做二次 Admission
```

### Rule 6: Route 自身完整性

```text
route.activation.state == "draft"
route.activation.source == "route_factory"
route.generation_status == "candidate_only"
→ 已由 Registry 保证（registry.py:111-122）
→ Frontier 不重复验证
```

---

## 12. Blocked vs Rejected

### 12.1 定义

```text
Rejected = Route 本身非法，不能进入 Registry
  → 由 Admission 处理
  → 结果: AdmissionDecision.accepted=False
  → Registry 拒绝注册

Blocked = Route 本身合法（已通过 Admission，已在 Registry 中），
          但当前动态前置条件尚未满足
  → 由 Frontier 处理
  → 结果: FrontierEntry.eligibility="blocked"
  → Route 仍在 Registry 中，条件满足后可以变为 eligible
```

### 12.2 示例

```text
合法 Route:
  canonical_id: cwe-94:probe_success:ssti-reflection:arithmetic-probe
  requires.current_state: probe_success

当前 state = init
  → blocked (STATE_REQUIREMENT_UNSATISFIED)
  → Route 仍在 Registry 中
  → 不是 rejected
```

```text
合法 Route:
  canonical_id: cwe-94:payload_injected:ssti-reflection:reflection-probe
  requires.signals: [expression_evaluated]

当前 state = payload_injected
当前 confirmed_signals = [] (expression_evaluated 尚未确认)
  → blocked (MISSING_REQUIRED_SIGNALS)
  → Route 仍在 Registry 中
```

### 12.3 Frontier 不得把 blocked route 从 Registry 删除

Frontier 只生成 blocked 分类。Blocked routes 依然出现在 snapshot 中。调用者（Planner adapter）自行决定是否对 blocked routes 采取行动（如等待、跳过、报告）。

---

## 13. Determinism Contract

### 13.1 要求

```text
给定:
  - 相同的 Registry snapshot（相同 routes, 相同顺序）
  - 相同的 FrontierContext（相同 current_state, signals, runtime_facts）

Frontier 必须:
  - 产生完全相同的 eligible/blocked 分类
  - diagnostics 顺序稳定
  - Route 顺序按 canonical ID 升序
  - context_fingerprint 相同
  - 不依赖时间、随机数、文件系统顺序或外部状态
```

### 13.2 context_fingerprint 包含的字段

```text
context_fingerprint = SHA-256(
  current_state +
  sorted(confirmed_signals) +
  sorted(runtime_facts items) +
  sorted(executed_route_fingerprints)  # empty for v1
)
```

必须确保:
- `confirmed_signals` 排序后 join
- `runtime_facts` 按键排序
- 空值表示一致（None → null in JSON）

---

## 14. Recommended Files

### 14.1 新增文件

```text
b/routes/frontier.py          # Frontier 主类 + FrontierContext + FrontierEntry + RouteFrontier
b/routes/context_adapter.py   # RuntimeFactAdapter — 只读适配 VerificationMemory → FrontierContext
```

### 14.2 小幅修改文件

```text
b/routes/schema.py            # RouteRequirements 增加 signals 字段
b/routes/normalizer.py        # 填充 requires.signals = ()
b/routes/admission.py         # 接受 requires.signals 字段
b/routes/primitive_adapter.py # 增加 get_confirmation_signal() 方法
b/routes/__init__.py          # 导出 Frontier API
```

### 14.3 新增测试

```text
b/test_routes.py              # 新增 Frontier 测试类
```

### 14.4 文件依赖图

```text
context_adapter.py
  ├── from memory.verification_memory import get_verification
  ├── from memory.exploit_trajectory import get_trajectory
  └── from routes.primitive_adapter import PrimitiveAdapter

frontier.py
  ├── from routes.schema import (FrontierDiagnostic, FrontierEntry, RouteFrontier,
  │                              FrontierContext, RegisteredRoute, RouteRegistrySnapshot)
  └── from routes.context_adapter import RuntimeFactAdapter
```

---

## 15. Files That Must Remain Untouched

```text
b/agents/planner.py
b/agents/validator.py
b/agents/executor.py
b/agents/evaluator.py
b/agents/consolidator.py
b/coordinator.py
b/control/anti_regression.py
b/core/template_manager.py
b/core/challenge_adapter.py
b/memory/exploit_primitives.py
b/memory/exploit_trajectory.py
b/memory/verification_memory.py
b/memory/primitive_learning.py
b/memory/primitive_transition_graph.py
b/data/confirmed_vuln.json
b/templates/builtin/*.yaml
b/templates/generated/*.yaml
b/policies/sandbox_policy.yaml
```

---

## 16. Test Plan

### 16.1 Core Eligibility Tests

```text
test_frontier_includes_route_when_all_requirements_satisfied
test_frontier_blocks_route_on_state_mismatch
test_frontier_blocks_route_on_missing_signal
test_frontier_blocks_route_on_missing_runtime_fact
test_frontier_does_not_reject_valid_but_blocked_route
test_frontier_does_not_remove_blocked_route_from_registry
```

### 16.2 Registry/Context Integrity Tests

```text
test_frontier_uses_registry_snapshot_only
test_frontier_does_not_accept_unadmitted_route
test_frontier_does_not_mutate_registry
test_frontier_does_not_mutate_context
```

### 16.3 Determinism Tests

```text
test_frontier_output_is_deterministic
test_frontier_order_is_canonical_id_sorted
test_context_fingerprint_is_deterministic
test_context_fingerprint_changes_when_context_changes
```

### 16.4 Signal/Runtime Fact Correctness Tests

```text
test_expected_signals_are_not_used_as_required_signals
test_requires_signals_are_checked_before_execution
test_runtime_fact_names_match_real_project_sources
test_unconfirmed_runtime_fact_does_not_satisfy_requirement
```

### 16.5 Negative Tests (Frontier 禁止的操作)

```text
test_frontier_does_not_rank_routes
test_frontier_does_not_select_best_route
test_frontier_does_not_execute_fallback
test_frontier_does_not_apply_unlock
test_frontier_does_not_advance_state
test_frontier_does_not_write_verification_memory
test_frontier_does_not_write_trajectory_memory
test_frontier_does_not_load_llm
test_frontier_does_not_start_docker
test_frontier_does_not_send_http
```

### 16.6 Replay Deferred Tests

```text
test_replay_is_explicitly_deferred
test_executed_route_fingerprints_is_empty_tuple_in_default_context
```

### 16.7 Signal Name Tests

```text
test_confirmed_signals_includes_evidence_requirements_when_primitive_confirmed
test_observable_signals_are_not_evidence_requirements
test_signal_name_not_in_observable_or_evidence_requirements_is_rejected
```

### 16.8 Regression Test

```text
test_all_existing_261_tests_still_pass
```

### 16.9 RuntimeFactAdapter Tests

```text
test_adapter_maps_injectable_endpoints_to_endpoint
test_adapter_maps_injectable_params_to_parameter
test_adapter_treats_method_as_unavailable
test_adapter_reads_template_engine_from_verification
test_adapter_reads_reflection_confirmed_as_boolean
test_adapter_does_not_write_verification_memory
test_adapter_does_not_write_trajectory_memory
```

---

## 17. Exact Codex Implementation Task

```text
阶段: Route Frontier v1 — 动态前置条件 Eligibility Gate

前置步骤 (SCHEMA_PATCH):
1. b/routes/schema.py:
   - RouteRequirements 增加 signals: tuple[str, ...] = ()
   - 新增 FrontierDiagnosticCode str Enum
   - 新增 FrontierContext, FrontierDiagnostic, FrontierEntry, RouteFrontier dataclass

2. b/routes/normalizer.py:
   - normalize_route_proposal() 中 requires 初始化时 signals=()

3. b/routes/admission.py:
   - _mapping_with_keys 的 requires required fields 更新为
     frozenset(("current_state", "runtime_facts", "signals"))
   - YAML requires 解析接受 signals list
   - 新增 UNKNOWN_REQUIRED_SIGNAL error code（如需验证信号名）

4. b/routes/primitive_adapter.py:
   - 增加 get_confirmation_signal(primitive_id: str) -> str | None

主要实现:

5. b/routes/context_adapter.py:
   - RuntimeFactAdapter 类
   - build_frontier_context(adapter: PrimitiveAdapter) -> FrontierContext
   - 只读适配 VerificationMemory → FrontierContext
   - 名称映射: injectable_endpoints→endpoint, injectable_params→parameter
   - 信号推断: working_primitives + reflection_confirmed → confirmed_signals

6. b/routes/frontier.py:
   - RouteFrontier 类
   - evaluate(snapshot: RouteRegistrySnapshot, context: FrontierContext) -> RouteFrontier
   - 5 条 eligibility rules
   - 确定性排序和 context_fingerprint

7. b/routes/__init__.py:
   - 导出 Frontier API

8. b/test_routes.py:
   - 新增 Frontier 测试类（上述所有测试）
   - 确认所有 261 现有测试仍然通过

硬约束:
- 不修改五层 Agent (Planner/Validator/Executor/Evaluator/Consolidator)
- 不修改 Coordinator
- 不修改 TemplateManager
- 不修改 PrimitiveRegistry / PrimitiveTransitionGraph
- 不修改 VerificationMemory / TrajectoryMemory
- 不修改 builtin/generated YAML
- 不修改 b/data/confirmed_vuln.json
- 不运行 Docker / HTTP / LLM / 靶机 / exploit pipeline
- 不 commit / 不 push
```

---

## 18. Deferred Items

| 项目 | 原因 | 目标阶段 |
|------|------|---------|
| Replay / execution history gate | 无结构化 route 执行历史 | v1.5+ |
| `method` runtime fact 确认 | 项目不存储 HTTP method 为确认事实 | v1.5+ (需 Coordinator 改动) |
| Endpoint-to-parameter 层级关系验证 | 需要更复杂的上下文匹配 | v1.5+ |
| Route 支持多个合法 state | `RouteRequirements` 需要扩展为 `tuple[str,...]` | v1.5+ |
| Route 支持 `forbidden_signals` | 需要额外的 negative signal 语义 | v1.5+ |
| Planner/Executor 接入 | Frontier 需要被 Pipeline 消费 | v2.0 |
| AntiRegression payload similarity | 超出 Frontier 范围 | v2.0 |
| `expression_evaluated` 移入 observable_signals | 需要修改 PrimitiveRegistry（不可修改的受保护文件） | 设计决策 |

---

## 19. Final Verdict

```text
SCHEMA_PATCH_REQUIRED_BEFORE_FRONTIER
```

### 最小 Schema Patch 范围

| 文件 | 修改 | 理由 |
|------|------|------|
| `b/routes/schema.py` | `RouteRequirements` + `signals: tuple[str, ...] = ()` | Frontier 需要检查 `requires.signals` |
| `b/routes/normalizer.py` | 填充 `requires.signals = ()` | 向后兼容；proposal 暂不声明 requires.signals |
| `b/routes/admission.py` | 更新 `requires` mapping keys to include `"signals"` | YAML load 需接受 signals 字段 |
| `b/routes/primitive_adapter.py` | 增加 `get_confirmation_signal()` | 使 `expression_evaluated` 可被 Frontier 检查 |

### Patch 后即可实现 Frontier v1

Frontier 本身是纯函数式 eligibility gate，不创建新的事实源，不推进状态，不调用外部系统。所有输入来自 Registry snapshot + VerificationMemory (只读适配)。所有输出是确定性的 eligible/blocked 分类。

### 确认不创建的新文件

```text
❌ routes/frontier.py 中的 VALID_STATES 副本
❌ routes/frontier.py 中的 SIGNAL_REGISTRY
❌ routes/frontier.py 中的 RuntimeTruths 全量副本
❌ routes/frontier.py 中的 PrimitiveTransitionGraph 副本
❌ routes/frontier.py 中的 replay history store
❌ routes/frontier.py 中的第二份 VerificationMemory
```

### 引用的真实文件、函数、行号

| 证据 | 文件 | 行号 |
|------|------|------|
| VALID_STATES | `b/memory/exploit_trajectory.py` | 11 |
| get_current_state() | `b/memory/exploit_trajectory.py` | 107-122 |
| ExploitTrajectoryNode.current_state | `b/memory/exploit_trajectory.py` | 21 |
| observable_signals (ssti_reflection) | `b/memory/exploit_primitives.py` | 17 |
| confirmation → evidence_requirements | `b/memory/exploit_primitives.py` | 19, 218 |
| _HEURISTIC_DETECTORS expression_evaluated | `b/memory/primitive_learning.py` | 42-43 |
| Evaluator _detect_primitives ssti_reflection | `b/agents/evaluator.py` | 398-402 |
| Evaluator _adjudicate_feedback_state | `b/agents/evaluator.py` | 634-665 |
| Coordinator _record_verified_facts | `b/coordinator.py` | 888-949 |
| Coordinator current_state usage | `b/coordinator.py` | 524, 655, 727, 896 |
| Reflection confirmed recording | `b/coordinator.py` | 917-919 |
| Planner current_state from trajectory | `b/agents/planner.py` | 1769 |
| Planner base_url from target_context | `b/agents/planner.py` | 1100 |
| RouteRequirements definition | `b/routes/schema.py` | 140-142 |
| ROUTE_FACTORY_V1_RUNTIME_FACTS | `b/routes/admission.py` | 42 |
| Admission requires validation | `b/routes/admission.py` | 204-224, 624-649 |
| Normalizer requires construction | `b/routes/normalizer.py` | 185-188 |
| ReplayPolicy definition | `b/routes/schema.py` | 166-168 |
| Admission replay rejection | `b/routes/admission.py` | 651-659 |
| VerificationMemory facts schema | `b/memory/verification_memory.py` | 8-30 |
| VerificationMemory add_working_primitive | `b/memory/verification_memory.py` | 133-155 |
| VerificationMemory get_injectable_params | `b/memory/verification_memory.py` | 180-181 |
| Trajectory get_failed_patterns | `b/memory/exploit_trajectory.py` | 161-192 |
| Route fingerprint algorithm | `b/routes/registry.py` | 22-29 |
| Registry snapshot | `b/routes/registry.py` | 319-323 |
| PrimitiveAdapter definition | `b/routes/primitive_adapter.py` | 11-88 |
| confirmed_vuln.json CWE-94 | `b/data/confirmed_vuln.json` | 6 |
| Test collection count 261 | `b/test_routes.py` | pytest --collect-only |
