# Route Factory v1 — 第一阶段实现边界审计报告

**审计日期:** 2026-07-24
**审计范围:** 只读审计，不修改任何文件
**分支:** competition-standard

---

## 1. Git Status

```
On branch competition-standard
Your branch is up to date with 'origin/competition-standard'.

Changes not staged for commit:
  deleted:    target_codebase/cybench_web_challenges/2/* (23 files, 745 deletions)

Untracked files:
  AUDIT_REPORT_MINIMAL_FIVE_LAYER.md
  target_codebase/cybench_web_challenges/1/
  附件2：作品报告模版.html
```

**结论:** 无未提交代码修改。在 `b/` 下没有任何修改。唯一变更是对 `target_codebase/` 中已删除的靶题文件的跟踪（非代码）。可以安全进行审计。

---

## 2. 当前 YAML 调用链

### 2.1 谁生成 YAML

| 组件 | 文件 | 函数 | 行号 | 输入 | 输出 | 写盘 |
|------|------|------|------|------|------|------|
| CLI `memory init-builtin` | `b/cli.py` | `cmd_memory_init_builtin()` | 681 | 内置 template 定义（硬编码 dict） | 17 个 `.yaml` 文件写入 `b/templates/builtin/` | **是** |
| CLI `memory add` | `b/cli.py` | `cmd_memory_add()` | 233 | 用户提供的 YAML 文件路径 | AttackTemplate（内存） | 否（解析输入用） |
| CLI `memory import` | `b/cli.py` | `cmd_memory_import()` | 280 | 用户提供的 YAML 文件路径 | AttackTemplate（通过 tm.import_template） | **是**（调用 tm.add_template → yaml.dump） |
| Consolidator seed warmup | `b/agents/consolidator.py` | `run_seed_warmup()` | 1022 | confirmed_vuln.json + LLM 生成的代码 | 向已有 YAML 文件追加 payload_templates 条目 | **是**（1157-1158行） |
| Consolidator global | `b/agents/consolidator.py` | `_sync_to_yaml_weapon_library()` | ~700 | LLM consolidation 输出 + CWE 信息 | 新的或追加的 YAML 文件 | **是**（594-595行） |
| Consolidator global | `b/agents/consolidator.py` | `_create_new_cwe_yaml()` | 603 | CWE ID + payload 数据 | 新建 YAML 文件 | **是** |
| Consolidator append | `b/agents/consolidator.py` | `_append_payload_to_yaml()` | 552 | 已有 YAML 路径 + payload entry | 更新的 YAML 文件 | **是**（594-595行） |
| TemplateManager | `b/core/template_manager.py` | `add_template()` | 180 | template_id, name, content, cwe_ids, … | `{target_type}/{template_id}.yaml` | **是**（210行） |

### 2.2 谁规范化

| 组件 | 文件 | 函数 | 行号 | 做什么 |
|------|------|------|------|--------|
| Consolidator | `b/agents/consolidator.py` | `_normalize_cwe_slug()` | 536-538 | `"CWE-502" → "cwe-502"`（仅用于文件匹配） |
| TemplateManager | `b/core/template_manager.py` | `_load_yaml_file()` | 88-97 | `yaml.safe_load()` → 校验必须有 `metadata.id` 和 `content` |

**结论:** 不存在 "deterministic normalizer" — `_normalize_cwe_slug` 仅做大小写转换。不存在 schema 版本检查、字段规范化或 canonical ID 生成。

### 2.3 谁验证

| 组件 | 文件 | 函数 | 行号 | 做什么 |
|------|------|------|------|--------|
| TemplateManager | `b/core/template_manager.py` | `_load_yaml_file()` | 88-97 | 仅检查 `metadata.id` 和 `content` 不为空 |
| Validator | `b/agents/validator.py` | `load_policies()` | 88 | `yaml.safe_load(open("sandbox_policy.yaml"))` — 读沙箱策略 |
| 无 | — | — | — | 不存在 YAML schema 验证器、JSON Schema 或 Pydantic 校验 |

### 2.4 谁把 YAML 注入 Planner

| 组件 | 文件 | 函数 | 行号 | 方式 |
|------|------|------|------|------|
| Planner | `b/agents/planner.py` | `_build_cwe_templates()` | 767-947 | 根据 CWE ID 从 TemplateManager.query_templates() 查询 → 转为提示文本 |
| TemplateManager | `b/core/template_manager.py` | `get_templates_for_target()` | 129-178 | 从 confirmed_vuln 取 CWE → query_templates() → 去重 → 跳过 `consolidator_reviewed:false` → 返回提示文本 |
| Planner | `b/agents/planner.py` | `_build_primitive_context()` (L4) | ~2032 | 从 VerificationMemory + PrimitiveRegistry 构建 primitive 上下文 |

### 2.5 完整调用链图

```
[confirmed_vuln.json] ──read──→ [Planner._build_cwe_templates()]
                                      │
                        query_templates(cwe_id)
                                      │
                                      ▼
                          [TemplateManager.get_templates_for_target()]
                                      │
                              ┌───────┴───────┐
                              ▼                 ▼
                     [templates/builtin/   [memory/tech.json]
                      *.yaml files]              │
                              │                  │
                     yaml.safe_load()    json.load()
                              │                  │
                              ▼                  ▼
                         AttackTemplate    payload_templates
                              │                  │
                              └────────┬─────────┘
                                       ▼
                            to_prompt_text() → Planner 上下文

[Consolidator LLM] ──generates──→ [yaml.dump()] ──writes──→ [templates/builtin/*.yaml]
                                                            [memory/tech.json]
                                                            [ChromaDB]
```

### 2.6 YAML 是否真正控制运行时？

**部分控制。** YAML 模板通过以下方式影响运行时：
1. Planner 将 `content` 字段作为攻击知识注入提示（`to_prompt_text()`）
2. `payload_templates` 中的 `template` 字段（当非空且非 null）由 Executor 作为 Python 代码执行
3. TemplateManager 基于 `cwe_ids` 匹配模板，基于 `consolidator_reviewed:false` 标签过滤

**YAML 不控制:**
- 状态机推进（由 Evaluator + Coordinator 决定）
- Primitive 选择（由 PrimitiveRegistry + PrimitiveTransitionGraph 决定）
- 执行沙箱策略（由 `policies/sandbox_policy.yaml` 决定）

---

## 3. SSTI 使用的 Canonical CWE

### 3.1 代码中的证据

| 位置 | 使用 | Canonical ID |
|------|------|-------------|
| `b/data/confirmed_vuln.json:6` | `"cwe_id": "CWE-94"` | **CWE-94** |
| `b/templates/builtin/cwe-94-ssti.yaml:4-6` | `cwe_ids: [CWE-94, CWE-917]` | **CWE-94** (primary) + CWE-917 (secondary) |
| `b/templates/builtin/cwe-94-cwe-94.yaml:4-5` | `cwe_ids: [CWE-94]` | **CWE-94** |
| `b/cli.py:360` | 内置 SSTI 模板: `"cwe_ids": ["CWE-94", "CWE-917"]` | **CWE-94** (primary) |
| `b/memory/primitive_transition_graph.py:168-172` | `"CWE-94": ["ssti_reflection"]`, `"CWE-917": ["ssti_reflection"]` | CWE-94 → ssti_reflection |
| `b/agents/planner.py:767` | `if "CWE-94" in cwe_set or "CWE-917" in cwe_set:` | **CWE-94** 用于 CWE 模板调度 |
| `b/agents/planner.py:1290-1303` | `_CWE_INFERENCE_TABLE`: SSTI 关键词 → `"CWE-1336"` | **CWE-1336**（推理表别名） |
| `b/memory/tech.json:770+` | 多个条目使用 `"cwe_ids": ["CWE-94"]` | **CWE-94** |

### 3.2 三路冲突分析

系统中存在 **三路 CWE 编号**，用于 SSTI：

| CWE ID | 含义 | 使用者 |
|--------|------|--------|
| **CWE-94** | Code Injection（代码注入） | confirmed_vuln, YAML metadata, Planner dispatch, PrimitiveTransitionGraph |
| **CWE-917** | Expression Language Injection（表达式语言注入） | cwe-94-ssti.yaml 中作为次要 cwe_id |
| **CWE-1336** | Template Injection（模板注入） | Planner 的 `_CWE_INFERENCE_TABLE` 仅此一处 |

### 3.3 结论

**Route Factory v1 应使用的唯一 canonical CWE: `CWE-94`**

理由：
1. `confirmed_vuln.json` — 唯一的事实来源 — 使用 `CWE-94`
2. 两个 SSTI YAML 文件都使用 `CWE-94` 作为 primary cwe_id
3. PrimitiveTransitionGraph 将 `CWE-94` 映射到 `ssti_reflection`
4. Planner 的 CWE 调度分支检查 `CWE-94` 和 `CWE-917`，但 `CWE-94` 是首要的
5. `CWE-1336` 仅存在于推理表中一次，不在任何 YAML metadata、confirmed_vuln、或 PrimitiveTransitions 中使用

**别名映射建议（单向，仅用于 Route Factory 查询）:**

```python
SSTI_CWE_ALIASES = {
    "CWE-94": "CWE-94",       # canonical
    "CWE-917": "CWE-94",      # alias → canonical
    "CWE-1336": "CWE-94",     # alias → canonical
}
```

Route Factory 内部应始终输出 `CWE-94`，从不同输入源接受其他别名并规范化。

---

## 4. 现有状态机事实源

### 4.1 权威状态定义

**唯一合法状态元组（单一事实源）:**

```python
# b/memory/exploit_trajectory.py:11
VALID_STATES = ("init", "probe_success", "payload_injected", "gadget_triggered", "oob_received")
```

还有一个**非标准状态** `"objective_verified"`：
- `b/coordinator.py:1176` — goal_verifier 确认 flag 后设置
- `b/test_run_isolation_evidence_guard.py:1738` — 测试数据中使用
- 不在 `VALID_STATES` 元组中，且仅在终端成功状态下使用

### 4.2 状态定义位置

| 模块 | 文件:行号 | 角色 |
|------|-----------|------|
| Valid State Enum | `b/memory/exploit_trajectory.py:11` | **权威来源** — `VALID_STATES` |
| State Order (Coordinator) | `b/coordinator.py:523,742` | 状态推进检测 |
| State Order (Evaluator) | `b/agents/evaluator.py:647` | 裁定反馈状态 |
| State Order (Validator) | `b/agents/validator.py:641` | 反回归索引查找 |
| Trajectory Node default | `b/memory/exploit_trajectory.py:21,110` | `current_state: str = "init"` |
| State gating (Coordinator) | `b/coordinator.py:906,916,936` | 基于状态记录事实 |
| Anti-regression | `b/control/anti_regression.py:221-231` | `validate_state_regression` |

### 4.3 Evaluator 如何推进状态

文件: `b/agents/evaluator.py`

| 函数 | 行号 | 推进到 | 条件 |
|------|------|--------|------|
| `_local_evidence_state()` | 597 | `"oob_received"` | OOB 标记存在 |
| `_local_evidence_state()` | 597 | `"gadget_triggered"` | OOB 不存在但其他证据存在 |
| `_local_evidence_state()` | 606 | `"gadget_triggered"` | 从 `injected_primitives` 检测到 |
| `_local_evidence_state()` | 616 | `"payload_injected"` | 注入的 primitives 集合非空 |
| `_local_evidence_state()` | 629 | `"probe_success"` | HTTP 成功（200/30x） |
| `_local_evidence_state()` | 631 | `"init"` | 无本地证据 |

Evaluator 随后通过 `_adjudicate_feedback_state()` （第646-665行）验证该状态：
- 检查请求的状态是否在 `state_order` 中有效
- 确保没有跳级（允许 `oob_received` 被请求但仅在存在 OOB 证据时授予）
- 将 `current_exploit_state` 写回 feedback dict

### 4.4 Verification Memory 如何参与

文件: `b/memory/verification_memory.py`

- **类 `VerificationMemory`**（第33行）：持久化已确认事实
- Coordinator 在每轮后调用 `get_verification().confirm(...)`（`coordinator.py:893`）记录状态
- Planner 将 VerificationMemory 注入到 `L4: Verified Facts` 上下文（`planner.py:2032`）
- 不推进状态 — 它记录状态推进

### 4.5 是否存在重复状态表？

**不存在。** `VALID_STATES`（`exploit_trajectory.py:11`）是唯一的事实源。Coordinator、Evaluator 和 Validator 都从同一元组中引用相同文本。不存在独立的 `StateMachine` 类、状态枚举或数据库表。

### 4.6 Primitive Transition Graph 如何参与导航

文件: `b/memory/primitive_transition_graph.py`

- `get_entry_primitives(cwe_ids)`（第165行） — 从 CWE 映射初始探测 primitive
- `get_all_upgrade_targets(active_primitives)`（第112行） — 给定当前已激活 primitive，返回可能的升级
- `find_shortest_path(from_id, to_id)`（第125行） — BFS 查找到目标 primitive 的最短路径
- `build_planner_context(active_primitives)`（第193行） — 注入 Planner 提示

**状态机控制漏洞利用"阶段"（探测→注入→触发器→OOB），Primitive Transition Graph 控制每个阶段内的技术选择。**

Route Factory 不得创建第二套权威状态机。

---

## 5. Primitive 事实源审计

### 5.1 `ssti_reflection` 定义位置

**文件: `b/memory/exploit_primitives.py:14-19`**

```python
"ssti_reflection": {
    "description": "Template expression reflected in output (e.g. {{7*7}} → 49)",
    "preconditions": ["user_input_reaches_template", "no_output_encoding"],
    "observable_signals": ["arithmetic_result_in_response", "expression_reflected_verbatim"],
    "payload_templates": ["{{7*7}}", "${7*7}", "<%=7*7%>", "#{7*7}", "{{7*'7'}}"],
    "confirmation": "expression_evaluated",
},
```

### 5.2 Payload Templates

在 `b/memory/exploit_primitives.py:18` 中定义：`["{{7*7}}", "${7*7}", "<%=7*7%>", "#{7*7}", "{{7*'7'}}"]`

还有跨目标语法映射（`b/memory/exploit_primitives.py:249-261`）：
```python
"template_expression_execution": {
    "jinja2": "{{7*7}}",
    "twig": "{{7*7}}",
    "freemarker": "${7*7}",
    "velocity": "#set($x=7*7)$x",
    "thymeleaf": "#{7*7}",
    ...
}
```

### 5.3 Observable Signals

在 `b/memory/exploit_primitives.py:17` 中定义：
- `arithmetic_result_in_response`
- `expression_reflected_verbatim`

确认标记（`b/memory/exploit_primitives.py:19`）：`expression_evaluated`

### 5.4 `expression_evaluated` 检测位置

**文件: `b/memory/primitive_learning.py:42-43`**

```python
("ssti_reflection", "expression reflected as computed value",
 re.compile(r"\{\{7\*7\}\}.*49|\$\{7\*7\}.*49|<%=7\*7%>.*49|#\{7\*7\}.*49", re.DOTALL),
 "expression_evaluated"),
```

检测逻辑在 `PrimitiveLearningEngine.learn_from_observation()`（第220行）：

1. 连接 `payload + response_body_snippet + stdout_snippet`
2. 对 `_HEURISTIC_DETECTORS` 中每个 `(primitive_id, desc, pattern, evidence_note)` 进行 regex 匹配
3. 成功时创建 `LearnedPrimitive`，若 `success=True` 且 `response_status` 为 2xx，则提高置信度
4. 持久化到 `b/memory/learned_primitives.json`

**Evaluator 也通过 `_detect_primitives()`（`evaluator.py:386-414`）检测：**

```python
# evaluator.py:400-402
detected.append("ssti_reflection")
confidence["ssti_reflection"] = 0.92
evidence["ssti_reflection"] = "{{7*7}} reflected as 49..."
```

### 5.5 检测结果如何写入 Verification Memory

`coordinator.py:892-896` 中的 `_record_facts_to_verification()`：

```python
verif = get_verification()
state = fb.get("current_exploit_state", "init")
# 基于状态和反馈记录确认的事实
```

### 5.6 PrimitiveTransitionGraph 如何使用该 Primitive

`b/memory/primitive_transition_graph.py`:

- **第25行:** `"ssti_reflection": ["ssti_execution", "blind_ssti"]` — 升级目标
- **第61行:** `"ssti_reflection->ssti_execution": "需确认 template engine 类型..."` — transition 条件
- **第171行:** `"CWE-94": ["ssti_reflection"]` — 从 CWE 到入口 primitive 的映射
- **第206行:** `ssti_chain = self.find_shortest_path("ssti_reflection", "credential_dump")` — 规划 exploit 链

### 5.7 Route Factory 可直接导入的公共接口

| 模块 | 函数/类 | 安全导入 |
|------|---------|---------|
| `memory.exploit_primitives` | `get_primitive_registry()` | ✅ 只读 |
| `memory.exploit_primitives` | `PrimitiveRegistry` | ✅ 只读查询 |
| `memory.exploit_primitives` | `ExploitPrimitive` (dataclass) | ✅ 纯数据 |
| `memory.exploit_primitives` | `INJECTION_PRIMITIVES` | ✅ 常量字典 |
| `memory.exploit_primitives` | `CROSS_TARGET_SYNTAX_MAP` | ✅ 常量字典 |
| `memory.primitive_transition_graph` | `get_transition_graph()` | ✅ 只读 |
| `memory.primitive_transition_graph` | `PrimitiveTransitionGraph` | ✅ 只读查询 |
| `core.template_manager` | `TemplateManager` | ✅ 只读查询 |
| `core.template_manager` | `AttackTemplate` (dataclass) | ✅ 纯数据 |

### 5.8 不应直接依赖的内部结构

| 模块 | 类/函数 | 原因 |
|------|---------|------|
| `memory.primitive_learning` | `PrimitiveLearningEngine` | 有副作用（自动保存），需要 trajectory 数据 |
| `memory.primitive_learning` | `_HEURISTIC_DETECTORS` | 内部实现细节，应通过 `PrimitiveRegistry.find_by_observable()` 间接访问 |
| `agents.evaluator` | `_detect_primitives()` | 内部 Evaluator 逻辑，有副作用 |
| `agents.evaluator` | `_local_evidence_state()` | 内部 Evaluator 逻辑 |
| `agents.consolidator` | YAML 写函数 | 全部有写盘副作用 |

### 5.9 确认：已存在的基础设施

| 结构 | 状态 | 位置 |
|--------|--------|----------|
| **PrimitiveRegistry** | ✅ 存在 | `b/memory/exploit_primitives.py:292` |
| **Signal-to-Primitive 映射** | ✅ 存在 | `PrimitiveRegistry._by_observable` + `find_by_observable()` |
| **Payload Template Lookup** | ✅ 存在 | `PrimitiveRegistry.match_payload_to_primitive()` + `payload_templates` 字段 |
| **Primitive Transition Lookup** | ✅ 存在 | `PrimitiveTransitionGraph.get_all_upgrade_targets()` |
| **Replay Fingerprint** | ❌ 不存在 | — |
| **Observer/Heuristic Detector** | ✅ 存在 | `PrimitiveLearningEngine._HEURISTIC_DETECTORS`（但不应直接依赖） |

---

## 6. Activation 状态合约

### 6.1 当前代码中实际支持的状态

通过对所有 `.py` 和 `.yaml` 文件的全面搜索，结果如下：

| 搜索词 | 代码中匹配 | 结论 |
|----------|----------|---------|
| `draft` | **0** | 不存在 |
| `active` | 27（作为形容词使用：`active_primitives`、`exploit_momentum_active`） | 不作为模板状态存在 |
| `disabled` | 4（仅关于 Docker 网络 `network_disabled=True`） | 不作为模板状态存在 |
| `candidate_only` | **0** | 不存在 |
| `candidate` | 33（作为通用变量名 "candidates"，与模板状态无关） | 不作为正式状态存在 |
| `activation` | **0** | 不存在 |
| `generated` | 7（通用使用） | 不作为正式状态存在 |
| `admission` | **0** | 不存在 |

### 6.2 模板过滤中实际使用的机制

唯一的模板过滤机制是标签 `consolidator_reviewed:false`：

- **`b/core/template_manager.py:166-171`**: `get_templates_for_target()` 检查 `"consolidator_reviewed:false" in t.tags` 并跳过这些模板
- **`b/agents/consolidator.py:586`**: 新创建的 payload 条目自动获取 `tags: [... "consolidator_reviewed:false"]`
- **`b/templates/builtin/cwe-94-cwe-94.yaml:74`**: 一个条目明确包含 `consolidator_reviewed:false`

### 6.3 第一阶段生成 YAML 的推荐状态

```yaml
activation:
  state: draft
  source: route_factory
```

**说明：**
- `draft` 目前在任何现有代码中**不存在** — 它是一个新概念，仅由 Route Factory 引入
- 现有代码对 `draft` 或 `candidate_only` 不做任何处理，因此可以安全引入，不会破坏现有管道
- `candidate_only` 应作为 `activation` 块内的 **admission control 标志**：

```yaml
activation:
  state: draft
  source: route_factory
  candidate_only: true   # 未被 Planner/Executor 收录
  reviewed_by: null
  promoted_at: null
```

这保证了：
1. 现有 `TemplateManager` 查询逻辑（检查 `consolidator_reviewed:false`）不受影响
2. 如果新标签不存在，现有代码可以安全忽略
3. 将来可以通过将 `candidate_only: true` → `candidate_only: false` 来提升，或添加适当的审查元数据

---

## 7. 现有 YAML Schema 审计

### 7.1 提取的三个真实 YAML

#### A. SSTI Builtin: `cwe-94-ssti.yaml`

```yaml
metadata:
  id: cwe-94-ssti
  name: SSTI/Template Injection
  cwe_ids: [CWE-94, CWE-917]
  target_type: generic
  tags: [ssti, jinja2, twig, freemarker, rce, template-injection]
  author: co-redteam
  severity: critical
content: |-
  (长字符串 — SSTI 检测和利用指南)
payload_templates:
  - name: network-connectivity-quick-probe
    description: ...
    lang: python
    template: |
      (可执行 Python 代码)
    tags: [network, connectivity, ...]
    source: consolidator
    severity: critical
```

#### B. 非 SSTI Builtin: `cwe-78-command-injection.yaml`

```yaml
metadata:
  id: cwe-78-command-injection
  name: OS Command Injection
  cwe_ids: [CWE-78]
  target_type: generic
  tags: [command-injection, rce, blind-injection, ...]
  author: co-redteam
  severity: critical
content: |-
  (长字符串 — 命令注入利用指南)
# 无 payload_templates
```

#### C. Consolidator Generated: `cwe-94-cwe-94.yaml`

```yaml
metadata:
  id: cwe-94-cwe-94
  name: CWE-94
  cwe_ids: [CWE-94]
  target_type: generic
  tags: [cwe-94, cwe-94]
  author: co-redteam-consolidator
  severity: critical
initial_prechecks: []
content: |
  Apache Velocity SSTI 通过反射调用 java.lang.Runtime.exec...
payload_templates:
  - name: velocity-ssti-rce-reflection
    description: ...
    lang: python
    template: null        # ← 存根！未填充的可执行代码
    source: consolidator
    severity: critical
  - name: velocity-ssti-form-parameter-rce
    template: ''          # ← 空字符串，另一个存根
    ...
```

### 7.2 字段存在性表

| 字段 | cwe-94-ssti | cwe-78-cmd | cwe-94-cwe-94 | 谁读取 | 影响运行时 | 可复用 |
|-------|-------------|------------|----------------|---------|-------------------|----------|
| `metadata.id` | ✅ | ✅ | ✅ | TemplateManager | 是（模板键） | ✅ |
| `metadata.name` | ✅ | ✅ | ✅ | Planner 提示 | 是（显示） | ✅ |
| `metadata.cwe_ids` | ✅ | ✅ | ✅ | TemplateManager.query_templates() | 是（匹配） | ✅ |
| `metadata.target_type` | ✅ | ✅ | ✅ | TemplateManager（目录结构） | 是（组织） | ✅ |
| `metadata.tags` | ✅ | ✅ | ✅ | TemplateManager（标签过滤） | 是（过滤） | ✅ |
| `metadata.author` | ✅ | ✅ | ✅ | 无 | 否 | ✅ |
| `metadata.severity` | ✅ | ✅ | ✅ | 排序 | 轻微 | ✅ |
| `content` | ✅ | ✅ | ✅ | Planner 提示 | 是（知识注入） | ✅ |
| `payload_templates` | ✅ | ❌ | ✅ | Executor（当 template 非空） | **是**（代码执行） | ✅ |
| `payload_templates[].name` | ✅ | — | ✅ | 注释 | 否 | ✅ |
| `payload_templates[].template` | ✅ (已填充) | — | ✅ (null/'') | **Executor** | **是**（如果非空） | ✅ |
| `payload_templates[].source` | ✅ | — | ✅ | 注释 | 否 | ✅ |
| `payload_templates[].lang` | ✅ | — | ✅ | Executor | 是（Python 执行） | ✅ |
| `initial_prechecks` | ❌ | ❌ | ✅ (空) | 无 | 否 | ⚠️ 未使用 |
| `schema_version` | ❌ | ❌ | ❌ | — | — | ❌ 需添加 |
| `canonical_id` | ❌ | ❌ | ❌ | — | — | ❌ 需添加 |
| `activation` | ❌ | ❌ | ❌ | — | — | ❌ 需添加 |
| `requires` | ❌ | ❌ | ❌ | — | — | ❌ 需添加 |
| `target_primitive` | ❌ | ❌ | ❌ | — | — | ❌ 需添加 |
| `expected_signals` | ❌ | ❌ | ❌ | — | — | ❌ 需添加 |
| `observer` | ❌ | ❌ | ❌ | — | — | ❌ 需添加 |
| `materialization` | ❌ | ❌ | ❌ | — | — | ❌ 需添加 |
| `success` | ❌ | ❌ | ❌ | — | — | ❌ 需添加 |
| `failure` | ❌ | ❌ | ❌ | — | — | ❌ 需添加 |
| `replay` | ❌ | ❌ | ❌ | — | — | ❌ 需添加 |

### 7.3 关键结论

1. 存在两种不同的 YAML schema：**Simple**（仅 metadata + content）和 **Payload Templates**（metadata + initial_prechecks + content + payload_templates）
2. Simple 模式（例如 `cwe-78-command-injection.yaml`）缺少 `payload_templates`、`initial_prechecks` 和 `schema_version`
3. 没有文件有 `schema_version` 字段 — 所有解析都依赖隐式结构假设
4. Consolidator 生成的模板（例如 `cwe-94-cwe-94.yaml`）有 `template: null` 或 `template: ''` — 等待 seed warmup 的存根
5. `cwe-94-ssti.yaml` 是混合模式 — 同时有 `content` 指南和 `payload_templates`

---

## 8. 可复用组件（Route Factory v1 直接导入）

| 组件 | 导入路径 | 仅用于查询 | 不可变 |
|----------|-------------|--------------|-----------|
| `PrimitiveRegistry` | `memory.exploit_primitives.get_primitive_registry()` | ✅ `.get()`, `.find_by_observable()`, `.get_by_type()`, `.get_entry_primitives()` | ✅ |
| `ExploitPrimitive` | `memory.exploit_primitives.ExploitPrimitive` | ✅ 纯数据类 | ✅ |
| `PrimitiveTransitionGraph` | `memory.primitive_transition_graph.get_transition_graph()` | ✅ `.get_entry_primitives()`, `.get_next_primitives()` | ✅ |
| `TemplateManager` | `core.template_manager.TemplateManager` | ✅ `.query_templates()`, `.get_template()`, `.list_templates()` | ⚠️ `.add_template()` 会写盘 |
| `AttackTemplate` | `core.template_manager.AttackTemplate` | ✅ 纯数据类 | ✅ |
| `VALID_STATES` | `memory.exploit_trajectory.VALID_STATES` | ✅ 常量元组 | ✅ |
| `ExploitTrajectoryMemory` | `memory.exploit_trajectory.get_trajectory()` | ✅ `.get_current_state()` | ✅ |
| `INJECTION_PRIMITIVES` | `memory.exploit_primitives.INJECTION_PRIMITIVES` | ✅ 常量字典 | ✅ |
| `CROSS_TARGET_SYNTAX_MAP` | `memory.exploit_primitives.CROSS_TARGET_SYNTAX_MAP` | ✅ 常量字典 | ✅ |
| yaml 模块 | `yaml.safe_load` / `yaml.safe_dump` | ✅ 标准库 | ✅ |

---

## 9. 重复的事实源（要避免的模式）

| 概念 | 权威来源 | 可能导致重复创建 | 如何避免 |
|-----------|-------------------|---------------------------|----------|
| **Exploit 状态** | `exploit_trajectory.VALID_STATES` | ❌ `routes/state_machine.py` | 直接从 `exploit_trajectory` 导入 `VALID_STATES` |
| **Primitive 定义** | `exploit_primitives.INJECTION_PRIMITIVES` | ❌ `routes/primitive_registry.py` | 直接导入，不重新创建 |
| **Primitive 注册表** | `exploit_primitives.PrimitiveRegistry` | ❌ `routes/capability_registry.py` | 直接使用 `get_primitive_registry()` |
| **Primitive 转换** | `primitive_transition_graph.PrimitiveTransitionGraph` | ❌ `routes/transition_map.py` | 直接使用 `get_transition_graph()` |
| **Signal→Primitive 映射** | `PrimitiveRegistry._by_observable` | ❌ `routes/signal_registry.py` | 使用 `.find_by_observable()` |
| **Payload 模板** | `ExploitPrimitive.payload_templates` | ❌ `routes/payload_registry.py` | 直接从 `ExploitPrimitive` 实例读取 |
| **模板存储** | `core.template_manager.TemplateManager` | ❌ `routes/yaml_store.py` | 对现有目录使用 TemplateManager |
| **CWE→Primitive 映射** | `PrimitiveTransitionGraph.get_entry_primitives()` | ❌ `routes/cwe_map.py` | 直接使用，不缓存副本 |

---

## 10. Route Factory 最小边界（第一阶段）

### 10.1 第一阶段实现

| 组件 | 做什么 | 输入 | 输出 |
|----------|------|-------|--------|
| **RouteProposal** 数据结构 | Route 候选数据类（不可变字段） | confirmed_vuln + CWE analysis | RouteProposal 实例 |
| **Primitive Adapter**（只读） | 包装现有 `PrimitiveRegistry` + `PrimitiveTransitionGraph` | CWE ID(s) | 推荐的入口 primitive，现有模板列表 |
| **Route Normalizer** | 确定性地规范化 RouteProposal 字段 | RouteProposal | 标准化 RouteProposal（canonical CWE，已解决的 primitive 引用） |
| **Draft YAML Writer** | 将 RouteProposal 写为 YAML 草稿 | 已规范化的 RouteProposal | `templates/generated/{route_id}.yaml` |
| **Generation Report** | 人类可读的生成摘要 | 已规范化的 RouteProposal | 日志/打印/JSON 报告 |

### 10.2 第一阶段明确不做

- ❌ Planner 集成
- ❌ Validator 集成
- ❌ Executor 集成
- ❌ Evaluator 修改
- ❌ Coordinator 修改
- ❌ Route Selector（比较候选）
- ❌ Route Frontier（多 route 搜索）
- ❌ DSpark（分布式变体搜索）
- ❌ CWE Top-K 排序
- ❌ 动态 K 参数
- ❌ 自动提升为 active
- ❌ Docker 启动
- ❌ HTTP 发送
- ❌ 真实 LLM 调用
- ❌ 完整 RCE 链生成
- ❌ `signal_registry.py`、`capability_registry.py`、`observer_registry.py`、`state_machine.py`、`primitive_registry.py`

---

## 11. 推荐文件

### 最小文件布局

```
b/routes/
  __init__.py              # 公共 API 导出
  schema.py                # RouteProposal 数据类 + activation 状态枚举
  primitive_adapter.py     # 现有 PrimitiveRegistry 的只读包装器
  normalizer.py            # 确定性规范化器
  writer.py                # YAML 草稿写入器 + 生成报告
```

### 文件目的

#### `b/routes/__init__.py`
```python
# 公共 API
from routes.schema import RouteProposal, ActivationState, RouteMetadata
from routes.primitive_adapter import PrimitiveAdapter
from routes.normalizer import RouteNormalizer
from routes.writer import DraftYamlWriter, GenerationReport
```

#### `b/routes/schema.py`
- `ActivationState` 枚举：`DRAFT`、`ACTIVE`、`DISABLED`
- `RouteProposal` 数据类：包含 `canonical_id`、`cwe_id`、`activation`、`target_primitive`、`expected_signals`、`payload_templates`、`schema_version`
- `RouteMetadata` 数据类：`generated_by`、`generated_at`、`source_cwe`、`candidate_only`

#### `b/routes/primitive_adapter.py`
- `PrimitiveAdapter` 类：包装 `get_primitive_registry()` 和 `get_transition_graph()`
- 方法：`get_entry_primitive(cwe_id)`、`get_payload_templates(primitive_id)`、`get_observable_signals(primitive_id)`、`get_upgrade_targets(primitive_id)`
- **只读 — 禁止写入路径**

#### `b/routes/normalizer.py`
- `RouteNormalizer` 类：规范化 CWE ID、解决 primitive 引用、验证信号
- 方法：`normalize_cwe(cwe_id)`（处理 94/917/1336 别名）、`normalize_primitive(primitive_id)`、`normalize_proposal(proposal)`
- 使用 `SSTI_CWE_ALIASES` 映射

#### `b/routes/writer.py`
- `DraftYamlWriter` 类：将 RouteProposal 序列化为 YAML
- `GenerationReport` 数据类：摘要统计
- 输出路径：`b/templates/generated/{route_id}.yaml`
- 始终附加 `tags: [consolidator_reviewed:false]` 或等效的 `candidate_only: true`

---

## 12. 必须保持未修改的文件

| 文件 | 原因 |
|------|--------|
| `b/memory/exploit_primitives.py` | Primitive 注册表事实源 |
| `b/memory/primitive_transition_graph.py` | Primitive 转换图事实源 |
| `b/memory/exploit_trajectory.py` | 状态机事实源 |
| `b/memory/verification_memory.py` | 验证事实源 |
| `b/memory/primitive_learning.py` | 学习引擎（有副作用） |
| `b/core/template_manager.py` | 现有模板加载/匹配逻辑 |
| `b/agents/evaluator.py` | 状态推进逻辑 |
| `b/agents/planner.py` | CWE 推理 + 模板调度 |
| `b/agents/validator.py` | 现有请求合约验证 |
| `b/agents/consolidator.py` | 现有 YAML 写入路径 |
| `b/agents/executor.py` | 现有 payload 执行 |
| `b/coordinator.py` | 主编排管道 |
| `b/control/anti_regression.py` | Payload 变异引擎 |
| `b/templates/builtin/*.yaml` | 全部 17 个内置模板 |
| `b/data/confirmed_vuln.json` | Vulnerability 事实源 |
| `b/policies/sandbox_policy.yaml` | 执行沙箱策略 |

---

## 13. 离线测试策略

### 13.1 测试基础设施

| 方面 | 现状 |
|--------|--------|
| **测试运行器** | pytest（已发现的测试，来自 `.pytest_cache/`） |
| **配置文件** | **无** — 无 `pytest.ini`、`pyproject.toml` 或 `setup.cfg` |
| **Conftest** | **无** — 无共享 fixtures |
| **测试目录** | 测试文件直接位于 `b/` 中（无专用 `tests/` 目录） |
| **测试文件** | `b/test_run_isolation_evidence_guard.py`（58 个测试函数，1994 行） |
| **测试模式** | 无 `@pytest.fixture` — 使用内联辅助函数和 Dummy 类 |
| **模拟 LLM** | `DummyLLM` 类返回预定义的 JSON（无网络调用） |
| **模拟 Memory** | `DummyMemory` 类记录调用（无 ChromaDB） |
| **临时目录** | `_memory_dir()` 函数创建/重置 `b/workspace/test_guard/` |
| **Windows 兼容性** | 文件路径使用 `Path()`，字符串中使用 `/` |

### 13.2 哪些 Fixture 会启动 Docker/HTTP/LLM

**无。** 所有测试完全离线：
- `DummyLLM` 返回预定义的 JSON 字符串 — 无 LLM 调用
- `DummyMemory` 记录到 Python 字典 — 无 ChromaDB
- `_memory_dir()` 使用临时文件目录 — 无 Docker
- 无 fixture 进行 HTTP 请求

### 13.3 推荐的 Route Factory 离线测试命令

```bash
cd b

# 运行所有现有测试（确认无回归）
python -m pytest test_run_isolation_evidence_guard.py -v --tb=short

# 仅运行 Route Factory 测试
python -m pytest test_routes.py -v --tb=short

# 使用覆盖率
python -m pytest test_routes.py -v --tb=short --cov=routes --cov-report=term-missing

# Windows: 使用显式路径（避免 ImportError）
python -m pytest b/test_routes.py -v --tb=short
```

### 13.4 推荐的测试文件：`b/test_routes.py`

| 测试类别 | 测试内容 | 离线 |
|-----------|----------|--------|
| `test_primitive_adapter` | `get_entry_primitive("CWE-94")` 返回 ssti_reflection | ✅ |
| `test_normalizer_cwe` | `normalize_cwe("CWE-1336")` → `"CWE-94"` | ✅ |
| `test_normalizer_cwe` | `normalize_cwe("CWE-917")` → `"CWE-94"` | ✅ |
| `test_normalizer_primitive` | `normalize_primitive("ssti_reflection")` 有效 | ✅ |
| `test_normalizer_primitive` | `normalize_primitive("nonexistent")` 抛出 | ✅ |
| `test_proposal_schema` | RouteProposal 字段验证 | ✅ |
| `test_proposal_schema` | 必需字段检查 | ✅ |
| `test_activation_state` | ActivationState.DRAFT 值 | ✅ |
| `test_writer_draft` | 写入 YAML 包含正确的 `activation.state: draft` | ✅（使用 tmp_path） |
| `test_writer_draft` | 生成的 YAML 可由 `yaml.safe_load()` 解析 | ✅（使用 tmp_path） |
| `test_writer_candidate_flag` | `candidate_only: true` 在生成的 YAML 中 | ✅（使用 tmp_path） |

### 13.5 Windows 路径兼容方式

```python
# 在测试中使用（与现有代码库惯例一致）
from pathlib import Path
tmp = Path(tmp_path) / "test.yaml"  # pytest tmp_path fixture

# 不要使用字符串拼接路径
# ❌ path = tmp_path + "\\test.yaml"
# ✅ path = Path(tmp_path) / "test.yaml"
```

---

## 14. 确切的 Route Factory v1 阶段 1 Codex 任务

```
阶段 1：Route Factory 基础设施搭建（只读适配器 + 草稿写入器）

实现：
1. b/routes/schema.py — RouteProposal 数据类：
   - canonical_id: str
   - cwe_id: str (canonical "CWE-94")
   - activation: ActivationState (DRAFT | ACTIVE | DISABLED)
   - target_primitive: str (例如 "ssti_reflection")
   - expected_signals: list[str]
   - payload_templates: list[str]
   - schema_version: str = "1.0.0"
   - candidate_only: bool = True
   - metadata: RouteMetadata

2. b/routes/primitive_adapter.py — PrimitiveAdapter：
   - 构造函数接收 PrimitiveRegistry + PrimitiveTransitionGraph（或使用 singleton）
   - get_entry_primitive(cwe_id: str) -> ExploitPrimitive | None
   - get_payload_templates(primitive_id: str) -> list[str]
   - get_observable_signals(primitive_id: str) -> list[str]
   - get_upgrade_targets(primitive_id: str) -> list[str]
   - 只读 — 不修改任何现有状态

3. b/routes/normalizer.py — RouteNormalizer：
   - 使用 SSTI_CWE_ALIASES 的 normalize_cwe(cwe_id)
   - 针对 PrimitiveAdapter 验证的 normalize_primitive(pid)
   - 返回标准化副本的 normalize_proposal(RouteProposal)
   - 确定性 — 相同输入产生相同输出

4. b/routes/writer.py — DraftYamlWriter + GenerationReport：
   - 将 RouteProposal 写入 b/templates/generated/{canonical_id}.yaml
   - 将 activation.state: draft、candidate_only: true 写入 YAML
   - 返回 GenerationReport，包含：proposal_id、cwe、primitive、template_count、warnings
   - 不修改 templates/builtin/ 下的任何文件

5. b/test_routes.py — 离线测试：
   - 通过现有 singleton 测试 PrimitiveAdapter（无 mock）
   - 使用 pytest tmp_path 测试 DraftYamlWriter
   - 测试所有 alias 的 CWE 规范化
   - 测试 RouteProposal 模式验证
   - 测试确定性规范化器
   - 0 网络调用、0 Docker 容器、0 LLM 调用

硬约束：
- 不修改 b/ 中的任何现有文件（仅添加 routes/ + test_routes.py）
- 不修改任何 .yaml 文件
- 不运行 Docker
- 不发送 HTTP
- 不调用 LLM
- 不读取 target_codebase/
- 不生成 exploit
- 不 commit
- 不 push
```

---

## 硬约束摘要

| # | 约束项 | 状态 |
|---|---------------|--------|
| 1 | 不修改代码 | ✅ 已遵守 — 只读审计 |
| 2 | 不修改测试 | ✅ 已遵守 |
| 3 | 不修改 YAML | ✅ 已遵守 |
| 4 | 不运行 Docker | ✅ 已遵守 |
| 5 | 不发送 HTTP | ✅ 已遵守 |
| 6 | 不调用 LLM | ✅ 已遵守 |
| 7 | 不读取靶题源码 | ✅ 已遵守（仅审计 b/ 目录） |
| 8 | 不生成 exploit | ✅ 已遵守 |
| 9 | 不 commit | ✅ 已遵守 |
| 10 | 不 push | ✅ 已遵守 |

---

## 引用文件索引

| 项目 | 文件 | 关键行号 |
|------|------|-----------|
| Valid states | `b/memory/exploit_trajectory.py` | 11 |
| Primitive definitions | `b/memory/exploit_primitives.py` | 13-167 |
| PrimitiveRegistry | `b/memory/exploit_primitives.py` | 292-429 |
| PrimitiveTransitionGraph | `b/memory/primitive_transition_graph.py` | 88-251 |
| Heuristic detectors | `b/memory/primitive_learning.py` | 38-105 |
| VerificationMemory | `b/memory/verification_memory.py` | 33-288 |
| TemplateManager | `b/core/template_manager.py` | 45-296 |
| YAML load (TemplateManager) | `b/core/template_manager.py` | 88-97 |
| YAML dump (TemplateManager) | `b/core/template_manager.py` | 209-210 |
| CWE inference table | `b/agents/planner.py` | 1288-1303 |
| CWE dispatch (SSTI) | `b/agents/planner.py` | 767 |
| SSTI detection (Evaluator) | `b/agents/evaluator.py` | 398-414 |
| State advancement (Evaluator) | `b/agents/evaluator.py` | 597-665 |
| State order (Coordinator) | `b/coordinator.py` | 523, 742 |
| State gating (Coordinator) | `b/coordinator.py` | 906-936 |
| YAML append (Consolidator) | `b/agents/consolidator.py` | 552-600 |
| Seed warmup YAML | `b/agents/consolidator.py` | 1022-1214 |
| Tag filtering | `b/core/template_manager.py` | 166-171 |
| SSTI mutations | `b/control/anti_regression.py` | 11-24 |
| confirmed_vuln.json | `b/data/confirmed_vuln.json` | 1-57 |
| cwe-94-ssti.yaml | `b/templates/builtin/cwe-94-ssti.yaml` | 1-79 |
| cwe-94-cwe-94.yaml | `b/templates/builtin/cwe-94-cwe-94.yaml` | 1-77 |
| cwe-78-command-injection.yaml | `b/templates/builtin/cwe-78-command-injection.yaml` | 1-38 |
| Test runner | `b/test_run_isolation_evidence_guard.py` | 1-1994 |
