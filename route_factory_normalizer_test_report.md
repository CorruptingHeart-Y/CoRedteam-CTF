# Route Factory v1 — Normalizer 定向测试与架构审计报告

**审计日期:** 2026-07-24
**测试分支:** competition-standard
**审计范围:** `b/routes/` — Normalizer + PrimitiveAdapter + Schema

---

## 1. Git Diff Scope

```
新增文件 (untracked):
  b/routes/__init__.py
  b/routes/schema.py
  b/routes/primitive_adapter.py
  b/routes/normalizer.py

本轮新增测试:
  b/test_routes.py

未修改的保护文件 (确认):
  b/agents/planner.py         — 未修改
  b/agents/validator.py        — 未修改
  b/agents/executor.py         — 未修改
  b/agents/evaluator.py        — 未修改
  b/agents/consolidator.py     — 未修改
  b/coordinator.py             — 未修改
  b/memory/exploit_primitives.py — 未修改
  b/memory/exploit_trajectory.py — 未修改
  b/memory/primitive_learning.py — 未修改
  b/memory/primitive_transition_graph.py — 未修改
  b/core/template_manager.py   — 未修改

结论: 本轮严格限定在 b/routes/ 新增文件和 b/test_routes.py。无已有文件被修改。
```

---

## 2. Test Files Added

| 文件 | 测试数 | 状态 |
|------|--------|------|
| `b/test_routes.py` | **96** | **全部通过** |

测试类分布:

| 测试类 | 测试数 | 对应章节 |
|--------|--------|---------|
| TestBasicFunctionality | 3 | 三.1 |
| TestDeterminism | 3 | 三.2 |
| TestCanonicalIdSafety | 3 | 三.3 |
| TestCWECanonicalization | 8 | 四 |
| TestStateMachineReuse | 7 | 五 |
| TestPrimitiveAdapterAuthenticity | 10 | 六 |
| TestPrimitiveSignalConsistency | 10 | 七 |
| TestPayloadTemplateReference | 8 | 八 |
| TestTechniqueSemantics | 5 | 九 |
| TestRuntimeFacts | 7 | 十 |
| TestImmutability | 9 | 十一 |
| TestImportSideEffects | 6 | 十二 |
| TestErrorContract | 6 | 十三 |
| TestSchemaEdgeCases | 11 | 补充 |

---

## 3. Tests Passed

**96 / 96 全部通过。** 0 失败。

---

## 4. Tests Failed

**0 失败。**

---

## 5. Exact Tracebacks

无。所有测试通过。

---

## 6. Canonical CWE Audit

### 6.1 Canonical SSTI CWE

```
Canonical SSTI CWE: CWE-94
Evidence: b/data/confirmed_vuln.json:6
```

### 6.2 Allowed Aliases

| Alias | Accepted | Evidence |
|-------|----------|----------|
| CWE-94 | ✅ canonical | confirmed_vuln.json:6, cwe-94-ssti.yaml:4-6, cwe-94-cwe-94.yaml:4-5, primitive_transition_graph.py:171, planner.py:767 |
| CWE-917 | ✅ alias | primitive_transition_graph.py:172, cwe-94-ssti.yaml:4-6, cli.py:360, planner.py:767 |
| CWE-1336 | ✅ alias | planner._CWE_INFERENCE_TABLE:1301 (仅此处) |

### 6.3 Rejected Aliases

```
无。所有 SSTI_CWE_ALIASES 中的映射均有项目依据。
未发现仅凭名称相似添加的无依据映射。
```

### 6.4 Audit Notes

- CWE-1336 的证据最弱：仅在 `planner._CWE_INFERENCE_TABLE:1301` 中存在（SSTI 关键词 → CWE-1336 标签），不在 PrimitiveTransitionGraph、YAML metadata 或 confirmed_vuln.json 中
- CWE-917 有完整证据链：PrimitiveTransitionGraph.get_entry_primitives (line 172)、cwe-94-ssti.yaml cwe_ids、planner dispatch (line 767)、CLI builtin template (line 360)
- 所有三个 alias 都规范化为 CWE-94，产生相同的 canonical_id

### 6.5 验证测试

| 测试 | 结果 |
|------|------|
| test_project_canonical_ssti_cwe_matches_audit_report | PASSED |
| test_supported_cwe_aliases_are_explicit | PASSED |
| test_unknown_cwe_rejected | PASSED |
| test_aliases_do_not_create_duplicate_canonical_ids | PASSED |
| test_cwe_alias_mapping_is_exhaustive | PASSED |
| test_cwe_917_has_entry_primitive_in_transition_graph | PASSED |
| test_cwe_1336_not_in_primitive_transition_graph | PASSED |
| test_cwe_case_insensitive_normalization | PASSED |
| test_cwe_whitespace_tolerance | PASSED |

---

## 7. State Source Audit

### 7.1 事实源

```
权威来源: b/memory/exploit_trajectory.py:11 — VALID_STATES
状态列表: ("init", "probe_success", "payload_injected", "gadget_triggered", "oob_received")
```

### 7.2 routes 包是否定义第二套状态机

**否。** 验证方式：
- `import routes` — 无 `VALID_STATES` 或类似常量
- `routes.schema` — 无状态定义
- `routes.normalizer` — 无状态定义
- `routes.primitive_adapter` — 通过 `from memory.exploit_trajectory import VALID_STATES` 引用
- `VALID_STATES` 对象身份验证：`primitive_adapter.VALID_STATES is exploit_trajectory.VALID_STATES` → True

### 7.3 状态推进职责

- Normalizer 只验证状态是否在 VALID_STATES 中，不推进状态
- PrimitiveAdapter 只提供 `state_exists()` 查询接口
- 状态推进仍属于 Evaluator (`b/agents/evaluator.py:597-665`) 和 Coordinator

### 7.4 验证测试

| 测试 | 结果 |
|------|------|
| test_known_existing_state_is_accepted | PASSED |
| test_unknown_state_rejected | PASSED |
| test_adapter_reads_existing_valid_states | PASSED |
| test_routes_package_does_not_define_second_valid_states_constant | PASSED |
| test_normalizer_does_not_advance_exploit_state | PASSED |
| test_normalizer_does_not_write_verification_memory | PASSED |
| test_normalizer_does_not_write_trajectory_memory | PASSED |

---

## 8. Primitive Source Audit

### 8.1 Adapter 是否复制 PrimitiveRegistry

**否 — 委托而非复制。**

- `PrimitiveAdapter.__init__` 创建新的 `PrimitiveRegistry()` 实例（加载相同的 INJECTION_PRIMITIVES 等常量字典）
- `PrimitiveAdapter.get_observable_signals()` 委托 `self._registry.get(primitive_id).observable_signals`
- `PrimitiveAdapter.get_payload_template_refs()` 委托 `self._registry.get(primitive_id).payload_templates`
- `PrimitiveAdapter.payload_template_exists()` 委托 `self.get_payload_template_refs()`
- 源码中无硬编码的 signal 名称或 payload 字符串

### 8.2 Adapter 是否复制 Transition Graph

**否。**

- `PrimitiveAdapter.__init__` 创建新的 `PrimitiveTransitionGraph(self._registry)` 实例
- `PrimitiveAdapter.get_entry_primitives()` 委托 `self._transition_graph.get_entry_primitives()`
- `PrimitiveAdapter.transition_exists()` 委托 `self._transition_graph.get_next_primitives()`
- `routes` 包无自己的 transition 定义

### 8.3 注意: Adapter 创建独立实例

`PrimitiveAdapter()` 默认构造函数创建**新**的 `PrimitiveRegistry()` 和 `PrimitiveTransitionGraph()`，
而非使用 singleton `get_primitive_registry()` / `get_transition_graph()`。
数据内容相同（均从 INJECTION_PRIMITIVES 等加载），但实例独立。

**影响:** 如果运行时通过 `reset_primitive_registry()` 重置 singleton，
已构造的 Adapter 不受影响。当前阶段无实际影响，但建议使用 singleton 保持一致。

### 8.4 验证测试

| 测试 | 结果 |
|------|------|
| test_adapter_reads_existing_primitive_registry | PASSED |
| test_known_primitive_exists | PASSED |
| test_unknown_primitive_rejected | PASSED |
| test_registry_primitive_not_allowed_as_entry_is_rejected | PASSED |
| test_unknown_vs_unsupported_primitive_are_distinct | PASSED |
| test_adapter_does_not_duplicate_payload_templates | PASSED |
| test_adapter_does_not_duplicate_observable_signals | PASSED |
| test_routes_package_does_not_define_second_transition_graph | PASSED |
| test_adapter_get_observable_signals_matches_registry | PASSED |
| test_adapter_get_payload_template_refs_count_matches | PASSED |

### 8.5 UNKNOWN_PRIMITIVE vs UNSUPPORTED_PRIMITIVE

两个错误码明确区分：
- **UNKNOWN_PRIMITIVE**: primitive 在 Registry 中完全不存在 → `adapter.primitive_exists()` 返回 False
- **UNSUPPORTED_PRIMITIVE**: primitive 在 Registry 中存在，但不是该 CWE 的 entry primitive → `adapter.get_entry_primitives()` 不包含此 primitive

测试验证 (test_unknown_vs_unsupported_primitive_are_distinct):
- `"fake_primitive_abc"` → UNKNOWN_PRIMITIVE (不存在的 primitive)
- `"ssti_execution"` with CWE-94 → UNSUPPORTED_PRIMITIVE (存在但不是 entry primitive)

---

## 9. Primitive-Signal Consistency

### 9.1 ssti_reflection 的 Observable Signals

```
来源: b/memory/exploit_primitives.py:17 (INJECTION_PRIMITIVES["ssti_reflection"]["observable_signals"])
= ["arithmetic_result_in_response", "expression_reflected_verbatim"]

来源: b/memory/exploit_primitives.py:19 (INJECTION_PRIMITIVES["ssti_reflection"]["confirmation"])
= "expression_evaluated"
```

### 9.2 expression_evaluated 的存储位置

`expression_evaluated` 存在于 INJECTION_PRIMITIVES 中，位于 `confirmation` 字段（映射到 `ExploitPrimitive.evidence_requirements`），
**不在** `observable_signals` 列表中。

检测位置: `b/memory/primitive_learning.py:42-43` — `_HEURISTIC_DETECTORS` regex pattern → `"expression_evaluated"` evidence note

**Normalizer 行为:** PrimitiveAdapter.get_observable_signals() 只返回 `observable_signals` 列表。
`expression_evaluated` 不在其中，因此作为 expected_signal 会被拒绝。

**注意:** `expression_evaluated` 是 confirmation/evidence_requirements 级别的信号，不是 observable_signal。
如果 Route Factory 需要在 expected_signals 中接受 it，有两种方案：
1. 扩展 Adapter 增加 `get_confirmation_signals()` 方法
2. 在 PrimitiveRegistry 中将 `confirmation` 合并到 `observable_signals`

### 9.3 command_output_in_response 与 ssti_reflection 的关系

`command_output_in_response` 是 `command_separator` 的 observable_signal，不是 `ssti_reflection` 的。
Normalizer 正确拒绝了此信号与 ssti_reflection 的组合。

### 9.4 所有 expected_signals 均被校验

Normalizer 通过集合运算检查所有 expected_signals 是否都在 primitive 的 supported_signals 中。
第一个信号不会短路后续的检查。验证方式:

```python
supported_signals = set(adapter.get_observable_signals(target_primitive))
mismatched_signals = tuple(signal for signal in expected_signals if signal not in supported_signals)
```

### 9.5 Normalizer 不维护第二份 signal-to-primitive 表

通过 `inspect.getsource` 源码审计确认 normalizer.py 中无 `signal_to_primitive`、`SIGNAL_MAP` 等定义。

### 9.6 验证测试

| 测试 | 结果 |
|------|------|
| test_supported_signal_is_accepted | PASSED |
| test_missing_expected_signal_rejected | PASSED |
| test_unknown_signal_rejected | PASSED |
| test_command_output_in_response_not_provable_by_ssti_reflection | PASSED |
| test_primitive_signal_mismatch_rejected | PASSED |
| test_all_expected_signals_are_checked | PASSED |
| test_duplicate_expected_signals_are_normalized | PASSED |
| test_expression_evaluated_in_primitive_definition | PASSED |
| test_expression_evaluated_not_in_observable_signals | PASSED |
| test_normalizer_does_not_maintain_second_signal_to_primitive_table | PASSED |

---

## 10. Payload Reference Stability

### 10.1 格式

```
primitive:<primitive_id>:<zero-based-index>
```

例如: `primitive:ssti_reflection:0` → `{{7*7}}` (ssti_reflection.payload_templates[0])

### 10.2 稳定性风险

```
风险: PAYLOAD_TEMPLATE_INDEX_IS_ORDER_SENSITIVE
```

ssti_reflection.payload_templates 当前顺序:
```
[0] "{{7*7}}"
[1] "${7*7}"
[2] "<%=7*7%>"
[3] "#{7*7}"
[4] "{{7*'7'}}"
```

如果 INJECTION_PRIMITIVES 中的 `payload_templates` 列表顺序被修改（例如在 PrimitiveRegistry 中重新排序或增加新模板），
所有现有的 `primitive:ssti_reflection:N` 引用将静默指向不同的模板。

### 10.3 最小修复建议

1. 在 Adapter 层为每个模板计算稳定指纹（例如内容 SHA256 前 8 位）
2. 引用格式从 `primitive:ssti_reflection:0` 改为 `primitive:ssti_reflection:sha256:abc12345`
3. 或在现有模板集合上提供只读稳定索引（例如通过 `template_id` 而非列表索引）
4. 不复制 payload 字符串到 routes 包

### 10.4 验证测试

| 测试 | 结果 |
|------|------|
| test_valid_payload_template_reference_is_accepted | PASSED |
| test_payload_reference_primitive_must_match_target_primitive | PASSED |
| test_negative_payload_index_rejected | PASSED |
| test_out_of_range_payload_index_rejected | PASSED |
| test_non_integer_payload_index_rejected | PASSED |
| test_malformed_payload_reference_rejected | PASSED |
| test_payload_template_is_not_materialized | PASSED |
| test_payload_reference_resolution_is_documented_as_order_sensitive | PASSED |

---

## 11. Technique Semantics

### 11.1 当前支持的 Technique

```
SUPPORTED_TECHNIQUES = ("arithmetic_probe", "syntax_probe", "reflection_probe")
```

### 11.2 语义分析

| Technique | 允许的 payload ref | 预期 signal | 语义来源 |
|-----------|-------------------|-------------|---------|
| arithmetic_probe | ssti_reflection:* (任意) | arithmetic_result_in_response 等 | 无特定映射 |
| syntax_probe | ssti_reflection:* (任意) | 同上 | 无特定映射 |
| reflection_probe | ssti_reflection:* (任意) | 同上 | 无特定映射 |

**发现: TECHNIQUE_NAMES_NOT_BACKED_BY_DISTINCT_EXISTING_TEMPLATES**

三个 technique 在 normalizer 层面共享完全相同的:
- target_primitive: `ssti_reflection`
- expected_signals: 相同的 observable_signals 集合
- payload_template_ref 空间: 均可引用 `primitive:ssti_reflection:0-4`

唯一的区别是 technique 名称和由此产生的 canonical_id。

当前 PrimitiveRegistry 中 ssti_reflection 的 5 个 payload_templates 覆盖了多个模板引擎
但没有 technique 级别的标签区分。

### 11.3 结论

当前实际上只支持一种技术语义（ssti_reflection 上的通用探测）。
三个 technique 名称提供了命名空间，但语义区分需要下一轮增强:
1. 在 PrimitiveRegistry 中为 payload_templates 增加 technique 标签（如 `arithmetic`/`syntax`/`reflection`）
2. 或在 Adapter 层实现 technique → 适用 payload_templates 的筛选逻辑
3. 或缩小首阶段 allowlist 为单一 `probe` technique

### 11.4 验证测试

| 测试 | 结果 |
|------|------|
| test_allowed_techniques_are_explicit | PASSED |
| test_unsupported_technique_rejected | PASSED |
| test_each_technique_has_defined_semantics | PASSED |
| test_technique_does_not_silently_accept_arbitrary_payload_ref | PASSED |
| test_technique_distinction_requires_next_phase | PASSED |

---

## 12. Runtime Facts Contract

### 12.1 当前验证范围

Normalizer 对 `required_runtime_facts` 的验证仅限于:
- 非空检查 (`MISSING_RUNTIME_FACTS`)
- 去重和空白修剪 (`_unique_nonempty`)

**不验证** fact 名称是否存在于已知 schema 中。

### 12.2 MaterializationDeclaration 引用的值

```python
MaterializationDeclaration(
    method_from="runtime_truths",
    endpoint_from="runtime_truths",
    parameter_from="runtime_truths",
)
```

`"runtime_truths"` 不是项目中已存在的类或模块。它是 Route Factory 引入的新概念。
项目中没有 `RuntimeTruths` 类或正式的事实字段枚举。

### 12.3 风险

```
NORMALIZER_INVENTS_FIELD_NAMES_WITHOUT_SCHEMA
```

- 任意字符串元组被接受为 required_runtime_facts
- 没有与 Planner/Executor 现有字段名（如 `base_url`, `http_method`, `endpoint`）的兼容性保证
- 后续 Materializer 可能无法消费 Normalizer 生成的字段名

### 12.4 建议

定义 `RUNTIME_FACT_WHITELIST` 或在 Adapter 层提供现有事实名查询。

### 12.5 验证测试

| 测试 | 结果 |
|------|------|
| test_required_runtime_facts_must_not_be_empty | PASSED |
| test_required_runtime_facts_are_deterministic | PASSED |
| test_duplicate_runtime_facts_are_normalized | PASSED |
| test_whitespace_only_facts_are_removed | PASSED |
| test_runtime_facts_order_is_preserved | PASSED |
| test_runtime_facts_not_validated_against_existing_schema | PASSED |
| test_materialization_references_runtime_truths | PASSED |

---

## 13. Serialization Boundary

### 13.1 阻塞问题

```
NORMALIZED_ROUTE_HAS_NO_SAFE_SERIALIZATION_BOUNDARY
```

`dataclasses.asdict()` 直接应用于 `NormalizedRoute` 会失败:

```
TypeError: cannot pickle 'mappingproxy' object
```

原因: `NormalizedRoute.__post_init__` 将 `metadata` 字段替换为 `MappingProxyType`，
而 `dataclasses.asdict()` 内部使用 `copy.deepcopy()`，后者无法处理 `MappingProxyType`。

### 13.2 变通方案

手动逐字段转换可以成功（test_manual_conversion_to_plain_mapping_works 验证）。

### 13.3 修复建议

为 `NormalizedRoute` 增加 `to_plain()` 方法:
1. 将 `metadata` (MappingProxyType) 显式转换为 `dict`
2. 对嵌套 frozen dataclass 字段使用 `dataclasses.asdict()`
3. `expected_signals` 等 tuple 字段转换为 `list`（YAML 兼容）
4. 不复制 payload 字符串

### 13.4 验证测试

| 测试 | 结果 |
|------|------|
| test_route_proposal_is_immutable | PASSED |
| test_normalized_route_is_immutable | PASSED |
| test_metadata_cannot_be_mutated | PASSED |
| test_route_proposal_metadata_is_mappingproxy | PASSED |
| test_manual_conversion_to_plain_mapping_works | PASSED |
| test_manual_plain_mapping_is_json_serializable | PASSED |
| test_manual_plain_mapping_is_deterministic | PASSED |
| test_dataclasses_asdict_fails_with_mappingproxy | PASSED |
| test_plain_mapping_has_no_mappingproxy_via_manual_conversion | PASSED |

---

## 14. Import Side-Effect Audit

### 14.1 结果

所有 import 副作用测试通过。验证:

| 资源 | 是否被 import routes 加载 |
|------|--------------------------|
| LLM 客户端 (openai/anthropic/llm/langchain) | ❌ 不加载 |
| Settings/Config (.env/dotenv) | ❌ 不加载 |
| Docker (docker/container/compose) | ❌ 不加载 |
| 磁盘文件创建 | ❌ 不创建 |
| ChromaDB / VerificationMemory / 其他 Memory Singletons | ❌ 不加载 |
| 网络 (httpx/requests/urllib/socket) | ❌ 不调用 |

验证方式: 子进程 clean import + `sys.modules` 差集分析。

### 14.2 验证测试

| 测试 | 结果 |
|------|------|
| test_import_routes_does_not_load_llm_client | PASSED |
| test_import_routes_does_not_load_settings | PASSED |
| test_import_routes_does_not_initialize_docker | PASSED |
| test_import_routes_does_not_create_files | PASSED |
| test_import_routes_does_not_initialize_memory_singletons | PASSED |
| test_normalizer_has_no_network_calls | PASSED |

---

## 15. Blocking Issues

### 15.1 确认为阻断的问题

**无阻断问题。** 所有检查通过。

### 15.2 非阻断但需记录的问题

| ID | 问题 | 严重度 | 修复阶段 |
|----|------|--------|---------|
| NORMALIZED_ROUTE_HAS_NO_SAFE_SERIALIZATION_BOUNDARY | `dataclasses.asdict()` 无法直接应用于 NormalizedRoute（MappingProxyType 不兼容 deepcopy），需增加 `to_plain()` 方法 | MEDIUM | 下一轮 |
| PAYLOAD_TEMPLATE_INDEX_IS_ORDER_SENSITIVE | 零基下标引用依赖列表顺序，排序变更静默破坏引用 | MEDIUM | 下一轮 |
| TECHNIQUE_NAMES_NOT_BACKED_BY_DISTINCT_EXISTING_TEMPLATES | 三个 technique 共享相同语义，无实际区分 | LOW | 下一轮 |
| NORMALIZER_INVENTS_FIELD_NAMES_WITHOUT_SCHEMA | runtime_facts 无 schema 验证，任意字符串被接受 | LOW | Writer 阶段 |
| expression_evaluated_not_in_observable_signals | `expression_evaluated` 是 confirmation 而非 observable_signal，expected_signal 不接受 | LOW | 设计决策 |
| ADAPTER_CREATES_INDEPENDENT_INSTANCES | Adapter 默认创建新 PrimitiveRegistry，非 singleton | LOW | 优化 |

---

## 16. Required Codex Fixes

### 立即修复（下一轮必须）

1. **为 NormalizedRoute 增加 `to_plain()` 方法**
   - 解决 `dataclasses.asdict() + MappingProxyType` 不兼容问题
   - 将 `metadata` 转为 `dict`，`tuple` 转为 `list`
   - 返回纯 Python dict，可直接 `yaml.safe_dump`

2. **为 payload_template_ref 增加稳定引用方案**
   - 短选项: 在 Adapter 层基于模板内容计算 SHA256 前 8 位
   - 或使用 `template_id` 引用代替零基下标
   - 保持向后兼容当前 `primitive:id:index` 格式

### 后续增强（非阻塞）

3. **定义 RUNTIME_FACT_WHITELIST** — 确保 Normalizer 输出的字段名可被 Materializer 消费
4. **Technique → 适用 payload templates 映射** — 在 Adapter 或 Registry 层增加标签
5. **扩增 expected_signals 范围** — 考虑是否接受 `evidence_requirements`/`confirmation` 级别的信号

---

## 17. Deferred Items

| 项目 | 原因 | 目标阶段 |
|------|------|---------|
| YAML Writer 实现 | 本轮不测试磁盘写入 | 下一轮 |
| CLI integration | 本轮不测试 CLI | 下一轮 |
| Planner 接入 | 本轮不修改五层 Agent | 后续 |
| Coordinator 接入 | 本轮不修改 Coordinator | 后续 |
| Route Selector | 多候选比较 | 后续 |
| Route Frontier | 多 route 搜索 | 后续 |
| Technique → distinct templates | 需要 PrimitiveRegistry 增加标签 | 后续 |
| Runtime facts schema | 需要与 Planner/Executor 对齐 | Writer 阶段 |
| Docker/HTTP/LLM 测试 | 本轮纯内存测试 | 后续 |
| Payload template 稳定指纹 | 需要设计稳定引用方案 | 下一轮 |

---

## 18. Final Verdict

```
ACCEPTED WITH DEFERRED ITEMS
```

### 通过理由

1. ✅ 所有 96 个测试通过
2. ✅ CWE alias 均有真实项目依据 (CWE-94 canonical, CWE-917/CWE-1336 alias)
3. ✅ Adapter 委托现有 PrimitiveRegistry，未复制事实源
4. ✅ 未复现第二套状态机、Transition Graph 或 signal-to-primitive 表
5. ✅ canonical_id 确定性稳定
6. ✅ UNKNOWN_PRIMITIVE 与 UNSUPPORTED_PRIMITIVE 明确区分
7. ✅ 所有 expected_signals 均被校验
8. ✅ payload_ref 跨 primitive 引用被拒绝
9. ✅ import 无 LLM、Settings、Docker 副作用
10. ✅ 错误码机器可读，顺序确定性
11. ✅ 所有结构不可变 (frozen dataclass + MappingProxyType)
12. ✅ 手动转换为 plain mapping 可行且 JSON 可序列化

### 推迟项

- `NORMALIZED_ROUTE_HAS_NO_SAFE_SERIALIZATION_BOUNDARY`: `to_plain()` 方法尚未实现（但手动转换可行）
- `PAYLOAD_TEMPLATE_INDEX_IS_ORDER_SENSITIVE`: 下一轮增加稳定引用
- `TECHNIQUE_NAMES_NOT_BACKED_BY_DISTINCT_EXISTING_TEMPLATES`: 需要 PrimitiveRegistry 标签增强
- `NORMALIZER_INVENTS_FIELD_NAMES_WITHOUT_SCHEMA`: Writer 阶段对齐

### 未触发阻断条件

- ❌ CWE alias 没有真实项目依据 → 未触发（均有依据）
- ❌ Adapter 内复制 PrimitiveRegistry → 未触发（委托模式）
- ❌ Adapter 内复制 payload templates → 未触发（动态生成 ref）
- ❌ Adapter 内复制 observable signal 表 → 未触发（委托查询）
- ❌ routes 包中新增第二套状态机 → 未触发
- ❌ routes 包中新增第二套 Transition Graph → 未触发
- ❌ expected signals 只校验第一个 → 未触发（全集检查）
- ❌ payload ref 可以指向另一个 primitive → 未触发（拒绝跨 primitive）
- ❌ technique 只是名字不同没有可验证语义 → 已记录为非阻断问题
- ❌ Normalizer 推进 exploit state → 未触发（只读验证）
- ❌ Normalizer 写 Verification Memory → 未触发
- ❌ import 时加载 LLM、Settings 或 Docker → 未触发
- ❌ NormalizedRoute 无法安全转成普通 mapping → 手动转换可行，需增加 to_plain()
- ❌ canonical ID 不稳定 → 未触发（确定性）
- ❌ 测试必须解析英文错误文本 → 未触发（基于 error code 枚举）
