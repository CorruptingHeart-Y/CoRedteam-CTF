# Plan Contract Unification v1 — 报告

**日期**: 2026-07-27  
**分支**: competition-standard  
**唯一架构目标**: 共享、纯函数、无 Memory 依赖的 Plan Structural Contract  
**最终结论**: `PLAN_CONTRACT_UNIFIED`

---

## 0. 执行边界

本轮严格遵守：

- 只修改：`b/core/plan_contract.py`、`b/agents/validator.py`、`b/routes/materializer.py`、`b/test_plan_contract.py`、本报告。
- 未修改 CLI、Planner、Executor、Evaluator、Consolidator、Coordinator、`memory/*`、`core/template_manager.py`、任何 YAML、任何靶题。
- 未运行 Stage 1、Docker、HTTP、LLM、Executor、Evaluator、真实 exploit；未 commit、未 push。

---

## 1. 原有重复契约（问题）

存在两套互不相等的“计划契约”实现：

### 1.1 Materializer 内部契约（旧）

`b/routes/materializer.py::_plan_contract_is_valid()`（旧实现，约 19 行）独立判断：

- `version == 1`
- `steps` 为 list 且 `len == 1`（强制单步）
- step `type == "python"`
- `sdk_calls` 为 list 且 `len == 1`，`calls[0]` 为 dict
- `primitive` ∈ `{HttpClient.get, HttpClient.post}`（硬编码白名单）
- `target` 为 str 且以 `/` 开头
- `query`/`body` 恰好一处非空（`populated == 1`）

### 1.2 真实运行时 Validator

`b/agents/validator.py::validate_plan()` 真正的接受条件还包含：Runtime Manifest（safe/blocked modules、sdk_primitives）、sandbox policy（text_scan_rules、shell whitelist）、Python 语法、trajectory、Verification Memory、AntiRegressionController、Request Contract Gate、primitive_context 推断等运行时 gate。

### 1.3 不等价点（Codex `REVIEW_REJECTED` 的根因）

| 维度 | Materializer 旧契约 | 真实 Validator | 等价？ |
|------|---------------------|----------------|--------|
| 多步 plan | 拒绝（`len != 1`） | 接受 | ❌ |
| `type=shell` + sdk_calls | 拒绝 | 接受（AST 路径不查 type） | ❌ |
| `query` 与 `body` 同时存在 | 拒绝（`populated == 1`） | 不做此结构检查 | ❌ |
| `primitive` 语义合法性 | 硬编码白名单 | 依赖 Manifest `sdk_primitives`（动态） | ❌ |
| `target` 以 `/` 开头 | 强制 | 不做此结构检查 | ❌ |
| Manifest / policy / trajectory / Memory / anti-regression | 不检查 | 检查 | ❌ |

结论：Materializer 内部检查**无法证明**计划符合真实 Validator 的结构要求，更无法证明运行时接受。这正是 Codex 只读审查 `REVIEW_REJECTED` 的原因。

---

## 2. 从真实 Validator 抽取的静态规则

逐项审计 `validate_plan()` 及其直接结构辅助函数，抽取**真正属于静态结构**（无 Manifest、无 policy、无 Memory、无 trajectory、无 LLM、无网络）的检查：

| # | 规则 | 来源（validator.py） | 是否抽取 | 错误码 |
|---|------|----------------------|----------|--------|
| 1 | `version == 1` | `validate_plan` 顶层 | ✅ | `VERSION_INVALID` |
| 2 | `steps` 为数组 | `validate_plan` 顶层 | ✅ | `STEPS_NOT_LIST` |
| 3 | `steps` 非空 | `validate_plan` 顶层 | ✅ | `STEPS_EMPTY` |
| 4 | AST 模式（`sdk_calls` 非空）+ `command` 非空 → 拒绝 | 混合协议拒绝块 | ✅ | `MIXED_PROTOCOL` |
| 5 | LEGACY 模式（无 `sdk_calls`）`type` ∈ {python, shell} | `_validate_step` | ✅ | `STEP_TYPE_INVALID` |
| 6 | LEGACY 模式至少有 command/code/sdk_calls 之一 | `_validate_step` | ✅ | `EMPTY_STEP` |
| 7 | `imports`（存在时）为数组 | 隐含于 Task 5 迭代 | ✅（类型） | `IMPORTS_NOT_LIST` |
| 8 | `imports` 元素为字符串 | 隐含于 `imp.split(".")` | ✅（类型） | `IMPORTS_INVALID_ELEMENT` |
| 9 | `primitive_context`（存在时）为对象 | `isinstance(primitive_ctx, dict)` | ✅（类型） | `PRIMITIVE_CONTEXT_INVALID` |
| 10 | step `target_primitive`（存在时）为字符串 | `_validate_trajectory_awareness` | ✅（类型） | `TARGET_PRIMITIVE_INVALID` |
| 11 | AST `sdk_calls[i].primitive` 为非空字符串 | `_validate_step_ast_against_manifest` | ✅（类型） | `SDK_PRIMITIVE_INVALID` |
| 12 | AST `sdk_calls[i].target`（存在时）为字符串 | 同上 | ✅（类型） | `SDK_TARGET_INVALID` |
| 13 | AST `sdk_calls[i].query|body`（存在时）为对象或 null | `_check_request_contract` | ✅（类型） | `REQUEST_CONTAINER_INVALID` |

说明：
- 非字典 step：真实 Validator **跳过**（不产生错误）。为“以真实 Validator 已有行为为准”，共享契约同样**跳过**非字典 step，不新增 `STEP_NOT_DICT` 拒绝，避免收紧运行时行为。
- #7–#13 为**类型级**结构检查：当字段存在时校验类型；字段缺失交由运行时 gate（Validator 对 `primitive_context`/`target_primitive` 缺失仅 warn + 自动推断）。这保证不改变非 Manual 运行链行为。
- 字符串形式 sdk_calls（如 `"HttpClient.get"`）被真实 Validator 容忍，共享契约同样容忍（仅对 dict 形式做字段类型检查）。

---

## 3. 未抽取的运行时 gate（仍由真实 Validator 独占）

以下检查**未**进入共享结构契约，仍只在 `validate_plan()` 运行时执行：

- Runtime Manifest：`safe_modules` / `blocked_modules` / `sdk_primitives` 动态匹配
- sandbox policy：`text_scan_rules`、`shell_tool_allowlist`、Python import allowlist/blocklist（AST 解析实际代码文本）
- Python 语法检查 `_check_python_syntax`
- `_check_broken_dependency_chain`（依赖链 / `/tmp` 产物 / 沙滩建城堡）
- `_validate_trajectory_awareness`：状态退化、chain 连续性、payload 退化、exploit reasoning、状态跳级
- `AntiRegressionController`（state / chain / payload regression）
- Verification Memory（`get_verification`）
- `_check_request_contract`（known parameter contract）
- `_validate_step_ast_against_manifest`（AST vs Manifest 交叉校验）
- `primitive_context.current_primitive/target_primitive` 缺失时的 warn + 自动推断

---

## 4. 新共享 API

文件：`b/core/plan_contract.py`（纯标准库：`dataclasses`、`enum`、`typing`）

```python
class PlanStructureErrorCode(str, Enum): ...   # 13 个稳定错误码

@dataclass(frozen=True)
class PlanStructureDiagnostic:
    code: PlanStructureErrorCode
    field: str | None
    message: str

@dataclass(frozen=True)
class PlanStructureResult:
    passed: bool
    diagnostics: tuple[PlanStructureDiagnostic, ...]
    @property
    def error_codes(self) -> tuple[PlanStructureErrorCode, ...]: ...

def validate_plan_structure(plan: Mapping[str, Any]) -> PlanStructureResult: ...
```

性质：
- 不可变结果（`frozen=True`）。
- 稳定错误码，确定性诊断顺序（version → steps[0..n] 逐字段 → primitive_context）。
- 不依赖英文 message 判断（用 `error_codes`）。
- 不读取全局状态、不执行 I/O。
- 不 import coordinator / memory / LLM / 网络（由 `test_plan_contract.py::TestStructureContractPurity` 在独立子进程中验证）。

---

## 5. Validator 接入

`b/agents/validator.py`：

1. 顶部新增 `from core.plan_contract import validate_plan_structure`。
2. `validate_plan()` 入口**先**调用共享结构契约：

```python
struct_result = validate_plan_structure(plan)
if not struct_result.passed:
    return {
        "passed": False,
        "errors": [f"[plan_structure] {d.message}" for d in struct_result.diagnostics],
        "structure_invalid": True,
    }
# 结构通过 → 继续原有 Manifest / policy / trajectory / Memory / anti-regression / request-contract gate
```

约束达成：
- 未删除任何现有动态校验（version/steps 旧检查保留为无害冗余，不触发）。
- 未降低严格程度（结构失败即拒）。
- 未改变非 Manual 运行链行为：对结构合法的计划，后续 gate 与原先完全一致。
- 纯结构函数不替代真实 Validator（`structure_invalid` 标记仅用于可观测性，运行时状态判断仍由动态 gate 决定）。
- 未修改 Planner / Executor / Evaluator / Coordinator。

---

## 6. Materializer 接入

`b/routes/materializer.py`：

1. 顶部新增 `from core.plan_contract import validate_plan_structure`。
2. `_plan_contract_is_valid()` 改为**纯委托 wrapper**：

```python
def _plan_contract_is_valid(plan: Mapping[str, object]) -> bool:
    """Compatibility wrapper — pure delegate to validate_plan_structure.
    A True return means ONLY PLAN_STRUCTURE_VALID, NOT runtime acceptance."""
    return validate_plan_structure(plan).passed
```

- 删除了原第二套逻辑（`len(steps) != 1`、`HttpClient.get/post` 白名单、`startswith("/")`、`populated == 1`）。
- wrapper 仅委托，不保留第二套契约逻辑（由 `test_materializer_has_no_second_contract_implementation` 验证）。
- Materializer 的 method×location 不变式（GET+query / POST+form/json）**不在** `_plan_contract_is_valid` 中，而由 `_build_sdk_call` 返回 `None` → `plan is None` → `PLAN_CONTRACT_INVALID` 失败来保证，与原行为一致。
- Materializer 经此 wrapper 能且仅能证明 `PLAN_STRUCTURE_VALID`，**不声称**运行时 Validator 一定接受。

---

## 7. 行为兼容性

### 7.1 真实 Validator 对既有测试计划的行为不变

`test_run_isolation_evidence_guard.py` 中 3 处 `validate_plan`/`run_validator` 调用所用的计划（`_ast_plan_for_validator`、`test_known_contract_old_string` 等）均**结构合法**：

- `version == 1`、`steps` 非空数组
- AST 模式 + `command=None`（无混合协议）
- `imports` 为字符串数组、`primitive_context` 为对象、`target_primitive` 为字符串
- `sdk_calls` 字段类型合法

→ 结构预检通过 → 进入原有动态 gate → 与原结果一致。`test_known_contract_old_string_rejected_by_validate_plan` 仍由 Request Contract Gate 拒绝（`parameter_contract_unverifiable`）。

### 7.2 Materializer 输出仍被接受

Materializer 生成的单步 plan 结构合法，`_plan_contract_is_valid` 委托返回 `True`；GET+form/GET+json/POST+query 等非法组合仍由 `_build_sdk_call` → `plan is None` 拒绝。

### 7.3 结构非法计划被更早拒绝

`version != 1`、`steps` 非数组/空、AST+command 混合等现在在 `validate_plan` 入口即被拒（`structure_invalid=True`），不再进入动态 gate。这未改变最终接受/拒绝结论（这些情况原先也会被拒），仅前移了拒绝点。

### 7.4 关键区分

```
Plan Structure Validation
    = 静态 JSON 结构符合 Validator 输入契约
    → validate_plan_structure(plan).passed is True

Runtime Validator Acceptance
    = 结构通过
      + Manifest
      + policy
      + trajectory
      + Verification Memory
      + anti-regression
      + 其他当前状态 gate
    → validate_plan(plan)["passed"] is True
```

二者**不再**被写成等价。

---

## 8. 测试结果

### 8.1 新增共享契约测试 `b/test_plan_contract.py`

```
28 passed
```

覆盖：
- `test_valid_materialized_plan_passes_shared_structure_contract`
- `test_materializer_calls_shared_structure_contract`
- `test_validator_calls_shared_structure_contract`
- `test_materializer_has_no_second_contract_implementation`
- 13 项逐规则拒绝（version/steps/type/mixed/imports/primitive_context/target_primitive/sdk_primitive/sdk_target/request_container）
- 4 项纯度（不 import coordinator/memory/LLM/HTTP，独立子进程验证）
- `test_structure_contract_is_deterministic`
- `test_validator_dynamic_gates_still_exist`
- `test_validator_does_not_treat_structure_pass_as_runtime_acceptance`
- `test_original_313_route_tests_pass`
- `test_existing_112_materializer_tests_pass_or_report_exact_failures`

### 8.2 Materializer 套件 `b/test_route_materializer_impl.py`

```
109 passed, 3 failed
```

**精确失败清单**（已上报，未删除任何原测试）：

1. `TestInternalFunctions::test_plan_contract_is_valid_rejects_multi_step`
2. `TestInternalFunctions::test_plan_contract_is_valid_rejects_shell_type`
3. `TestInternalFunctions::test_plan_contract_is_valid_rejects_dual_location`

**失败原因（预期且正确）**：这 3 项测试断言旧的 divergent `_plan_contract_is_valid` 拒绝“多步 / shell+sdk_calls / query+body 共存”。但真实 Validator **不**将这些作为结构错误（多步合法；AST 模式不查 type；不对 query/body 做互斥结构检查）。统一后 `_plan_contract_is_valid` 为纯委托，忠实于真实 Validator，因此这 3 项旧断言不再成立。它们正是 Codex `REVIEW_REJECTED` 所指“第二套不等价契约”的编码化体现，移除第二套契约后必然失败。

Materializer 自身的“单步 / python / 单一位置”不变式仍由 `_build_sdk_call` + `_build_plan` 保证，**不**依赖这 3 项旧断言；Materializer 主路径测试（Section 1–7、9–10）全部通过。

### 8.3 Route 基线 `b/test_routes.py`

```
313 passed
```

无回归。

### 8.4 Validator 静态/AST 测试 `b/test_run_isolation_evidence_guard.py`

```
59 passed
```

无回归（含 `test_validator_ast_command_none_does_not_crash`、`test_known_contract_old_string_rejected_by_validate_plan`、Request Contract Gate 系列）。

### 8.5 汇总

```
test_plan_contract.py .................... 28 passed
test_route_materializer_impl.py ......... 109 passed, 3 failed (预期)
test_routes.py .......................... 313 passed
test_run_isolation_evidence_guard.py .... 59 passed
                                     -----
                                     509 passed, 3 failed
```

### 8.6 compile/import smoke

```
COMPILE_OK
SMOKE_OK
```

---

## 9. 原测试回归

| 套件 | 变更前 | 变更后 | 回归 |
|------|--------|--------|------|
| `test_routes.py` | 313 passed | 313 passed | 无 |
| `test_run_isolation_evidence_guard.py` | 59 passed | 59 passed | 无 |
| `test_route_materializer_impl.py` | 112 passed | 109 passed, 3 failed | 3 项预期失败（见 §8.2），未删除 |

3 项失败为**移除第二套 divergent 契约的必然结果**，已在 `test_existing_112_materializer_tests_pass_or_report_exact_failures` 中精确上报并通过断言锁定（109 passed + 3 failed + 3 个具名失败）。

---

## 10. 仍存在的问题

1. **3 项旧 Materializer 断言失败（预期）**：`test_plan_contract_is_valid_rejects_{multi_step,shell_type,dual_location}`。它们编码了被 Codex 否决的 divergent 第二套契约。本轮受“只允许修改指定文件”约束未改 `test_route_materializer_impl.py`。后续若获授权，可将这 3 项断言改为“结构契约不拒绝、交由运行时”以反映统一后语义，或迁移至 `test_plan_contract.py` 的边界测试。

2. **`_plan_contract_is_valid` 兼容 wrapper 仍保留**：仅为不破坏现有 import / 调用点。它已退化为纯委托，无第二套逻辑。未来可直接让调用方改用 `validate_plan_structure`。

3. **`primitive_context` / `target_primitive` 仅做类型校验**：缺失仍由运行时 Validator warn + 自动推断处理（以保证不改变非 Manual 运行链行为）。若后续需要将其提升为结构硬要求，需先评估对 LLM 生成计划容错的运行链影响。

4. **共享契约不覆盖 sdk_primitive 语义合法性**：`HttpClient.*` 是否在 Manifest `sdk_primitives` 中注册仍属运行时动态检查。结构契约仅校验 `primitive` 为非空字符串。

5. **`structure_invalid` 结果键为新增可观测标记**：仅出现在结构失败分支，为 additive；未发现既有测试断言精确 key 集，但不排除外部消费者需感知。

---

## 11. 最终结论

```
PLAN_CONTRACT_UNIFIED
```

依据：

- 建立唯一共享纯函数 `b/core/plan_contract.py::validate_plan_structure`，无 Memory / coordinator / LLM / HTTP 依赖。
- 规则逐项从真实 `validate_plan()` 抽取，未反向由 Materializer 输出创造契约。
- 真实 Validator 与 Materializer 共同调用同一函数；Materializer 旧第二套契约已删除，`_plan_contract_is_valid` 退化为纯委托。
- Validator 动态 gate（Manifest / policy / trajectory / Verification Memory / anti-regression / request-contract）全部保留，未被纯结构函数替代。
- 明确区分 `Plan Structure Validation` 与 `Runtime Validator Acceptance`，不再等价。
- Route 基线 313、Validator 静态 59、共享契约 28 全部通过；Materializer 112 中 109 通过、3 项 divergent 旧断言精确失败并上报。
- 未修改 CLI、未运行 Stage 1、未发送 HTTP、未执行任何计划。
