# Route Frontier v1.4a — 最小 Schema Contract Patch 实现报告

**日期:** 2026-07-25  
**分支:** competition-standard  
**基线:** 261 passed  
**最终:** 294 passed (+33 项新增)  
**范围:** `b/routes/` + `b/test_routes.py` — 只读 patch，不触及生产代码

---

## 1. Git Scope

```text
branch: competition-standard
untracked: b/routes/, b/test_routes.py (pre-existing)
no commits, no push
```

修改限于:

| 文件 | 变更性质 |
|------|---------|
| `b/routes/schema.py` | RouteRequirements + signals; RouteProposal + required_signals; 3 new error codes |
| `b/routes/normalizer.py` | SCHEMA_VERSION 1.0.0→1.1.0; required_signals 处理 |
| `b/routes/admission.py` | requires mapping + signals; Admission validation |
| `b/routes/primitive_adapter.py` | get_confirmation_signal(); get_supported_requirement_signals() |
| `b/test_routes.py` | +33 tests (294 total) |

未修改:

```text
b/routes/writer.py       — auto-compatible via to_plain()
b/routes/factory.py      — auto-compatible via normalize_route_proposal()
b/routes/registry.py     — auto-compatible via route_fingerprint() / to_plain()
b/routes/__init__.py     — RouteRequirements already exported; new error codes in AdmissionErrorCode
```

未触及其他任何文件。

---

## 2. Files Modified

### 2.1 `b/routes/schema.py`

**Changes:**

1. `RouteRequirements` 增加 `signals: tuple[str, ...] = ()` (line 143)
2. `RouteProposal` 增加 `required_signals: tuple[str, ...] = ()` (line 115)
3. `RouteProposal.__post_init__` 增加 `_string_tuple(self.required_signals, "required_signals")` (line 131)
4. `AdmissionErrorCode` 增加三个新错误码 (lines 53-55):
   - `UNKNOWN_REQUIRED_SIGNAL`
   - `DUPLICATE_REQUIRED_SIGNAL`
   - `MISSING_REQUIRED_SIGNALS`

**Design decisions:**
- `signals` 默认空 tuple — 向后兼容所有现有 Route
- `required_signals` 默认空 tuple — 现有 Proposal 调用方无需修改
- 新错误码与 `PRIMITIVE_SIGNAL_MISMATCH` 独立，严格区分执行前/执行后

### 2.2 `b/routes/primitive_adapter.py`

**新增方法:**

```python
def get_confirmation_signal(self, primitive_id: str) -> str | None:
    """从 ExploitPrimitive.evidence_requirements 读取 confirmation signal"""
    primitive = self._registry.get(primitive_id)
    if primitive is None:
        return None
    return primitive.evidence_requirements or None

def get_supported_requirement_signals(self, primitive_id: str) -> tuple[str, ...]:
    """动态组合 observable_signals + evidence_requirements"""
    # 不硬编码任何 signal 名称
```

**验证:**
- `test_confirmation_signal_is_not_hardcoded_in_routes` — 源码中无 `"expression_evaluated"` 字面量
- `test_observable_signals_behavior_is_unchanged` — 原方法行为不变
- `test_supported_requirement_signals_includes_both_sources` — 动态组合正确

### 2.3 `b/routes/normalizer.py`

**Changes:**

1. `SCHEMA_VERSION = "1.1.0"` (line 21)
2. 新增 `required_signals` 处理 (lines 112-115):
   ```python
   required_signals = _unique_nonempty(proposal.required_signals)
   # required_signals may legitimately be empty for first-stage probes;
   # that is not an error.
   ```
3. `RouteRequirements` 构造增加 `signals=required_signals` (line 192)

**关键保证:**
- 不复制 `expected_signals` → `requires.signals`
- 空 `required_signals` 不报错（首阶段探测合法）
- 确定性去重、trim、排序

### 2.4 `b/routes/admission.py`

**Changes:**

1. `_mapping_with_keys` for `requires` 更新为 `frozenset(("current_state", "runtime_facts", "signals"))` (line 209)
2. `normalized_route_from_plain()` 新增 `requires.signals` 解析 (lines 225-231):
   ```python
   requires_signals, error = _string_list(requires["signals"], "requires.signals")
   ```
3. `NormalizedRoute` 构造增加 `signals=requires_signals` (line 348)
4. `_admit_parsed_route()` 新增 `"required_signals"` 验证块 (lines 660-693):
   - `DUPLICATE_REQUIRED_SIGNAL` — 重复 signal 名称
   - `MISSING_REQUIRED_SIGNALS` — 空字符串 signal
   - `UNKNOWN_REQUIRED_SIGNAL` — 不在 `get_supported_requirement_signals()` 中

**严格性:**
- 旧版缺少 `requires.signals` 的 YAML → `SCHEMA_INVALID`（不静默兼容）
- 类型错误 → `SCHEMA_INVALID`
- 不自动补齐缺失 signals
- 不自动复制 expected_signals

### 2.5 `b/test_routes.py`

新增 33 项测试，分组如下:

| 分组 | 测试数 | 覆盖 |
|------|--------|------|
| RouteRequirements signals field | 2 | 字段存在、默认空 |
| RouteProposal required_signals | 1 | 默认空、向后兼容 |
| Normalizer behaviour | 4 | 写入、不复制、去重、独立性 |
| PrimitiveAdapter queries | 6 | confirmation、unknown、无硬编码、observable不变、组合、空 |
| YAML output | 4 | 包含、空列表、round-trip、to_plain |
| Admission validation | 8 | 接受valid/empty、拒绝missing/wrong/dup/empty/unknown、confirmation可接受、expected不变 |
| Registry fingerprint | 3 | 包含signals、duplicate、conflict |
| Schema version | 2 | 版本一致性、旧版拒绝 |
| Constraint enforcement | 2 | 无frontier模块、无context_adapter模块 |

---

## 3. Schema Version Decision

```text
SCHEMA_VERSION: 1.0.0 → 1.1.0
```

**理由:**
- `requires.signals` 是新增字段，不是向后兼容的变更
- 旧版 YAML（缺少 `requires.signals`）被 Admission 严格拒绝
- 当前尚无正式生产 YAML，升级无破坏性影响
- Normalizer 输出新版本，Writer 自动跟随
- 不修改 builtin YAML（不属于 Route Factory schema）

**使用位置审计:**
| 位置 | 行号 | 影响 |
|------|------|------|
| `normalizer.py:21` | `SCHEMA_VERSION = "1.1.0"` | 定义 |
| `normalizer.py:181` | `schema_version=SCHEMA_VERSION` | NormalizedRoute 构造 |
| `admission.py:12` | `from routes.normalizer import SCHEMA_VERSION` | 导入 |
| `admission.py:399` | `route.schema_version != SCHEMA_VERSION` | Admission 校验 |

---

## 4. RouteRequirements Changes

```python
# Before
@dataclass(frozen=True)
class RouteRequirements:
    current_state: str
    runtime_facts: tuple[str, ...]

# After
@dataclass(frozen=True)
class RouteRequirements:
    current_state: str
    runtime_facts: tuple[str, ...]
    signals: tuple[str, ...] = ()
```

默认空 tuple 保证向后兼容。

---

## 5. RouteProposal Changes

```python
# Before
@dataclass(frozen=True)
class RouteProposal:
    ...
    expected_signals: tuple[str, ...]
    metadata: Mapping[str, Any] = field(default_factory=dict)

# After
@dataclass(frozen=True)
class RouteProposal:
    ...
    expected_signals: tuple[str, ...]
    required_signals: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)
```

`required_signals` 默认空 tuple；`__post_init__` 增加 string tuple 类型校验；现有调用方无需修改。

---

## 6. Primitive Confirmation Adapter

新增两个只读查询方法:

| 方法 | 输入 | 输出 | 数据来源 |
|------|------|------|---------|
| `get_confirmation_signal()` | primitive_id | `str \| None` | `ExploitPrimitive.evidence_requirements` |
| `get_supported_requirement_signals()` | primitive_id | `tuple[str, ...]` | `observable_signals` + `evidence_requirements` |

**不修改:**
- PrimitiveRegistry
- INJECTION_PRIMITIVES
- 现有 `get_observable_signals()` 行为

**不硬编码:**
- 无 `"expression_evaluated"` 字面量
- 无 `"arithmetic_result_in_response"` 字面量
- 全部从现有数据结构动态读取

---

## 7. Normalizer Behavior

```text
RouteProposal.required_signals
  → _unique_nonempty()  (trim, dedup, remove empties, stable order)
  → RouteRequirements.signals

NOT:  RouteProposal.expected_signals → RouteRequirements.signals
```

首阶段 SSTI discovery route 输出:
```yaml
requires:
  current_state: init
  runtime_facts:
    - endpoint
    - parameter
  signals: []
```

---

## 8. Admission Behavior

**接受的 YAML:**
```yaml
requires:
  current_state: init
  runtime_facts: [...]
  signals: []
```
```yaml
requires:
  current_state: payload_injected
  runtime_facts: [...]
  signals:
    - expression_evaluated
```

**拒绝的 YAML + 错误码:**

| 场景 | 错误码 |
|------|--------|
| 缺少 `requires.signals` 字段 | `SCHEMA_INVALID` |
| `signals` 类型非 list | `SCHEMA_INVALID` |
| 重复 signal 名称 | `DUPLICATE_REQUIRED_SIGNAL` |
| 空字符串 signal | `MISSING_REQUIRED_SIGNALS` |
| 不在 `get_supported_requirement_signals()` 中 | `UNKNOWN_REQUIRED_SIGNAL` |

**不混用错误码:**
- `PRIMITIVE_SIGNAL_MISMATCH` → 仅用于 `expected_signals`（执行后）
- `UNKNOWN_REQUIRED_SIGNAL` → 仅用于 `requires.signals`（执行前）

---

## 9. YAML Round Trip

验证:
- `to_plain()` 输出包含 `requires.signals` (as JSON list)
- 空 signals → `[]`
- `yaml.safe_dump` / `yaml.safe_load` round-trip 后 signals 一致
- JSON 可序列化

---

## 10. Registry Fingerprint Behavior

- Fingerprint 基于完整 `route.to_plain()` → 自动包含 `requires.signals`
- signals 变化 → fingerprint 变化
- 相同 signals → fingerprint 相同
- source path 不影响 fingerprint
- 未修改 fingerprint 算法

---

## 11. New Tests

```text
新增: 33 tests (294 - 261 = 33)
全部通过: 294 passed in 2.46s
```

---

## 12. Full Test Result

```text
============================= 294 passed in 2.46s =============================
```

内部分解:
- 原 261 项: 全部通过 (0 regression)
- 新增 33 项: 全部通过
- Compile smoke: 通过
- Import smoke: 通过
- E2E smoke (Proposal→Normalizer→YAML→Admission→Registry): 通过

---

## 13. Blocking Issues

**无阻断问题。**

所有检查通过:
- ✅ 原 261 项测试无回归
- ✅ required_signals 不复制 expected_signals
- ✅ routes 包不硬编码 confirmation signal 名称
- ✅ 不修改 PrimitiveRegistry
- ✅ 不修改 VerificationMemory
- ✅ 不修改 Trajectory
- ✅ required signal 和 expected signal 使用不同错误语义
- ✅ Admission 不静默补齐缺失 signals
- ✅ Writer 不丢失 signals
- ✅ Registry fingerprint 包含 signals
- ✅ 无 Frontier 或 ContextAdapter 模块
- ✅ 无五层 Agent 修改
- ✅ 无 Coordinator 修改
- ✅ 无 TemplateManager 修改
- ✅ 无 Docker/HTTP/LLM/exploit

---

## 14. Deferred Runtime Fact Adapter

本轮未修复:
- `endpoint` ↔ `injectable_endpoints` 名称映射
- `parameter` ↔ `injectable_params` 结构适配
- `method` 不存在为确认事实
- RuntimeFactAdapter 实现

这些属于:
```text
Route Frontier v1.4b — Context Adapter
```

---

## 15. Ready for Context Adapter

Schema Patch 完成后，下一步可以实现:

```text
b/routes/context_adapter.py  — RuntimeFactAdapter (只读)
b/routes/frontier.py         — RouteFrontier (eligibility gate)
```

前置条件已满足:
- `RouteRequirements.signals` 字段就绪
- `PrimitiveAdapter.get_confirmation_signal()` 就绪
- `PrimitiveAdapter.get_supported_requirement_signals()` 就绪
- `SCHEMA_VERSION = "1.1.0"` 锁定
- Admission 严格验证 `requires.signals`

---

## 16. Final Verdict

```text
SCHEMA_PATCH_ACCEPTED
```

### 变更摘要

| 维度 | 结果 |
|------|------|
| schema_version | 1.0.0 → 1.1.0 |
| RouteRequirements | + signals: tuple[str, ...] = () |
| RouteProposal | + required_signals: tuple[str, ...] = () |
| PrimitiveAdapter | + get_confirmation_signal(), get_supported_requirement_signals() |
| Normalizer | 处理 required_signals → requires.signals |
| Admission | 严格验证 requires.signals |
| AdmissionErrorCode | + UNKNOWN_REQUIRED_SIGNAL, DUPLICATE_REQUIRED_SIGNAL, MISSING_REQUIRED_SIGNALS |
| Writer | 自动兼容（via to_plain()） |
| Registry | 自动兼容（via to_plain() / route_fingerprint()） |
| 测试 | 261 → 294 (all passed) |
| Regression | 0 |
