# Offline Route Materializer — 验收报告

**日期**: 2026-07-27  
**分支**: competition-standard  
**基线测试**: 313 passed  
**新增测试**: 112 → 128 passed (验收加固后)  
**验收加固后合计**: 528 passed, 0 failed, 0 skipped, 0 xfailed  

---

## 1. 继承的现有代码

接管文件 `b/routes/materializer.py`（约 498 行），包含以下完整实现：

| 组件 | 行数 | 状态 |
|------|------|------|
| `MaterializationErrorCode` (enum, 11 个错误码) | 20–31 | 已完成 |
| `MaterializationDiagnostic` (dataclass) | 34–38 | 已完成 |
| `MaterializationResult` (dataclass + `error_codes` property) | 41–55 | 已完成 |
| `_REQUIRED_RUNTIME_FACTS` (5 字段常量) | 58–64 | 已完成 |
| `_SUPPORTED_METHODS` / `_SUPPORTED_REQUEST_LOCATIONS` | 65–66 | 已完成 |
| `_STABLE_PAYLOAD_REF` (sha256 regex) | 67–69 | 已完成 |
| `_normalize_runtime_facts()` | 104–152 | 已完成 |
| `_resolve_target()` (URL 安全验证) | 155–191 | 已完成 |
| `_resolve_payload()` (通过 PrimitiveAdapter) | 194–208 | 已完成 |
| `_build_sdk_call()` (HttpClient.get/post) | 211–236 | 已完成 |
| `_build_plan()` (完整 plan 结构) | 239–327 | 已完成 |
| `_plan_contract_is_valid()` (内部 contract 校验) | 330–348 | 已完成 |
| `_resolve_output_path()` (路径安全) | 351–358 | 已完成 |
| `_atomic_write_text()` (原子写入 + 临时文件清理) | 361–395 | 已完成 |
| `materialize_route_plan()` (主入口) | 398–498 | 已完成 |

所有核心功能在接管时已实现，本轮未从零重写。

---

## 2. 实际修改

### 2.1 `b/routes/__init__.py`

新增 4 个 lazy export：

```python
"MaterializationDiagnostic": ("routes.materializer", "MaterializationDiagnostic"),
"MaterializationErrorCode": ("routes.materializer", "MaterializationErrorCode"),
"MaterializationResult": ("routes.materializer", "MaterializationResult"),
"materialize_route_plan": ("routes.materializer", "materialize_route_plan"),
```

同步更新 `__all__` 列表。

### 2.2 `b/test_route_materializer_impl.py`（新增）

新增 112 项测试，覆盖 10 个测试类。

### 2.3 `b/routes/materializer.py`

**未修改**。本轮未改动任何实现代码。

---

## 3. Validator Contract

Materializer 与真实 Validator 共用 `b/core/plan_contract.py::validate_plan_structure()`。

该函数只验证**静态 JSON 结构**。它不检查 Runtime Manifest (`safe_modules`/`blocked_modules`/`sdk_primitives`)、sandbox policy、trajectory、Verification Memory、AntiRegressionController 或 Request Contract Gate。

**关键区分**：

```
Plan Structure Validation (validate_plan_structure)
    = 静态 JSON 结构符合 Validator 输入契约
    → 纯函数，不读取全局状态，不执行 I/O

Runtime Validator Acceptance (validate_plan)
    = 结构通过 + Manifest + policy + trajectory
      + Verification Memory + anti-regression + request-contract
    → 动态 gate，依赖当前运行时状态
```

受控 fixture 测试（`test_plan_passes_real_validator`、`test_real_validator_accepts_materialized_plan_in_controlled_context`）证明 Materializer plan 可在明确合法的运行时上下文中通过真实 `validate_plan()`，但不保证所有真实运行状态下无条件通过。

`test_structure_pass_does_not_imply_runtime_validator_pass` 明确证明：结构合法（含 blocked import `os`）的 plan 被运行时 Manifest gate 拒绝。

---

## 4. Materializer API

```python
def materialize_route_plan(
    route: NormalizedRoute,
    *,
    adapter: PrimitiveAdapter,
    runtime_facts: Mapping[str, object],
    output_path: Path,
    overwrite: bool = False,
) -> MaterializationResult
```

### 输入

| 参数 | 类型 | 说明 |
|------|------|------|
| `route` | `NormalizedRoute` | 已 admitted 的候选路由 |
| `adapter` | `PrimitiveAdapter` | 只读 primitive 查询接口 |
| `runtime_facts` | `Mapping[str, object]` | 5 个必需字符串字段 |
| `output_path` | `Path` | 目标 JSON 文件路径 |
| `overwrite` | `bool` | 默认 False |

### Runtime Facts 契约

```python
{
    "base_url": "http://127.0.0.1:1337",   # HTTP/HTTPS origin only
    "endpoint": "/",                        # relative path
    "parameter": "text",                    # injection parameter name
    "method": "POST",                       # GET or POST
    "request_location": "form",             # query, form, or json
}
```

### 返回值

`MaterializationResult` (frozen dataclass):

| 字段 | 类型 | 说明 |
|------|------|------|
| `success` | `bool` | 是否成功写入 |
| `route_id` | `str \| None` | canonical_id |
| `plan_path` | `str \| None` | 已解析的输出路径 |
| `payload_template_ref` | `str \| None` | stable sha256 ref |
| `resolved_endpoint` | `str \| None` | 规范化后的 endpoint |
| `resolved_parameter` | `str \| None` | runtime parameter |
| `resolved_method` | `str \| None` | GET 或 POST |
| `request_location` | `str \| None` | query/form/json |
| `diagnostics` | `tuple[MaterializationDiagnostic, ...]` | 错误诊断 |
| `error_codes` | `tuple[MaterializationErrorCode, ...]` | 便捷属性 |

---

## 5. Route-to-Plan 映射

```
RouteProposal (CWE-1336)
  → Normalizer (canonical → CWE-94)
    → YAML Writer (candidate file)
      → Admission (admitted_candidate)
        → Registry (1 route)
          → Frontier (eligible)
            → Materializer
              → plan.json (1 step)
```

关键映射：

| Route 字段 | Plan 字段 |
|-----------|----------|
| `canonical_id` | `metadata.route_id` |
| `cwe_id` | `metadata.cwe_id` + `vuln_summary` |
| `target_primitive` | `metadata.target_primitive` + `primitive_context.*` + `step.target_primitive` |
| `technique` | `metadata.technique` + `step.purpose` |
| `payload_template_ref` | `metadata.payload_template_ref` (stable sha256) |
| `expected_signals` | `metadata.expected_signals` + `step.expected_outcome` |
| `current_state` | `history_state.current_state` + `metadata.current_state` |

---

## 6. 测试结果

### 6.1 原有测试

```
313 passed in 2.22s
```

全部 313 项原有测试保持不变通过。

### 6.2 新增测试（验收加固后）

```
128 passed in 0.79s
```

| 测试类 | 测试数 | 覆盖范围 |
|--------|--------|---------|
| `TestPayloadRefResolution` | 5 | 稳定 ref 解析、legacy/unknown/跨 primitive/畸形 ref 拒绝 |
| `TestRuntimeFactsValidation` | 10+16 | 5 个 fact 逐一缺失/空/空白拒绝；不猜测 method/location；不支持类型拒绝 |
| `TestMethodLocationCombinations` | 8 | GET×query/POST×form/POST×json 成功；GET×form/json + POST×query 拒绝；payload 单位置；大小写 |
| `TestURLSafety` | 10 | 外部/scheme-relative endpoint 拒绝；origin 保留；非 HTTP base；path/query/fragment 拒绝；反斜杠/控制字符；斜杠确定性；凭据拒绝 |
| `TestPlanContract` | 13 | 1 step；version=1；内部 contract；真实 Validator 受控 fixture（fail closed）；metadata 保留；确定性；JSON 有效性；无随机 ID；platform=offline；4 项新 Validator 测试 |
| `TestOutputFileBehavior` | 12 | 默认不覆盖；显式覆盖；原子写入无残留；路径穿越/目录拒绝；父目录创建；不同 route 不同 plan；3 项新原子写入故障注入 |
| `TestNonInterference` | 15 | 不修改 Route/Registry；不写 Verification/Trajectory Memory；不 import Planner；不加载 LLM；不发送 HTTP；不调用 Executor；import 无副作用；6 项新 side-effect 测试（网络/Executor/Verification/Trajectory/subprocess import） |
| `TestInternalFunctions` | 20 | 各内部函数单元测试；3 项旧测试替换为 6 项遵循共享契约语义的新测试 |
| `TestEdgeCases` | 8 | 最小/深层 endpoint；query string/fragment 拒绝；不同 parameter 名；state 检查；非 NormalizedRoute 拒绝；resolved 字段；error_codes 属性 |
| `TestMaterializerConstants` | 7 | 常量验证；错误码唯一性；不可变性 |
| **合计** | **128** | |

---

## 7. 全部测试保留

```
b/test_routes.py ........................ 313 passed
b/test_route_materializer_impl.py ....... 128 passed
b/test_plan_contract.py .................  28 passed
b/test_run_isolation_evidence_guard.py ..  59 passed
                                         ---
                                         528 passed, 0 failed, 0 skipped, 0 xfailed
```

原有测试文件 `b/test_routes.py` **未做任何修改**。`b/test_route_materializer_impl.py` 经验收加固从 112 项扩展至 128 项（3 项旧 divergent 契约测试替换为 6 项共享契约测试 + 4 项 Validator 测试 + 3 项原子写入故障注入 + 6 项 side-effect 测试）。

---

## 8. 离线 Release Smoke

```
Smoke test: CWE-1336 RouteProposal
  → Normalizer (canonical → CWE-94)
  → schema 1.1.0 YAML
  → Admission           = admitted_candidate  ✓
  → Registry            = 1 route             ✓
  → Frontier eligible   = 1                   ✓
  → Materializer        = success             ✓
  → plan steps          = 1                   ✓
  → Plan Structure      = passed              ✓
  → Runtime Validator (controlled fixture) = passed  ✓

  HTTP calls            = 0
  Executor calls        = 0
  Memory writes         = 0

  ALL SMOKE CHECKS PASSED
```

---

## 9. 完整最新 YAML 示例

```yaml
schema_version: "1.1.0"
canonical_id: "cwe-94:init:ssti-reflection:arithmetic-probe"
cwe_id: "CWE-94"
current_state: "init"
technique: "arithmetic_probe"
metadata:
  generated_by: "route_factory"
  source_cwe: "CWE-94"
  canonical_cwe: "CWE-94"
activation:
  state: "draft"
  source: "route_factory"
requires:
  current_state: "init"
  runtime_facts:
    - "endpoint"
    - "parameter"
  signals: []
target_primitive: "ssti_reflection"
payload_template_ref: "primitive:ssti_reflection:sha256:d095461aa3182fe4"
expected_signals:
  - "arithmetic_result_in_response"
  - "expression_reflected_verbatim"
materialization:
  type: "http_request"
  method_from: "runtime_truths"
  endpoint_from: "runtime_truths"
  parameter_from: "runtime_truths"
  payload_template_ref: "primitive:ssti_reflection:sha256:d095461aa3182fe4"
success:
  match: "any"
  expected_signals:
    - "arithmetic_result_in_response"
    - "expression_reflected_verbatim"
failure:
  state_change: "none"
replay:
  enabled: false
generation_status: "candidate_only"
```

---

## 10. 脱敏 plan.json

```json
{
  "version": 1,
  "plan_id": "route-a1a7990d01c18e05ce4356bc",
  "vuln_summary": "CWE-94: arithmetic_probe",
  "rationale": "Offline materialization of admitted route cwe-94:init:ssti-reflection:arithmetic-probe",
  "chain_design": "single_step_route_materialization",
  "history_state": {
    "current_state": "init"
  },
  "primitive_context": {
    "current_primitive": "ssti_reflection",
    "target_primitive": "ssti_reflection",
    "transition_edge": "init",
    "fallback_primitive": null
  },
  "target_context": {
    "base_url": "http://127.0.0.1:1337"
  },
  "metadata": {
    "source": "route_factory",
    "route_id": "cwe-94:init:ssti-reflection:arithmetic-probe",
    "route_fingerprint": "b50b943e0e453917efd3ff43d4fe229cd5d67cb4c853d5607225af1dee131132",
    "target_primitive": "ssti_reflection",
    "payload_template_ref": "primitive:ssti_reflection:sha256:d095461aa3182fe4",
    "expected_signals": ["arithmetic_result_in_response", "expression_reflected_verbatim"],
    "cwe_id": "CWE-94",
    "technique": "arithmetic_probe",
    "current_state": "init",
    "request_location": "form",
    "resolved_url": "http://127.0.0.1:1337/"
  },
  "steps": [
    {
      "id": 1,
      "status": "PLANNED",
      "type": "python",
      "imports": [],
      "sdk_calls": [
        {
          "primitive": "HttpClient.post",
          "target": "/",
          "query": null,
          "body": {
            "text": "<REDACTED_PAYLOAD>"
          },
          "body_format": "form"
        }
      ],
      "purpose": "arithmetic_probe",
      "expected_outcome": "arithmetic_result_in_response, expression_reflected_verbatim",
      "depends_on": null,
      "on_failure": "BLOCK_AND_DEBUG",
      "target_primitive": "ssti_reflection",
      "why_this_step_advances_state": "Observe the declared signals for ssti_reflection.",
      "why_this_payload_is_a_mutation": "Use the payload template selected by the admitted route.",
      "why_this_is_not_regression": "Remain on the admitted route at state init.",
      "why_this_primitive_advances_chain": "Exercise the admitted primitive ssti_reflection."
    }
  ],
  "platform": "offline"
}
```

说明：
- `plan_id` 基于确定性 SHA-256，不包含随机值
- payload 已脱敏为 `<REDACTED_PAYLOAD>`
- steps 严格为 1
- payload 仅出现在 `body` 位置（`query` 为 null）
- `platform` 标记为 `"offline"` 确保不会触发在线执行路径

---

## 11. 阻断问题

**无阻断问题。**

已知注意点（已通过测试覆盖纠正）：

1. **真实 Validator 测试已 Fail Closed**：`test_plan_passes_real_validator` 不再捕获 ImportError + warning。Import 失败 → 测试失败。测试通过受控 fixture（monkeypatch Manifest / trajectory / Verification Memory / AntiRegressionController）构造确定性合法环境，并记录调用计数证明 `validate_plan()` 被实际执行。不把 `validate_plan_structure()` 当成真实 Validator 的等价替代。

2. **Materializer 与 Validator 共用 `validate_plan_structure()`**：该函数只验证静态 JSON 结构。真实 `validate_plan()` 还取决于 Runtime Manifest、sandbox policy、trajectory、Verification Memory、AntiRegressionController 和 Request Contract Gate。受控 fixture 测试证明当前 Materializer plan 可在明确合法的运行时上下文中通过 Validator，但不保证所有真实运行状态下无条件通过。

3. **结构合法 ≠ 运行时 Validator 通过**：由 `test_structure_pass_does_not_imply_runtime_validator_pass` 明确证明：结构合法的 plan（含 blocked import `os`）被运行时 Manifest gate 拒绝。

4. **`urllib.parse` 用于 URL 解析而非 HTTP 请求**：Materializer 导入 `urllib.parse.urlsplit/urlunsplit` 仅用于 URL 结构解析和安全验证，不发起任何网络请求。网络入口 monkeypatch 测试已精确验证。

5. **原子写入故障路径已测试**：`test_atomic_write_cleans_temp_after_replace_failure`、`test_atomic_overwrite_failure_preserves_original_file`、`test_atomic_failure_returns_stable_error_code` 覆盖了 os.replace() 失败时的清理和保护行为。

---

## 12. 测试结果（验收加固后）

```
collected = 528
passed    = 528
failed    = 0
skipped   = 0
xfailed   = 0
warnings  = 3  (paramiko CryptographyDeprecationWarning — external library, not project code)
```

### 按套件：

| 套件 | 通过 |
|------|------|
| `test_routes.py` | 313 |
| `test_route_materializer_impl.py` | 128 |
| `test_plan_contract.py` | 28 |
| `test_run_isolation_evidence_guard.py` | 59 |
| **合计** | **528** |

### compile / import / side-effect smoke：

| 检查 | 结果 |
|------|------|
| `py_compile` | COMPILE_OK |
| 子进程 import | returncode=0, stderr 无 Traceback |
| import 不加载 Planner/Coordinator/LLM | NO_FORBIDDEN_IMPORTS |
| 网络接口调用 | 0 |
| Executor 调用 | 0 |
| Verification Memory 写入 | 0 |
| Trajectory 变更 | 0 |

## 13. 最终结论

```
MATERIALIZER_ACCEPTANCE_HARDENED
```

**依据**：

- Materializer 实现完整，本轮仅最小修改 `b/routes/materializer.py`（无修改）
- 128 项 Materializer 测试全部通过（0 failed, 0 skipped, 0 xfailed）
- 313 项原有 Route 测试全部保留通过
- 28 项共享契约测试全部通过
- 59 项 Validator 静态/AST 测试全部通过
- 3 项旧 divergent 契约测试已替换为遵循共享契约语义的 6 项新测试
- 真实 Validator 测试已 Fail Closed：受控 fixture 证明 Materializer plan 可被真实 `validate_plan()` 接受
- `test_structure_pass_does_not_imply_runtime_validator_pass` 明确证明结构合法 ≠ 运行时通过
- 原子写入故障注入测试覆盖 os.replace() 失败时的清理和保护
- 网络/Executor/Verification Memory/Trajectory side-effect 测试全部 fail-fast
- 子进程 import smoke 通过：returncode=0, 无 Planner/Coordinator/LLM 加载
- 离线 smoke test 完整通过：CWE-1336 → CWE-94 → Normalizer → Admission → Registry → Frontier → Materializer → 单步 plan.json
- 全过程零 HTTP、零 Docker、零 LLM、零 Executor
- Plan contract 通过真实 Validator 受控 fixture 校验
- 仅允许 `primitive:<id>:sha256:<16 hex>` payload ref，通过 PrimitiveAdapter 动态解析
- URL 安全：仅 HTTP/HTTPS origin，endpoint 必须为相对路径，拒绝 scheme-relative 和跨域
- 原子写入，确定性内容，默认不覆盖
- 不修改 Route、Registry、Verification Memory、Trajectory Memory
