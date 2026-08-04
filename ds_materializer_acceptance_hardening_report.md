# Materializer Acceptance Hardening — 最终验收报告

**日期**: 2026-07-27  
**分支**: competition-standard  
**最终结论**: `MATERIALIZER_ACCEPTANCE_HARDENED`

---

## 1. 修改文件

| 文件 | 操作 | 说明 |
|------|------|------|
| `b/test_route_materializer_impl.py` | 修改 | 替换 3 项过时测试，新增 Validator fail-closed 测试，新增原子写入故障注入，新增 side-effect 测试 |
| `b/test_plan_contract.py` | 修改 | 更新回归 meta-test 以反映 0 failed |
| `offline_route_materializer_report.md` | 修改 | 纠正 false claims，更新测试计数 |
| `ds_materializer_acceptance_hardening_report.md` | 新增 | 本报告 |

**未修改**：
- `b/routes/materializer.py`（生产实现无需修改）
- `b/core/plan_contract.py`
- `b/agents/validator.py`
- `b/cli.py`、`b/agents/planner.py`、`b/agents/executor.py`、`b/agents/evaluator.py`、`b/agents/consolidator.py`、`b/coordinator.py`、`b/memory/*`、任何 YAML、任何靶题源码

---

## 2. 三个过时测试的改写

### 旧测试（编码已被废弃的 Materializer 私有契约）

| 旧测试 | 旧断言 | 问题 |
|--------|--------|------|
| `test_plan_contract_is_valid_rejects_multi_step` | `_plan_contract_is_valid` 拒绝多 step | 真实 Validator 接受多 step；共享契约不拒绝 |
| `test_plan_contract_is_valid_rejects_shell_type` | AST sdk_calls 模式下 type=shell 被拒绝 | AST 模式不检查 type 字段 |
| `test_plan_contract_is_valid_rejects_dual_location` | query 和 body 同时存在被拒绝 | 共享契约只做字段类型检查，不做互斥 |

### 新测试（遵循共享契约语义）

#### multi-step → 拆为 2 项

1. **`test_shared_plan_structure_contract_does_not_reject_valid_multi_step_plan`**
   - 调用 `validate_plan_structure()` 直接验证
   - 多 step plan 返回 `passed=True`
   - 证明共享契约忠实于真实 Validator

2. **`test_materializer_output_still_contains_exactly_one_step`**
   - 通过 `materialize_route_plan()` 主路径生成
   - 断言 `len(plan["steps"]) == 1`
   - 证明 Materializer 产品边界仍然是单步（由 `_build_plan` 保证）

#### shell type → 拆为 2 项

3. **`test_shared_contract_follows_validator_ast_type_behavior`**
   - AST 模式 (sdk_calls 存在) + `type=shell`：共享契约不拒绝
   - LEGACY 模式 (无 sdk_calls) + `type=ruby`：共享契约正确拒绝 (`STEP_TYPE_INVALID`)
   - 证明共享契约与真实 Validator 行为一致

4. **`test_materializer_itself_generates_python_step`**
   - Materializer 输出始终 `type == "python"`
   - 证明 Materializer 自身不变式由构造流程保证

#### dual-location → 拆为 2 项

5. **`test_shared_structure_contract_only_checks_request_container_types`**
   - query 和 body 同时为 dict → 结构通过
   - query 为非 dict 字符串 → 结构拒绝 (`REQUEST_CONTAINER_INVALID`)
   - 证明共享契约只做类型检查，不做互斥

6. **`test_materializer_output_places_payload_in_exactly_one_location`**
   - GET+query, POST+form, POST+json 三种组合
   - 每个组合中 payload 仅在 query 或 body 一个位置
   - 证明 `_build_sdk_call` 保证单位置不变式

---

## 3. 真实 Validator 测试 — Fail Closed

### 旧行为（已纠正）

```python
try:
    from agents.validator import validate_plan
    validation = validate_plan(plan)
    assert validation["passed"]
except ImportError:
    warnings.warn("Real Validator import skipped...")  # ← FALSE PASS
```

问题：
- ImportError → warning → pytest 仍计为 passed
- `validate_plan()` 没有被实际调用时也算 passed
- 没有返回值检查时也算 passed

### 新行为 — 4 项 Fail Closed 测试

7. **`test_plan_passes_real_validator`**（重写）
   - Import 失败 → 测试失败（无 try/except ImportError）
   - 受控 monkeypatch fixture：Manifest (`HttpClient.get/post` 在 `sdk_primitives` 中)、trajectory (`init` 状态)、Verification Memory (空)、AntiRegressionController (全部返回 ok)
   - 调用计数器 `call_record["called"]` 证明 `validate_plan()` 被实际执行
   - 断言 `validation["passed"] is True`

8. **`test_real_validator_is_actually_called`**（新增）
   - monkeypatch wrapper 记录调用次数
   - 断言 `call_flag["hit"] >= 1`

9. **`test_real_validator_accepts_materialized_plan_in_controlled_context`**（新增）
   - 完整端到端：Materializer → plan → 真实 `validate_plan()` → `passed=True`
   - 所有动态依赖 monkeypatch 为合法状态

10. **`test_real_validator_import_failure_is_not_silently_accepted`**（新增）
    - 直接 import 并验证 callable
    - ImportError → 测试自然失败（不捕获）
    - 不允许 warning/skip/xfail

11. **`test_structure_pass_does_not_imply_runtime_validator_pass`**（新增）
    - 构造结构合法但含 blocked import `"os"` 的 plan
    - `validate_plan_structure()` → `passed=True`
    - `validate_plan()` → `passed=False`（Manifest gate 拒绝）
    - `structure_invalid` 不为 `True`（拒绝来自运行时 gate）
    - **明确证明：结构合法 ≠ 运行时通过**

---

## 4. 受控 Validator Fixture

真实 `validate_plan()` 依赖以下运行时组件，fixture 中全部 monkeypatch 为确定性的合法状态：

| 组件 | Monkeypatch | 作用 |
|------|-------------|------|
| `_MANIFEST_SAFE_MODULES` | `{"json", "base64", "re", "time", "hashlib", "urllib.parse"}` | 允许 Materializer 使用的 import |
| `_MANIFEST_BLOCKED_MODULES` | `{"os", "subprocess", "socket", "ctypes", "requests"}` | 阻断危险模块 |
| `_MANIFEST_SDK_PRIMITIVES` | `{"HttpClient.get", "HttpClient.post"}` | 允许 Materializer 使用的 HttpClient 原语 |
| `_manifest_imported` | `True` | 跳过 manifest lazy-load |
| Trajectory `get_current_state` | `"init"` | 与 Route 的 `init` state 一致 |
| Trajectory `get_current_chain` | `[]` | 空链，无断裂 |
| Verification Memory | `reset_verification()` + `_default_facts()` | 无阻断条目 |
| `AntiRegressionController.validate_state_regression` | `(True, "")` | 无状态退化 |
| `AntiRegressionController.validate_chain_break` | `(True, "")` | 无链断裂 |
| `AntiRegressionController.validate_payload_regression` | `(True, "")` | 无 payload 退化 |
| `AntiRegressionController.validate_exploit_reasoning` | `(True, [])` | 无 reasoning 问题 |
| `sandbox_policy.yaml` | 不 monkeypatch（实际文件存在且合法） | 正常加载 |

**不绕过 `validate_plan_structure()`**：结构预检仍在 `validate_plan()` 入口执行。

**不把 `validate_plan()` 整体 mock 掉**：调用计数器证明函数被实际执行。

**不保证所有运行时无条件通过**：fixture 只证明 Materializer plan 在明确合法的上下文中可被接受。

---

## 5. 原子替换失败注入

### 情形 A：新文件写入时 os.replace() 失败

12. **`test_atomic_write_cleans_temp_after_replace_failure`**
    - monkeypatch `os.replace` → `OSError`
    - 断言：
      - 返回 `WRITE_FAILED`
      - `.tmp` 文件被清理（`tmp_path.glob(".*.tmp")` 为空）
      - 目标文件不存在
      - 目录中无残留

### 情形 B：overwrite 时 os.replace() 失败

13. **`test_atomic_overwrite_failure_preserves_original_file`**
    - 预写 `"original content, not JSON"` 到目标文件
    - monkeypatch `os.replace` → `OSError`
    - 断言：
      - 返回 `WRITE_FAILED`
      - 原目标内容仍是 `"original content, not JSON"`
      - `.tmp` 文件被清理
      - 只有 `plan.json` 一个文件存在

### 情形 C：稳定错误码

14. **`test_atomic_failure_returns_stable_error_code`**
    - 连续 5 次失败
    - 每次错误码集合相同
    - 错误码为 `WRITE_FAILED`

---

## 6. 网络、Executor、Memory、Trajectory 测试

### 6.1 网络

15. **`test_materializer_does_not_call_network_interfaces`**
    - monkeypatch `socket.socket.connect` → `AssertionError`
    - monkeypatch `urllib.request.urlopen` → `AssertionError`
    - 调用 Materializer 后断言 `socket_called["hit"]` 和 `urllib_called["hit"]` 均为 `False`
    - 允许 `urllib.parse` 用于 URL 解析

### 6.2 Executor

16. **`test_materializer_does_not_call_executor_interface`**
    - 验证 Materializer 不 import 或调用任何 executor 模块
    - 源码检查已在 `test_does_not_call_executor` 中覆盖

### 6.3 Verification Memory

17. **`test_materializer_does_not_write_verification_memory`**
    - monkeypatch `VerificationMemory.set` / `add_verification` → `AssertionError`
    - 调用后写入计数为 0

### 6.4 Trajectory Memory

18. **`test_materializer_does_not_mutate_trajectory`**
    - 记录执行前 current_state / node_count / transition_count
    - monkeypatch `add_node` / `advance` / `add_transition` → `AssertionError`
    - 执行后全部不变

### 6.5 子进程 Import

19. **`test_materializer_import_subprocess_returns_zero`**
    - 子进程 `from routes.materializer import materialize_route_plan`
    - `returncode == 0`，stderr 无 `Traceback`

20. **`test_materializer_import_has_no_planner_or_coordinator_side_effects`**
    - 子进程 import 前后 `sys.modules` 差集
    - 不含 `planner` / `coordinator` / `evaluator` / `consolidator`

### 6.6 源码扫描（原有，保留）

- `test_does_not_write_verification_memory`（源码扫描）
- `test_does_not_write_trajectory_memory`（源码扫描）
- `test_does_not_import_planner`（源码扫描）
- `test_does_not_load_llm`（源码扫描）
- `test_does_not_send_http`（源码扫描）
- `test_does_not_call_executor`（源码扫描）
- `test_import_has_no_side_effects`（子进程磁盘检查）

---

## 7. 子进程 Import 结果

| 检查 | 结果 |
|------|------|
| `returncode` | `0` |
| stderr Traceback | 无 |
| Planner 加载 | 否 |
| Coordinator 加载 | 否 |
| Evaluator 加载 | 否 |
| Consolidator 加载 | 否 |
| LLM client 加载 | 否 |
| 磁盘文件创建 | 无 |

---

## 8. 完整测试数量

```
collected = 528
passed    = 528
failed    = 0
skipped   = 0
xfailed   = 0
warnings  = 3  (paramiko CryptographyDeprecationWarning — external library)
```

### 按套件

| 套件 | 通过 |
|------|------|
| `test_routes.py` | 313 |
| `test_route_materializer_impl.py` | 128 |
| `test_plan_contract.py` | 28 |
| `test_run_isolation_evidence_guard.py` | 59 |
| **合计** | **528** |

### compile / import smoke

| 检查 | 结果 |
|------|------|
| `py_compile` | COMPILE_OK |
| 子进程 import | returncode=0, stderr 无 Traceback |
| import 不加载 Planner/Coordinator/LLM | NO_FORBIDDEN_IMPORTS |

---

## 9. failed / skipped / xfailed / warnings

| 指标 | 值 |
|------|-----|
| `failed` | **0** |
| `skipped` | **0** |
| `xfailed` | **0** |
| `warnings` | **3** — `paramiko` `CryptographyDeprecationWarning` (TripleDES, Blowfish)，外部库，非项目代码 |

无 warning 掩盖失败。所有 3 个 warning 均来自 paramiko SSH 库的加密算法弃用提示。

---

## 10. 离线 Release Smoke

```
Smoke test: CWE-1336 RouteProposal
  → Normalizer (canonical → CWE-94)
  → schema_version = 1.1.0        OK
  → canonical CWE = CWE-94        OK  (from CWE-1336)
  → Admission = admitted_candidate OK
  → Materializer success = True   OK
  → plan steps = 1                OK
  → Plan Structure = passed       OK
  → Runtime Validator fixture = passed OK

  HTTP calls = 0
  Executor calls = 0
  Memory writes = 0

  ALL SMOKE CHECKS PASSED
```

---

## 11. 纠正后的验收声明

### 纠正前（offline_route_materializer_report.md 旧版）

| 旧声明 | 问题 | 纠正 |
|--------|------|------|
| ImportError 时测试自动跳过 | `test_plan_passes_real_validator` catch ImportError + warning → false pass | Fail closed：ImportError → 测试失败 |
| 内部 `_plan_contract_is_valid` 等价于真实 Validator | 只验证静态结构，不验证 Manifest/policy/trajectory/Memory | 明确区分 Structure Validation 与 Runtime Acceptance |
| 112 passed 证明真实 Validator 完整通过 | ImportError 时 `validate_plan()` 根本没被调用 | 受控 fixture + 调用计数器证明实际执行 |
| Validator 必须加载完整 LLM 链 | 仅指结构预检；运行时 gate 仍需动态依赖 | 结构预检纯函数无依赖；运行时 gate 由 fixture 模拟 |

### 纠正后

```
Plan Structure Validation (validate_plan_structure)
    = 静态 JSON 结构符合 Validator 输入契约
    → 纯函数，不读取全局状态，不执行 I/O

Runtime Validator Acceptance (validate_plan)
    = 结构通过 + Manifest + policy + trajectory
      + Verification Memory + anti-regression + request-contract
    → 动态 gate，依赖当前运行时状态

Materializer plan:
    → validate_plan_structure: PASSED
    → validate_plan (controlled fixture): PASSED
    → 不保证所有真实运行状态下无条件通过
```

---

## 12. 阻断问题

**无阻断问题。**

所有测试通过（528 passed, 0 failed, 0 skipped, 0 xfailed）。

生产代码 `b/routes/materializer.py` 无需修改。原子写入故障注入测试证明故障路径的清理和保护行为正确。

---

## 13. 最终结论

```
MATERIALIZER_ACCEPTANCE_HARDENED
```

依据：

- 3 项过时 divergent 契约测试已替换为 6 项遵循共享契约语义的测试
- 真实 Validator 测试已 Fail Closed：4 项新测试（受控 fixture + 调用计数器 + 结构≠运行时的明确证明）
- 3 项原子写入故障注入测试覆盖 os.replace() 失败时的清理和保护
- 6 项 side-effect 测试覆盖网络/Executor/Verification Memory/Trajectory/subprocess import
- 2 项子进程 import smoke 验证无 Planner/Coordinator/LLM 加载
- 528 passed, 0 failed, 0 skipped, 0 xfailed
- 3 warnings 全部来自 paramiko 外部库，非项目代码
- 离线 release smoke 完整通过：CWE-1336 → Normalizer → Admission → Materializer → Plan Structure → Runtime Validator fixture
- 全过程零 HTTP、零 Docker、零 LLM、零 Executor
- 未修改 CLI、未运行 Stage 1、未发送 HTTP、未执行 exploit、未 commit、未 push
