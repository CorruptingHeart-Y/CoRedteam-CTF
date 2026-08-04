# Materializer Final Fix — 验收报告

**日期**: 2026-07-28  
**分支**: competition-standard  
**最终结论**: `MATERIALIZER_FINAL_FIX_READY`

---

## 1. 修改文件

| 文件 | 操作 | 说明 |
|------|------|------|
| `b/core/plan_contract.py` | 修改 | 新增 `STEP_NOT_DICT` 错误码；`_validate_step` 拒绝非 Mapping step |
| `b/agents/validator.py` | 修改 | 删除与共享结构契约重复的 version/steps/mixed protocol/step type/empty step 静态规则 |
| `b/test_route_materializer_impl.py` | 修改 | 修复 Executor/Memory/Trajectory 副作用测试；删除宽泛 `except Exception`；子进程 LLM client 显式检查 |
| `b/test_route_materializer_acceptance.py` | 新增 | 完整离线 release smoke 测试 + STEP_NOT_DICT 回归测试 |
| `ds_materializer_final_fix_report.md` | 新增 | 本报告 |

**未修改**：
- `b/routes/materializer.py`（无需修改）
- `b/cli.py`、`b/agents/planner.py`、`b/agents/executor.py`、`b/agents/evaluator.py`、`b/agents/consolidator.py`、`b/coordinator.py`、`b/memory/*`、任何 YAML、任何靶题源码

---

## 2. Fix 1 — 拒绝非 Mapping step

### 问题

Codex REVIEW_REJECTED 指出：`validate_plan_structure()` 中的 `_validate_step()` 对非 dict step 执行 `return`（静默跳过），但真实 Validator 在 `st.get()` 处会对非 Mapping 类型崩溃。

### 修改

**文件**：`b/core/plan_contract.py`

1. 新增错误码 `STEP_NOT_DICT = "STEP_NOT_DICT"`
2. `_validate_step()` 不再跳过非 dict step，改为产生诊断：

```python
if not isinstance(st, Mapping):
    diags.append(_diag(
        PlanStructureErrorCode.STEP_NOT_DICT,
        f"steps[{idx}]",
        f"each step must be a JSON object (dict), got {type(st).__name__}",
    ))
    return
```

### 测试

4 项新测试（`b/test_route_materializer_acceptance.py::TestStepNotDictRejection`）：

| 测试 | 输入 | 预期 |
|------|------|------|
| `test_non_dict_step_rejected_by_structure_contract` | `steps: ["string"]` | `STEP_NOT_DICT` |
| `test_non_dict_step_with_int_rejected` | `steps: [42]` | `STEP_NOT_DICT` |
| `test_non_dict_step_with_none_rejected` | `steps: [None]` | `STEP_NOT_DICT` |
| `test_mixed_dict_and_non_dict_steps_rejected` | `steps: [{...}, 12345]` | `STEP_NOT_DICT` |

---

## 3. Fix 2 — 清理 Validator 中冗余静态规则

### 问题

`validate_plan()` 在调用 `validate_plan_structure()` 后，仍保留了重复的静态结构检查：
- `version != 1`
- `steps` 非数组/空
- AST 模式 + command 混合协议
- LEGACY 模式 type 无效
- LEGACY 模式空 step

这些检查与共享结构契约完全重复，Codex 要求删除。

### 修改

**文件**：`b/agents/validator.py`

1. **删除 version 检查**（原 lines 896-897）：
   ```python
   # 旧：if plan.get("version") != 1: errors.append(...)
   # → 已由 validate_plan_structure() 处理
   ```

2. **删除 steps 类型/空检查**（原 lines 899-901）：
   ```python
   # 旧：if not isinstance(steps, list) or not steps: errors.append(...)
   # → 已由 validate_plan_structure() 处理
   ```

3. **删除混合协议检查**（原 lines 944-953）：
   ```python
   # 旧：if is_ast_mode and cmd: errors.append(mixed protocol...)
   # → 已由 validate_plan_structure() 的 MIXED_PROTOCOL 处理
   ```

4. **简化 `_validate_step()`**（原 lines 336-393）：
   - 删除 type 有效性检查（`step_type not in ("python", "shell")`）
   - 删除空 step 检查（`not has_command and not has_code and not has_sdk`）
   - **保留**：text_scan_rules、shell whitelist、output template 等动态 gate

### 保留的动态 gate（Validator 独占）

| Gate | 函数 | 说明 |
|------|------|------|
| Manifest import allowlist/blocklist | `_validate_step_ast_against_manifest` + inline checks | 动态读取 `_MANIFEST_*` |
| Manifest sdk_primitives | `_validate_step_ast_against_manifest` + inline checks | 动态读取 |
| sandbox policy text_scan_rules | `_scan_text` | 读取 `sandbox_policy.yaml` |
| shell whitelist | `_check_shell_whitelist` | 读取 policy |
| Python syntax | `_check_python_syntax` | `ast.parse()` |
| Python import check | `_check_python_imports` | AST 解析实际代码 |
| Broken dependency chain | `_check_broken_dependency_chain` | prior_feedback |
| Trajectory awareness | `_validate_trajectory_awareness` | trajectory + AntiRegression |
| Request contract | `_check_request_contract` | parameter_contract |
| Output template | `_check_python_output_template` | 代码模式匹配 |

---

## 4. Fix 3 — 副作用测试修复

### 4.1 Executor 测试

**旧代码**（`test_materializer_does_not_call_executor_interface`）：
- 错误地 patch 了 `builtins.exec`
- 不验证实际 Executor 入口点
- 无意义（Materializer 当然不调 `exec()`）

**新代码**：
- 直接 patch `agents.executor.run_executor` 和 `agents.executor._run_step`
- monkeypatch 为 fail-fast（计数 + raise AssertionError）
- 导入失败本身即证明 Materializer 不加载 Executor
- 断言调用计数为 0

### 4.2 Verification Memory 测试

**旧代码**（`test_materializer_does_not_write_verification_memory`）：
```python
try:
    from memory.verification_memory import get_verification
    ...  # setup
except Exception:      # ← 宽泛吞噬所有异常
    pass               # ← fixture 失败静默跳过
```

**新代码**：
- 删除 `try: ... except Exception: pass`
- 导入失败 → 测试失败（fail closed）
- monkeypatch 所有已知写入方法（`confirm`, `confirm_endpoint`, `confirm_injectable`, `add_accepted_field`, `add_rejected_field`, `add_blacklist`, `add_bypass`, `add_working_primitive`, `add_flag`, `_save`）
- 断言 `verif_writes["count"] == 0`

### 4.3 Trajectory Memory 测试

**旧代码**（`test_materializer_does_not_mutate_trajectory`）：
```python
try:
    from memory.exploit_trajectory import get_trajectory, reset_trajectory
    ...  # setup
except Exception:      # ← 宽泛吞噬所有异常
    pass               # ← fixture 失败静默跳过
```

**新代码**：
- 删除 `try: ... except Exception: pass`
- 导入失败 → 测试失败（fail closed）
- monkeypatch 所有已知写入方法（`add_node`, `advance`, `add_transition`, `append_to_chain`, `record_action`, `_save`）
- 断言调用计数为 0
- 断言 state/node/transition 不变

### 4.4 子进程 LLM Client 检查

**旧代码**（`test_materializer_import_has_no_planner_or_coordinator_side_effects`）：
- 只检查 `planner`, `coordinator`, `evaluator`, `consolidator`
- 未检查 OpenAI / Anthropic / LangChain / LiteLLM

**新代码**：
- 新增 LLM client 模块检查：
  ```python
  forbidden = {'planner', 'coordinator', 'evaluator', 'consolidator',
               'openai', 'anthropic', 'langchain', 'litellm'}
  ```
- 断言子进程输出不含 `FORBIDDEN_MODULES`

---

## 5. Fix 4 — 完整离线 Release Smoke 测试

**文件**：`b/test_route_materializer_acceptance.py`

### 端到端 Smoke 测试

`TestOfflineReleaseSmoke::test_full_pipeline_cwe1336_to_validator_acceptance`

完整串联：

```
CWE-1336 RouteProposal
  → Normalizer (canonical → CWE-94)
  → YAML Writer (schema_version=1.1.0)
  → Admission (= admitted_candidate)
  → Registry (= 1 route)
  → Frontier (eligible = 1)
  → Materializer (success = true)
  → plan steps = 1
  → Plan Structure = passed
  → Runtime Validator fixture = passed
```

断言清单：

| # | 断言 | 值 |
|---|------|-----|
| 1 | Normalizer ok | True |
| 2 | canonical CWE | CWE-94 |
| 3 | YAML write ok | True |
| 4 | schema_version | 1.1.0 |
| 5 | Admission accepted | True |
| 6 | Admission status | admitted_candidate |
| 7 | Registry registered | True |
| 8 | Registry size | 1 |
| 9 | Frontier eligible | >= 1 |
| 10 | Materializer success | True |
| 11 | plan.json exists | True |
| 12 | plan steps | 1 |
| 13 | validate_plan_structure passed | True |
| 14 | validate_plan called | True (counter) |
| 15 | Runtime Validator passed | True |

### STEP_NOT_DICT 回归测试

4 项测试覆盖 string/int/None/mixed 等多种非 dict step 类型。

---

## 6. 完整测试数量

```
collected = 534
passed    = 534
failed    = 0
skipped   = 0
xfailed   = 0
warnings  = 3
```

### Warnings 明细

```
D:\11\Lib\site-packages\paramiko\pkey.py:82:
  CryptographyDeprecationWarning: TripleDES has been moved to
  cryptography.hazmat.decrepit.ciphers.algorithms.TripleDES
  and will be removed from this module in 48.0.0.

D:\11\Lib\site-packages\paramiko\transport.py:219:
  CryptographyDeprecationWarning: Blowfish has been moved to
  cryptography.hazmat.decrepit.ciphers.algorithms.Blowfish
  and will be removed from this module in 45.0.0.

D:\11\Lib\site-packages\paramiko\transport.py:243:
  CryptographyDeprecationWarning: TripleDES has been moved to
  cryptography.hazmat.decrepit.ciphers.algorithms.TripleDES
  and will be removed from this module in 48.0.0.
```

全部 3 个 warning 来自 `paramiko` 外部库的加密算法弃用提示，非项目代码。无 warning 掩盖失败。

### 按套件

| 套件 | 通过 | 说明 |
|------|------|------|
| `test_routes.py` | 313 | Route Factory 基线 |
| `test_route_materializer_impl.py` | 128 | Materializer 实现测试（含 3 项过时测试替换 + 4 项 Validator fail-closed + 3 项原子写入 + 6 项 side-effect） |
| `test_plan_contract.py` | 28 | 共享契约单测（含回归 meta-test） |
| `test_run_isolation_evidence_guard.py` | 59 | Validator 静态/AST/隔离测试 |
| `test_route_materializer_acceptance.py` | 6 | 离线 release smoke + STEP_NOT_DICT 回归 |
| **合计** | **534** | |

---

## 7. failed / skipped / xfailed / warnings

| 指标 | 值 |
|------|-----|
| `failed` | **0** |
| `skipped` | **0** |
| `xfailed` | **0** |
| `warnings` | **3** — paramiko CryptographyDeprecationWarning（外部库） |

---

## 8. 离线 Release Smoke

```
Smoke test: CWE-1336 RouteProposal
  → Normalizer (canonical → CWE-94)
  → schema_version = 1.1.0        OK
  → canonical CWE = CWE-94        OK  (from CWE-1336)
  → Admission = admitted_candidate OK
  → Registry = 1 route            OK
  → Frontier eligible = 1         OK
  → Materializer success = true   OK
  → plan steps = 1                OK
  → Plan Structure = passed       OK
  → Runtime Validator fixture = passed OK (called=True)

  HTTP calls = 0
  Executor calls = 0
  Memory writes = 0

  ALL SMOKE CHECKS PASSED
```

---

## 9. 纠正后的 Validator 结构关系

```
Plan Structure Validation (validate_plan_structure)
    = 静态 JSON 结构检查（14 个稳定错误码）
    → 纯函数，无 I/O，无全局状态
    → 现在包含 STEP_NOT_DICT 拒绝非 Mapping step

Runtime Validator Acceptance (validate_plan)
    = validate_plan_structure()   ← 共享入口
      + Manifest (safe/blocked modules, sdk_primitives)
      + sandbox policy (text_scan, shell whitelist)
      + trajectory awareness (state/chain/payload regression)
      + Verification Memory
      + AntiRegressionController
      + Request Contract Gate
      + Python syntax / import AST checks (LEGACY mode)
    → 动态 gate，依赖当前运行时状态

冗余静态规则已从 validate_plan() 中删除。
Validator 只保留 Manifest、policy、trajectory、Memory、
anti-regression、request-contract 等动态 gate。
```

---

## 10. 阻断问题

**无阻断问题。**

所有 534 项测试通过。生产代码 `b/routes/materializer.py` 无需修改。

---

## 11. 最终结论

```
MATERIALIZER_FINAL_FIX_READY
```

依据：

1. **非 Mapping step 被拒绝**：`STEP_NOT_DICT` 错误码 + 4 项回归测试，防止 Validator 在 `st.get()` 处崩溃
2. **Validator 冗余静态规则已删除**：version/steps/mixed protocol/step type/empty step 检查统一由 `validate_plan_structure()` 处理；Validator 只保留动态 gate
3. **副作用测试已修复**：
   - Executor 测试直接 patch `run_executor` / `_run_step`
   - Memory/Trajectory 测试删除 `except Exception: pass`
   - 子进程检查包含 OpenAI / Anthropic / LangChain / LiteLLM
4. **离线 release smoke 测试**：完整串联 CWE-1336 → Normalizer → YAML Writer → Admission → Registry → Frontier → Materializer → validate_plan_structure → controlled validate_plan，所有断言失败即测试失败
5. **534 passed, 0 failed, 0 skipped, 0 xfailed**
6. **3 warnings** 全部来自 paramiko 外部库，非项目代码
7. 未实现 CLI，未运行 Stage 1，未发送 HTTP，未执行 exploit，未 commit，未 push
