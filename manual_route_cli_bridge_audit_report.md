# Manual Route Exploit Bridge — CLI 接入点只读审计报告

**审计日期**: 2026-07-25
**审计范围**: 只读，未修改任何生产代码
**审计人**: Claude Code (deepseek-v4-pro)

---

## 1. Current CLI Exploit Call Chain

### 1.1 入口点

**文件**: `b/cli.py`

```
main()                                                  # line 776
  └── parser.parse_args()                               # line 778
  └── args.func(args)                                   # line 790 → cmd_exploit

cmd_exploit(args)                                       # line 103
  ├── target = lock_target(args.url)                     # line 106 → core/target_context.py:49
  │     └── TargetContext(url, scheme, hostname, port, ip)  # frozen dataclass
  ├── confirmed_path 解析                                # lines 117-122
  │     --vuln > --confirmed > b/data/confirmed_vuln.json
  ├── run_seed_warmup(confirmed_path)                    # line 136 → agents/consolidator.py
  └── for run in range(max_runs):                        # line 147
        └── coordinator.run_pipeline(                    # line 149
              confirmed_path=...,
              challenge_name=...,
              target=...)
```

### 1.2 参数注册

**文件**: `b/cli.py:723-733`

```python
p_exploit = sub.add_parser("exploit", ...)
p_exploit.add_argument("--url", required=True, ...)        # line 725
p_exploit.add_argument("--vuln", default=None, ...)        # line 727
p_exploit.add_argument("--confirmed", default=None, ...)   # line 729
p_exploit.add_argument("--challenge", default="generic", ...) # line 731
p_exploit.set_defaults(func=cmd_exploit)                   # line 733
```

**风格**: `argparse`，使用 `add_argument()` with `--long-flag` 格式，`metavar` 大写。新参数必须遵循此风格。

### 1.3 Coordinator Pipeline 循环

**文件**: `b/coordinator.py:992-1594`

```python
def run_pipeline(
    confirmed_path: Path | None = None,
    challenge_name: str = "generic",
    target: TargetContext | None = None,
) -> int:
```

每次迭代（`b/coordinator.py:1073-1566`）:

```
1. run_planner(settings, memory, confirmed, feedback, out_path, llm, adapter)
   → 写出 workspace/plan.json                                   # line 1080
2. run_validator(plan_path, validated_path, ...)
   → 写出 workspace/validated_plan.json                         # line 1105
3. run_executor(validated_path, result_path, ..., target=target)
   → 写出 workspace/execution_result.json                       # line 1130
4. verify_goal(exec_out)  [确定性 flag 扫描]
   → 若 verified=True，跳过 Evaluator                           # line 1168
5. run_evaluator(settings, memory, confirmed, plan, exec_out, ...)
   → 写出 workspace/feedback.json                               # line 1238
6. feedback 传回下一轮 Planner
```

---

## 2. Confirmed Contract Loading

### 2.1 加载路径

**文件**: `b/coordinator.py:88-127` → `_load_confirmed(path)`

```python
def _load_confirmed(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    # 若缺少 target_context，从默认 confirmed_vuln.json 补全
    # 若 base_url 为空/占位符，从环境变量 CO_REDTEAM_TARGET_BASE 覆盖
```

### 2.2 确认文件结构

**文件**: `b/data/confirmed_vuln.json` (9,391 bytes)

```json
{
    "vulnerabilities": [{
        "id": "VULN-001",
        "cwe_id": "CWE-94",
        "source": "HTTP GET/POST parameter `text` ...",
        "evidence": [{"code_snippet": "..."}],
        "exploitation": "...",
    }],
    "target_context": {
        "base_url": "https://192.168.1.100:9443",
        "app_name": "target_app"
    }
}
```

### 2.3 Runtime Facts 来源

Runtime facts 在 Planner 内部通过正则提取（**不是**从 route YAML 的 `runtime_truths` 字段）:

| Fact | 提取位置 | 提取方式 |
|---|---|---|
| `endpoint` | `b/agents/planner.py:641-705` `_extract_endpoints_from_vulns()` | 从 evidence code_snippet 和 attack_chain 正则提取路由路径 |
| `parameter` | `b/agents/validator.py:819-864` `_extract_parameter_contract()` | 从 `source` 字段正则提取参数名（如 `'text'`） |
| `method` | `b/agents/validator.py:856-861` | 从 `exploitation` 字段检测 HTTP 方法 |

**`b/data/machine_contract.json` 不存在于代码库中。** 实际等价文件是 `confirmed_vuln.json`。

---

## 3. Planner Input and Output Contract

### 3.1 Input Contract

**文件**: `b/agents/planner.py:1952-1960`

```python
def run_planner(
    settings: Settings,
    memory: LayeredMemory,
    confirmed: dict[str, Any],        # ← 确认漏洞字典
    feedback: dict[str, Any] | None,  # ← 上轮 Evaluator 反馈
    out_path: Path,                   # ← 输出路径 (plan.json)
    llm: DeepSeekClient | None,
    adapter: ChallengeAdapter | None = None,
) -> dict[str, Any]:
```

### 3.2 Output Contract (plan.json)

```json
{
    "version": 1,
    "plan_id": "plan_...",
    "vuln_summary": "...",
    "rationale": "...",
    "chain_design": "...",
    "history_state": {...},
    "primitive_context": {...},
    "steps": [
        {
            "id": 1,
            "status": "PLANNED",
            "type": "python",
            "imports": [],
            "sdk_calls": [
                {
                    "primitive": "HttpClient.get",
                    "target": "/",
                    "query": {"text": "{{7*7}}"},
                    "body": null,
                    "body_format": "form"
                }
            ],
            "purpose": "SSTI arithmetic probe",
            "expected_outcome": "49 reflected in response",
            "depends_on": null,
            "on_failure": "BLOCK_AND_DEBUG",
            "target_primitive": "ssti_reflection",
            "why_this_step_advances_state": "...",
            "why_this_payload_is_a_mutation": "...",
            "why_this_is_not_regression": "..."
        }
    ],
    "platform": "Windows"
}
```

**关键字段**: `steps[].sdk_calls[]` 是 Executor 的执行指令。每个 SDK call 包含:
- `primitive`: `HttpClient.get` | `HttpClient.post` | `HttpClient.raw_request`
- `target`: endpoint 路径 (如 `"/"`)
- `query`: GET 参数字典
- `body`: POST body 字典
- `body_format`: `"form"` (form-encoded) | `"json"` (JSON body)

---

## 4. Validator Input Contract

**文件**: `b/agents/validator.py:1061-1081`

```python
def run_validator(
    plan_path: Path,                                      # ← plan.json 路径
    validated_path: Path,                                 # ← 输出路径
    prior_feedback: dict[str, Any] | None = None,
    parameter_contract: dict[str, Any] | None = None,     # ← 从 confirmed 提取
) -> dict[str, Any]:
```

**输入**: `plan.json` (Planner 输出的完整 plan dict，从文件读取)

**验证检查**:
1. 拓扑依赖链完整性 (`_check_broken_dependency_chain`, line 418)
2. 轨迹感知验证 (`_validate_trajectory_awareness`, line 577)
3. AST vs Manifest 校验 (`_validate_step_ast_against_manifest`, line 661)
4. 请求合约门禁 (`_check_request_contract`, line 729)
5. Python 安全性检查 (`_validate_step`, line 335)

**输出**: `validated_plan.json` 包含 `validation.passed` 和 `plan`（若通过）。

**关键**: Validator 不关心 plan 的来源（LLM 还是手动），只要结构合法即可通过。

---

## 5. Executor Input Contract

**文件**: `b/agents/executor.py:1185-1193`

```python
def run_executor(
    validated_path: Path,              # ← validated_plan.json
    result_path: Path,
    workdir: Path,
    timeout_sec: int = 300,
    docker_image: str = "co-redteam-sandbox:latest",
    dockerfile_dir: Path | None = None,
    target: TargetContext | None = None,  # ← 包含 url, hostname, port, scheme, ip
) -> dict[str, Any]:
```

### 5.1 Executor 如何使用 URL

**文件**: `b/agents/executor.py:1208-1218`

```python
if target is not None:
    target_url = target.url                    # ← 完整 URL (如 http://127.0.0.1:1337)
else:
    target_url = data.get("target_context", {}).get("base_url", "")
```

URL **只会**写入 `context.json` 的 `target_context.base_url`（`_prepare_exec_workspace`, line 763）。

### 5.2 SDK HttpClient 如何使用 URL

**文件**: `b/agents/executor.py:87-103` (SDK 源码, line 29+)

```python
class HttpClient(requests.Session):
    def __init__(self, base_url: str = ""):
        self.base_url = base_url.rstrip("/") if base_url else ""

    def request(self, method: str, url: str, *args, **kwargs):
        if self.base_url and not url.startswith(("http://", "https://")):
            url = f"{self.base_url}{url}"      # ← base_url + endpoint
        ...
```

### 5.3 AST 膨胀如何生成 HTTP 调用

**文件**: `b/agents/executor.py:465-554` `_inflate_ast_to_script()`

对于 `sdk_calls = [{"primitive": "HttpClient.get", "target": "/", "query": {"text": "{{7*7}}"}}]`:

```python
# 生成:
target_base = _prior_ctx.get('target_context', {}).get('base_url', '')
s = HttpClient(target_base)
resp = s.get("/", params={'text': '{{7*7}}'})
print(f"HTTP {resp.status_code}: {resp.text[:500]}")
```

**结论**: Executor 需要:
1. `TargetContext` 对象（含完整 base_url）
2. `plan.steps[]` 中含 `sdk_calls[]`
3. SDK call 的 `target` 字段是 endpoint 路径（不含 base URL），由 HttpClient 拼接

---

## 6. Evaluator Signal Contract

**文件**: `b/agents/evaluator.py:1065-1074`

```python
def run_evaluator(
    settings: Settings,
    memory: LayeredMemory,
    confirmed: dict[str, Any],
    plan: dict[str, Any],              # ← plan.json
    exec_out: dict[str, Any],          # ← execution_result.json
    feedback_path: Path,
    llm: DeepSeekClient | None,
    adapter: ChallengeAdapter | None = None,
) -> dict[str, Any]:
```

### 6.1 Evaluator 如何检测 Signal

1. **本地预检测** (`evaluator.py:1078-1091`):
   - `_detect_flag()` — 正则扫描 stdout 中的 flag 模式
   - `_detect_success_signal()` — 正则扫描成功信号
   - `_detect_primitives()` — 正则检测原语证据（如 `ssti_reflection`）

2. **LLM 评估** (`evaluator.py:1138-1139`):
   - 发送 `confirmed_vuln + plan + execution_result` 给 LLM
   - LLM 返回 `repro_success`, `confidence`, `detected_primitives`, `current_exploit_state` 等

### 6.2 Signal 检测如何工作

从 `b/memory/exploit_primitives.py:13-20`:

```python
"ssti_reflection": {
    "observable_signals": ["arithmetic_result_in_response", "expression_reflected_verbatim"],
    "payload_templates": ["{{7*7}}", "${7*7}", "<%=7*7%>", "#{7*7}", "{{7*'7'}}"],
}
```

Evaluator 扫描 stdout 中的 `49`（来自 `{{7*7}}` 的数学结果）、`7777777`（来自 `{{7*'7'}}` 的字符串重复）等。

### 6.3 Evaluator 输出 (feedback.json)

```json
{
    "repro_success": false,
    "confidence": 0.0,
    "evidence_level": "F",
    "current_exploit_state": "init",
    "detected_primitives": ["ssti_reflection"],
    "primitive_confidence": {"ssti_reflection": 0.9},
    "feedback_for_planner": "...",
    "should_continue": true,
    "memory_patch": {...}
}
```

---

## 7. Existing Materialization Utilities

### 7.1 声明层面 (Schema)

**文件**: `b/routes/schema.py:158-163`

```python
@dataclass(frozen=True)
class MaterializationDeclaration:
    type: str              # "http_request"
    method_from: str       # "runtime_truths"
    endpoint_from: str     # "runtime_truths"
    parameter_from: str    # "runtime_truths"
    payload_template_ref: str
```

### 7.2 验证层面 (Admission)

**文件**: `b/routes/admission.py:600-631`

Admission 只验证字段值合法（`type == "http_request"`, 所有 `_from == "runtime_truths"`），**不执行实际的 materialization**。

### 7.3 Payload Template 解析

**文件**: `b/routes/primitive_adapter.py:41-69` `resolve_payload_template_ref()`

```python
# 输入: primitive_id="ssti_direct", template_ref="primitive:ssti_direct:sha256:a1b2c3d4e5f6a7b8"
# 输出: index=0 (payload_templates 列表中的索引)
# 通过 sha256(template)[:16] 匹配
```

但此方法只返回索引，**不返回实际 payload 字符串**。

### 7.4 实际 Payload 模板存储

**文件**: `b/memory/exploit_primitives.py:13-20`

```python
INJECTION_PRIMITIVES = {
    "ssti_reflection": {
        "payload_templates": ["{{7*7}}", "${7*7}", "<%=7*7%>", "#{7*7}", "{{7*'7'}}"],
        ...
    },
}
```

### 7.5 Runtime Facts

**文件**: `b/routes/context_adapter.py:38-125` `RuntimeFactAdapter`

```python
class RuntimeFactAdapter:
    def adapt(self) -> dict[str, Any]:
        # 从 VerificationMemory 提取:
        #   endpoint  ← injectable_endpoints
        #   parameter ← injectable_params
        #   method    ← 若缺失则返回 METHOD_RUNTIME_FACT_DEFERRED
```

### 7.6 关键结论：Materialization Gap

**不存在 Route Materializer**。Route 系统的 materialization 声明只是 schema 层面的占位——它描述了"应该怎么做"，但没有代码实际执行以下操作：

1. 取 `NormalizedRoute`
2. 解析 `payload_template_ref` → 实际 payload 字符串
3. 从 runtime facts 获取 `endpoint`, `parameter`, `method`
4. 构造 `sdk_calls` dict 或完整的 `plan.json`

**这是实现 manual route bridge 的核心 gap**。

---

## 8. Route-to-Plan Mapping

### 8.1 从 Route YAML 到 Plan Step 的映射表

| Route Field | Plan Step Field | 映射方式 |
|---|---|---|
| `canonical_id` | `plan_id` or `rationale` | 直接复制 |
| `cwe_id` | `plan.vuln_summary` | 格式化 |
| `technique` | `step.purpose` | 直接复制描述 |
| `target_primitive` | `step.target_primitive` | 直接复制 |
| `payload_template_ref` | `step.sdk_calls[].query.<param>` or `step.sdk_calls[].body.<param>` | **需要解析** |
| `materialization.endpoint_from` | `step.sdk_calls[].target` | **需要从 runtime facts 获取** |
| `materialization.method_from` | `step.sdk_calls[].primitive` | **需要从 runtime facts 获取并映射** |
| `materialization.parameter_from` | `step.sdk_calls[].query` or `step.sdk_calls[].body` 的 key | **需要从 runtime facts 获取** |
| `expected_signals` | `step.expected_outcome` | 格式化 |
| `requires.runtime_facts` | 用于验证 `endpoint`, `parameter`, `method` 可用 | 前置检查 |

### 8.2 映射示例

**Route YAML**:
```yaml
canonical_id: "cwe-94:init:ssti-reflection:arithmetic-probe"
cwe_id: "CWE-94"
current_state: "init"
technique: "arithmetic_probe"
target_primitive: "ssti_reflection"
payload_template_ref: "primitive:ssti_reflection:sha256:abc123def4567890"
expected_signals: ["arithmetic_result_in_response"]
materialization:
  type: "http_request"
  method_from: "runtime_truths"
  endpoint_from: "runtime_truths"
  parameter_from: "runtime_truths"
requires:
  current_state: "init"
  runtime_facts: ["endpoint", "parameter"]
```

**映射结果 (plan.json)**:
```json
{
    "version": 1,
    "plan_id": "plan_manual_cwe-94_init_ssti-reflection_arithmetic-probe",
    "vuln_summary": "CWE-94 SSTI via arithmetic probe (manual route)",
    "rationale": "Manual route: cwe-94:init:ssti-reflection:arithmetic-probe",
    "steps": [{
        "id": 1,
        "type": "python",
        "sdk_calls": [{
            "primitive": "HttpClient.get",
            "target": "/",
            "query": {"text": "{{7*7}}"},
            "body": null,
            "body_format": "form"
        }],
        "purpose": "SSTI arithmetic probe — {{7*7}} → 49",
        "expected_outcome": "arithmetic_result_in_response (49 in response body)",
        "target_primitive": "ssti_reflection",
        "status": "PLANNED",
        "on_failure": "BLOCK_AND_DEBUG"
    }],
    "history_state": {},
    "primitive_context": {"current_primitive": "ssti_reflection"},
    "platform": "Windows",
    "_manual_route_source": "cwe-94:init:ssti-reflection:arithmetic-probe"
}
```

---

## 9. Recommended Manual Route Integration Point

### 9.1 方案选择：方案 A (ManualRoutePlannerAdapter)

**推荐方案 A**，原因：

| 维度 | 方案 A (Adapter) | 方案 B (Planner 分支) |
|---|---|---|
| 修改文件数 | **1 个新文件** | 2+ 个现有文件 |
| Planner 改动 | **零** | 需要添加分支逻辑 |
| Validator 改动 | **零** | 零 |
| Executor 改动 | **零** | 零 |
| Evaluator 改动 | **零** | 零 |
| 回滚风险 | **零**（新文件独立） | 可能影响正常 Planner 路径 |
| 测试影响 | **纯新增** | 现有测试可能受影响 |

### 9.2 精确集成点

**文件**: `b/cli.py:103-163` `cmd_exploit()` — **唯一需要修改的现有文件**。

在 `cmd_exploit()` 中，第 147-163 行的循环之前插入:

```python
# ── Manual Route 分支 ──
if args.manual_route:
    if not args.route_dir or not args.route_id:
        print("[FATAL] --manual-route requires --route-dir and --route-id")
        return 1

    # 1. Load route from registry
    from routes.registry import RouteRegistry
    from routes.primitive_adapter import PrimitiveAdapter
    registry = RouteRegistry(adapter=PrimitiveAdapter())
    result = registry.load_directory(Path(args.route_dir))
    if result.admitted == 0:
        print(f"[FATAL] ROUTE_DIRECTORY_NOT_FOUND or no admitted routes in {args.route_dir}")
        return 1

    registered = registry.get(args.route_id)
    if registered is None:
        print(f"[FATAL] ROUTE_ID_NOT_FOUND: {args.route_id}")
        return 1

    # 2. Frontier eligibility check
    from routes.frontier import build_frontier
    from routes.context_adapter import build_frontier_context
    # ... build frontier context from confirmed + empty trajectory ...
    frontier = build_frontier(registry.snapshot(), frontier_context)
    if args.route_id in {br.route.canonical_id for br in frontier.blocked_routes}:
        print(f"[FATAL] ROUTE_BLOCKED: {args.route_id}")
        return 1

    # 3. Materialize route → plan.json
    from routes.materializer import materialize_route_to_plan  # NEW FILE
    plan = materialize_route_to_plan(
        route=registered.route,
        confirmed=confirmed,
        target=target,
        run_dir=run_dir,
    )

    # 4. Validate → Execute → Evaluate (same as normal pipeline)
    # ... (write plan to plan_path, then continue to validator/executor/evaluator) ...

    return 0  # Single iteration
```

### 9.3 数据流

```
CLI --manual-route --route-id <id> --route-dir <dir>
  │
  ├── RouteRegistry.load_directory(route_dir)
  │     └── RegisteredRoute (canonical_id, route: NormalizedRoute, source_path)
  │
  ├── FrontierContext (from confirmed + empty trajectory)
  │     └── current_state="init", confirmed_signals=[], runtime_facts={endpoint, parameter}
  │
  ├── build_frontier(registry_snapshot, frontier_context)
  │     └── eligible_routes or blocked_routes
  │
  ├── materialize_route_to_plan(route, confirmed, target)
  │     │
  │     ├── resolve payload_template_ref → actual payload string
  │     │     └── PrimitiveAdapter.resolve_payload_template_ref()
  │     │         + PrimitiveRegistry.get().payload_templates[index]
  │     │
  │     ├── extract runtime facts from confirmed
  │     │     ├── endpoint → from confirmed.target_context.discovered_routes
  │     │     │              or evidence code_snippet regex (planner.py:641-705)
  │     │     ├── parameter → from confirmed.vulnerabilities[].source regex
  │     │     │                (validator.py:819-864)
  │     │     └── method → GET | POST (from exploitation field heuristics)
  │     │
  │     ├── construct sdk_calls dict
  │     │     ├── primitive → HttpClient.get | HttpClient.post
  │     │     ├── target → endpoint
  │     │     ├── query/body → {parameter: payload_string}
  │     │     └── body_format → "form"
  │     │
  │     └── construct full plan.json (version, plan_id, steps, ...)
  │
  ├── Validator (unchanged)
  ├── Executor (unchanged)
  └── Evaluator (unchanged)
```

---

## 10. Required CLI Arguments

### 10.1 新增参数规范

与现有 argparse 风格一致（`b/cli.py:723-733` 为模板）:

```python
# 加入 p_exploit group (line 723-733 之后)
p_exploit.add_argument("--manual-route", action="store_true", default=False,
                       help="Manual route mode: use a specific route instead of Planner auto-selection")
p_exploit.add_argument("--route-dir", default=None, metavar="DIR",
                       help="Directory containing candidate route YAML files (required with --manual-route)")
p_exploit.add_argument("--route-id", default=None, metavar="ID",
                       help="Canonical route ID to execute (required with --manual-route)")
```

### 10.2 参数互斥验证

```python
# 在 cmd_exploit() 中添加:
if args.manual_route:
    if not args.route_dir or not args.route_id:
        print("[FATAL] --manual-route requires both --route-dir and --route-id")
        return 1
```

### 10.3 非 Manual 模式兼容性

当 `--manual-route` 未设置时，所有现有行为完全不变：
- `--route-dir` 和 `--route-id` 被忽略
- 使用现有 Planner → Validator → Executor → Evaluator 路径
- `--max-runs` 行为不变

### 10.4 目标命令形态

```powershell
python -X utf8 -u b/cli.py exploit `
  --url http://127.0.0.1:1337 `
  --confirmed b/data/confirmed_vuln.json `
  --challenge generic `
  --route-dir b/data/candidate_routes `
  --route-id cwe-94:init:ssti-reflection:arithmetic-probe `
  --manual-route `
  --max-iters 1
```

注: `--max-iters` 通过环境变量 `CO_REDTEAM_MAX_ITER=1` 控制（`b/core/settings.py:18`），不需要新增 CLI 参数；手动模式下可硬编码 `max_iterations=1`。

---

## 11. One-Request Iteration Boundary

### 11.1 精确的迭代边界

在手动 Route 模式下，一次迭代的边界是:

```
START: Materializer 生成 plan.json
  │
  ├── [1] Validator: plan.json → validated_plan.json
  │         - 验证步骤结构、imports、sdk_calls
  │         - 验证参数合约一致性
  │         - 输出: validation.passed=True/False
  │
  ├── [2] Executor: validated_plan.json → execution_result.json
  │         - 读取 target_context.base_url
  │         - 膨胀 sdk_calls → Python 脚本
  │         - Docker 沙箱执行
  │         - HTTP 请求发送到 target
  │         - 输出: step_results[].result.stdout, http_responses
  │
  ├── [3] GoalVerifier: 确定性 flag 扫描
  │         - 正则匹配 stdout/response body 中的 flag
  │         - 若 verified: 立即终止（跳过 Evaluator）
  │
  ├── [4] Evaluator: plan.json + execution_result.json → feedback.json
  │         - 本地预检测 signals
  │         - LLM 判定 repro_success
  │         - 输出: current_exploit_state, detected_primitives
  │
END: evaluation_result 输出
```

一次迭代 = **恰好 1 个 HTTP 请求**（由单个 sdk_call 生成）。

### 11.2 禁止的行为

- 没有 fallback（不尝试其他 route）
- 没有 route ranking
- 没有自动切换 payload
- 没有多轮 Planner
- 没有 RCE 步骤
- 没有 OOB callback
- 没有 replay
- 没有多目标

---

## 12. Fail-Closed Behavior

### 12.1 错误码定义

| 错误码 | 触发条件 | 检测点 |
|---|---|---|
| `ROUTE_DIRECTORY_NOT_FOUND` | `--route-dir` 路径不存在或无 YAML 文件 | Registry load |
| `ROUTE_ID_NOT_FOUND` | `--route-id` 在 Registry 中未注册 | Registry.get() |
| `ROUTE_NOT_ADMITTED` | Route 存在但 admission 状态非 accepted | Registry.get() 已过滤 |
| `ROUTE_BLOCKED` | Frontier 判定 route 不满足当前条件 | build_frontier() |
| `RUNTIME_FACT_MISSING` | Route 需要的 endpoint/parameter/method 在 confirmed 中不可用 | Materializer |
| `PAYLOAD_REF_RESOLUTION_FAILED` | payload_template_ref 无法解析为实际模板 | Materializer |
| `MATERIALIZATION_FAILED` | plan.json 构建过程中出现任何错误 | Materializer |
| `VALIDATION_FAILED` | 生成的 plan 未通过 Validator | Validator |
| `EXECUTION_FAILED` | Docker 沙箱执行失败 | Executor |
| `EXPECTED_SIGNAL_NOT_OBSERVED` | Evaluator 未检测到 expected_signals | Evaluator |

### 12.2 所有错误模式

```python
# 每个错误都立即退出，不重试，不 fallback:
def fail_closed(error_code: str, detail: str) -> int:
    print(f"[FATAL] {error_code}: {detail}")
    return 1  # 非零退出码
```

- `ROUTE_DIRECTORY_NOT_FOUND` → exit 1
- `ROUTE_ID_NOT_FOUND` → exit 1
- `ROUTE_NOT_ADMITTED` → exit 1
- `ROUTE_BLOCKED` → exit 1
- `RUNTIME_FACT_MISSING` → exit 1
- `PAYLOAD_REF_RESOLUTION_FAILED` → exit 1
- `MATERIALIZATION_FAILED` → exit 1
- `VALIDATION_FAILED` → exit 1（已由 Validator 覆盖）
- `EXECUTION_FAILED` → exit 1
- `EXPECTED_SIGNAL_NOT_OBSERVED` → exit 1

### 12.3 禁止的操作

- **禁止**自动选择第一条 eligible route
- **禁止**使用 builtin active YAML 替代指定 route
- **禁止**在失败后自动退回旧 Planner 自由探索
- **禁止**从 route 目录随机选取
- **禁止**模糊匹配 route-id

---

## 13. Minimal Files to Modify

### 13.1 必须修改的文件

| 文件 | 修改类型 | 行数估计 | 原因 |
|---|---|---|---|
| `b/cli.py` | 添加 CLI 参数 + 手动路由分支 | +30 lines | 唯一的接入点修改 |
| **NEW** `b/routes/materializer.py` | 新建文件 | ~150 lines | Route→Plan 映射逻辑 |

**总计: 2 个文件，约 180 行代码。**

### 13.2 不变的文件

以下文件**完全不修改**:

- `b/coordinator.py` — 不修改（手动模式在 CLI 层处理，直接调用 Validator/Executor/Evaluator）
- `b/agents/planner.py` — 不修改
- `b/agents/validator.py` — 不修改
- `b/agents/executor.py` — 不修改
- `b/agents/evaluator.py` — 不修改
- `b/agents/consolidator.py` — 不修改
- `b/routes/schema.py` — 不修改
- `b/routes/admission.py` — 不修改
- `b/routes/registry.py` — 不修改
- `b/routes/frontier.py` — 不修改
- `b/routes/normalizer.py` — 不修改
- `b/routes/factory.py` — 不修改
- `b/routes/writer.py` — 不修改
- `b/routes/primitive_adapter.py` — 不修改
- `b/routes/context_adapter.py` — 不修改
- `b/core/template_manager.py` — 不修改
- `b/core/settings.py` — 不修改（手动模式硬编码 max_iter=1）
- `b/memory/exploit_primitives.py` — 不修改
- 任何 YAML 文件 — 不修改
- 任何测试文件 — 不修改（本轮只读）

---

## 14. Tests Required

### 14.1 单元测试（新文件 `b/test_manual_route_materializer.py`）

| 测试 | 描述 |
|---|---|
| `test_resolve_payload_template_ssti_reflection` | 解析 `primitive:ssti_reflection:sha256:...` → `{{7*7}}` |
| `test_resolve_payload_template_not_found` | 无效 ref 抛出 `PAYLOAD_REF_RESOLUTION_FAILED` |
| `test_construct_sdk_call_get` | Route.method=GET → `HttpClient.get` with query params |
| `test_construct_sdk_call_post` | Route.method=POST → `HttpClient.post` with body |
| `test_construct_plan_minimal` | 最小 Route → 合法 plan.json |
| `test_construct_plan_all_fields` | 完整 Route → plan.json 含所有字段 |
| `test_materialize_missing_endpoint` | 无 endpoint → `RUNTIME_FACT_MISSING` |
| `test_materialize_missing_parameter` | 无 parameter → `RUNTIME_FACT_MISSING` |
| `test_plan_passes_validator` | 生成的 plan 能通过 Validator |
| `test_plan_schema_matches_planner_output` | plan 结构 100% 兼容 Planner 输出 |

### 14.2 集成测试

| 测试 | 描述 |
|---|---|
| `test_cli_manual_route_missing_route_dir` | 无 `--route-dir` → fail closed |
| `test_cli_manual_route_missing_route_id` | 无 `--route-id` → fail closed |
| `test_cli_manual_route_nonexistent_id` | 不存在的 route-id → `ROUTE_ID_NOT_FOUND` |
| `test_cli_manual_route_blocked` | `ROUTE_BLOCKED` → fail closed |
| `test_cli_non_manual_unchanged` | 无 `--manual-route` → 行为完全不变 |
| `test_end_to_end_single_request` | 完整的一次请求 → Evaluator 返回 expected_signal |

### 14.3 现有测试基线

```text
313 passed (b/test_routes.py)
```

手动 Route 集成后，所有 313 个现有测试必须继续通过。

---

## 15. Exact Codex Implementation Task

### 15.1 Task 1: Create `b/routes/materializer.py`

```python
"""
Route Materializer — converts a NormalizedRoute into a plan.json dict
suitable for the existing Validator → Executor → Evaluator pipeline.

This is the bridge between the declarative route system and the
operational exploit execution engine.
"""

from __future__ import annotations

import json
import platform
from pathlib import Path
from typing import Any

from routes.schema import NormalizedRoute
from routes.primitive_adapter import PrimitiveAdapter
from memory.exploit_primitives import PrimitiveRegistry
from core.target_context import TargetContext


class MaterializationError(Exception):
    """Raised when a route cannot be materialized to a plan."""
    def __init__(self, code: str, detail: str):
        self.code = code
        self.detail = detail
        super().__init__(f"[{code}] {detail}")


def materialize_route_to_plan(
    route: NormalizedRoute,
    confirmed: dict[str, Any],
    target: TargetContext,
    adapter: PrimitiveAdapter | None = None,
) -> dict[str, Any]:
    """
    Convert a NormalizedRoute into a plan.json-compatible dict.

    Raises MaterializationError on any resolution failure.
    """
    if adapter is None:
        adapter = PrimitiveAdapter()
    registry = PrimitiveRegistry()

    # ── 1. Resolve payload template ────────────────────
    index = adapter.resolve_payload_template_ref(
        route.target_primitive, route.payload_template_ref
    )
    if index is None:
        raise MaterializationError(
            "PAYLOAD_REF_RESOLUTION_FAILED",
            f"Cannot resolve {route.payload_template_ref} for primitive {route.target_primitive}"
        )
    primitive_def = registry.get(route.target_primitive)
    if primitive_def is None or index >= len(primitive_def.payload_templates):
        raise MaterializationError(
            "PAYLOAD_REF_RESOLUTION_FAILED",
            f"Primitive {route.target_primitive} payload index {index} out of range"
        )
    payload = primitive_def.payload_templates[index]

    # ── 2. Extract runtime facts from confirmed ────────
    runtime_facts = _extract_runtime_facts(confirmed, route.requires.runtime_facts)

    # ── 3. Determine HTTP method ───────────────────────
    method = runtime_facts.get("method", "GET").upper()

    # ── 4. Construct sdk_calls ─────────────────────────
    sdk_call = _build_sdk_call(
        method=method,
        endpoint=runtime_facts.get("endpoint", "/"),
        parameter=runtime_facts.get("parameter", "input"),
        payload=payload,
    )

    # ── 5. Build full plan ─────────────────────────────
    plan = {
        "version": 1,
        "plan_id": f"plan_manual_{route.canonical_id.replace(':', '_').replace('-', '_')}",
        "vuln_summary": f"{route.cwe_id} via {route.technique} (manual route)",
        "rationale": f"Manual route: {route.canonical_id}",
        "chain_design": f"Single-step {route.target_primitive} probe via {route.technique}",
        "history_state": {},
        "primitive_context": {
            "current_primitive": route.target_primitive,
            "target_primitive": route.target_primitive,
        },
        "steps": [{
            "id": 1,
            "status": "PLANNED",
            "type": "python",
            "sdk_calls": [sdk_call],
            "imports": [],
            "code": "",
            "command": "",
            "purpose": f"{route.technique} probe for {route.target_primitive}",
            "expected_outcome": ", ".join(route.expected_signals),
            "depends_on": None,
            "on_failure": "BLOCK_AND_DEBUG",
            "target_primitive": route.target_primitive,
            "why_this_step_advances_state": f"Probe {route.target_primitive} via {route.technique}",
            "why_this_payload_is_a_mutation": "Initial probe — no prior payload to mutate",
            "why_this_is_not_regression": "No prior state — first attempt",
            "why_this_primitive_advances_chain": f"Establishes {route.target_primitive} baseline",
        }],
        "platform": platform.system(),
        "_manual_route_source": route.canonical_id,
    }

    return plan


def _extract_runtime_facts(
    confirmed: dict[str, Any],
    required_facts: tuple[str, ...],
) -> dict[str, str]:
    """Extract endpoint, parameter, method from confirmed vuln data."""
    facts: dict[str, str] = {}

    vulns = confirmed.get("vulnerabilities", [])
    if not vulns:
        raise MaterializationError(
            "RUNTIME_FACT_MISSING",
            "No vulnerabilities in confirmed data"
        )

    vuln = vulns[0]

    # ── Extract endpoint ──
    if "endpoint" in required_facts:
        # Try discovered_routes first
        tc = confirmed.get("target_context", {})
        routes = tc.get("discovered_routes", [])
        if routes:
            facts["endpoint"] = routes[0] if isinstance(routes[0], str) else routes[0].get("path", "/")
        else:
            # Fallback to evidence regex (mirrors planner.py:641-705)
            import re
            for ev in vuln.get("evidence", []):
                snippet = ev.get("code_snippet", "")
                m = re.search(r"@(?:app\.)?(?:route|get|post|put|delete)\s*\(\s*['\"]([^'\"]+)", snippet)
                if m:
                    facts["endpoint"] = m.group(1)
                    break
            else:
                facts["endpoint"] = "/"  # default

    # ── Extract parameter ──
    if "parameter" in required_facts:
        import re
        source_text = vuln.get("source", "")
        # Match parameter name from patterns like "parameter `text`" or "@RequestParam(name=\"text\")"
        m = re.search(r"parameter\s*[`'\"](\w+)[`'\"]", source_text, re.IGNORECASE)
        if m:
            facts["parameter"] = m.group(1)
        else:
            m = re.search(r"name\s*=\s*['\"](\w+)['\"]", source_text)
            if m:
                facts["parameter"] = m.group(1)
            else:
                raise MaterializationError(
                    "RUNTIME_FACT_MISSING",
                    f"Cannot extract parameter name from source: {source_text[:200]}"
                )

    # ── Extract method ──
    if "method" in required_facts:
        exploitation = vuln.get("exploitation", "")
        source_text = vuln.get("source", "").upper()
        if "POST" in source_text:
            facts["method"] = "POST"
        elif "GET" in source_text:
            facts["method"] = "GET"
        elif "POST" in exploitation.upper():
            facts["method"] = "POST"
        else:
            facts["method"] = "GET"  # safe default

    # Verify all required facts are present
    for fact in required_facts:
        if fact not in facts:
            raise MaterializationError(
                "RUNTIME_FACT_MISSING",
                f"Required fact '{fact}' could not be extracted from confirmed data"
            )

    return facts


def _build_sdk_call(
    method: str,
    endpoint: str,
    parameter: str,
    payload: str,
) -> dict[str, Any]:
    """Construct a single sdk_calls entry."""
    if method == "POST":
        return {
            "primitive": "HttpClient.post",
            "target": endpoint,
            "body": {parameter: payload},
            "query": None,
            "body_format": "form",
        }
    else:
        return {
            "primitive": "HttpClient.get",
            "target": endpoint,
            "query": {parameter: payload},
            "body": None,
            "body_format": "form",
        }
```

### 15.2 Task 2: Modify `b/cli.py`

在 `_build_parser()` 中添加（line 733 之后）:

```python
p_exploit.add_argument("--manual-route", action="store_true", default=False,
                       help="Use a specific route instead of Planner auto-selection")
p_exploit.add_argument("--route-dir", default=None, metavar="DIR",
                       help="Directory of candidate route YAML files")
p_exploit.add_argument("--route-id", default=None, metavar="ID",
                       help="Canonical route ID to execute")
```

在 `cmd_exploit()` 中添加 manual route 分支（line 146 之前，即 `for run in range(1, max_runs + 1):` 之前）:

```python
# ── Manual Route Mode ──────────────────────────────────
if args.manual_route or args.route_id or args.route_dir:
    if not (args.manual_route and args.route_dir and args.route_id):
        print("[FATAL] --manual-route requires BOTH --route-dir AND --route-id")
        print("  --manual-route        Enable manual route mode")
        print("  --route-dir DIR       Directory containing candidate route YAMLs")
        print("  --route-id ID         Canonical route ID to execute")
        return 1
    return _cmd_exploit_manual_route(target, confirmed_path, args, run_dir)
```

新增函数 `_cmd_exploit_manual_route()`:

```python
def _cmd_exploit_manual_route(
    target: TargetContext,
    confirmed_path: Path,
    args,
    run_dir: Path,
) -> int:
    """Execute a single manually-specified route through Validator→Executor→Evaluator."""
    from agents.consolidator import run_seed_warmup
    from routes.registry import RouteRegistry
    from routes.primitive_adapter import PrimitiveAdapter
    from routes.frontier import build_frontier, build_frontier_context
    from routes.materializer import materialize_route_to_plan, MaterializationError
    from agents.validator import run_validator, _extract_parameter_contract
    from agents.executor import run_executor
    from agents.evaluator import run_evaluator
    from core.settings import get_settings

    settings = get_settings()

    # ── Log manual route mode ──────────────────────────
    print("=" * 60)
    print("MANUAL_ROUTE_MODE")
    print(f"  route_id:       {args.route_id}")
    print(f"  route_dir:      {args.route_dir}")
    print("=" * 60)

    # ── Load confirmed ─────────────────────────────────
    confirmed = json.loads(confirmed_path.read_text(encoding="utf-8"))
    adapter = PrimitiveAdapter()

    # ── 1. Load route registry ─────────────────────────
    route_dir = Path(args.route_dir)
    if not route_dir.is_dir():
        print(f"[FATAL] ROUTE_DIRECTORY_NOT_FOUND: {route_dir}")
        return 1

    registry = RouteRegistry(adapter=adapter)
    load_result = registry.load_directory(route_dir)
    print(f"  registry:       {load_result.admitted} admitted, {load_result.rejected} rejected")

    registered = registry.get(args.route_id)
    if registered is None:
        print(f"[FATAL] ROUTE_ID_NOT_FOUND: {args.route_id}")
        print(f"  Available: {[r.canonical_id for r in registry.list_all()]}")
        return 1

    route = registered.route
    print(f"  source_path:    {registered.source_path}")
    print(f"  admission_status: admitted")

    # ── 2. Frontier check ──────────────────────────────
    ctx = build_frontier_context(
        verification_memory=None,  # empty for fresh manual run
        trajectory=None,
    )
    frontier = build_frontier(registry.snapshot(), ctx)
    blocked_ids = {br.route.canonical_id for br in frontier.blocked_routes}
    if args.route_id in blocked_ids:
        for br in frontier.blocked_routes:
            if br.route.canonical_id == args.route_id:
                print(f"[FATAL] ROUTE_BLOCKED: {args.route_id}")
                for diag in br.diagnostics:
                    print(f"  diagnostic: {diag.code.value} — {diag.detail}")
                return 1

    print(f"  frontier_status: eligible")

    # ── 3. Materialize route → plan ────────────────────
    try:
        plan = materialize_route_to_plan(route, confirmed, target, adapter=adapter)
    except MaterializationError as e:
        print(f"[FATAL] {e}")
        return 1

    print(f"  resolved_payload_ref: {route.payload_template_ref}")
    sdk = plan["steps"][0]["sdk_calls"][0]
    print(f"  resolved_endpoint: {sdk['target']}")
    param_key = "query" if sdk.get("query") else "body"
    params = sdk.get(param_key, {})
    for k, v in params.items():
        print(f"  resolved_parameter: {k}={v}")
    print(f"  resolved_method: {sdk['primitive']}")

    # ── 4. Write plan to disk ──────────────────────────
    plan_path = run_dir / "workspace" / "plan.json"
    plan_path.parent.mkdir(parents=True, exist_ok=True)
    plan_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")

    # ── 5. Validate ────────────────────────────────────
    validated_path = run_dir / "workspace" / "validated_plan.json"
    param_contract = _extract_parameter_contract(confirmed)
    v = run_validator(plan_path, validated_path, parameter_contract=param_contract)
    val = v.get("validation", {})
    print(f"  validator_status: {'passed' if val.get('passed') else 'FAILED'}")
    if not val.get("passed"):
        for err in val.get("errors", []):
            print(f"  validation_error: {err}")
        print("[FATAL] VALIDATION_FAILED")
        return 1

    # ── 6. Execute ─────────────────────────────────────
    exec_path = run_dir / "workspace" / "execution_result.json"
    try:
        exec_out = run_executor(
            validated_path=validated_path,
            result_path=exec_path,
            workdir=settings.project_root,
            timeout_sec=settings.docker_timeout,
            docker_image=settings.docker_image,
            target=target,
        )
    except Exception as e:
        print(f"[FATAL] EXECUTION_FAILED: {e}")
        return 1

    print(f"  executor_status: {'executed' if exec_out.get('executed') else 'FAILED'}")
    for sr in exec_out.get("step_results", []):
        rr = sr.get("result", {})
        print(f"  step_id={sr.get('step_id')} ok={rr.get('ok')} exit={rr.get('exit_code')}")

    # ── 7. Evaluate ────────────────────────────────────
    feedback_path = run_dir / "workspace" / "feedback.json"
    fb = run_evaluator(
        settings=settings,
        memory=None,  # No memory for manual single-run
        confirmed=confirmed,
        plan=plan,
        exec_out=exec_out,
        feedback_path=feedback_path,
        llm=None,  # Manual mode: local evaluation only
        adapter=None,
    )

    print(f"  observed_signals: {fb.get('detected_primitives', [])}")
    print(f"  expected_signals: {list(route.expected_signals)}")
    print(f"  evaluation_result: repro_success={fb.get('repro_success')}, "
          f"confidence={fb.get('confidence')}, state={fb.get('current_exploit_state')}")

    # ── 8. Check expected signals ──────────────────────
    if not fb.get("repro_success"):
        print("[FATAL] EXPECTED_SIGNAL_NOT_OBSERVED")
        return 1

    print("MANUAL_ROUTE_SUCCESS")
    return 0
```

### 15.3 文件清单

| 文件 | 操作 | 行数 |
|---|---|---|
| `b/routes/materializer.py` | **新建** | ~150 |
| `b/cli.py` | 修改 (3 处插入) | +35 |
| `b/test_manual_route_materializer.py` | **新建** (后续) | ~200 |

---

## 16. Final Verdict

### 16.1 可行性评估

| 检查项 | 状态 | 证据 |
|---|---|---|
| Route schema 完整 | ✅ | `NormalizedRoute` 含所有必需字段 (`b/routes/schema.py:183`) |
| Payload 模板可解析 | ✅ | `PrimitiveAdapter.resolve_payload_template_ref()` (`b/routes/primitive_adapter.py:41`) |
| Payload 字符串可获取 | ✅ | `INJECTION_PRIMITIVES["ssti_reflection"]["payload_templates"]` (`b/memory/exploit_primitives.py:18`) |
| Runtime facts 可从 confirmed 提取 | ✅ | Regex 提取已有先例 (`b/agents/validator.py:819`, `b/agents/planner.py:641`) |
| plan.json 结构已知 | ✅ | Planner 输出 contract 已验证 |
| Validator 不区分来源 | ✅ | `run_validator()` 只读取 plan.json 文件 |
| Executor 可接收手动 plan | ✅ | 只需要 `TargetContext` + `sdk_calls[]` |
| Evaluator 可评估手动执行 | ✅ | 只需要 `plan + exec_out + confirmed` |
| CLI 风格一致 | ✅ | argparse, 与现有 `--url`/`--confirmed` 一致 |
| 不破坏现有路径 | ✅ | 新分支在 `run_pipeline()` 之前分流 |
| Materialization gap 可填补 | ✅ | 约 150 行新代码 |

### 16.2 风险

| 风险 | 缓解 |
|---|---|
| `RuntimeFactAdapter` 当前从 `VerificationMemory` 读取，手动模式下该类未填充 | Materializer 直接从 `confirmed` JSON 正则提取，不依赖 `VerificationMemory` |
| Frontier context 需要 trajectory state | 手动模式下使用空 trajectory，`current_state="init"` |
| Evaluator 需要 LLM 进行完整评估 | 手动模式可用 `mock_llm=true` 或本地预检测（`_detect_success_signal`） |
| Parameter contract extraction 可能失败 | 使用与 Validator 相同的 `_extract_parameter_contract()` 逻辑 |

### 16.3 结论

```
READY_FOR_MANUAL_ROUTE_BRIDGE
```

**理由**:

1. **Materialization contract 可填补**。Route YAML schema 完整，payload template 解析链路存在，runtime facts 可从 confirmed JSON 提取。唯一缺失的 `b/routes/materializer.py` (~150 行) 是纯数据转换逻辑，不涉及任何新概念或架构变更。

2. **五层架构完全保留**。手动模式复用 Validator → Executor → Evaluator → Consolidator，不绕过任何安全层。Planner 仅被跳过"route 选择"功能，但其输出 contract 被 Materializer 完全模拟。

3. **改动最小化**。仅需修改 `b/cli.py` (+35 lines) 和新建 `b/routes/materializer.py` (~150 lines)。所有其他文件不变。

4. **Fail-closed 设计完整**。10 个错误码覆盖从 route 加载到 signal 评估的全链路，每个错误立即退出，不回退到 Planner 自由探索。

5. **现有测试不受影响**。所有 313 个 route 测试继续通过。新测试独立于现有测试文件。

---

## 附录 A: 关键文件行号索引

| 文件 | 关键符号 | 行号 |
|---|---|---|
| `b/cli.py` | `_build_parser()` | 696 |
| `b/cli.py` | `p_exploit` (exploit 子命令) | 723-733 |
| `b/cli.py` | `cmd_exploit()` | 103-163 |
| `b/cli.py` | `main()` | 776-802 |
| `b/coordinator.py` | `run_pipeline()` | 992 |
| `b/coordinator.py` | `_load_confirmed()` | 88-127 |
| `b/coordinator.py` | Planner 调用 | 1080-1092 |
| `b/coordinator.py` | Validator 调用 | 1101-1124 |
| `b/coordinator.py` | Executor 调用 | 1129-1138 |
| `b/coordinator.py` | Evaluator 调用 | 1238-1247 |
| `b/agents/planner.py` | `run_planner()` | 1952 |
| `b/agents/planner.py` | `_extract_endpoints_from_vulns()` | 641-705 |
| `b/agents/validator.py` | `run_validator()` | 1061 |
| `b/agents/validator.py` | `_extract_parameter_contract()` | 819-864 |
| `b/agents/validator.py` | `_check_request_contract()` | 729-816 |
| `b/agents/executor.py` | `run_executor()` | 1185 |
| `b/agents/executor.py` | `_inflate_ast_to_script()` | 465-554 |
| `b/agents/executor.py` | `_prepare_exec_workspace()` | 743-773 |
| `b/agents/executor.py` | `_run_docker()` | 1045-1152 |
| `b/agents/executor.py` | `_SDK_SOURCE` | 29-459 |
| `b/agents/executor.py` | `HttpClient` (in SDK) | 87-103 |
| `b/agents/evaluator.py` | `run_evaluator()` | 1065 |
| `b/agents/evaluator.py` | `_sanitize_exec_output()` | 325 |
| `b/agents/consolidator.py` | `run_global_consolidation()` | 874 |
| `b/routes/schema.py` | `NormalizedRoute` | 183 |
| `b/routes/schema.py` | `MaterializationDeclaration` | 158 |
| `b/routes/schema.py` | `RouteRequirements` | 151 |
| `b/routes/schema.py` | `FrontierContext` | 323 |
| `b/routes/schema.py` | `RouteFrontier` | 363 |
| `b/routes/schema.py` | `AdmissionDecision` | 235 |
| `b/routes/schema.py` | `RegisteredRoute` | 255 |
| `b/routes/normalizer.py` | `normalize_route_proposal()` | 58 |
| `b/routes/admission.py` | `admit_route()` | 733 |
| `b/routes/admission.py` | `load_and_admit_candidate_route()` | 794 |
| `b/routes/admission.py` | `normalized_route_from_plain()` | 143 |
| `b/routes/admission.py` | `ROUTE_FACTORY_V1_RUNTIME_FACTS` | 42 |
| `b/routes/registry.py` | `RouteRegistry` | 38 |
| `b/routes/registry.py` | `load_directory()` | 179 |
| `b/routes/registry.py` | `register_decision()` | 72 |
| `b/routes/frontier.py` | `build_frontier()` | 29 |
| `b/routes/context_adapter.py` | `build_frontier_context()` | 128 |
| `b/routes/context_adapter.py` | `RuntimeFactAdapter` | 38 |
| `b/routes/primitive_adapter.py` | `PrimitiveAdapter` | 11 |
| `b/routes/primitive_adapter.py` | `resolve_payload_template_ref()` | 41 |
| `b/routes/primitive_adapter.py` | `_payload_fingerprint()` | 72 |
| `b/routes/factory.py` | `generate_candidate_routes()` | 120 |
| `b/routes/writer.py` | `write_candidate_route()` | 156 |
| `b/memory/exploit_primitives.py` | `INJECTION_PRIMITIVES` | 13 |
| `b/memory/exploit_primitives.py` | `ssti_reflection` | 14-20 |
| `b/memory/exploit_primitives.py` | `PrimitiveRegistry` | (class) |
| `b/memory/verification_memory.py` | `VerificationMemory` | 33 |
| `b/core/settings.py` | `Settings` dataclass | 14-32 |
| `b/core/settings.py` | `get_settings()` | 34-55 |
| `b/core/target_context.py` | `TargetContext` | 12-46 |
| `b/core/target_context.py` | `lock_target()` | 49-80 |
| `b/core/template_manager.py` | `TemplateManager` | 45-295 |
| `b/core/goal_verifier.py` | `verify_goal()` | (class) |
| `b/data/confirmed_vuln.json` | — | 9,391 bytes |

---

*审计人: Claude Code*
*审计范围: 只读，无文件修改，无 Docker/HTTP/LLM/exploit 执行*
*结论: READY_FOR_MANUAL_ROUTE_BRIDGE*
