# Route Frontier v1.4b — 最小 Frontier 实现报告

**日期:** 2026-07-25  
**范围:** 纯离线资格判断  
**基线:** 294 passed  
**最终:** 313 passed

## 1. 修改文件

| 文件 | 修改 |
|---|---|
| `b/routes/frontier.py` | 新增 `build_frontier()` 与稳定 context fingerprint |
| `b/routes/context_adapter.py` | 新增只读 Context/Runtime Fact 适配 |
| `b/routes/schema.py` | 新增 frozen FrontierContext、FrontierEntry、RouteFrontier 与诊断码 |
| `b/routes/__init__.py` | 导出 Frontier 与 ContextAdapter API |
| `b/test_routes.py` | 新增 Frontier、Context 不可变、适配与边界测试 |
| `route_frontier_implementation_report.md` | 本报告 |

未修改:

- `b/agents/*`
- `b/coordinator.py`
- `b/core/template_manager.py`
- `b/memory/*`
- PrimitiveRegistry
- PrimitiveTransitionGraph
- VerificationMemory
- TrajectoryMemory

## 2. Frontier API

```python
def build_frontier(
    registry_snapshot: RouteRegistrySnapshot,
    context: FrontierContext,
) -> RouteFrontier
```

辅助 API:

```python
def context_fingerprint(context: FrontierContext) -> str

def build_frontier_context(
    adapter: PrimitiveAdapter,
    *,
    trajectory=None,
    verification_memory=None,
    runtime_facts_source=None,
) -> FrontierContext
```

`RouteFrontier` 只包含:

- `eligible_routes`
- `blocked_routes`
- `context_fingerprint`

没有 rank、score、selected route 或 best route。

## 3. Context 来源

`FrontierContext` 是 `@dataclass(frozen=True)`:

```python
class FrontierContext:
    current_state: str
    confirmed_signals: tuple[str, ...]
    runtime_facts: Mapping[str, object]
```

适配关系:

| Context 字段 | 只读来源 |
|---|---|
| `current_state` | `trajectory.get_current_state()` |
| `confirmed_signals` | VerificationMemory 的 `working_primitives` / `reflection_confirmed`，信号名称由现有 PrimitiveAdapter 查询 |
| `runtime_facts.endpoint` | VerificationMemory `injectable_endpoints` |
| `runtime_facts.parameter` | VerificationMemory `injectable_params` |
| 额外 runtime facts | 显式传入的已验证 `runtime_facts_source` snapshot |

Context 构造时会:

- 对 signal 去重并按名称排序
- 复制并冻结 runtime facts
- 将嵌套 list 转为 tuple、mapping 转为只读 mapping
- `to_plain()` 每次返回新的 plain dict/list 树

Frontier 不持有 Trajectory 或 VerificationMemory 引用。

## 4. Eligibility Rules

对 Registry snapshot 中的 route 按 `canonical_id` 排序后，严格按以下顺序检查:

1. `route.requires.current_state == context.current_state`
2. `route.requires.signals ⊆ context.confirmed_signals`
3. `route.requires.runtime_facts` 的每个 key 存在于 `context.runtime_facts`

Runtime fact 第一版只检查 key，不解释 endpoint、parameter、method 的值或语义。

`route.expected_signals` 完全不参与资格判断；它仍表示执行后的预期观察。

## 5. Blocked Rules

稳定诊断码:

- `STATE_REQUIREMENT_UNSATISFIED`
- `MISSING_REQUIRED_SIGNALS`
- `MISSING_RUNTIME_FACT`

一条 route 可同时得到多个诊断，顺序固定为 State → Signals → Runtime Facts。

`blocked` 不等于 `rejected`:

- rejected 仍由 Admission 处理，非法 route 不进入 Registry snapshot
- blocked route 合法且保留在 `blocked_routes`，只是当前条件不足

## 6. Deferred Items

以下均未实现:

- route 排序策略、评分、选择
- fallback、unlock、replay
- payload 生成、HTTP、exploit 执行
- state 推进
- VerificationMemory / TrajectoryMemory 写入
- Planner / Coordinator / Agent 接入
- LLM
- endpoint 与 parameter 的层级语义验证

`method` 当前没有稳定的 VerificationMemory 确认源。  
`RuntimeFactAdapter.adapt()` 因此返回:

```text
METHOD_RUNTIME_FACT_DEFERRED
```

并且不在 Context 中伪造 `method` key。只有调用方显式提供已验证 runtime fact snapshot 时才加入。

## 7. Test Results

基线:

```text
python -B -m pytest b/test_routes.py -q
294 passed in 1.62s
```

最终:

```text
python -B -m pytest b/test_routes.py -q
313 passed in 1.85s
```

说明:

- v1.4a 中两项“Frontier/ContextAdapter 不得存在”的阶段性 guard 与 v1.4b 目标直接冲突，已由正向 API 与边界测试替代
- 未使用 skip、xfail、删除失败断言或放宽 Admission 测试
- import smoke: `frontier-import-ok`
- 新模块静态检查未发现 HTTP、LLM、Docker、subprocess、random/time 或 memory 写入依赖

未运行:

- Docker
- HTTP
- LLM
- exploit
- Planner/Coordinator pipeline

未 commit，未 push。
