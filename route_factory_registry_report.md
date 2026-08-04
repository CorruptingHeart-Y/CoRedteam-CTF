# Route Factory v1.3 — 离线 Route Registry 实现报告

**日期：** 2026-07-25  
**结论：** 完成；离线全套测试 261 项通过，原 212 项基线全部保留。

## 1. 修改文件

- `b/routes/registry.py`：新增进程内 `RouteRegistry`、稳定 fingerprint、目录加载、显式注册、静态查询和 snapshot。
- `b/routes/schema.py`：新增 Registry 稳定错误码与 frozen dataclass；metadata 改为递归冻结，确保 Registry route/snapshot 不暴露内部可变容器。
- `b/routes/__init__.py`：以既有 lazy export 风格导出 Registry API，不在 import 时扫描或读取 YAML。
- `b/test_routes.py`：新增 49 个 Registry 测试项。
- `route_factory_registry_report.md`：本报告。

未修改 `b/routes/admission.py`，Registry 直接复用现有 Admission。未修改任何 Agent、Coordinator、TemplateManager、Memory、状态机、Primitive Graph、builtin/generated YAML。用户原有的 `target_codebase/cybench_web_challenges/2/` 23 个删除保持不变。

## 2. Registry 调用链

```text
调用者显式创建 RouteRegistry(adapter)
  -> 显式调用 load_directory(directory)
  -> 仅枚举目录当前层的 .yaml/.yml（稳定路径顺序）
  -> 校验 real path 仍位于显式目录内
  -> 对每个文件调用 load_and_admit_candidate_route()
  -> 只将 accepted=True + status=admitted_candidate + route 非空的 decision
     交给 register_decision()
  -> 对 route.to_plain() 计算 fingerprint
  -> canonical_id 去重或冲突判定
  -> 存入进程内 Registry
```

显式注册 API 同样只接收 `AdmissionDecision`；普通 dict、rejected decision、缺 route、错误 status、被篡改为 active/non-candidate 的 decision 均失败关闭。

## 3. 数据结构

新增的结构均为 `@dataclass(frozen=True)`，并提供 `to_plain()`：

- `RegisteredRoute`
- `RegistryDiagnostic`
- `RegistryRegistrationResult`
- `RegistryLoadResult`
- `RouteRegistrySnapshot`
- `RegistryErrorCode`

`RegistryDiagnostic` 使用 Registry 稳定错误码；Admission 拒绝文件时，同时在 `admission_code` 保留原始 `AdmissionErrorCode`，不解析英文 message 判断类型。

## 4. Fingerprint 算法

```python
sha256(
    json.dumps(
        route.to_plain(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
).hexdigest()
```

Fingerprint 不包含 source path，不依赖 YAML 缩进、键顺序、时间或随机数。Route 已经通过 Admission，因此只包含稳定 payload ref，不包含真实 payload。

## 5. Duplicate 与 Conflict

- 同 canonical ID + 同 fingerprint：保留第一条，后续返回 `DUPLICATE_ROUTE`，不重复注册，不视为 fatal。
- 同 canonical ID + 不同 fingerprint：保留第一条，拒绝后续定义并返回 `CONFLICTING_ROUTE_DEFINITION`，绝不覆盖或合并。
- 不同 canonical ID：分别注册。

目录加载计数中，`files_admitted` 包含通过 Admission 后成为 duplicate/conflict 的文件；`rejected` 只计 Admission/路径安全拒绝，duplicate 和 conflict 由独立字段计数。

## 6. 目录加载行为

- 只读取调用者显式给出的目录，不创建目录。
- 只读取当前层 `.yaml` / `.yml`，不递归；JSON 和其他文件不计入 candidate。
- 文件按规范化绝对路径的确定性字典序处理。
- 每个 YAML 都经过既有 safe loader 与 Admission；单文件失败不会中断后续文件。
- 文件 real path 必须仍在目录 real path 内；逃逸路径返回 `UNSAFE_REGISTRY_PATH`。
- 不存在目录、非目录分别返回 `REGISTRY_DIRECTORY_NOT_FOUND`、`REGISTRY_PATH_NOT_DIRECTORY`。
- Registry 不写文件、不修改 YAML、Verification Memory 或 Trajectory Memory。

## 7. 查询 API

支持：

```python
registry.get(canonical_id)
registry.list_all()
registry.query(
    cwe_id=None,
    current_state=None,
    target_primitive=None,
    technique=None,
)
len(registry)
```

查询条件使用 AND，结果为按 canonical ID 排序的 tuple。CWE 查询直接复用现有 `SSTI_CWE_ALIASES`；未知 CWE 返回空 tuple。查询仅比较静态字段，不检查 RuntimeTruths/requires，不评分、排名或选择 route。

## 8. Snapshot

`snapshot()` 返回 frozen `RouteRegistrySnapshot`：route 与 diagnostic 均为稳定 tuple；`NormalizedRoute.metadata` 递归冻结为 mapping proxy/tuple；`to_plain()` 每次生成隔离的普通 dict/list。后续 Registry 注册不会改变已有 snapshot，snapshot 不含内部 Registry dict 引用或真实 payload。

## 9. 新增测试

在原 212 项基础上新增 49 项，覆盖：

- Admission decision 注册边界和 dict/伪造 active decision 绕过防护；
- get/list/query 与 AND 过滤、CWE alias、无 runtime 判定；
- fingerprint 确定性、路径无关、YAML 键序无关、内容变化；
- duplicate/conflict 与 first-wins；
- YAML/YML、非递归、稳定顺序、错误继续、目录错误和路径逃逸；
- active、legacy payload ref、state mutation 永不入库；
- 无文件写入、无 Memory 修改、无 LLM/Docker/HTTP；
- snapshot 不可变、隔离、稳定顺序和 plain JSON 序列化。

Windows 当前环境不允许创建真实 OS symlink，因此 symlink 用例以 monkeypatch 精确模拟 `Path.resolve()` 指向目录外，覆盖相同的 real-path containment 拒绝分支；真实 OS symlink 集成验证保留为环境相关项。

## 10. 验证结果

```text
修改前基线：212 passed in 1.25s
Registry 定向：51 passed, 208 deselected in 0.72s
最终全套：261 passed in 1.92s
Python compileall：passed
routes/Registry import smoke：passed
git diff --check：passed
```

额外临时目录 smoke：生成 3 个 YAML，3 个均通过 Admission；Registry 结果为：

```text
files_discovered=3
files_admitted=3
routes_registered=1
duplicates=1
conflicts=1
rejected=0
static query result=1
snapshot route count=1
```

## 11. 原 212 项保留情况

修改前在可写 workspace basetemp 下实测 `212 passed`。最终同一 `b/test_routes.py` 收集并通过 261 项，因此原 212 项全部保留且无回归。

## 12. Deferred

- Planner/Validator/Executor/Evaluator/Coordinator 接入。
- runtime requires/RuntimeTruths eligibility。
- route 排名、评分、选择、fallback、unlock、replay。
- active/disabled promotion 与 YAML 写回。
- snapshot 持久化、SQLite/ChromaDB、全局 singleton、目录监听。
- Docker、HTTP、LLM、靶机和 exploit pipeline 验证。
- 真实 Windows OS symlink 创建权限下的集成用例（确定性 containment 分支已覆盖）。

## 13. Git 摘要

普通 `git diff --stat` 仍只显示用户原有的 23 个 target 删除（745 行删除），因为 `b/routes/`、`b/test_routes.py` 和本报告均为未跟踪文件。Registry 源码改动不能用普通 tracked diff 表示；本轮没有恢复、覆盖或处理这些 target 删除，也没有 commit 或 push。

本轮没有运行 Docker、HTTP、LLM、靶机或 exploit pipeline。
