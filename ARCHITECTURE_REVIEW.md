# 架构审查报告：双模型评估架构

**审查日期**: 2026-05-19  
**审查范围**: `b/agents/evaluator.py`, `b/agents/planner.py`, `b/agents/validator.py`, `b/agents/consolidator.py`, `b/coordinator.py`, `b/cli.py`, `b/core/llm_client.py`, `b/core/settings.py`, `b/core/challenge_adapter.py`, `b/.env`  
**审查维度**: 配置解耦 / 硬编码通用性 / 容错降级 / JSON 鲁棒性

---

## 总评

**架构健康，可以合并。** 发现 4 个低风险改进点和 1 个中风险问题（LLM HTTP 超时无重试），均不影响当前功能，建议在下个迭代中逐步修复。

---

## 维度一：配置与接口解耦（OpenAI 兼容 API / vLLM / Ollama）

### 1.1 【低风险】Settings 字段命名与实现语义不一致

**位置**: `b/core/settings.py:17-19`

```python
deepseek_api_key: str | None
deepseek_base_url: str
deepseek_model: str
```

字段名全部带有 `deepseek_` 前缀，但 `DeepSeekClient` (`b/core/llm_client.py:33`) 实际上是泛化的 OpenAI-compatible 客户端。任何兼容 OpenAI SDK 的 API（vLLM、Ollama、OpenRouter、本地 llama.cpp server）都可以使用。当前命名会误导用户以为只支持 DeepSeek。

**建议**: 重命名为 `llm_api_key` / `llm_base_url` / `llm_model`，保持 Settings 与实现语义一致。

```python
# 建议的重构（保持向后兼容）
@dataclass(frozen=True)
class Settings:
    llm_api_key: str | None
    llm_base_url: str
    llm_model: str
    # ...

def get_settings() -> Settings:
    return Settings(
        llm_api_key=os.getenv("LLM_API_KEY") or os.getenv("DEEPSEEK_API_KEY"),
        llm_base_url=os.getenv("LLM_BASE_URL", os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")),
        llm_model=os.getenv("LLM_MODEL", os.getenv("DEEPSEEK_MODEL", "deepseek-chat")),
        # ...
    )
```

### 1.2 【低风险】DeepSeekClient 类名与实际能力不匹配

**位置**: `b/core/llm_client.py:33`

`DeepSeekClient` 没有使用任何 DeepSeek 特有的 API 参数或行为。它是一个纯粹的 OpenAI SDK 封装。命名为 `LLMClient` 或 `OpenAICompatClient` 更准确。

**建议**: 重命名类，保留 `DeepSeekClient` 作为别名以保证向后兼容。

### 1.3 【低风险】双模型配置模式不统一

**位置**: `b/.env:4,28-30` vs `b/agents/consolidator.py`

主模型通过 `Settings` dataclass 统一管理，但 Consolidator 的模型配置直接在 `.env` 中声明独立的环境变量 (`CONSOLIDATOR_API_KEY`, `CONSOLIDATOR_BASE_URL`, `CONSOLIDATOR_MODEL`)，由 `consolidator.py` 直接通过 `os.getenv` 读取。

这种差异造成了两种 LLM 配置模式共存，且 Consolidator 的配置没有在 `Settings` 中体现，不利于集中管理和文档化。

**建议**: 统一纳入 `Settings` dataclass，或在 `Settings` 中增加一个 `ConsolidatorConfig` 嵌套 dataclass。

### 1.4 【低风险】run_evaluator / run_planner 没有 LLM 抽象接口

**位置**: `b/agents/evaluator.py:371`, `b/agents/planner.py`

两个核心 agent 的签名都是 `llm: DeepSeekClient | None`，直接依赖具体类。如果将来需要切换 LLM 提供商（如使用 Anthropic SDK 而非 OpenAI SDK），需要修改所有调用链。

**建议**: 引入 `Protocol` 或 ABC：

```python
from typing import Protocol

class LLMClient(Protocol):
    def complete_json(self, system: str, user: str) -> dict[str, Any]: ...
```

---

## 维度二：硬编码与靶场特异性耦合

### 2.1 【低风险】EVAL_SYSTEM 中的 JWT Polyglot 规则

**位置**: `b/agents/evaluator.py:155-157`

```python
【JWT/JSON Polyglot 构造错误识别】：
- 所有 stdout 中出现 "Invalid base64-encoded string: ..." → ...
- 所有 stdout 中出现 "Invalid JWS Object" 或 "Invalid format" → ...
```

这是 JWT-specific 的错误识别逻辑，直接写入 Evaluator 的 base prompt。对于非 JWT 挑战（如 SQL 注入、SSTI），这些规则不会被触发，也不影响评估结果——**它们是惰性规则（只在匹配时才生效）**，因此不构成通用性破坏。

**判定**: 可接受。规则本身是反应式的，不影响控制流。同等逻辑的 REST API 规则（第 159-163 行）、Blind RCE 规则都是这个模式。

### 2.2 【低风险】coordinator.py 中 Polyglot 错误的字符串匹配

**位置**: `b/coordinator.py:649-661`

```python
if "Invalid base64-encoded string" in stdout_all:
    polyglot_errors.append(...)
elif "Invalid JWS Object" in stdout_all:
    polyglot_errors.append(...)
```

与 2.1 同理——这些是惰性检测器，仅在特定错误字符串出现时才追加反馈。不会影响 SQLi/XSS/SSTI 等其他攻击类型。

**建议**: 长期来看，可以将这类特定错误模式提取到 `ChallengeAdapter.http_semantic_errors()` 或新建一个 `error_patterns` 扩展点，但当前规模不需要。等积累到 5+ 个此类模式再抽象。

### 2.3 【低风险】_check_polyglot_correctness 属于 JWT 专用语义检测

**位置**: `b/agents/validator.py:230-270`

该函数检测三种 JWT 反模式 (json.dumps polyglot / .rstrip('=') / alg:none)，但仅向 `syntax_warnings` 追加告警，不阻塞非 JWT 计划。对非 JWT 挑战零影响。

**判定**: 结构良好。无侵入性，不需要修改。

### 2.4 【良好实践】ChallengeAdapter 扩展点设计

**位置**: `b/core/challenge_adapter.py`

```python
class ChallengeAdapter:
    def extra_rules(self) -> str: ...
    def http_semantic_errors(self) -> dict[str, str]: ...
    def eval_extra_rules(self) -> str: ...
```

适配器模式使挑战特定逻辑可以孤立注入 Planner/Evaluator。`ApexSurviveAdapter`（`b/core/adapters/apexsurvive.py`）是此模式的正确应用。

**判定**: 良好。此模式可直接复用到其他挑战。

---

## 维度三：容错与优雅降级

### 3.1 【中风险】LLM HTTP 调用无超时、无网络层重试

**位置**: `b/core/llm_client.py:66`

```python
resp = self._client.chat.completions.create(**kwargs)
```

OpenAI client 没有传入 `timeout` 参数（默认无超时）。如果 API 网关长时间无响应（TCP 半开连接、后端排队），整个 pipeline 会永久挂起。

同时，`complete_json()` 的重试循环（第 50-78 行）仅捕获 `json.JSONDecodeError` 和 `ValueError`，不捕获 `openai.APITimeoutError`、`openai.APIConnectionError`、`openai.RateLimitError` 等网络层异常。

**建议修复**:

```python
import openai

def complete_json(self, system: str, user: str) -> dict[str, Any]:
    if self._client is None:
        raise RuntimeError("未配置 API 密钥或已启用 MOCK 模式")
    
    if "json" not in system.lower():
        system += "\n\n请严格输出合法的 JSON 格式数据。"
    
    max_retries = 3
    last_exception = None

    for attempt in range(max_retries):
        try:
            kwargs: dict[str, Any] = dict(
                model=self._settings.deepseek_model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                temperature=0.2 + (attempt * 0.1),
                max_tokens=8192,
                timeout=120.0,  # ← 新增
            )
            if self._settings.json_mode:
                kwargs["response_format"] = {"type": "json_object"}
            resp = self._client.chat.completions.create(**kwargs)
            content = resp.choices[0].message.content or ""
            return _extract_json_object(content)

        except (json.JSONDecodeError, ValueError) as e:
            last_exception = e
            print(f"\n[llm] JSON解析失败，重试 {attempt+1}/{max_retries}: {e}")
            continue
        
        except (openai.APITimeoutError, openai.APIConnectionError,
                openai.RateLimitError, openai.InternalServerError) as e:
            last_exception = e
            wait = 2 ** attempt  # 指数退避
            print(f"\n[llm] API错误，{wait}s后重试 {attempt+1}/{max_retries}: {e}")
            time.sleep(wait)
            continue

    print(f"\n[llm] 连续 {max_retries} 次失败")
    raise last_exception
```

### 3.2 【低风险】cli.py 外层重试缺少运行间隔离

**位置**: `b/cli.py:134,138-154`

```python
max_runs = int(os.environ.get("CO_REDTEAM_MAX_RUNS", "3"))
```

使用 `os.environ.get()` 而非 `os.getenv()`——与 `settings.py` 风格不一致（后者用 `os.getenv()`）。功能等价，但风格不统一。

另外，外层循环没有 try/except 包裹 `run_pipeline()`。如果某次 run 因未预期异常崩溃，整个 `cmd_exploit()` 会直接退出，不会尝试剩余 runs。

```python
# 建议
for run_idx in range(1, max_runs + 1):
    try:
        result = run_pipeline(...)
    except Exception as e:
        warn(f"Run {run_idx}/{max_runs} crashed: {e}")
        continue
    ...
```

### 3.3 【低风险】Consolidator 异常被完全吞没

**位置**: `b/coordinator.py:913-921`

```python
try:
    from agents.consolidator import run_global_consolidation
    run_global_consolidation(...)
except Exception as e:
    print(f"[Consolidator] ⚠️ 复盘过程发生异常，但不影响本次任务结果: {e}")
```

意图正确（Consolidator 是 non-critical path），但异常信息过于简单，不利于调试。建议在 verbose 模式下打印 traceback。

### 3.4 【良好实践】Mock 模式的完整降级链路

**位置**: `b/agents/evaluator.py:387-392`

```python
if settings.mock_llm or llm is None:
    fb = _mock_evaluate(confirmed, plan, clean_exec_out)
    ...
    return fb
```

当 API 不可用时，Evaluator 降级到基于本地正则的 `_mock_evaluate()`，包含 Blind RCE 检测和 flag 匹配。Pipeline 不会因缺少 LLM 而崩溃。此设计正确。

---

## 维度四：JSON 解析鲁棒性

### 4.1 【良好实践】_extract_json_object 的多层容错

**位置**: `b/core/llm_client.py:12-30`

```python
def _extract_json_object(text: str) -> dict[str, Any]:
    text = text.strip()
    text = re.sub(r'```json\s*', '', text)
    text = re.sub(r'\s*```', '', text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    m = re.search(r"(\{[\s\S]*\}|\[[\s\S]*\])", text)
    if not m:
        raise ValueError("模型输出中未找到 JSON 对象")
    return json.loads(m.group(0))
```

三层防护: (1) 清除 markdown 代码块标记 → (2) 直接 json.loads → (3) 正则提取 + 再解析。覆盖了 DeepSeek/OpenAI/Claude 常见的输出格式（裸 JSON、被 markdown 包裹的 JSON、带说明文字的 JSON）。

**判定**: 鲁棒。

### 4.2 【低风险】json.loads 的 markdown 清理有遗漏场景

当前清理逻辑:
```python
text = re.sub(r'```json\s*', '', text)
text = re.sub(r'\s*```', '', text)
```

此逻辑假设代码块只有一对 fence。如果模型输出中包含两个代码块（例如：一段说明文字 + ```json + JSON + ``` + 又一段说明 + ```python + 代码 + ```），第二个 fence 的 ``` 会被错误删除，导致结构破坏。

**场景评估**: 概率极低——`complete_json()` 的 system prompt 明确要求"请严格输出合法的 JSON 格式数据"，模型几乎不会输出多段代码块。现有容错已足够。

### 4.3 【低风险】缺少 JSON Schema 验证

**位置**: `b/core/llm_client.py:43-68`

`complete_json()` 返回 `dict[str, Any]`，对返回值的结构不做任何校验。如果模型输出缺失字段（如 Evaluator 的 `repro_success` 字段），调用方通过 `.get()` / `.setdefault()` 兜底。

各调用方（evaluator.py:429-475, planner.py）都有完善的 `.setdefault()` 兜底。此模式分散但有效。

**建议**: 长期可以在 `complete_json()` 增加可选的 JSON Schema 参数，但目前各 agent 的兜底足够健壮，不需要。

### 4.4 【良好实践】memory_patch 的防御性应用

**位置**: `b/agents/evaluator.py:518`

```python
memory.apply_evaluator_patch(fb.get("memory_patch") or {})
```

`or {}` 确保即使 LLM 未返回 `memory_patch` 字段，也不会 crash。

---

## 发现清单汇总

| 编号 | 维度 | 风险 | 位置 | 问题 |
|------|------|------|------|------|
| 1.1 | 配置解耦 | 低 | `settings.py:17-19` | `deepseek_*` 命名与实际泛化能力不一致 |
| 1.2 | 配置解耦 | 低 | `llm_client.py:33` | `DeepSeekClient` 类名具有误导性 |
| 1.3 | 配置解耦 | 低 | `.env` + `consolidator.py` | 双模型配置模式不统一 |
| 1.4 | 配置解耦 | 低 | `evaluator.py:371` | `llm` 参数类型是具体类而非接口 |
| 3.1 | 容错降级 | **中** | `llm_client.py:66` | HTTP 调用无超时、无网络层重试 |
| 3.2 | 容错降级 | 低 | `cli.py:134` | 外层 retry 缺少 run 级 try/except |
| 3.3 | 容错降级 | 低 | `coordinator.py:921` | Consolidator 异常信息过于简略 |

## 通用性评估

- **JWT Polyglot 规则** (evaluator:155-157, coordinator:649-661, validator:230-270): 惰性规则，仅在匹配时生效，不破坏其他挑战类型的通用性。**无需移除**。
- **REST API 规则** (evaluator:159-163): 同上，惰性规则。
- **ChallengeAdapter 扩展点**: 设计良好，ApexSurviveAdapter 验证了此模式的可行性。
- **VERBATIM COPY 规则** (planner:666-679): 跨挑战通用——它约束的是模型行为而非特定 exploit，对所有 CWE 模板有效。

## 结论

**架构健康，可以合并。** 未发现违背"高内聚、低耦合"原则的严重问题。当前架构支持 OpenAI 兼容 API（DeepSeek/vLLM/Ollama/OAI Proxy）无缝接入，名字虽然带有 DeepSeek 但实际通用。JWT-specific 的检测逻辑以惰性规则的形式存在，不影响其他挑战类型。唯一的中风险问题是 LLM HTTP 调用无超时保护，建议在下个 PR 中修复。

---

*审查人: Claude (Principal Architect)*