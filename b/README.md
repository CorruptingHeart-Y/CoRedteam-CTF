# Co-RedTeam — 基于状态机与验证驱动的多Agent CTF漏洞利用系统

**一句话定义**：Co-RedTeam 是一套以 Exploit State Machine 为核心、以 Verification Memory 为判据、以 Primitive Transition Graph（原语跃迁图）为导航的五智能体闭环漏洞利用系统，解决传统 LLM Agent "载荷随机游走、攻击链崩塌" 的根本缺陷。

---

## 1. 项目简介（Project Overview）

### 1.1 传统 LLM CTF Agent 的六类系统性问题

| # | 问题 | 现象 | 根因 |
|---|------|------|------|
| A | **载荷随机游走** | 每轮随机生成新 payload，无收敛方向 | LLM 无状态记忆，每次都从零"猜测" |
| B | **重复模糊测试** | 同一 payload 反复尝试，浪费迭代预算 | 缺少已失败载荷黑名单与相似度检测 |
| C | **无攻击链记忆** | 上一轮已确认的可注入端点下一轮就被遗忘 | 无持久化 trajectory 记录 |
| D | **缺失漏洞学习能力** | JWT alg:none 在 3 个不同目标上都失败了 4 次 | 无跨任务经验提炼机制 |
| E | **无状态推进逻辑** | 已经在读 /etc/passwd 了，下一轮又重新探测端口 | 无 exploit state machine |
| F | **攻击链崩塌** | 一个 step 的语法错误导致整条链断裂，无法恢复 | 无链式连续性保障与断点恢复 |

### 1.2 Co-RedTeam 对应解决方案

| # | 方案 | 实现模块 | 效果 |
|---|------|----------|------|
| A | **状态机驱动** | Evaluator 五阶段状态机 `init→probe_success→payload_injected→gadget_triggered→oob_received` | 每轮有明确推进目标，不可回退 |
| B | **验证记忆** | VerificationMemory 持久化已核验事实 | 已确认的注入点/字段/原语永不丢失 |
| C | **攻击轨迹记忆** | ExploitTrajectoryMemory 记录每轮完整状态快照 | Planner 可回溯历史，避免重复 |
| D | **原语抽象** | PrimitiveRegistry + PrimitiveTransitionGraph | 学习的是"攻击原语"而非"载荷字符串" |
| E | **防退化校验** | AntiRegressionController 四层防线 | 禁止状态回退、载荷退化、链断裂、原语跳跃 |
| F | **载荷迭代演化** | PayloadEvolutionEngine 三类变异函数 | 载荷沿结构梯度升级，非随机替换 |
| G | **攻击链连续性** | Review Agent 全局复盘 + Validator 链断裂检测 | 断点自动诊断、策略强制切换 |

---

## 2. 系统总体架构（Architecture）

```
                            ┌─────────────────────────────────────────┐
                            │           Coordinator (协调中枢)          │
                            │  · 智能体调度  · 内存数据注入              │
                            │  · 状态循环推进 · 漏洞学习循环             │
                            │  · 熔断器(Breaker) · 攻击面轮换(Rotator)  │
                            └──────┬──────────────┬───────────────────┘
                                   │              │
              ┌────────────────────┼──────────────┼────────────────────┐
              │                    │              │                    │
              ▼                    ▼              ▼                    ▼
     ┌──────────────┐    ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
     │   Planner    │    │  Validator   │   │  Executor    │   │  Evaluator   │
     │  攻击规划     │    │  安全校验     │   │  沙箱执行     │   │  结果评估     │
     │  (plan.json) │───▶│(validated)   │──▶│(exec_result) │──▶│(feedback)    │
     └──────────────┘    └──────────────┘   └──────────────┘   └──────┬───────┘
            ▲                                                         │
            │                   ◄─── feedback loop ───                 │
            │                                                         │
            │               ┌──────────────┐                          │
            └───────────────│  Review      │◄─────────────────────────┘
                            │ (Consolidator)│   迭代预算耗尽后唤醒
                            └──────┬───────┘
                                   │ 写入 patterns / techs / strategies / YAML
                                   ▼
                     ┌─────────────────────────┐
                     │   LayeredMemory (ChromaDB) │
                     │  L1: patterns (漏洞模式)   │
                     │  L2: strategies (利用策略)  │
                     │  L3: techs (技术载荷)       │
                     └─────────────────────────┘
```

**Coordinator 核心工作循环**：

1. **智能体调度**：按 P→V→E→E 固定链路串行调度四个 Agent，迭代耗尽后唤醒 Review Agent
2. **内存数据注入**：每轮从 ChromaDB 三层记忆 + Trajectory + Verification + Primitive Graph 构建上下文注入 Planner
3. **熔断器（Breaker）**：检测连续失败/策略停滞 → 强制策略切换或攻击面轮换
4. **漏洞学习循环**：Review Agent 复盘全轨迹 → 提炼 pattern/strategy/tech → 写入 ChromaDB → 下次 Planner 可见

---

## 3. 五智能体协同架构（Five-Agent Collaborative Architecture）

### 3.1 闭环流转流程

```
┌───────────────────────────────────────────────────────────────────┐
│                        单轮微观闭环 (4-Agent Loop)                  │
│                                                                   │
│   Planning ───────▶ Validation ───────▶ Execution ───────▶ Evaluation
│   (Planner)         (Validator)          (Executor)        (Evaluator)
│       ▲                                                       │
│       └─────────────── feedback loop ─────────────────────────┘
│                                                                   │
│   迭代预算耗尽时：                                                  │
│   全轨迹 ──────▶ Review (Consolidator) ──▶ patterns/techs ──▶ Planner(下一任务)
└───────────────────────────────────────────────────────────────────┘
```

固定运行链路：**Planning → Validation → Execution → Evaluation → (多轮迭代) → Review**

### 3.2 增设第五个智能体（Review/Consolidator）的必要性

| 三/四 Agent 架构 | Co-RedTeam 五 Agent 架构 |
|---|---|
| 仅能局部行动（单轮优化） | 全局复盘学习（跨任务经验提炼） |
| 同一 payload 在不同目标重复失败 | Review 将失败提炼为 failure pattern → 写入 ChromaDB |
| 攻击链崩塌后从零开始 | Review 写入"禁止项"黑名单，Planner 后续自动避开 |
| 无跨任务知识沉淀 | Consolidator 生成 YAML 武器库模板，可跨目标复用 |
| "遗忘"是常态 | 永久记忆库跨会话持久化 |

---

## 4. 五个 Agent 的职责

### 4.1 Planner Agent（攻击规划智能体）

**文件**：`agents/planner.py`

**核心范式转换**：

```
旧式（目标导向）：         "给我一个 RCE payload" → LLM 随机输出
本系统（状态推进导向）：    当前 state=payload_injected → 查 Primitive Graph →
                         下一级 target=command_execution → 选 payload_templates →
                         输出的 step 必须填写 target_primitive + why_this_primitive_advances_chain
```

**Planner 每轮读取的五层上下文**：

| 层次 | 来源 | 内容 |
|------|------|------|
| 1 | ChromaDB 三层记忆 | L1 pattern / L2 strategy / L3 tech（带 target_tags 元数据过滤） |
| 2 | Trajectory Memory | 已成功/已失败 payload 列表、端点黑名单、WAF 检测特征 |
| 3 | Verification Memory | 已确认可达端点、已接受字段名、已确认 template engine |
| 4 | Primitive Context | 当前 primitive、推荐升级目标、transition condition |
| 5 | 上一轮 Feedback | current_exploit_state、state_transition_blocker、milestones_achieved |

**输出结构范式**：

```json
{
  "version": 1,
  "plan_id": "CWE-94-3",
  "vuln_summary": "Jinja2 SSTI via format parameter",
  "rationale": "基于 trajectory 反馈：当前 state=payload_injected，需升级到 ssti_execution",
  "chain_design": "ssti_reflection→ssti_execution→command_execution→arbitrary_file_read",
  "steps": [{
    "id": 1,
    "type": "python",
    "command": "import json,urllib3; urllib3.disable_warnings()\n...",
    "purpose": "升级到 class traversal 读取 config 对象",
    "target_primitive": "ssti_execution",
    "why_this_step_advances_state": "当前 state=payload_injected，此步骤触发 __class__.__mro__ 链",
    "why_this_payload_is_a_mutation": "基于成功 payload {{7*7}}，保留双大括号结构，升级内部原语为 {{config}}",
    "why_this_is_not_regression": "仅升级内部原语，不改变已验证的语法格式"
  }],
  "history_state": {"tried_payloads": ["{{7*7}}"], "failed_reasons": [], "consecutive_failures_per_category": {}},
  "primitive_context": {"current_primitive": "ssti_reflection", "target_primitive": "ssti_execution"}
}
```

### 4.2 Validator Agent（攻击链稳定性控制器）

**文件**：`agents/validator.py`

**定位**：不生成攻击逻辑，只做安全策略与结构校验。

**四层校验防线**：

| 层 | 检测项 | 检测逻辑 | 业务实例 |
|----|--------|----------|----------|
| 1 | **状态回退检测** | 当前 state≥payload_injected 时，禁止 step 中出现 fuzz/scan/discover 信号词 | 已在读 /flag.txt，plan 的 step_1 又写 "探测端点"→拒绝 |
| 2 | **载荷退化检测** | 新 payload 与 trajectory 中已失败 payload 相似度 > 0.8 →拒绝 | 上一轮 `{{7*7}}` 失败，本轮 `{{7*'7'}}` 相似度 0.9 →拒绝 |
| 3 | **攻击链断裂检测** | 已验证 /search 可注入，新 plan 的 step_1 不是 /search →警告 | Planner 跳到了 /admin →提示链断裂风险 |
| 4 | **原语连续性检测** | step 的 target_primitive 必须引用 transition graph 中存在的边 | step 声称从 ssti_reflection 直接跳到 credential_dump →拒绝（图中无边） |

**额外检查**：AST import 白名单扫描、危险代码文本正则拦截、Fire-and-Forget 预防（HTTP 请求后无验证 print）

### 4.3 Executor Agent（纯执行引擎）

**文件**：`agents/executor.py`

**核心原则**：只执行，不推理。

| 类别 | 具体能力 | 实现方式 |
|------|----------|----------|
| 网络请求 | GET/POST/PUT/DELETE, raw_request（保留 `#` `%00` `..;/`） | Docker 内 `redteam_sdk.HttpClient` |
| 载荷注入 | Python 脚本执行 | `sandbox.run_python_script()` |
| 命令执行 | Shell 命令 | `sandbox.run_shell_command()` |
| 自动化浏览器 | Selenium/Playwright（预留） | Docker + headless browser |
| 日志采集 | stdout/stderr/HTTP 响应体自动捕获 | `_extract_http_responses_from_stdout()` |
| Session 持久化 | Cookie/Session 跨 step 自动保存恢复 | Executor 包装层注入 `ensure_session_persisted()` |

**Executor 自动注入的 HTTP 日志包装层**：

```python
# Executor 在每个 step 脚本外层自动注入:
_hc_req_orig = HttpClient.request
def _hc_req(self, method, url, *a, **kw):
    try:
        resp = _hc_req_orig(self, method, url, *a, **kw)
        body = (resp.text or '')[:500]
        print(f'[HTTP] {resp.status_code} {method} {url} => {body}')
        return resp
    except Exception as _e:
        print(f'[HTTP_ERR] {method} {url}: {_e}')
        raise
HttpClient.request = _hc_req
```

所有 HTTP 请求自动带日志输出 — Planner 无需手动打印响应。

### 4.4 Evaluator Agent（漏洞验证引擎）

**文件**：`agents/evaluator.py`

**定位**：不是简单的成功/失败二元判定，而是**状态推导 + 原语识别 + 证据核验 + 里程碑判定**。

**五阶段漏洞状态机（核心创新）**：

```
  init ──▶ probe_success ──▶ payload_injected ──▶ gadget_triggered ──▶ oob_received
   │              │                   │                   │                  │
   │  端点可达      │  payload被接受    │  gadget被激活       │  铁证如Flag/OOB   │
   │  HTTP 200     │  SSTI: {{7*7}}   │  SSTI: config dump │  flag{...}       │
   │               │  返回 49         │  RCE: uid=0 输出    │  OOB callback    │
```

**每个状态的判定依据**：

| 状态 | 判定条件 | 证据等级 | 下一步动作 |
|------|----------|----------|------------|
| `init` | 尚未证实攻击面可达 | — | 探测端点连通性 / 获取认证 |
| `probe_success` | HTTP 200+ 端点可达，或认证成功 | B 级（间接） | 注入探测 payload |
| `payload_injected` | SSTI: 响应含 `49` 或 payload 回显；SQLi: 响应差异 | A 级（直接） | 触发 gadget 升级 |
| `gadget_triggered` | SSTI: config dump/class traversal；RCE: `uid=xxx`/`whoami` 输出 | A 级 | 收集 S 级铁证 |
| `oob_received` | OOB HTTP/DNS 回调到达，或 flag 已捕获 | S 级（铁证） | 结束任务 |

**状态机 vs 二元判定对比**：

```
二元判定模式：  "成功了吗？" → Yes/No → 下一个随机 payload
状态机模式：    "当前在哪个阶段？payload_injected → 查 graph → 下一阶段 gadget_triggered
               → 需要 ssti_execution primitive → 选 class traversal payload
               → 执行 → 验证是否进入下一阶段 → 记录里程碑 → 继续推进"
```

### 4.5 Review Agent（Consolidator，全局复盘学习器）

**文件**：`agents/consolidator.py`

**核心定位**：不参与单轮攻击执行。在宏观四智能体闭环耗尽迭代预算后唤醒，使用独立高级大模型对全轨迹进行跨任务战略级经验提炼。这是系统从 "单纯攻击" 升级为 "自主学习攻击" 的关键模块。

**五大工作内容**：

| # | 工作场景 | 读取数据 | 输出 |
|---|----------|----------|------|
| 1 | **失败路径复盘** | 全 trajectory nodes、execution_result、feedback | 根因分析（为什么卡死？WAF？沙箱冲突？格式错误？） |
| 2 | **攻击链提炼** | plan.json 的 chain_design、step 的 target_primitive | 提炼成功/失败链的通用模式，写入 `strategy.json` |
| 3 | **原语演化总结** | 所有 step 的 payload 序列 + target_primitive | 总结合并原语演化路径，更新 `pattern.json` |
| 4 | **规划策略修正** | Planner 的重犯错误（如重试相同 payload） | 写入"禁止项"黑名单到记忆，下次 Planner 自动避开 |
| 5 | **漏洞学习累积** | 成功案例的完整攻击链 | 生成 YAML 武器库模板，写入 `templates/builtin/` |

**Consolidator 内的 Expert System Prompt（690+ 行专家规则）**：

```text
【沙箱冲突诊断 — 最高优先级】
  - "[SECURITY] PYTHON_BLOCKED pattern='os_system_exec'" -> Planner 写了 os.system 字面量
  - Validator passed=True 但 Executor 有 SECURITY_BLOCKED -> import 检查通过但正则拦截
  - 同一类 PYTHON_BLOCKED 出现 ≥ 2 轮 -> Planner 陷入死循环，你需要介入
  针对每种冲突，输出 executable_patch（完整可运行代码块，仅使用白名单模块）

【高级代码 Patch 固化】
  - pickle 反序列化攻击 -> 用 struct/bytes 硬编码 pickle 操作码，0 行 import
  - CRLF + Memcached 协议注入 -> 用 bytes 构造 HTTP cookie 原始字节，用 raw_request() 发送
```

---

## 5. Memory System（核心创新）

### 5.1 Exploit Trajectory Memory（攻击轨迹记忆）

**文件**：`memory/exploit_trajectory.py`

**记录存储字段**（ExploitTrajectoryNode dataclass）：

```python
@dataclass
class ExploitTrajectoryNode:
    round_id: int               # 轮次编号
    timestamp: str              # UTC 时间戳
    current_state: str          # 当前 exploit 状态（init/probe_success/...）
    target_state: str           # 目标状态
    action_type: str            # probe / inject / trigger / exfiltrate
    payload: str               # 实际使用的 payload 片段
    endpoint: str              # 目标 endpoint
    method: str                # HTTP method
    evidence: str              # HTTP 响应证据
    success: bool              # 本轮是否产生了状态转换
    blocker: str               # 状态转换阻塞点
    state_transition: str      # 如 "init -> probe_success"
    why_failed: str            # 失败根因
    reusable: bool             # payload 是否可跨目标复用
    detected_primitive: str    # 检测到的 exploit primitive
    primitive_confidence: float # 置信度
    primitive_evidence: str    # 证据
```

**持久化路径**：`b/memory/exploit_trajectory.json`

**轨迹记忆 vs 会话历史对比**：

```
会话历史（session memory）：
  本轮: payload {{7*7}} 成功, 响应含 49
  → 仅在本会话可用，重启即丢失

Trajectory Memory：
  R1: state=init, payload={{7*7}}, endpoint=/time, primitive=ssti_reflection✓
  R2: state=probe_success, payload={{config}}, transition=probe_success→payload_injected
  R3: state=payload_injected, payload={{lipsum.__globals__...}}, transition=payload_injected→gadget_triggered
  → 持久化 JSON，跨会话可读，Planner 任何时候都能恢复完整上下文
```

### 5.2 Verification Memory（验证记忆）

**文件**：`memory/verification_memory.py`

**核心原则**：仅留存已核验的真实漏洞条件。不存储推测、不记录 "可能"。

**存储内容示例**：

```json
{
  "confirmed_base_url": "https://192.168.1.100:9443",
  "confirmable_endpoints": ["/time", "/api/search"],
  "injectable_params": {"/time": ["format"]},
  "injectable_endpoints": ["/time"],
  "accepted_fields": ["format", "email", "fullName"],
  "rejected_fields": ["username"],
  "template_engine": "jinja2",
  "reflection_confirmed": true,
  "payload_blacklist": ["__import__", "os.system"],
  "payload_bypass_techniques": ["double_encoding_%2523_worked"],
  "working_primitives": [
    {"primitive_id": "ssti_reflection", "confidence": 0.95, "evidence": "{{7*7}} → 49", "engine": "jinja2"},
    {"primitive_id": "ssti_execution", "confidence": 0.85, "evidence": "{{config}} dump visible", "engine": "jinja2"}
  ],
  "confirmed_flags": ["HTB{t1m3_b4s3d_sst1}"],
  "waf_detected": false,
  "auth_status": "unauthenticated"
}
```

**记忆不丢失特性**：每个 `verif.confirm()` 调用立即写盘，进程崩溃也不丢失已核验事实。

### 5.3 Primitive Learning Engine（原语学习引擎）

**文件**：`memory/primitive_learning.py`

**载荷记忆 vs 原语记忆差异**：

```
载荷记忆（传统做法）：
  "{{7*7}}" → "这个 payload 成功过"
  → 换一个目标（Twig 模板），payload 废了，记忆无用

原语记忆（本系统）：
  Observation: payload="{{7*7}}", response contained "49", engine=jinja2
  → 学习到: primitive=ssti_reflection, engine=jinja2, payload_template="{{expr}}"
  → 换到 Twig 目标时：查 CROSS_TARGET_SYNTAX_MAP → Twig 语法是 {{expr}}
  → 从 registry.get("ssti_reflection").payload_templates 得到 "{{7*7}}" → 复用成功
```

**实际检测规则示例**：

```python
_HEURISTIC_DETECTORS = [
    ("ssti_reflection", "expression reflected", re.compile(r"\{\{7\*7\}\}.*49|\$\{7\*7\}.*49", re.DOTALL), "expression_evaluated"),
    ("ssti_execution", "class traversal output", re.compile(r"<class\s|__globals__|__subclasses__|__mro__", re.IGNORECASE), "object_introspection_succeeded"),
    ("sql_boolean", "boolean-based differentiation", re.compile(r"1=1|1=2", re.IGNORECASE), "boolean_condition_injected"),
    ("command_execution", "command output in response", re.compile(r"uid=\d+|gid=\d+|www-data", re.IGNORECASE), "command_output_detected"),
]
```

### 5.4 Primitive Transition Graph（原语跃迁图谱）

**文件**：`memory/primitive_transition_graph.py`

**核心思想**：Planner 必须沿此有向图推进，而不是随机生成 payload。每个 primitive 都有明确的 "下一阶段" 目标，payload 只是沿边前进的实例化手段。

**ASCII 跃迁流程图**：

```
                        ┌──────────────────────────────────────────┐
                        │         POST-EXPLOITATION LAYER           │
                        │                                          │
              ┌─────────┴─────────┐                                │
              │ command_execution │◄───────────────────────────────┤
              └────────┬─────────┘                                │
                       │                                           │
        ┌──────────────┼──────────────┬──────────────┐             │
        ▼              ▼              ▼              ▼             │
  ┌──────────┐  ┌────────────┐  ┌─────────────┐  ┌────────────┐   │
  │ arbitrary │  │ privilege  │  │ credential  │  │ filesystem │   │
  │ _file_read│  │ _discovery │  │ _dump       │  │ _traversal │   │
  └──────────┘  └────────────┘  └─────────────┘  └────────────┘   │
                                                                   │
  ┌──────────────────────────────────────────────────────────────┐ │
  │                    INJECTION PRIMITIVES                       │ │
  │                                                              │ │
  │  ┌─────────────────┐    ┌─────────────────┐                  │ │
  │  │ ssti_reflection │───▶│ ssti_execution  │──▶ cmd_exec      │ │
  │  └────────┬────────┘    └────────┬────────┘                  │ │
  │           │                      │                            │ │
  │           ▼                      ▼                            │ │
  │  ┌─────────────────┐    ┌─────────────────┐                  │ │
  │  │   blind_ssti    │───▶│ http_callback   │──▶ blind_rce_oob │ │
  │  └─────────────────┘    └────────┬────────┘                  │ │
  │                                  │                            │ │
  │  ┌─────────────────┐             ▼                            │ │
  │  │  sql_boolean    │───▶┌─────────────────┐                  │ │
  │  └─────────────────┘    │   sql_union     │──▶ cmd_exec      │ │
  │                         └────────┬────────┘                  │ │
  │                                  │                            │ │
  │  ┌─────────────────┐             ▼                            │ │
  │  │ command_        │───▶┌─────────────────┐                  │ │
  │  │ separator       │    │ command_exec    │                  │ │
  │  └─────────────────┘    └─────────────────┘                  │ │
  └──────────────────────────────────────────────────────────────┘
```

**每条边的 transition condition**：

```
ssti_reflection → ssti_execution: "确认 template engine 类型（jinja2/twig/freemarker）"
ssti_execution → command_execution: "成功访问 os.popen 或 subprocess 模块"
sql_union → command_execution: "数据库支持 xp_cmdshell / COPY TO PROGRAM / UDF"
command_execution → arbitrary_file_read: "任意命令已可执行，直接 cat / read 文件"
```

---

## 6. Verification-Driven Exploitation（验证驱动漏洞利用）

**对比传统 Agent 盲目攻击模式**：

```
传统:  生成 payload → 发射 → 看是否拿到 flag → 没拿到 → 再随机生成 → 再发射 → ...
        ↑ 完全不知道中间发生了什么，只能猜

Co-RedTeam:
       每轮核心目标：推进漏洞状态（而非直接拿 flag）
       Round 1: init→probe_success (确认 /time 可达, 认证成功)
       Round 2: probe_success→payload_injected (注入 {{7*7}}, 响应含 49, SSTI 已确认)
       Round 3: payload_injected→gadget_triggered (注入 {{config}}, config dump 成功)
       Round 4: gadget_triggered→oob_received (注入 RCE payload, 读取 /flag.txt → flag{...})
```

**分阶段执行逻辑**：

| 阶段 | 本轮核心任务 | 验证手段 | 判定条件 |
|------|-------------|----------|----------|
| init→probe_success | 确认端点可达 | HTTP 状态码 + 响应体正常 | 200/302, 非错误页面 |
| probe_success→payload_injected | 注入探测 payload | 响应体搜索 `49`、算术结果 | SSTI 确认：表达式被求值 |
| payload_injected→gadget_triggered | 激活 gadget | 响应体搜索 `<class`、`uid=` 等 | class traversal 输出可见 |
| gadget_triggered→oob_received | 收集铁证 | OOB 回调或 flag 正则匹配 | `flag{...}` 或 OOB hit |

---

## 7. Payload Evolution Engine（载荷演化引擎）

**文件**：`control/anti_regression.py` — `PayloadEvolutionEngine` 类

**载荷随机游走的弊端**：

```
随机游走: {{7*7}} → ;id → ' OR 1=1 → ${7*7} → <script>alert(1)</script>
           ↑ 完全无关，四种不同漏洞类型随机跳，没有一个深入
```

**三类变异函数**：

| 函数 | 触发条件 | 变异策略 | 示例 |
|------|----------|----------|------|
| `mutate_from_success()` | 上一轮 payload 成功 | 在预定义演变链上向前推进一级（保留结构，升级执行原语） | `{{7*7}}`→`{{config}}`→`{{self.__init__.__globals__}}` |
| `mutate_from_failure()` | 上一轮 payload 失败 | 跨格式/编码变异（保留语义，换语法） | `{{7*7}}` 失败 → 尝试 `${7*7}`, `#{7*7}`, `<%=7*7%>` |
| `preserve_working_structure()` | 新 primitive 需要新 payload | 保留已确认结构外壳，替换内部原语 | `{{...}}` 结构保留，内部替换为 `lipsum.__globals__['os']...` |

**SSTI 实战案例：载荷渐进升级流程**：

```
Round 1: {{7*7}}                              → 响应含 49     → ssti_reflection 确认 ✓
Round 2: {{config}}                            → 响应含 Config → ssti_execution 升级 ✓
Round 3: {{''.__class__}}                      → 响应含 <class> → 对象内省成功       ✓
Round 4: {{self.__init__.__globals__}}         → os module 可见 → RCE 入口可见      ✓
Round 5: {{lipsum.__globals__['os'].popen('cat /flag.txt').read()}} → flag{...} 🏁
```

每一步都在前一步成功的基础上做**单维度变异**：语法格式不变，只升级内部执行层级。

---

## 8. Anti-Regression System（防退化体系）

**文件**：`control/anti_regression.py` — `AntiRegressionController` 类

**攻击链崩塌的五大成因与防护目标**：

```
        成因                              防护目标                    约束规则
  ┌──────────────────┐          ┌──────────────────────┐    ┌──────────────────────────┐
  │ 1. 状态回退       │    →     │ 只能前进不可回退       │    │ state≥payload_injected时  │
  │ gadget_triggered  │          │                      │    │ 禁止 fuzz/discover/scan  │
  │ 后重新探测端点     │          │                      │    │                          │
  ├──────────────────┤          ├──────────────────────┤    ├──────────────────────────┤
  │ 2. 载荷重复失败    │    →     │ 相似度 >0.8 则禁止    │    │ 与 trajectory 中已失败    │
  │ 同一 payload 反复  │          │                      │    │ payload 比对相似度        │
  ├──────────────────┤          ├──────────────────────┤    ├──────────────────────────┤
  │ 3. 攻击链断裂      │    →     │ 已确认注入点必须延续   │    │ injectable_endpoints 中   │
  │ 跳转到无关端点     │          │                      │    │ 的端点必须在 step_1 出现   │
  ├──────────────────┤          ├──────────────────────┤    ├──────────────────────────┤
  │ 4. 已被拒绝字段     │    →     │ 黑名单拦截            │    │ rejected_fields 中字段    │
  │ 仍在使用           │          │                      │    │ 不得出现在 payload 中      │
  ├──────────────────┤          ├──────────────────────┤    ├──────────────────────────┤
  │ 5. 原语跳跃        │    →     │ Graph 中必须有边       │    │ target_primitive 必须      │
  │ 跨级不连续         │          │                      │    │ 在 graph edge 列表中存在   │
  └──────────────────┘          └──────────────────────┘    └──────────────────────────┘
```

**防退化控制器约束规则（代码级）**：

```python
class AntiRegressionController:
    def validate_state_regression(self, planned_steps):
        # 已处于 payload_injected+ → 禁止重新 fuzz/discover

    def validate_payload_regression(self, payload):
        # 与已失败 payload 相似度 > 0.8 → 拒绝

    def validate_chain_break(self, planned_steps, current_chain):
        # 已验证 injectable_endpoints 必须出现在 step_1 中

    def validate_primitive_continuity(self, step):
        # target_primitive 必须在 graph edge 列表中存在
```

---

## 9. Primitive Abstraction Layer（原语抽象层 — 核心创新点）

**文件**：`memory/exploit_primitives.py` + `memory/primitive_learning.py`

**传统载荷中心 vs 本系统原语中心设计**：

| | 载荷中心（传统） | 原语中心（Co-RedTeam） |
|---|---|---|
| 记忆内容 | payload 字符串 `"{{7*7}}"` | primitive 类型 + 特征 + `payload_templates` + `cross_target_syntax` |
| 换目标后 | payload 废了 | 查 cross_target_syntax → 找到对应语法 → 从 template 实例化 |
| 攻击链推理 | 无法推理 | TransitionGraph 有向图驱动 Planner 沿边推进 |
| 知识复用 | 不可复用 | 同一 primitive 知识跨 CWE/CVE 共享 |

**跨目标泛化实例**：

```
原始目标 (Jinja2 + Flask):
  primitive=ssti_reflection, engine=jinja2, payload="{{7*7}}" → 成功

新目标 (Freemarker + Spring):
  Planner 读取: "当前 CWE=CWE-94 SSTI"
  → 查 CROSS_TARGET_SYNTAX_MAP["ssti_reflection"]
  → freemarker 语法是 "${...}" → 从 payload_templates 选 "${7*7}"
  → 无需重新 "学习" SSTI — 只需语法适配
```

**多模板注入语法 → 统一底层原语**：

```
jinja2:    {{7*7}}          ─┐
freemarker: ${7*7}           ├── 统一原语: ssti_reflection
thymeleaf: #{7*7}           ─┤   (expression_evaluated)
ejs:       <%= 7*7 %>       ─┘
```

**四个核心能力**：

| 能力 | 说明 |
|------|------|
| 跨目标泛化 | 同一 primitive 映射到不同引擎/框架的语法，切换目标时不从零开始 |
| 攻击链推理 | TransitionGraph 有向图提供推理基础，Planner 不随机猜测 |
| 适配变异 | `preserve_working_structure()` 保留结构，替换内部原语 |
| 知识复用 | 一个 SSTI 链经验可复用于 4+ 种模板引擎 |

---

## 10. 全局复盘机制（Global Review Loop）

**触发时机**：微观 4-Agent 闭环迭代预算耗尽后。

**数据读取范围**：
- `plan.json` / `validated_plan.json`：Plan 层的迭代演变
- `execution_result.json`：所有 step 的 stdout/stderr/HTTP 响应
- `feedback.json`：Evaluator 每一轮的判定
- `exploit_trajectory.json`：完整攻击轨迹
- ChromaDB 三层记忆：已有 patterns / strategies / techs

**复盘五大工作场景与实际业务案例**：

| 场景 | 输入信号 | 复盘动作 | 输出到记忆 |
|------|----------|----------|------------|
| **沙箱冲突诊断** | `PYTHON_BLOCKED os_system_exec` 重复≥2轮 | 生成 `executable_patch`：用 struct/bytes 硬编码 pickle 操作码，0行import | `tech.json` |
| **Payload 格式死胡同** | `All fields are required` 重复3轮 | Planner 忽略了字段名证据 → 写入强制规则 | `strategy.json` failure |
| **WAF 绕过失败** | 同一 WAF 特征出现2轮 | 提炼 bypass 方案：double encoding → chunked transfer | `pattern.json` bypass |
| **攻击链提炼** | 连续2轮成功推进到 gadget_triggered | 萃取整条链的 primitive 序列 → 生成 YAML 武器库模板 | `templates/builtin/` |
| **原语学习固化** | Evaluator 检测到新的 primitive 组合 | 验证 → 写入 PrimitiveRegistry → 更新 TransitionGraph | `exploit_primitives.py` |

**漏洞学习累积的核心价值**：第 N+1 次任务启动时，Planner 的 system prompt 已包含从前面 N 个任务中提炼出的 "禁止项" 黑名单、"已确认 bypass 技术" 白名单、"已验证 primitive 跃迁路径"。每次新攻击都站在所有历史经验的肩膀上。

---

## 11. 系统数据流（Data Flow）

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │ Planner  │───▶│Validator │───▶│ Executor │───▶│Evaluator │              │
│  │          │    │          │    │          │    │          │              │
│  │ 读取:    │    │ 校验:    │    │ 执行:    │    │ 判定:    │              │
│  │ ·Traject.│    │ ·状态回退│    │ ·沙箱脚本 │    │ ·状态推导│              │
│  │ ·Verif.  │    │ ·载荷退化│    │ ·HTTP注入 │    │ ·原语识别│              │
│  │ ·ChromaDB│    │ ·链断裂  │    │ ·命令执行 │    │ ·里程碑  │              │
│  │ ·Primitive│   │ ·原语连续│    │ ·日志采集 │    │ ·证据    │              │
│  └──────────┘    └──────────┘    └──────────┘    └────┬─────┘              │
│       ▲                                               │                    │
│       │            ◄─── feedback.json ───              │                    │
│       │                                               │                    │
│       │         ┌─────────────────────────┐           │                    │
│       │         │  _record_trajectory_entry│◄─────────┘                    │
│       │         │  _record_primitive_learn│                                │
│       │         │  _record_verified_facts │                                │
│       │         └───────────┬─────────────┘                                │
│       │                     │                                              │
│       │                     ▼                                              │
│       │         ┌─────────────────────────┐                                │
│       │         │   Persistent Memories   │                                │
│       │         │  · exploit_trajectory   │                                │
│       │         │  · verification_memory  │                                │
│       │         │  · primitive_learning   │                                │
│       │         │  · transition_graph     │                                │
│       │         └───────────┬─────────────┘                                │
│       │                     │                                              │
│       │                     │  迭代预算耗尽                                 │
│       │                     ▼                                              │
│       │         ┌─────────────────────────┐                                │
│       │         │    Review/Consolidator  │                                │
│       └─────────│    (全局复盘学习)        │                                │
│                 └───────────┬─────────────┘                                │
│                             │                                              │
│                             ▼                                              │
│                 ┌─────────────────────────┐                                │
│                 │   ChromaDB 长期记忆      │                                │
│                 │  L1: patterns.json      │                                │
│                 │  L2: strategy.json      │                                │
│                 │  L3: tech.json          │                                │
│                 └─────────────────────────┘                                │
│                                                                             │
│  ◄═══════════════ 五阶段循环 = 闭环漏洞学习系统 ═══════════════►              │
│                                                                             │
│   单轮：P→V→E→E→(feedback)→P  (状态推进循环)                                │
│   跨轮：ExecOut→Trajectory+Verification→PrimitiveLearning→ChromaDB           │
│   跨任务：AllTrajectories→Review→Patterns/Techs→Planner(未来任务)             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 12. 创新点总结（Innovations）

| # | 创新点 | 一句话定义 | 解决的实际问题 |
|---|--------|------------|----------------|
| 1 | **验证驱动利用** | 每轮核心目标为推进漏洞状态而非获取 Flag | Payload 随机发射、无反馈闭环 |
| 2 | **漏洞状态机** | 五阶段状态 `init→probe_success→payload_injected→gadget_triggered→oob_received` | 无状态推进逻辑、攻击链回退 |
| 3 | **原语中心学习** | 学习的是 Primitive 类型而非 Payload 字符串 | 换目标后 payload 失效、知识不可迁移 |
| 4 | **攻击轨迹记忆** | ExploitTrajectoryMemory 持久化每轮完整状态快照 | 无历史记忆、重复已失败路径 |
| 5 | **防退化校验** | AntiRegressionController 四层硬约束防线 | 载荷退化、状态回退、链断裂、原语跳跃 |
| 6 | **载荷演化引擎** | 三类变异函数：沿梯度升级/跨格式变异/保留结构替换 | 载荷随机游走、无收敛方向 |
| 7 | **原语跃迁图** | PrimitiveTransitionGraph 有向图驱动 Planner 沿边推进 | 攻击链无推理依据、跨级跳跃 |
| 8 | **跨目标泛化** | CROSS_TARGET_SYNTAX_MAP 映射同一原语到不同引擎语法 | 每个新目标都从零开始 |
| 9 | **复盘式漏洞学习** | Review Agent 跨任务提炼经验 → 写入 ChromaDB 永久记忆 | 同一错误跨任务重复、无经验积累 |
| 10 | **状态留存规划** | Planner 读取 Trajectory+Verification+Primitive 三层上下文 | Planner 每轮从零 "猜测"、无视历史 |
| 11 | **ChromaDB 元数据过滤** | 三层向量检索加 `target_tags` where 过滤 | 打 LockTalk 搜出致远 OA 脚本 |
| 12 | **衰减式动态迭代引擎** | 质变里程碑奖励 + 连续无进展主动放弃 | 固定迭代预算浪费或过早退出 |
| 13 | **沙箱 HTTP 自动日志注入** | Executor 包装层自动拦截所有 HTTP 请求并打印 `[HTTP]` 标记 | Planner 忘记打印响应体导致 Evaluator 无数据 |

---

## 13. 项目目录结构

```
b/                                    # 项目根目录
├── coordinator.py                    # 协调中枢：Agent调度、记忆注入、熔断器、攻击面轮换
├── cli.py                           # CLI入口：argparse参数解析、目标白名单锁定
├── Dockerfile                       # Docker沙箱镜像定义
├── requirements.txt                 # Python依赖清单
├── .env / .env.example              # 环境变量配置
│
├── agents/                          # 五智能体实现
│   ├── __init__.py
│   ├── planner.py                   # [1] Planner — 攻击规划，读取5层上下文生成plan.json
│   ├── validator.py                 # [2] Validator — 安全校验，四层防线+AST allowlist扫描
│   ├── executor.py                  # [3] Executor — 沙箱执行，HTTP自动日志注入+Session持久化
│   ├── evaluator.py                 # [4] Evaluator — 五阶段状态机判定+flag检测+原语识别
│   └── consolidator.py              # [5] Review — 全局复盘学习，YAML武器库生成
│
├── memory/                          # 记忆子系统（5个模块）
│   ├── __init__.py
│   ├── exploit_trajectory.py        # 攻击轨迹记忆：ExploitTrajectoryNode+持久化JSON
│   ├── verification_memory.py       # 验证记忆：已核验事实的去重知识集合
│   ├── exploit_primitives.py        # 原语注册表：20+ injection/post-exploitation primitive定义
│   ├── primitive_learning.py        # 原语学习引擎：Observation→Primitive启发式推断
│   ├── primitive_transition_graph.py # 原语跃迁图：30+ transition edge+condition定义
│   ├── exploit_trajectory.json      # 轨迹持久化文件
│   ├── pattern.json                 # L1 漏洞模式 (ChromaDB 数据源)
│   ├── strategy.json                # L2 利用策略 (ChromaDB 数据源)
│   └── tech.json                    # L3 技术载荷 (ChromaDB 数据源)
│
├── control/                         # 控制子系统
│   ├── __init__.py
│   └── anti_regression.py           # 防退化控制器+载荷演化引擎
│
├── core/                            # 基础设施
│   ├── __init__.py
│   ├── settings.py                  # 全局配置：API Key、最大迭代、Docker参数
│   ├── llm_client.py                # DeepSeek OpenAI-compatible client封装
│   ├── memory_store.py              # ChromaDB三层向量存储: pattern/strategy/tech
│   ├── challenge_adapter.py         # 挑战适配器基类: 加载靶场特定规则
│   ├── target_context.py            # 目标白名单锁定: URL→IP解析+hostname隔离
│   ├── template_manager.py          # YAML武器库模板加载器
│   ├── ui.py                        # Rich终端渲染: 迭代头/Eval反馈/汇总表
│   └── adapters/                    # 挑战专属适配器
│       ├── __init__.py
│       └── apexsurvive.py           # ApexSurvive适配器示例
│
├── data/
│   └── confirmed_vuln.json          # 输入：审计阶段产出的漏洞报告JSON
│
├── templates/builtin/               # YAML武器库（14+ 模板）
│   ├── cwe-94-ssti.yaml             # SSTI 模板注入
│   ├── cwe-89-sqli.yaml             # SQL 注入
│   ├── cwe-78-command-injection.yaml # 命令注入
│   ├── cwe-502-deserialization.yaml # 反序列化
│   ├── cwe-918-ssrf.yaml            # SSRF
│   ├── cwe-79-xss-css.yaml          # XSS
│   ├── cwe-434-file-upload.yaml     # 文件上传
│   ├── cve-2022-39227-jwt-polyglot.yaml # JWT polyglot 攻击
│   └── ...
│
├── policies/
│   └── sandbox_policy.yaml          # 沙箱安全策略: AST allowlist/denylist
│
└── workspace/                       # 每轮运行时输出
    ├── plan.json                    # Planner输出
    ├── validated_plan.json          # Validator输出
    ├── execution_result.json        # Executor输出
    └── feedback.json                # Evaluator输出
```

**agents/ 下五个文件与智能体对应关系**：

| 文件 | 智能体 | 在闭环中的位置 | 核心函数 |
|------|--------|---------------|----------|
| `planner.py` | Planner | 起点（生成计划） | `run_planner()`, `build_dynamic_prompt()` |
| `validator.py` | Validator | 第2步（校验计划） | `run_validator()`, `_validate_step()` |
| `executor.py` | Executor | 第3步（执行脚本） | `run_executor()`, `_execute_python_step()` |
| `evaluator.py` | Evaluator | 第4步（评估结果） | `run_evaluator()`, `_detect_exploit_state()` |
| `consolidator.py` | Review | 迭代耗尽后（全局复盘） | `run_global_consolidation()` |

---

## 14. 快速开始（Quick Start）

### 14.1 环境依赖安装

```bash
# 1. Python 3.10+
python --version

# 2. 安装依赖
cd b/
pip install -r requirements.txt

# 3. Docker (沙箱执行必需)
docker --version

# 4. 构建沙箱镜像
docker build -t co-redteam-sandbox .
```

### 14.2 密钥配置

```bash
# 复制环境变量模板
cp .env.example .env

# 编辑 .env
# DEEPSEEK_API_KEY=sk-your-key-here
# DEEPSEEK_BASE_URL=https://api.deepseek.com/v1
# 可选：CO_REDTEAM_TARGET_BASE=https://target-ip:port
```

### 14.3 项目启动命令

```bash
# 方式一：直接启动 pipeline
python coordinator.py --confirmed data/confirmed_vuln.json \
    --challenge generic --url https://192.168.1.100:9443

# 方式二：CLI 启动
python cli.py exploit --confirmed data/confirmed_vuln.json --url https://192.168.1.100:9443

# 方式三：Mock 模式（不调用 LLM，测试结构流转）
python coordinator.py --challenge generic
# 设置 export CO_REDTEAM_MOCK_LLM=true
```

### 14.4 演示案例运行

```bash
# 准备 data/confirmed_vuln.json：
{
  "vulnerabilities": [{
    "cwe_id": "CWE-94",
    "title": "Jinja2 SSTI via format parameter",
    "source": "user_input:format",
    "sink": "render_template_string()"
  }],
  "target_context": {
    "base_url": "https://192.168.1.100:9443",
    "app_name": "TimeKORP"
  }
}

# 运行
python coordinator.py --confirmed data/confirmed_vuln.json \
    --url https://192.168.1.100:9443

# 观察终端输出:
# [Planner] → [Validator] → [Executor] → [Evaluator] → [Consolidator]
# 每轮显示 current_exploit_state, milestones, confidence
```

### 14.5 轨迹数据与验证内存查看

```bash
# 查看攻击轨迹
cat memory/exploit_trajectory.json | python -m json.tool

# 查看验证记忆
cat memory/verification_memory.json | python -m json.tool

# 查看 ChromaDB 统计
python -c "
from core.memory_store import LayeredMemory
from core.settings import get_settings
m = LayeredMemory(get_settings().memory_dir)
print(m.get_stats())
"
```

```python
# 程序化读取验证记忆
from memory.verification_memory import get_verification

verif = get_verification()
print(f"已确认端点: {verif.facts['confirmable_endpoints']}")
print(f"可注入端点: {verif.facts['injectable_endpoints']}")
print(f"已接受字段: {verif.facts['accepted_fields']}")
print(f"模板引擎:   {verif.facts['template_engine']}")
print(f"已确认原语: {verif.facts['working_primitives']}")
print(f"已捕获Flag: {verif.facts['confirmed_flags']}")
```

---

## 15. 如何扩展系统

### 15.1 新增漏洞原语（Exploit Primitive）

在 `memory/exploit_primitives.py` 的 `INJECTION_PRIMITIVES` 中添加：

```python
"xxe_injection": {
    "description": "XML External Entity injection",
    "preconditions": ["xml_parser_accepts_user_input", "external_entities_enabled"],
    "observable_signals": ["file_content_in_response", "dns_callback"],
    "payload_templates": [
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    ],
    "confirmation": "file_content_or_oob_received",
},
```

然后在 `memory/primitive_transition_graph.py` 中添加跃迁边：

```python
"xxe_injection": ["arbitrary_file_read", "http_callback", "ssrf_exploitation"],

# 在 TRANSITION_CONDITIONS 中添加条件
"xxe_injection->arbitrary_file_read": "需确认外部实体未被禁用，且文件内容在响应中回显",
```

### 15.2 新增校验规则

在 `agents/validator.py` 中添加检测函数：

```python
def _validate_no_hardcoded_creds(code: str) -> list[str]:
    if re.search(r'(?:password|api_key)\s*=\s*["\'][^"\']{3,}', code):
        return ["检测到可能硬编码的凭据，请使用 ContextStore 传递"]
    return []
```

然后在 `run_validator()` 中调用。

### 15.3 新增漏洞状态

在 `memory/exploit_trajectory.py` 的 `VALID_STATES` 中添加：

```python
VALID_STATES = ("init", "probe_success", "payload_injected",
                "gadget_triggered", "privilege_escalated",  # 新增
                "oob_received")
```

在 `agents/evaluator.py` 的 `_detect_exploit_state()` 中添加对应判定逻辑。

### 15.4 新增载荷演化策略

在 `control/anti_regression.py` 中：

```python
# 扩展 _STRUCTURE_PATTERNS
(r"<!DOCTYPE.*\[.*<!ENTITY", "xxe"),

# 扩展 _PRIMITIVE_MUTATION_MAP
"xxe": [
    '<!ENTITY xxe SYSTEM "file:///etc/passwd">',
    '<!ENTITY xxe SYSTEM "php://filter/.../resource=index.php">',
    '<!ENTITY xxe SYSTEM "http://oob-server/xxe-callback">',
],
```

### 15.5 新增复盘启发规则

在 `agents/consolidator.py` 的 `CONSOLIDATOR_SYSTEM_PROMPT` 中添加新诊断信号：

```text
【XXE 专项诊断】
  "XML parsing error" + 响应中包含文件内容 → 确认 XXE 已触发
  "External entities are not allowed" → 尝试 parameter entity 或 XInclude 绕过
```

### 15.6 新增挑战适配器

```python
# core/adapters/my_challenge.py
from core.challenge_adapter import ChallengeAdapter, register_adapter

@register_adapter
class MyChallengeAdapter(ChallengeAdapter):
    challenge_name = "my_challenge"

    def extra_rules(self) -> str:
        return "此靶场使用 Spring Boot + Thymeleaf，SSTI语法为 #{...}"

    def http_semantic_errors(self) -> dict[str, str]:
        return {"Invalid CSRF Token": "需要先 GET /form 获取 CSRF token"}
```