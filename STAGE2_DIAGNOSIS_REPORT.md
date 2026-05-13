# Stage2 四智能体协同诊断报告

> 基于对 a.txt 执行日志（8轮迭代）+ 全部源码的深度分析
> 日期：2026-05-10 | 分析范围：planner / validator / executor / evaluator / coordinator

---

## 一、执行日志关键发现（a.txt 8轮迭代全景）

### 迭代1：Planner 生成了"占位符计划"
```
step 2: s.cookies.update(json.loads(''''{"session":"SESSION_PLACEHOLDER"}'''))
step 3: s.cookies.update(json.loads(''''{"session":"SESSION_PLACEHOLDER"}'''))
step 4: ctx=json.loads(''''{"antiCSRFToken":"TOKEN_PLACEHOLDER"}''')
```
**问题**：Planner 生成的代码中包含 `SESSION_PLACEHOLDER`、`TOKEN_PLACEHOLDER` 等硬编码占位符，
而不是使用 `os.environ.get('CO_REDTEAM_CONTEXT')` 读取上一步的真实输出。这导致：
- step2 login 用假 session → **exit_code=1 (KeyError)**
- step3 用假 session 去 settings → **401 Unauthorised**
- step4 用假 token 去 profile → **401 Unauthorised**

### 迭代2：Planner 开始用 chain_context，但 antiCSRFToken 获取方法错误
```
step 3: match=re.search(r'name="antiCSRFToken"[^>]*value="([^"]+)"', r.text)
→ token="" (HTML里根本没有这个字段！)
→ step 5 profile: "CSRF Detected! hold your horses you punk!" (401)
```
**问题**：尽管 adapter 规则明确说了"antiCSRFToken 在 JWT payload 里"，Planner **仍然**
用正则从 HTML 提取。而且 step3 有语法错误被跳过。

### 迭代3：继续犯同样的错误
```
step 3: match=re.search(r'name="antiCSRFToken"[^>]*value="([^"]+)"',r.text)
→ 又是语法错误被跳过！
→ 后续步骤全部 401
```

### 迭代4：终于改了 token 提取方式？没有！
```
step 3: match=re.search(r'name="antiCSRFToken"[^>]*value="([^"]+)"',r.text)  ← 还是老样子！
→ 401
step 5: sendVerification 用了 POST data={'antiCSRFToken':token}  ← 应该是 GET 无参数！
→ 405 Method Not Allowed
```
**新增错误**：sendVerification 方法也错了。

### 迭代5-8：陷入死循环
每次迭代都在重复同样的错误模式：
1. ✅ 注册成功（200）
2. ✅ 登录成功（200），拿到真实 JWT session cookie
3. ❌ antiCSRFToken 提取：**始终用正则从 HTML 提取**（得到空字符串）
4. ❌ profile 注入：因为 token 为空 → CSRF 检测失败（401）或 401 Unauthorised
5. ❌ sendVerification：有时用错 HTTP 方法（POST→405）
6. ❌ 读 flag：404

**8轮迭代后，系统从未成功获取到 antiCSRFToken，从未成功注入 SSTI payload，从未拿到 flag。**

---

## 二、根因分析（Root Cause Analysis）

### 根因 #1 [致命] Planner 的 LLM 不遵守指令 —— "幻觉式规划"

**现象**：
- `_COMMON_RULES` 和 adapter 的 `extra_rules()` 都明确写了：
  > "antiCSRFToken 不在HTML页面中！它嵌入在 session cookie (JWT) 的 payload 里！"
  > "正确获取方式：base64解码 session cookie 的第二段"
- 但 LLM 在 8 轮迭代中，**至少 6 轮**仍然生成 `re.search(r'...antiCSRFToken...' , r.text)`
- 即使 feedback 明确指出 "CSRF Detected! hold your horses you punk!"，LLM 的修正方向
  是"换个正则 pattern"而不是"换JWT解码方法"

**深层原因**：
1. **Prompt 过长导致注意力稀释**：`_COMMON_RULES` 有 ~150 行规则 + `build_dynamic_prompt()`
   生成的 system prompt 可能有 3000-5000 tokens。LLM（DeepSeek-chat）在如此长的上下文中，
   容易"遗忘"或"忽略"特定约束。
2. **反馈信号不够结构化**：coordinator 传递给 planner 的 feedback 是自然语言文本，
   不是结构化的错误码。LLM 可能误解修复方向。
3. **没有强制约束机制**：当前完全依赖 LLM "自觉遵守" prompt 中的规则。
   如果 LLM 忽略了某条规则，没有任何代码层面的兜底。

**影响等级**：🔴 致命 —— 这是整个系统无法工作的最主要原因

---

### 根因 #2 [严重] Chain Context 传播断裂 —— 步骤间数据流不连贯

**现象**：
- 迭代1：Planner 直接写 `SESSION_PLACEHOLDER` 硬编码，完全不读 chain_context
- 迭代2开始：Planner 开始用 `os.environ.get('CO_REDTEAM_CONTEXT')`，但：
  - key 名不对：用 `ctx.get('cookies')` 但上一步输出的 key 可能是别的名字
  - 当某步因语法错误被跳过时（validator skip），后续步骤拿到的 chain_context
    缺少该步输出，导致级联失败
  - step3（token提取）反复语法错误被跳过 → step4/5 拿不到 token → 全部 401

**深层原因**：
1. **跨步依赖声明形同虚设**：每个 step 有 `depends_on` 字段，但 executor 并不真正
   使用它来排序或等待依赖完成。skip 了的步骤不会自动让下游步骤也 skip。
2. **chain_context 的 key 命名不一致**：Planner 自由选择输出 key 名
   （如 `cookies`、`session`、`login_status`、`step1`、`step2`），下游步骤必须
   猜测上游用了什么 key 名。
3. **没有 fallback 机制**：当某个中间步骤失败时，没有"回退到上一个已知良好状态"的能力。

**影响等级**：🟠 严重 —— 导致攻击链在中间环节断开

---

### 根因 #3 [严重] Python 单行代码语法错误高频出现

**现象**：
```
迭代2 step[3]: python 语法错误: invalid syntax (line=1, offset=314)  ← 被跳过
迭代3 step[3]: python 语法错误: invalid syntax (line=1, offset=215)  ← 被跳过
迭代5 step[3]: python 语法错误: invalid syntax (line=1, offset=270)  ← 被跳过
迭代8 step[4]: python 语法错误                              ← 被跳过
```
**几乎每一轮都有 1 个 step 因语法错误被 validator 跳过！**

**深层原因**：
1. **LLM 生成带嵌套引号的复杂单行代码**：当 command 中同时包含单引号和双引号时
   （如 `re.search(r'pattern', r.text)` 外层又套了 shell 的单引号包装），
   引号转义极其容易出错。
2. **validator 的 _fix_truncated_code 能力有限**：只能补全括号/引号数量，
   无法修复语义级别的语法错误（如缩进块残留、未闭合的三引号等）。
3. **被跳过的步骤 = 攻击链缺口**：如果被跳过的是关键步骤（如 token 提取），
   整条链就断了。而且 planner 收到的 feedback 只说"语法错误被跳过",
   不知道具体哪一步、什么语法错误。

**影响等级**：🟠 严重 —— 约 15-20% 的步骤因语法错误失效

---

### 根因 #4 [中等] Evaluator 评估标准宽松，误导迭代方向

**现象**：
查看 `feedback.json`（某次迭代的评估结果）：
```json
{
  "repro_success": true,
  "confidence": 0.6,
  "summary": "SSTI攻击链执行成功...最后一步读取flag.txt返回404",
  "should_continue": true
}
```
**Evaluator 判定 repro_success=True（置信度0.6），但实际上 flag 从未被获取！**

**深层原因**：
1. **SSTI 盲执行的评判标准过于宽松**：只要攻击链"完整执行"就判 True，
   不管 flag 是否真的拿到了。这导致 coordinator 认为任务接近成功，
   进入"定向修复迭代"而非重新设计攻击链。
2. **confidence=0.6 太低却仍然触发 success 分支**：coordinator 中
   `conf >= 0.65` 才算达标，所以 0.6 会继续迭代。但 `repro_success=True`
   这个信号本身就有误导性——它告诉 planner "你的方案基本正确，微调即可"，
   而实际情况是"核心逻辑完全没跑通"。
3. **feedback_for_planner 质量不高**：evaluator 给出的建议是
   "尝试其他路径如/tmp/flag.txt 或使用外带方式"，但没有指出最关键的
   问题——antiCSRFToken 从未成功获取。

**影响等级**：🟡 中等 —— 导致迭代方向偏离，浪费迭代次数

---

### 根因 #5 [中等] Feedback 循环信息损失严重

**数据流**：
```
executor 输出 → coordinator 检测HTTP错误 → evaluator 评估 → feedback.json → planner(下一轮)
```

**每层的信息损失**：

| 层 | 输入信息量 | 输出信息量 | 损失 |
|---|---|---|---|
| executor | 每步 stdout/stderr/exit_code/chain_output (~2KB/步) | step_results JSON (~1KB) | 丢失原始响应体 |
| coordinator | step_results + HTTP语义错误检测 | 合并到 feedback_for_planner 文本 (~500字) | 结构化错误→自然语言 |
| evaluator | plan + execution_result | feedback JSON (~1KB) | 丢失每步详细stderr |
| **planner 收到的** | | **feedback_for_planner (~300字文本)** | **~95% 信息丢失** |

**具体例子**：
- executor 明确输出了 `step 3: antiCSRFToken="", status=401`
- coordinator 检测到了 `"Unauthorised access detected!"` 错误
- evaluator 说 "SSTI攻击链前5步全部成功"
- **planner 收到的最终反馈完全没有提到 antiCSRFToken 为空的问题！**

**影响等级**：🟡 中等 —— planner 无法精确定位问题所在

---

### 根因 #6 [低] 没有自我诊断和自愈能力

**现象**：
整个系统是一个纯前向循环：plan → validate → execute → evaluate → plan(下一轮)

缺失的能力：
1. **没有"计划预检"阶段**：planner 生成计划后，没有模拟执行来检查
   - 占位符是否存在？（如 SESSION_PLACEHOLDER）
   - chain_context 的 key 是否匹配？
   - 依赖图是否完整？
2. **没有"错误归因"模块**：当执行失败时，没有组件专门负责分析
   - 这是 LLM 幻觉？（规则写了但不遵守）
   - 这是数据流断裂？（chain_context 没传过来）
   - 这是目标环境问题？（目标API变了）
3. **没有"策略切换"机制**：当同一策略连续 N 轮失败时，
   不会自动尝试完全不同的方法（比如放弃 SSTI，尝试 CSS injection 或 race condition）

**影响等级**：🟡 中等 —— 系统缺乏自适应能力

---

## 三、各 Agent 具体问题清单

### 3.1 Planner Agent

| # | 问题 | 位置 | 严重度 | 出现频率 |
|---|------|------|--------|----------|
| P1 | 生成占位符代码（SESSION_PLACEHOLDER/TOKEN_PLACEHOLDER） | run_planner() → LLM output | 🔴致命 | 迭代1 |
| P2 | 忽略 antiCSRFToken JWT 解码规则，坚持用 HTML 正则提取 | build_dynamic_prompt() → adapter.extra_rules() | 🔴致命 | 6/8轮 |
| P3 | 生成含嵌套引号的复杂单行代码导致语法错误 | run_planner() → LLM output | 🟠严重 | 4/8轮 |
| P4 | sendVerification 用 POST 而非 GET | run_planner() → LLM output | 🟠严重 | 2/8轮 |
| P5 | chain_context key 命名不一致，上下游不匹配 | run_planner() → user dict construction | 🟠严重 | 5/8轮 |
| P6 | 反复注册已存在的邮箱（Email already exists! 403） | run_planner() → LLM output | 🟡低 | 3/8轮 |
| P7 | Prompt 过长（3000+ tokens），LLM 注意力稀释 | _COMMON_RULES + build_dynamic_prompt() | 🟡中 | 持续 |

### 3.2 Validator Agent

| # | 问题 | 位置 | 严重度 | 影响 |
|---|------|------|--------|------|
| V1 | 语法错误的 step 被静默跳过，但**不影响下游步骤执行** | validate_plan() → syntax_warnings | 🟠严重 | 导致链断裂 |
| V2 | 不检查占位符（PLACEHOLDER/SAMPLE/TODO） | _validate_step() | 🟡中 | 让迭代1的假代码通过 |
| V3 | 不检查 chain_context key 的一致性 | validate_plan() | 🟡中 | 上游输出key≠下游读取key |
| V4 | 自动补全 import os 但可能破坏已有导入顺序 | _normalize_plan() | 🟡低 | import os;import requests,os (重复) |

### 3.3 Executor Agent

| # | 问题 | 位置 | 严重度 | 影响 |
|---|------|------|--------|------|
| E1 | 跳过步骤后 chain_context 不更新，下游读到旧值/空值 | run_executor() → skip_indices | 🟠严重 | 级联401 |
| E2 | chain_output 解析只找第一个 ###CHAIN_OUTPUT###，如果有多个会丢数据 | run_executor() → marker search | 🟡低 | 数据丢失 |
| E3 | 不做任何执行前的"合理性检查"（如检测 PLACEHOLDER） | _run_step() → _run_docker() | 🟡中 | 执行无意义代码 |

### 3.4 Evaluator Agent

| # | 问题 | 位置 | 严重度 | 影响 |
|---|------|------|--------|------|
| E1 | SSTI 盲执行判定过于宽松：repro_success=True 但 flag 未获取 | EVAL_SYSTEM | 🟡中 | 误导迭代方向 |
| E2 | feedback_for_planner 未指出最关键问题（antiCSRFToken 为空） | EVAL_SYSTEM + LLM judgment | 🔴严重 | planner不知道要修什么 |
| E3 | should_continue 几乎总是 True，缺少终止条件 | EVAL_SYSTEM | 🟡中 | 浪费迭代次数 |
| E4 | memory_patch 记录了"成功"但实际上 flag 没拿到 | run_evaluator() | 🟡低 | 污染长期记忆 |

### 3.5 Coordinator（编排器）

| # | 问题 | 位置 | 严重度 | 影响 |
|---|------|------|--------|------|
| C1 | HTTP 语义错误检测有效但注入 feedback 的信息量太少 | _detect_http_failures_from_chain() | 🟡中 | ~95% 信息损失 |
| C2 | 没有计划预检/模拟执行阶段 | run_pipeline() | 🟡中 | 让有问题的计划直接执行 |
| C3 | 连续同类失败没有触发策略切换 | run_pipeline() for loop | 🟡中 | 8轮都在试同一个失败策略 |
| C4 | 失败教训记录到 ChromaDB 但检索质量不稳定 | _save_failure_lessons() + memory query | 🟡低 | 教训记了但没用上 |

---

## 四、核心矛盾总结

```
┌─────────────────────────────────────────────────────────────┐
│                     核心矛盾拓扑                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Planner (LLM)                                             │
│   ├── 生成能力：✅ 能生成多步攻击链                           │
│   ├── 遵守规则：❌ 关键规则反复违反（antiCSRFToken方法）      │
│   ├── 自我修正：❌ 同一错误连续 6 轮不改正                   │
│   └── 根因：Prompt太长 + 反馈不够结构化 + 无强制约束        │
│         ↓                                                   │
│   Executor                                                  │
│   ├── 执行能力：✅ Docker沙箱运行正常                        │
│   ├── 数据传递：⚠️ chain_context 断裂（skip步骤导致）       │
│   └── 根因：无预检 + skip不阻断下游                          │
│         ↓                                                   │
│   Evaluator                                                 │
│   ├── 评估能力：⚠️ SSTI盲执行误判为success                  │
│   ├── 反馈质量：❌ 未指出核心问题（token为空）               │
│   └── 根因：评估标准宽松 + 信息损失严重                      │
│         ↓                                                   │
│   Coordinator                                               │
│   ├── 编排能力：⚠️ 前向循环能运转                          │
│   ├── 自愈能力：❌ 无策略切换/无诊断/无预检                 │
│   └── 根因：纯前向架构，无反思回路                          │
│                                                             │
│   【一句话总结】                                            │
│   系统是一个"能转但转不好"的前向循环：                       │
│   Planner 不听规则 → 生成有问题的计划 → Executor 盲目执行     │
│   → Evaluator 宽松评估 → Coordinator 继续下一轮 → 重复      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 五、建议改进方向（供 Gemini 参考讨论）

### 方向 A：强化约束层（解决 P1/P2 —— LLM 不守规矩）

**思路**：不在 prompt 里"请求"LLM 遵守规则，而是在代码层面**强制**约束。

具体做法：
1. **Plan Post-Processor**：planner 输出 plan 后，增加一个代码层的后处理：
   - 扫描所有 step 的 command，检测 `PLACEHOLDER`、`SAMPLE`、`TODO` 等关键词
   - 发现则直接拒绝该 plan，要求重生成（附带具体错误信息）
   - 检测 `re.search.*antiCSRFToken.*r.text` 模式，发现则自动替换为 JWT 解码模板
2. **Template Injection 替代 Prompt Instruction**：对于 antiCSRFToken 这种
   关键操作，不要靠 LLM "记住"方法，而是直接在代码层把 JWT 解码步骤
   作为固定模板注入到 plan 中（类似 validator 自动补全 import os）

**预期效果**：消除"LLM 幻觉式规划"，确保关键操作的正确性

### 方向 B：结构化 Feedback Loop（解决 C1/E2 —— 信息损失）

**思路**：将自然语言 feedback 改为结构化错误码 + 上下文。

具体做法：
1. 定义错误码枚举：
   ```
   ERR_CSRF_TOKEN_EMPTY     = "antiCSRFToken 提取结果为空"
   ERR_SESSION_NOT_PROPAGATED = "session cookie 未传递到下游步骤"
   ERR_WRONG_HTTP_METHOD    = "HTTP方法错误（应为GET/POST）"
   ERR_SYNTAX_ERROR_SKIP    = "步骤因语法错误被跳过，导致链断裂"
   ```
2. Evaluator 输出的 feedback_for_planner 包含：
   ```json
   {
     "structured_errors": ["ERR_CSRF_TOKEN_EMPTY", "ERR_SESSION_NOT_PROPAGATED"],
     "failed_steps": [
       {"id": 3, "error": "ERR_CSRF_TOKEN_EMPTY", "detail": "regex from HTML got empty"},
       {"id": 4, "error": "ERR_CSRF_TOKEN_EMPTY", "detail": "used empty token in profile"}
     ],
     "text_summary": "..."
   }
   ```
3. Planner 的 prompt 中加入错误码→修复动作的映射表

**预期效果**：planner 能精确知道"哪里错了、为什么错、怎么修"

### 方向 C：Plan Pre-flight Check（解决 C2/V2 —— 有问题的计划直接拦截）

**思路**：在 execute 之前增加一个轻量级的"计划预检"阶段。

具体做法：
1. 新增 `preflight_check(plan, confirmed)` 函数，检查项：
   - [ ] 所有 step 的 command 不含 PLACEHOLDER/SAMPLE/TODO
   - [ ] depends_on 形成 DAG 且无环
   - [ ] chain_context 的写入 key 和读取 key 匹配
   - [ ] 关键操作（如 token 提取）使用了正确的方法
   - [ ] HTTP 方法与端点匹配（sendVerification=GET）
2. 预检不通过 → 直接返回结构化错误给 planner 重生成，
   **不消耗一次完整的 Docker 执行迭代**

**预期效果**：每轮迭代的质量大幅提升，减少无效执行

### 方向 D：Strategy Switching / 自愈机制（解决 C3 —— 死循环）

**思路**：当同一类错误连续出现 N 轮时，自动切换策略。

具体做法：
1. 在 coordinator 中维护一个 `error_history` 队列
2. 如果连续 3 轮都出现 `ERR_CSRF_TOKEN_EMPTY`：
   - 自动在 planner prompt 中注入**更强的提示**（不是自然语言，
     而是直接给出可复制的正确代码片段）
   - 或者：临时禁用 LLM 的 token 提取步骤生成能力，
     强制使用代码模板
3. 如果连续 5 轮 confidence < 0.3：
   - 触发"策略切换"：从当前攻击向量（SSTI）切换到下一个
     （CSS injection / race condition / file upload RCE）

**预期效果**：避免 8 轮都在重复同一个失败的策略

### 方向 E：Evaluatior 评估标准收紧（解决 E1/E3）

**思路**：区分"攻击链完整性"和"实际利用成功率"。

具体做法：
1. 新增 `flag_acquired` 字段：只有当 flag 真正被获取时才为 True
2. `repro_score` 拆分为多个维度：
   - `chain_completeness`: 攻击链是否完整执行（0-1）
   - `vulnerability_triggered`: 漏洞是否确实被触发（0-1）
   - `goal_achieved`: 最终目标是否达成（0-1，即 flag）
3. 只有 `goal_achieved == True` 时才设置 `should_continue = False`

**预期效果**：避免"伪成功"导致的迭代方向偏离

---

## 六、优先级排序建议

| 优先级 | 方向 | 解决的核心问题 | 预期收益 | 实现难度 |
|--------|------|----------------|----------|----------|
| P0 | A: 强化约束层 | LLM 不遵守关键规则（antiCSRFToken等） | 🔴🔴🔴 消除最主要的失败原因 | 中 |
| P1 | B: 结构化Feedback | 信息损失 95%，planner 不知道怎么修 | 🔴🔴 提升迭代效率 | 低 |
| P2 | C: Plan Pre-flight | 有问题的计划浪费整轮Docker执行 | 🔴🔴 减少无效迭代 | 中 |
| P3 | D: Strategy Switching | 8轮重复同一失败策略 | 🔴🔴 避免死循环 | 中高 |
| P4 | E: 评估标准收紧 | 伪成功误导迭代方向 | 🟡🟡 方向更准确 | 低 |

---

*本报告基于实际执行日志（a.txt，8轮迭代，36个步骤执行记录）和全部源码分析生成。*
*建议将此报告提交给 Gemini 讨论，重点询问方向 A（强化约束层）的具体实现方案。*
