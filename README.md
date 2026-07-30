# November — Autonomous Exploit Reasoning System

**Constrained Agency · Verification-Driven Planning · Self-Adaptive Exploit Evolution**

> *"The problem is not that LLMs hallucinate. The problem is that we give them an unbounded action space and expect convergent exploit chains."*

---

## 1. Project Synopsis

**November** is an autonomous vulnerability discovery, validation, and controlled exploitation framework built on the principle of **Constrained Agency** — the radical proposition that an LLM's exploit reasoning capability *improves* when its action space is surgically restricted rather than expanded. The system enforces a **Verification-Driven Planning** regime in which every agent action is cross-validated against a static **Runtime Manifest** before execution, eliminating the primary failure mode of LLM-based red-team systems: **Hybrid Representation Collapse** — the phenomenon where a model oscillates between natural language reasoning and code generation, degrading both.

### The Three Plagues of LLM-Driven Exploitation

| Plague | Manifestation | November Countermeasure |
|--------|--------------|------------------------|
| **Probabilistic Hallucination Ceiling** | Free-form Python generation produces semantically plausible but syntactically invalid payload chains that fail at runtime | AST-declarative plan format — Planner outputs structured `imports`/`sdk_calls` arrays, never raw free-text Python |
| **Attention Collapse** | After 3+ rounds of iterative exploitation, the model's context window saturates with stale stdout, causing it to forget verified injection points and re-execute failed payloads | Six-layer **Attention Routing Topology** with physical character-level memory budget enforcement at each layer |
| **Data Contract Drift** | Planner imports `requests` directly; Validator blocks it; Executor silently fails — the three agents operate on *different* capability assumptions | Single-source-of-truth **RUNTIME_MANIFEST** in `coordinator.py:29-57`, replicated in every agent's system prompt and cross-validated at runtime |

### System Identity

```
                     █▄ █ █▀█ █░█ █▀▀ █▀▄▀█ █▄▄ █▀▀ █▀█
                     █░▀█ █▄█ ▀▄▀ ██▄ █░▀░█ █▄█ ██▄ █▀▄
              Autonomous Exploit Reasoning System v2
```

November is not a fuzzer. It does not spray payloads and hope. It maintains a persistent **Exploit State Machine** (`init → probe_success → payload_injected → gadget_triggered → oob_received`), advances along a directed **Primitive Transition Graph**, and learns cross-target exploit patterns through a **Consolidator** agent that performs verbal reinforcement learning on completed trajectories. The system runs exploit payloads inside fully air-gapped Docker bridge-network containers with seccomp profiles, strict memory limits (256 MB), and CPU throttling (50% single-core quota).

---

## 2. Research Novelty

### 2.1 Capability Grounding via Explicit Manifest Registration

> **Core insight:** An LLM's tendency to hallucinate available capabilities is *structurally identical* to the symbol-grounding problem in classical AI. We solve it by forcing the agent to operate on a closed, enumerated set of primitives.

Traditional LLM agents infer their runtime capabilities through exploratory code execution — "try `import os`, if it fails, try `import subprocess`." This leaks environmental information and wastes iteration budget on capability discovery that should be *a priori*.

November introduces **Capability Grounding**: every agent component derives its action space from a single **RUNTIME_MANIFEST** embedded in the coordinator at `b/coordinator.py:29-57`:

```python
RUNTIME_MANIFEST = {
    "sdk_primitives": [
        "HttpClient.get", "HttpClient.post",
        "HttpClient.raw_request", "HttpClient.last_response",
    ],
    "safe_modules": [
        "json", "base64", "re", "time", "struct",
        "urllib.parse", "http.cookies", "hashlib", "hmac",
        "redteam_sdk",
    ],
    "blocked_modules": [
        "os", "subprocess", "socket", "ctypes", "cffi", "pty",
        "pickle", "marshal", "requests", "urllib3", "urllib",
        "builtins", "gc", "inspect", "ast", "code", "compileall",
        # ... 24 modules total
    ],
}
```

**This is not a "prompt suggestion" — it is a hard constraint.** The Validator agent performs AST-level import cross-checking against this manifest. Any `import` statement whose root module falls outside `safe_modules` is rejected with `valid:false` before execution. The Planner's system prompt is constructed from this manifest, not the other way around.

The architectural implication is profound: **the manifest is the source of truth, not the model weights.** This inverts the standard LLM-agent paradigm where the model's parametric knowledge defines the action space, and runtime errors serve as (expensive, delayed) negative feedback.

### 2.2 Attention Routing: Topological Reordering for Long-Horizon Stability

> **Core insight:** Transformer attention is distance-weighted. Information placed at position *k* in the prompt receives exponentially less attention weight than information at position *k-1*. In a 15,000-character system prompt, the user's goal — the *only* thing that matters — is literally invisible to the model.

LLM-based exploit agents degrade over long-horizon runs because the growing context window (accumulated stdout, trajectory logs, feedback) pushes critical constraints out of the model's effective attention radius. The model begins to "forget" that it cannot import `os`, that the target base URL changed, or that a specific injection endpoint was already confirmed.

November enforces a strict **six-layer Attention Routing topology** with physical character-level budgets per layer:

```
┌──────────────────────────────────────────────────────────┐
│  L1: Runtime Manifest        (≤ 800 chars)  [最高权重]    │
│  L2: Hard Constraints        (≤ 600 chars)               │
│  L3: SDK Contract            (≤ 500 chars)               │
│  L4: Verified Facts           (≤ 800 chars)               │
│      ├─ primitive_context     (≤ 500)                     │
│      ├─ verification_context  (≤ 300)                     │
│      └─ memory_context        (≤ 400)                     │
│  L5: Trajectory State         (≤ 300 chars)               │
│  L6: User Goal                (≤ 2500 chars) [最低权重]    │
├──────────────────────────────────────────────────────────┤
│  FINAL_PAYLOAD_HARD_CAP = 5000 chars                      │
│  (Dual-safety: per-layer + final truncation)              │
└──────────────────────────────────────────────────────────┘
```

This ordering is not arbitrary. L1 (Manifest) occupies the highest-attention position because capability boundaries must be the first and strongest signal the model receives. L6 (User Goal) occupies the lowest because the model will naturally attend to the most recent instruction in the user message anyway. Each layer is physically truncated — not "trimmed with a warning printed to stdout" but sliced at the byte level before assembly.

**Why this works:** Transformer self-attention computes pairwise dot products across all token positions, but the resulting attention matrix is dominated by proximity effects. A constraint at position 3000 has ~10× less influence than an identical constraint at position 300, *even though the model "saw" both*. By topologically sorting constraints by priority and enforcing per-layer character budgets, we guarantee that the Manifest and hard constraints remain within the model's high-attention radius regardless of how much trajectory history accumulates.

### 2.3 Strict Memory Budgeting: Non-Parametric Rule Preservation via Dense Dehydration

> **Core insight:** Long-term memory in exploit agents should store *failure abstractions* (non-parametric rules), not verbose Chain-of-Thought traces (parametric noise).

November's memory system enforces a **≤ 5,000-character hard cap** on the aggregated memory block injected into the Planner's system prompt. This is achieved through:

1. **Physical truncation** — `_physical_truncate()` slices at the byte level; no "soft trimming"
2. **Head-body-tail preservation** — truncated memory retains `[head:33%] ... [tail:67%]` to preserve both high-signal opening context and high-signal closing rules
3. **Dense extraction** — the `_extract_user_goal_dense()` function compresses a 19,000-character confirmed vulnerability report into ≤ 2,500 characters by extracting only `base_url`, top-20 endpoints, CWE+title, and 300-character evidence snippets

```python
_MAX_MEM_BODY = 5000
if len(body) > _MAX_MEM_BODY:
    body = (
        body[:_MAX_MEM_BODY // 3]
        + f"\n...[TRUNCATED {len(body)} → {_MAX_MEM_BODY} chars]...\n"
        + body[-_MAX_MEM_BODY * 2 // 3:]
    )
```

The critical design decision is that truncated content is **discarded, not summarized**. Summarization introduces parametric noise — the LLM performing the compression may hallucinate or emphasize the wrong signal. Physical slicing preserves verbatim facts while respecting the attention budget.

### 2.4 AST-Declarative Planning: Eliminating Syntax Drift

The Planner outputs structured JSON with declarative `imports` and `sdk_calls` arrays instead of free-form Python strings:

```json
{
  "steps": [{
    "id": 1,
    "type": "python",
    "imports": ["json", "re", "redteam_sdk"],
    "sdk_calls": ["HttpClient.get", "HttpClient.post"],
    "command": "",
    "purpose": "Probe SSTI reflection via {{7*7}}",
    "target_primitive": "ssti_reflection"
  }]
}
```

The Executor's `_inflate_ast_to_script()` function (at `b/agents/executor.py:465`) compiles this declarative representation into runnable Python *deterministically* — no model hallucination can introduce a syntax error, a missing import, or an undefined variable. The Validator cross-checks every `imports` entry against the Manifest *before* the Executor sees it, eliminating the entire class of "passed validation, failed at runtime" bugs.

### 2.5 Dual-Model Architecture for Strategic Consolidation

The Consolidator agent uses an **independent, higher-capability model** (`DeepSeek-V4-Pro` via separate `CONSOLIDATOR_*` environment variables) that is architecturally *decoupled* from the tactical loop model (`GLM-4.5-Flash`). This prevents the tactical model's context saturation from degrading the strategic model's analysis quality. The Consolidator reads the full trajectory after the tactical loop terminates and produces **YAML weaponized templates** that seed the next task's Planner with hardened payloads.

---

## 3. System Architecture

### 3.1 Agent Topology

November operates a **five-agent staged pipeline** with a **Coordinator** as the central orchestration hub:

```
                           ┌──────────────────────────────────────┐
                           │         COORDINATOR (调度中枢)         │
                           │  · Agent scheduling (P→V→E→E→C)      │
                           │  · Memory injection into Planner      │
                           │  · Circuit Breaker (3x failure→force  │
                           │    strategy switch)                   │
                           │  · Attack Surface Rotator             │
                           │  · Decaying Dynamic Iteration Engine  │
                           └──────┬──────────┬────────────────────┘
                                  │          │
             ┌────────────────────┼──────────┼────────────────────┐
             │                    │          │                    │
             ▼                    ▼          ▼                    ▼
    ┌──────────────┐    ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
    │   PLANNER    │    │  VALIDATOR   │   │  EXECUTOR    │   │  EVALUATOR   │
    │  (决策层)     │    │  (逻辑拦截层) │   │  (物理执行层)  │   │  (状态感知层) │
    │              │    │              │   │              │   │              │
    │ plan.json ───┼───▶│ validated ───┼──▶│ exec_result ─┼──▶│ feedback ────┼──┐
    └──────────────┘    └──────────────┘   └──────────────┘   └──────┬───────┘  │
           ▲                                                         │          │
           │                   ◄─── feedback loop ──────────────────┘          │
           │                                                                    │
           │               ┌──────────────┐                                    │
           └───────────────│ CONSOLIDATOR │◄───────────────────────────────────┘
                           │  (战略进化层) │   迭代预算耗尽后唤醒
                           └──────┬───────┘
                                  │ 写入 patterns / strategies / techs
                                  ▼
                    ┌─────────────────────────┐
                    │  LayeredMemory (ChromaDB)│
                    │  L1: patterns (漏洞模式)  │
                    │  L2: strategies (策略)    │
                    │  L3: techs (技术载荷)      │
                    └─────────────────────────┘
```

**Fixed execution pipeline:** `Planner → Validator → Executor → Evaluator → (multi-round) → Consolidator`

### 3.2 Agent Responsibility Matrix

#### 3.2.1 Planner — Decision Layer (`b/agents/planner.py`, ~1,800 lines)

| Aspect | Implementation |
|--------|---------------|
| **Input** | 5-layer context: ChromaDB (L1/L2/L3), Trajectory Memory, Verification Memory, Primitive Context, prior-round Feedback |
| **Output** | Structured JSON plan with AST-declarative `imports`/`sdk_calls` arrays per step |
| **Prompt Assembly** | Six-layer Attention Routing topology with per-layer physical truncation |
| **CWE Inference** | `_infer_vuln_classification()` using 10-rule keyword scoring table from title/source/sink/description |
| **Memory RAG** | `_build_memory_context()` with ChromaDB `target_tags` metadata filtering — prevents "searching for LockTalk, retrieving Zhiyuan OA scripts" |

**Key architectural constraint**: The Planner never writes raw Python. Every step declares its capability requirements declaratively; the Executor performs deterministic AST→code inflation. This eliminates the entire error class of "Planner wrote os.system() and got blocked."

#### 3.2.2 Validator — Logical Interception Layer (`b/agents/validator.py`, ~850 lines)

The Validator is the **AST Prosecutor** — it does not generate attack logic; it only enforces security policy and structural conformance.

| Check Layer | Guard | Mechanism |
|-------------|-------|-----------|
| **Declarative Imports Check** | Every `imports[i]` root must be in `safe_modules`; any `blocked_modules` match → `valid:false` | `_validate_step_ast_against_manifest()` |
| **SDK Call Registration** | Every `sdk_calls[i]` must prefix-match an entry in `MANIFEST_SDK_PRIMITIVES` | String prefix matching against authorized primitives |
| **Python Syntax Check** (legacy mode) | `ast.parse()` on raw `command` string | Skipped when step uses declarative `sdk_calls` format |
| **Import Blocklist Scan** (legacy mode) | AST walk of import nodes against `_BLOCKED_IMPORTS` | Skipped when step uses declarative format |
| **Dangerous Pattern Scan** | Regex against `os.system(`, `subprocess.run(`, `__import__(` text literals | `_scan_text()` with severity `error` |
| **Trajectory Awareness** | State regression detection, payload degeneration detection | `_validate_trajectory_awareness()` |

**Critical design decision**: The Validator downgrades `exploit_reasoning` and `target_primitive` field violations from **errors** (→ plan rejection) to **warnings** (→ noted, plan proceeds). Only import/sdk_calls manifest violations are strict rejections. This prevents over-blocking on reasoning metadata while maintaining ironclad capability enforcement.

#### 3.2.3 Executor — Physical Execution Layer (`b/agents/executor.py`, ~1,340 lines)

The Executor is a **deterministic compilation engine**, not an intelligent agent. It performs zero reasoning.

| Capability | Implementation |
|------------|---------------|
| **AST→Code Inflation** | `_inflate_ast_to_script()` at line 465 — converts `imports`/`sdk_calls` arrays to runnable Python |
| **Docker Sandbox** | Bridge-network container, seccomp profile, 256 MB memory, 50% CPU quota, 30s timeout |
| **HTTP Auto-Instrumentation** | Monkey-patches `HttpClient.request` to auto-log `[HTTP] status method url => body` |
| **Security Interception** | `_check_python_safety()` — regex blacklist scan before Docker dispatch; violations → `security_blocked` |
| **Session Persistence** | Automatic cross-step cookie/session save and restore |
| **SDK Injection** | Writes `redteam_sdk.py` (full `HttpClient`, `ContextStore`, `OOBReceiver` implementation) into sandbox workspace |

**Sandbox execution flow:**

```python
# Executor auto-injects this wrapper around every step script:
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

#### 3.2.4 Evaluator — State Perception Layer (`b/agents/evaluator.py`, ~800 lines)

The Evaluator rejects binary success/failure classification in favor of **continuous state transition confidence scoring**.

**Five-stage Exploit State Machine:**

```
init ──▶ probe_success ──▶ payload_injected ──▶ gadget_triggered ──▶ oob_received
 │              │                   │                   │                  │
 │ endpoint     │ payload accepted  │ gadget activated   │ ironclad proof   │
 │ reachable    │ SSTI: {{7*7}}     │ SSTI: config dump  │ flag{...}        │
 │ HTTP 200     │ returns 49        │ RCE: uid=0 output  │ OOB callback     │
```

**Multi-dimensional progress signals** (12 signals, `_compute_progress_signals()`):
1. State machine advancement (ordinal position comparison)
2. New exploit primitive detected (set difference)
3. Primitive confidence increase (Δ ≥ 0.10)
4. New endpoint accessed (set difference)
5. New HTTP status code observed (set difference)
6. Payload mutation (token overlap < 60% → significant mutation)
7. Verified facts recorded (fresh fact count)
8. Evaluator milestone flag
9. Partial primitive confidence sum (Δ ≥ 0.20 across 8 sub-signals)
10. `ok_count` increase
11. EPE (Exploit Progress Engine) `progress_score` increase (Δ ≥ 0.03)
12. State transition probability increase (Δ ≥ 0.05)

**Blind RCE self-healing**: When the Evaluator detects `ok=True` with blank stdout (command execution confirmed but no output), it injects a `BLIND_RCE_FEEDBACK` directive instructing the Planner to escalate to OOB (Out-of-Band) exfiltration via `redteam_sdk.OOBReceiver`.

#### 3.2.5 Consolidator — Strategic Evolution Layer (`b/agents/consolidator.py`, ~400 lines)

The Consolidator activates *only after* the tactical loop exhausts its iteration budget. It uses a separate LLM model with its own dedicated API key, base URL, and model name (configured via `CONSOLIDATOR_*` environment variables).

| Output Artifact | Destination | Purpose |
|-----------------|-------------|---------|
| `diagnosis` | Console + memory | Root-cause analysis of failure modes |
| `patterns[]` | `memory/pattern.json` | Generalized error fingerprints with root causes |
| `strategies[]` | `memory/strategy.json` | Attack chain templates with success/failure annotations |
| `techs[]` | `memory/tech.json` | Executable code patches with `executable_patch` fields |
| `yaml_templates[]` | `templates/builtin/` | YAML weaponized payload library with CWE-tagged templates |

**Expert System Prompt**: 690+ lines of hardcoded diagnostic rules covering sandbox conflict resolution, payload format dead-end detection, WAF bypass synthesis, and attack chain abstraction.

### 3.3 Coordinator — Orchestration Hub (`b/coordinator.py`, ~1,544 lines)

The Coordinator implements the following control-plane mechanisms:

| Mechanism | Behavior |
|-----------|----------|
| **Circuit Breaker** | 3 consecutive failures or strategy stagnation (same error fingerprint across window) → forces strategy switch with CWE-keyed memory retrieval |
| **Attack Surface Rotator** | When a vulnerability's entire plan is BLOCKED, rotates to the next unblocked candidate in `confirmed_vuln.json` |
| **Decaying Dynamic Iteration Engine** | Initial budget = 8; each milestone grants `max(1, 5 - milestone_count)` bonus iterations; hard cap at 20; 4 consecutive zero-progress rounds → abort |
| **Multi-dimensional Progress Detection** | 12 signals evaluated per round; progress resets the zero-progress streak even if no milestone was achieved |
| **Context Window Sliding** | Retains last 3 rounds' full execution summaries; collapses older rounds to single-line summaries |
| **Automatic Failure Lesson Logging** | Every execution failure is auto-logged as a `strategy` entry to ChromaDB with stderr analysis and HTTP semantic error detection |

---

## 4. Memory Architecture & Hierarchical RAG

### 4.1 ChromaDB Three-Layer Memory Topology

The memory system uses **ChromaDB** as a vector database with three semantically distinct collection layers, each queried independently with metadata filtering (`where` clauses on `target_tags`):

```
┌─────────────────────────────────────────────────────────────────┐
│                    LayeredMemory (ChromaDB)                      │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  L1: Pattern Layer (漏洞模式层)                             │  │
│  │  · Topological associations of golden exploit primitives   │  │
│  │  · "SSTI in email field → class traversal → os.popen       │  │
│  │     requires blind exfiltration, not response-body check"  │  │
│  │  · Collection: pattern_collection                          │  │
│  │  · Query: n_results=3                                      │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  L2: Strategy Layer (利用策略层)                             │  │
│  │  · Path-level tactical guidance when attack chains stall   │  │
│  │  · Bifurcated: success strategies vs. failure lessons      │  │
│  │  · success → "What worked and why"                         │  │
│  │  · failure → "BLACKLIST: never try payload X against Y"    │  │
│  │  · Collection: strategy_collection                         │  │
│  │  · Query: n_results=6 (3 success + 3 failure)              │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  L3: Technique Layer (技术载荷层)                            │  │
│  │  · Hardened, executable payloads and bypass scripts        │  │
│  │  · Contains `executable_patch` — copy-paste ready code     │  │
│  │  · "pickle sandbox bypass: struct pack opcodes, 0 imports" │  │
│  │  · Collection: tech_collection                             │  │
│  │  · Query: n_results=8, deduplicated by payload content     │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 Metadata-Filtered Retrieval

The critical innovation that prevents cross-target contamination:

```python
# Phase 1: extract tech-stack tags from confirmed_vuln.json
target_tags = ["python", "flask", "jinja2", "werkzeug"]

# Phase 2: query ChromaDB with WHERE clause
patterns = memory.query_patterns(
    query, n_results=3,
    where={"tags_str": {"$contains": "jinja2"}}
)

# Phase 3: if filtered results empty, degrade to unfiltered
# (never skip retrieval entirely)
```

Without this, a Planner attacking "LockTalk" (Python/JWT) would retrieve payloads for "Zhiyuan OA" (Java/serialization) based purely on embedding similarity — because the vector space conflates "JWT token manipulation" with "token-based authentication" across entirely different technology stacks.

### 4.3 Persistence Layer

| Memory Store | File | Schema |
|-------------|------|--------|
| **Exploit Trajectory** | `memory/exploit_trajectory.json` | 18-field `ExploitTrajectoryNode` dataclass per round |
| **Verification Memory** | `memory/verification_memory.json` | Confirmed facts: endpoints, injectable params, accepted/rejected fields, template engine, working primitives, captured flags. Write-through on every `confirm()` call. |
| **Primitive Registry** | `memory/exploit_primitives.py` | 20+ injection and post-exploitation primitive definitions with payload templates, preconditions, observable signals |
| **Primitive Transition Graph** | `memory/primitive_transition_graph.py` | 30+ directed edges with transition conditions; Planner must traverse edges — cannot jump `ssti_reflection → command_execution` directly |
| **Primitive Learning Engine** | `memory/primitive_learning.py` | Heuristic detectors for 4 primitive types based on stdout/response body pattern matching |

### 4.4 Primitive Transition Graph (Directed Exploit Navigation)

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
  │  ssti_reflection ──▶ ssti_execution ──▶ command_execution    │ │
  │  blind_ssti ───────▶ http_callback ───▶ blind_rce_oob        │ │
  │  sql_boolean ──────▶ sql_union ───────▶ command_execution    │ │
  │  command_separator ▶ command_execution                       │ │
  └──────────────────────────────────────────────────────────────┘
```

Each edge has an explicit transition condition:
```
ssti_reflection → ssti_execution: "确认 template engine 类型"
ssti_execution → command_execution: "成功访问 os.popen 或 subprocess 模块"
sql_union → command_execution: "数据库支持 xp_cmdshell / COPY TO PROGRAM / UDF"
command_execution → arbitrary_file_read: "任意命令已可执行"
```

The Planner *must* reference these edges in every step's `target_primitive` and `why_this_primitive_advances_chain` fields. The Validator cross-checks that the claimed transition exists in the graph — a step claiming `ssti_reflection → credential_dump` is rejected because that edge does not exist.

---

## 5. Safety Architecture

### 5.1 Docker Sandbox Isolation

```
┌─────────────────────────────────────────────────────────┐
│  Docker Bridge Network (isolated)                        │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │  co-redteam-sandbox container                    │   │
│  │  · User: sandbox (non-root)                     │   │
│  │  · Memory: 256 MB hard limit                    │   │
│  │  · CPU: 50,000 μs quota (50% single core)       │   │
│  │  · Timeout: 30s per step                        │   │
│  │  · Network: bridge → target container IP only   │   │
│  │  · Seccomp: default Docker profile              │   │
│  │  · No host volume mounts (all writes ephemeral) │   │
│  │  · /workspace/ mounted as tmpfs                 │   │
│  └─────────────────────────────────────────────────┘   │
│                         │                               │
│                         ▼                               │
│              Target Container (bridge network)          │
│              Access: container IP only                  │
│              Blocked: host.docker.internal, LAN, WAN    │
└─────────────────────────────────────────────────────────┘
```

### 5.2 Target URL Whitelist Lock

```python
from core.target_context import lock_target

# All network access is locked to this exact host + port
target = lock_target("https://192.168.1.100:9443")
# → Resolves hostname → IP
# → Locks port 9443
# → Blocks all other destinations
# → Overrides any host.docker.internal in JSON config
```

### 5.3 Defense in Depth

| Layer | Mechanism | Failure Mode Blocked |
|-------|-----------|---------------------|
| **Coordinator** | `_check_python_safety()` regex scan | `os.system()` text literals in step code |
| **Validator** | AST import allowlist | `import os`, `import subprocess` statements |
| **Validator** | Manifest sdk_calls cross-check | Unregistered HTTP primitives |
| **Executor** | Security regex before Docker dispatch | Bypass attempts between Validator and Executor |
| **Docker** | seccomp + non-root user + memory limit | Container escape, resource exhaustion |
| **Network** | Bridge + target IP only | Lateral movement, C2 callbacks to internet |

---

## 6. Benchmark & Evaluation Framework

### 6.1 Multi-Source Heterogeneous Dataset

The system is evaluated on a deliberately diverse corpus spanning five vulnerability classes:

| Domain | Challenge Examples | Vulnerability Types |
|--------|-------------------|---------------------|
| **Web** | TimeKORP, LockTalk, ApexSurvive | SSTI (CWE-94), JWT manipulation (CWE-347), Path Traversal (CWE-22) |
| **Deserialization** | SerialFlow | Insecure Deserialization (CWE-502) |
| **Command Injection** | (planned) | OS Command Injection (CWE-78) |
| **Reverse Engineering** | (planned) | Binary analysis → exploit primitive identification |
| **Cryptography** | (planned) | Padding oracle, timing side-channels, weak key derivation |

### 6.2 PAR-2 Scoring Metric

November adopts the **Penalized Average Runtime (PAR-2)** metric from the algorithm selection literature, adapted for autonomous exploit evaluation:

$$\text{PAR-2}(s, I) = \frac{1}{|I|} \sum_{i \in I} \begin{cases} t_s(i) & \text{if solved} \\\ 2 \cdot T_{\max} & \text{otherwise} \end{cases}$$

Where:
- $t_s(i)$ = wall-clock time (seconds) from system invocation to confirmed flag capture for instance $i$
- $T_{\max}$ = maximum allowed budget (iterations × per-iteration timeout)
- $I$ = set of evaluation instances

**Why PAR-2 over accuracy:** A system that captures the flag in 3 iterations on half the targets and times out on the other half (PAR-2 ≈ 1.5 × $T_{\max}$) is objectively better than a system that captures the flag in 18 iterations on 70% of targets (PAR-2 ≈ 1.3 × $T_{\max}$ if convergence is slow). PAR-2 penalizes *both* failure and inefficiency, aligning with the operational reality of time-boxed penetration testing.

### 6.3 Auxiliary Metrics

| Metric | Definition | Captures |
|--------|-----------|----------|
| **State Transition Rate** | E[states advanced / iteration] | Chain progression efficiency |
| **Primitive Generalization Ratio** | # targets where learned primitive reused / total targets | Cross-target knowledge transfer |
| **Anti-Regression Hit Rate** | # regression attempts blocked / # regression attempts attempted | Safety guard efficacy |
| **Consolidator Contribution Score** | (success rate with Consolidator) − (success rate without) | Strategic learning value |

---

## 7. Artifacts & Competition Readiness

### 7.1 Deliverable Pipeline

```
Input: source_code/ ──▶ Phase 1 (audit) ──▶ confirmed_vuln.json
                                              │
                                              ▼
                       Phase 2 (exploit) ──▶ flag{...} + exploit_trajectory.json
                                              │
                                              ▼
                       Phase 3 (consolidate) ──▶ YAML weapons library + ChromaDB
```

The system forms a closed loop: **static analysis → dynamic exploitation → experiential learning → improved static analysis**. Each completed task enriches the YAML template library and ChromaDB vector store, making the next task's Planner more informed.

### 7.2 Competition Targets

| Competition | Alignment |
|-------------|-----------|
| **全国大学生信息安全竞赛 (CISCN) — 作品赛** | November's multi-agent architecture, primitive reasoning engine, and anti-regression system provide the theoretical depth and engineering rigor required for national-level innovation awards |
| **"挑战杯" 揭榜挂帅赛道** | The system's cross-target generalization capability (CROSS_TARGET_SYNTAX_MAP for SSTI across 4 template engines) demonstrates the "揭榜" spirit — solving a class of problems, not a single instance |

### 7.3 Reproducibility

All experiments are fully deterministic given:
1. Fixed LLM model + temperature (0.2 + attempt × 0.1)
2. Fixed Docker sandbox image (pinned `alpine:3.18` base)
3. Fixed RUNTIME_MANIFEST (version-locked in `coordinator.py`)
4. All memory artifacts persisted to JSON (human-auditable, replayable)

The `CO_REDTEAM_MOCK_LLM=true` flag enables full pipeline testing without API calls — every agent's output is structurally validated even in mock mode.

---

## 8. Quick Start

```bash
# 1. Environment
cd b/
pip install -r requirements.txt
docker build -t co-redteam-sandbox .

# 2. Configure
cp .env.example .env
# Edit DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL, DEEPSEEK_MODEL

# 3. Phase 1 — Static Vulnerability Discovery
python cli.py audit --target target_codebase/

# 4. Phase 2 — Autonomous Exploitation
python cli.py exploit --url https://192.168.1.100:9443 --confirmed data/confirmed_vuln.json

# 5. View trajectory
cat b/memory/exploit_trajectory.json | python -m json.tool
```

---

## 9. Project Structure

```
b/
├── coordinator.py              # Orchestration hub (1,544 lines)
├── cli.py                      # CLI entry point (802 lines)
├── Dockerfile                  # Alpine 3.18 sandbox image
├── .env                        # Runtime configuration
│
├── agents/
│   ├── planner.py              # [1] Planner — AST-declarative plan generation
│   ├── validator.py            # [2] Validator — Manifest cross-check + syntax guard
│   ├── executor.py             # [3] Executor — AST→code inflation + Docker sandbox
│   ├── evaluator.py            # [4] Evaluator — State machine assessment + blind RCE detection
│   └── consolidator.py         # [5] Consolidator — Strategic experiential learning
│
├── memory/
│   ├── exploit_trajectory.py   # Trajectory persistence (ExploitTrajectoryNode × round)
│   ├── verification_memory.py  # Verified facts with write-through persistence
│   ├── exploit_primitives.py   # 20+ primitive definitions with payload templates
│   ├── primitive_learning.py   # Heuristic primitive detection from execution output
│   ├── primitive_transition_graph.py  # Directed exploit navigation graph (30+ edges)
│   ├── exploit_trajectory.json # Trajectory state file
│   ├── pattern.json            # L1 ChromaDB data source
│   ├── strategy.json           # L2 ChromaDB data source
│   └── tech.json               # L3 ChromaDB data source
│
├── control/
│   └── anti_regression.py      # AntiRegressionController + PayloadEvolutionEngine
│
├── core/
│   ├── settings.py             # Frozen Settings dataclass (16 fields)
│   ├── llm_client.py           # DeepSeekClient with exponential backoff + json_mode fallback
│   ├── memory_store.py         # ChromaDB LayeredMemory with metadata-filtered queries
│   ├── challenge_adapter.py    # Pluggable per-challenge rule adapters
│   ├── target_context.py       # URL whitelist lock with DNS resolution
│   ├── template_manager.py     # YAML weaponized template CRUD
│   └── ui.py                   # Rich terminal rendering
│
├── templates/builtin/          # YAML weaponized payload library (9 templates)
├── data/confirmed_vuln.json    # Phase 1 output → Phase 2 input
└── workspace/                  # Per-round runtime artifacts
```

---

## 10. Citation

If you use November in your research, please cite:

```bibtex
@software{november2025,
  title     = {November: Autonomous Exploit Reasoning via Constrained Agency
               and Verification-Driven Multi-Agent Planning},
  year      = {2025},
  note      = {National University Student Information Security Competition (CISCN)},
}
```

---

*November — where exploit reasoning meets formal verification, and every payload must justify its existence to a runtime manifest before it can touch the target.*