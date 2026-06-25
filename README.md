# Co-RedTeam — LLM-Driven Autonomous Exploit Reasoning System

**Constrained Agency · Exploit State Inference · Incremental Capability Accumulation · Dual-Model Strategic Reflexion**

> *"The failure of LLM-driven exploitation is not a capability ceiling — it is a feedback resolution problem. When the only signal is flag/no-flag, every round before the flag is indistinguishable noise. We fix this by making side-effects legible."*

---

## 1. Project Overview

Co-RedTeam is **not** an automated CTF solver. It is a research-grade **autonomous state-inference and incremental exploitation system** built on the following thesis:

**Given a static vulnerability report (source audit / SAST output), an LLM-driven multi-agent pipeline can autonomously navigate a constrained exploit state machine — detecting sub-flag-caliber side effects, accumulating partial capability, and synthesizing staged payload chains — to reach verified weaponized exploitation without human intervention.**

The system spans the full kill-chain:

```
Source Code / Vuln Report  →  Constrained State Inference  →  Staged Payload Synthesis  →  Sandbox Execution  →  Side-Effect Scoring  →  Momentum-Preserving Iteration  →  Flag Capture / Strategic Consolidation
```

Unlike prior work that treats exploitation as a binary search problem ("success" or "failure" per round), Co-RedTeam introduces a **continuous exploit progress manifold** where every observable side-effect — timing anomalies, response-length mutations, parser state changes, template evaluation artifacts — contributes to an accumulated progress score. This prevents the pipeline from prematurely abandoning a viable attack path simply because the flag hasn't materialized yet.

---

## 2. Core Innovations

### 2.1 Exploit Progress Engine (EPE) & Momentum Preservation

**The Problem.** Traditional LLM-based exploitation pipelines collapse under a fatal feedback sparsity problem: the Evaluator can only detect `flag{...}` or `uid=0(root)`, so every intermediate round — where the payload *does* perturb the backend but doesn't yet produce an S-tier indicator — is scored as `repro_success=false, confidence=0.2`. After 3 consecutive "failures," the circuit breaker fires and the pipeline abandons a perfectly viable attack path.

**The Insight.** Exploitation is not a binary state transition but a **continuous capability accumulation** process. A payload that causes a 2.3s response delay (vs. 0.05s baseline) has *not* failed — it has demonstrated that injected input reaches a blocking operation (sleep, DNS resolution, subprocess execution). That is progress.

**EPE Architecture.** The Evaluator (`b/agents/evaluator.py:710-894`) implements a four-level tiered scoring system:

```
Level 4 — Objective Signals (weight: multiplicative, λ=1.0 on flag detection)
  ├─ flag_captured, blind_rce_oob
  │
Level 3 — Capability Signals (weight: 0.40 cumulative layer)
  ├─ command_execution (uid=0), arbitrary_file_read (/etc/passwd), credential_dump, ssti_execution
  │
Level 2 — Primitive Signals (weight: 0.35 cumulative layer)
  ├─ ssti_reflection ({{7*7}}→49), deserialization_fault, oob_attempt, command_usage_fragment
  │
Level 1 — Surface Signals (weight: 0.25 cumulative layer)
  ├─ response_length_change (±100 bytes), timing_anomaly (>2s), error_triggered (500 post-payload),
  │  payload_reflection (≥2 tokens), error_message_fragment
  │
Level 0 — No detectable perturbation (progress=0.0, momentum=false)
```

Within each level, signals are combined via non-linear accumulation: `L_k = 1 - ∏(1 - w_i)` over all detected signals `i` in level `k`. The total progress score is a weighted stack:

$$\text{progress} = L_1 \cdot 0.25 + L_2 \cdot 0.35 + L_3 \cdot 0.40 + L_4 \quad \text{(capped at 0.99 without objective)}$$

**Behavioral Signal Detection.** Beyond CWE-specific primitive patterns, EPE detects abstract behavioral evidence that generalizes across vulnerability classes:

| Behavioral Signal | Detection Mechanism | Confidence |
|---|---|---|
| `backend_parser_state_changed` | HTTP response mutation after payload injection | 0.15–0.18 |
| `backend_deserialization_fault_detected` | Type confusion / ClassNotFound / marshal.loads errors | 0.35 |
| `process_crash_or_worker_restart` | Connection refused AFTER successful HTTP 200 | 0.25 |
| `outbound_controlled_channel_established` | DNS/HTTP interaction from target (curl/wget/OOB) | 0.55 |
| `filesystem_side_effect` | File listing fragments (drwx, total N, ls/cat output) | 0.60 |
| `template_evaluation_artifact` | Expression computation from template engine | 0.38 |

**Momentum-Preserving Anti-Regression.** When `exploit_momentum` is active (L1+L2+L3 > 0.05), the Coordinator injects a hard anti-regression constraint into the Planner's feedback:

```
🛑 ANTI-REGRESSION CONSTRAINT:
  1. DO NOT restart fuzzing from scratch
  2. DO NOT pivot to a different vulnerability type
  3. DO NOT abandon the current injection point/endpoint
  4. STAY on the current chain and incrementally escalate payload complexity
  5. Refine: add more stages, tune encoding, or amplify the side-effect
```

This converts the traditional "fail → pivot" loop into a directed "side-effect → escalate" trajectory.

### 2.2 Constraint-Aware Synthesis & Physical Constraint Extraction

**The Problem.** LLM Planners, when asked to "achieve RCE," default to generating monolithic `Runtime.getRuntime().exec("cat /flag")` payloads — regardless of whether the target environment has an 86-byte input length limit, requires multipart/form-data encoding, or passes all input through `htmlspecialchars()`. The result is a full round of execution that fails silently because the payload never reached the vulnerable sink in a parseable form.

**The Insight.** The Planner must be *informed* of physical constraints at the injection boundary — not as natural language warnings buried in a 12,000-character context, but as topologically prioritized, budget-enforced constraints at the highest attention positions in the prompt.

**Six-Layer Attention Routing Topology.** The Planner's system prompt (`b/agents/planner.py:130-250`) is assembled using a strict topological ordering with per-layer physical character budgets:

```
┌──────────────────────────────────────────────────────────┐
│  L1: Runtime Manifest        (≤ 800 chars)  [最高权重]    │
│      └─ SDK primitives, safe/blocked modules, network mode│
│  L2: Hard Constraints        (≤ 600 chars)               │
│      └─ Absolute bans: no os/subprocess/socket/pickle     │
│  L3: SDK Contract            (≤ 500 chars)               │
│      └─ Authorized API surface: HttpClient, OOBReceiver   │
│  L3.5: FSM Constraints       (≤ 600 chars)               │
│      └─ Current capability level, blocked surfaces        │
│  L4: Verified Facts + Memory (≤ 800 chars)               │
│      ├─ primitive_context    (≤ 500)                      │
│      ├─ verification_context (≤ 300)                      │
│      └─ memory_context       (≤ 400)                      │
│  L5: Trajectory State        (≤ 300 chars)               │
│      └─ Dehydrated trajectory JSON                        │
│  L6: User Goal               (≤ 800 chars)               │
│      └─ Dense extraction of confirmed_vuln.json           │
├──────────────────────────────────────────────────────────┤
│  FINAL_PAYLOAD_HARD_CAP = 5000 chars                      │
└──────────────────────────────────────────────────────────┘
```

This ordering is not cosmetic. Transformer self-attention computes pairwise dot products across all token positions, but the resulting attention matrix is dominated by proximity effects — a constraint at position 3000 has approximately 10× less influence than an identical constraint at position 300, even though the model "saw" both. By placing the Manifest and Hard Constraints at the highest-attention positions and enforcing hard character budgets, we guarantee that capability boundaries remain within the model's effective attention radius regardless of how much trajectory history accumulates.

**Physical Truncation, Not Summarization.** Each layer is sliced at the byte level via `_physical_truncate()`. Truncated content is discarded, not LLM-summarized — summarization introduces parametric noise where the compression model may hallucinate or emphasize the wrong signal. A dual safety mechanism enforces both per-layer budgets and a global 5,000-character hard cap on the final assembled prompt.

**High-Priority Lessons Frontloading.** Before the 6-layer assembly, the system extracts hard-won lessons from failure history (`b/agents/planner.py:165-263`): persistent failure fingerprints across all rounds, verification memory blacklists (rejected fields, blocked payload patterns), CWE-specific known lessons (Velocity single-quote leakage, URL encoding of `#` in GET parameters, reflection chain blocking), and prior evaluator hypotheses. These are prepended as guidance ("建议"), not hard constraints ("禁令"), preserving exploration space while steering the Planner away from known dead ends.

### 2.3 Dual-Model Reflexion Architecture

**Micro-Tactical Loop (4-Agent Closed Loop).** Four specialized agents — Planner, Validator, Executor, Evaluator — form a tight iterative cycle. Each round produces a structured JSON feedback artifact that feeds into the next round's Planner context:

```
Planner → Validator → Executor → Evaluator
   ↑                                  │
   └──────── feedback loop ───────────┘
```

The Validator enforces a **Zero-Trust Manifest** (`b/agents/validator.py`): every `import` statement is AST-cross-referenced against `RUNTIME_MANIFEST.safe_modules`; every `sdk_calls` entry is prefix-matched against `MANIFEST_SDK_PRIMITIVES`. Violations are rejected with `valid:false` before execution, eliminating the entire class of "passed planning, failed at runtime" errors.

The Evaluator enforces a **Zero-Trust Epistemological Guard** (`b/agents/evaluator.py:17-48`): inference markers ("should," "likely," "therefore," "因此," "应可," "推断") are detected and stripped from `verified_facts`. Primitive evidence containing inference language is downgraded to ≤ 0.35 confidence. The Evaluator refuses to elevate `current_exploit_state` without physical evidence in `raw_stdout` — HTTP 200 is never sufficient.

**Macro-Strategic Consolidator (Dual-Model).** After the tactical loop exhausts its iteration budget, a separate **Consolidator agent** (`b/agents/consolidator.py`) is awakened. It uses an independent, higher-capability model (DeepSeek-V4-Pro, configured via separate `CONSOLIDATOR_*` environment variables) that is architecturally decoupled from the tactical model. The Consolidator reads the full trajectory and performs **Verbal Reinforcement Learning**:

- **Diagnosis:** Root-cause analysis of why the tactical loop stalled (sandbox constraint conflict, WAF signature, payload format dead-end)
- **Pattern Extraction:** Generalized error fingerprints with root causes → `memory/pattern.json`
- **Strategy Encoding:** Attack chain templates with success/failure annotations → `memory/strategy.json`
- **Technique Hardening:** Executable code patches with `executable_patch` fields → `memory/tech.json`
- **YAML Weaponization:** CWE-tagged payload templates → `templates/builtin/`

This dual-model separation prevents the tactical model's context saturation from degrading the strategic model's analysis quality — a design pattern validated in the Reflexion and ExpeL literature.

---

## 3. System Pipeline

### 3.1 Phase Architecture

```
Phase 1 (Static Discovery)                Phase 2 (Dynamic Exploitation)
══════════════════════════                ══════════════════════════════

Source Code / Target Directory            confirmed_vuln.json
        │                                        │
        ▼                                        ▼
   Static Analysis Engine              ┌─────────────────────┐
   (SAST + LLM Audit)                  │   COORDINATOR       │
        │                              │   (iteration loop)  │
        ▼                              └────────┬────────────┘
   confirmed_vuln.json                         │
        │                              ┌────────┴────────────┐
        └──────────────────────────────┤  Constraint Extraction│
                                       └────────┬────────────┘
                                                │
                              ┌─────────────────┴─────────────────┐
                              │                                   │
                              ▼                                   ▼
                      ┌──────────────┐                    ┌──────────────┐
                      │   PLANNER    │                    │  VALIDATOR   │
                      │  6-Layer     │───────────────────▶│  Manifest    │
                      │  Prompt      │    plan.json       │  Cross-check │
                      └──────────────┘                    └──────┬───────┘
                                                                │
                                                                ▼
                                                       ┌──────────────┐
                                                       │  EXECUTOR    │
                                                       │  Docker      │
                                                       │  Sandbox     │
                                                       │  + SDK       │
                                                       └──────┬───────┘
                                                              │
                                                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         EVALUATOR (EPE)                                  │
│  ┌─────────────┐  ┌────────────────┐  ┌──────────────┐  ┌────────────┐ │
│  │ Flag/Signal │  │ Blind RCE      │  │ Primitive     │  │ EPE Score  │ │
│  │ Detection   │  │ Detection      │  │ Detection     │  │ Computation│ │
│  └──────┬──────┘  └──────┬─────────┘  └──────┬────────┘  └─────┬──────┘ │
│         └────────────────┴──────────────────┴───────────────┘         │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │   COORDINATOR           │
                    │   Momentum Check        │
                    │   ┌─────────────────┐   │
                    │   │ Progress ≥ 0.03? │──▶ Yes → Preserve path, escalate
                    │   └────────┬────────┘   │
                    │            │ No          │
                    │   ┌────────┴────────┐   │
                    │   │ Breaker check?   │──▶ Yes → Force strategy rotation
                    │   └────────┬────────┘   │
                    │            │ No          │
                    │   ┌────────┴────────┐   │
                    │   │ Iterate         │──▶ Continue with enriched context
                    │   └─────────────────┘   │
                    └─────────────────────────┘
                                 │
                    (budget exhausted or flag captured)
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │   CONSOLIDATOR          │
                    │   Strategic Reflexion   │
                    │   → ChromaDB + YAML     │
                    └─────────────────────────┘
```

### 3.2 Exploit State Machine

The Evaluator enforces a strict five-stage state machine (`b/agents/evaluator.py:188-223`). Each stage requires specific physical evidence before transition is permitted:

```
init ──▶ probe_success ──▶ payload_injected ──▶ gadget_triggered ──▶ oob_received
  │            │                  │                     │                  │
  │     HTTP 200 +          Payload accepted/     S-tier evidence:    OOB callback
  │     normal response    processed by target    uid=0, /etc/passwd,  with flag/data
  │     body observed      (reflected, stored,    flag{...}, SSTI
  │                         JWT accepted)         config dump
  │
  └── Connection refused, 403/401, SyntaxError, NameError
```

**State transition rules:**
- Sequential only — no skipping stages (init → gadget_triggered is rejected)
- No regression — once a stage is reached, `current_exploit_state` must not decrease
- `state_transition_blocker` must cite specific HTTP response fields blocking advancement
- Blind RCE (exit_code=0, stdout empty) caps at `payload_injected` with confidence ≤ 0.5

### 3.3 Coordinator Control-Loop Mechanisms

| Mechanism | Trigger | Action |
|---|---|---|
| **Circuit Breaker** | 3 consecutive failures OR same error fingerprint across window | Forces strategy switch with CWE-keyed ChromaDB retrieval + breaker hard-interrupt prompt injection |
| **Attack Surface Rotator** | All steps in plan are BLOCKED | Rotates to next unblocked vulnerability in `confirmed_vuln.json`; resets breaker state |
| **Decaying Dynamic Iteration** | is_milestone=true | Extends budget by `max(1, 5 - milestone_count)` iterations; hard cap at `max_iterations_cap` (default 20) |
| **Zero-Progress Abort** | 4 consecutive rounds with no progress signal | Terminates pipeline; triggers Consolidator for post-mortem |
| **AI Abort (suggest_abort)** | Evaluator detects unfixable dead-end (target down, WAF permablock, strategy exhaustion) | Ignored for first 4 iterations (mandatory exploration minimum); honored thereafter |
| **EPE Momentum Lock** | `exploit_momentum=true` | Injects anti-regression constraint: DO NOT pivot, stay on current endpoint, escalate payload |
| **HTTP Semantic Auto-Fix** | Response body matches known error patterns | Auto-detects `AllFieldsRequired`, `InvalidEmail`, `CSRFDetected` etc. and injects field-specific fix instructions |
| **Semantic Sliding Window** | Each round | Retains last 5 rounds of distilled execution snapshots; evicts older rounds but permanently retains failure fingerprints across ALL rounds |

---

## 4. Quick Start

### 4.1 Prerequisites

- Python 3.10+
- Docker Desktop (with Linux containers on Windows)
- DeepSeek API access (or any OpenAI-compatible endpoint)

### 4.2 Installation

```bash
cd b/

# Install Python dependencies
pip install -r requirements.txt

# Build the Docker sandbox image
docker build -t co-redteam-sandbox .

# Configure API credentials
cp .env.example .env
# Edit: DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL, DEEPSEEK_MODEL
```

### 4.3 Phase 1 — Static Vulnerability Discovery

```bash
# Audit a target codebase to produce confirmed_vuln.json
python cli.py audit --target ../target_codebase/<challenge_name>/

# Output: data/confirmed_vuln.json
```

### 4.4 Phase 2 — Autonomous Exploitation

```bash
# Launch full autonomous exploitation pipeline with URL whitelist lock
python cli.py exploit \
  --url https://192.168.1.100:9443 \
  --confirmed data/confirmed_vuln.json \
  --challenge generic

# With challenge-specific adapter
python cli.py exploit \
  --url https://127.0.0.1:1337 \
  --confirmed data/confirmed_vuln.json \
  --challenge timekorp
```

### 4.5 Quick Test (Mock Mode — No API Calls)

```bash
# Set mock mode to test the full pipeline without API costs
$env:CO_REDTEAM_MOCK_LLM = "true"
python cli.py exploit --url https://127.0.0.1:8080 --confirmed data/confirmed_vuln.json
```

### 4.6 Memory Management

```bash
# List memory collections
python cli.py memory list

# Show collection contents
python cli.py memory show --collection tech

# Query memory with a search term
python cli.py memory query --text "SSTI jinja2"

# Initialize built-in payload templates
python cli.py memory init-builtin

# Export/import memory for cross-project transfer
python cli.py memory export --output memory_backup/
python cli.py memory import --input memory_backup/
```

---

## 5. Project Structure

```
├── README.md
├── run_pipeline.py                # Top-level pipeline entry
├── vul_doc_ini.py                 # Phase 1 static analysis engine
│
├── b/
│   ├── coordinator.py             # Orchestration hub (~1,870 lines)
│   ├── cli.py                     # Unified CLI (audit + exploit + memory)
│   ├── Dockerfile                 # Alpine sandbox image
│   ├── .env                       # API credentials
│   │
│   ├── agents/
│   │   ├── planner.py             # 6-layer attention-routed plan synthesis
│   │   ├── validator.py           # Manifest cross-check + AST import guard
│   │   ├── executor.py            # AST→code inflation + Docker sandbox + HTTP instrumentation
│   │   ├── evaluator.py           # EPE scoring + exploit state machine + zero-trust guard
│   │   └── consolidator.py        # Dual-model strategic reflexion + YAML weaponization
│   │
│   ├── control/
│   │   ├── anti_regression.py     # Payload evolution engine + anti-regression controller
│   │   ├── exploit_state_machine.py  # Capability-centric exploit FSM
│   │   └── response_distiller.py     # Execution output → structured exploit facts
│   │
│   ├── memory/
│   │   ├── exploit_trajectory.py     # 18-field per-round trajectory node
│   │   ├── verification_memory.py    # Write-through verified facts store
│   │   ├── exploit_primitives.py     # 20+ primitive definitions with payload templates
│   │   ├── primitive_learning.py     # Heuristic primitive detection engine
│   │   ├── primitive_transition_graph.py  # 30+ directed edges with transition conditions
│   │   ├── runtime_truths.py         # Verified runtime facts (HTTP method, WAF, OOB availability)
│   │   ├── pattern.json / strategy.json / tech.json  # ChromaDB persistence layers
│   │   └── payload_registry.json     # Payload scoring & fingerprint database
│   │
│   ├── core/
│   │   ├── settings.py            # Frozen Settings dataclass
│   │   ├── llm_client.py          # DeepSeekClient with exponential backoff
│   │   ├── memory_store.py        # ChromaDB LayeredMemory with metadata-filtered RAG
│   │   ├── challenge_adapter.py   # Pluggable per-challenge rule adapters
│   │   ├── target_context.py      # URL whitelist lock with DNS resolution
│   │   ├── template_manager.py    # YAML weaponized template CRUD
│   │   ├── payload_registry.py    # Payload fingerprint scoring system
│   │   └── ui.py                  # Rich terminal rendering
│   │
│   ├── templates/builtin/         # YAML weaponized payload library
│   ├── data/confirmed_vuln.json   # Phase 1 output → Phase 2 input
│   └── workspace/                 # Per-round runtime artifacts
│
└── target_codebase/               # CTF challenge source code for Phase 1 audit
```

---

## 6. Next Phase Roadmap

### 6.1 Staged/Chunked Payload Assembly with Engineering Validation

**Motivation.** The current system generates monolithic payloads per step. When the target enforces a hard length constraint (e.g., 86 bytes in a URL parameter), the Planner has no mechanism to automatically decompose a payload into multiple stages that:
1. Stage 1: Write a minimal dropper (≤ 86 bytes) that fetches stage 2
2. Stage 2: Execute the full payload retrieved from stage 1

**Planned implementation:**
- Integrate a **Constraint Extractor** pre-processor that parses HTTP response headers (`Content-Length` limits, `413 Payload Too Large`, WAF rejection patterns) to infer injection boundary constraints
- Extend the Planner's `_build_hard_constraints_block()` with dynamically detected length limits
- Implement a **Chunked Payload Assembler** in the Executor that automatically splits oversized payloads into `n` sequential HTTP requests with session continuity
- Validate against CTF challenges with known payload length limits (e.g., 86-byte SSTI injection → 3-stage chunked shell write)

### 6.2 Dynamic Baseline Calibration for Weak Signal Detection

**Motivation.** EPE's current Level 1 signals (`timing_anomaly`, `response_length_change`) use fixed thresholds (2.0s delay, ±100 bytes difference). These are brittle across heterogeneous targets — a Flask app with 200ms baseline and a Java Spring app with 800ms baseline require different anomaly thresholds. A single fixed threshold either over-triggers on slow targets or misses real anomalies on fast ones.

**Planned implementation:**
- **Probe Phase:** Before exploitation begins, execute N baseline requests (no payload, varying input lengths) and compute `μ_response_time`, `σ_response_time`, `μ_content_length`, `σ_content_length`
- **Adaptive Thresholding:** Replace fixed thresholds with z-score based anomaly detection — a timing anomaly is `response_time > μ + 3σ` rather than `response_time > 2.0s`
- **CUSUM Change Detection:** For targets where the baseline shifts over time (warming JIT, DB connection pooling), apply cumulative sum control charts to detect step-change deviations from a sliding baseline
- **Side-Channel Calibration:** For blind/time-based SQL injection, calibrate `SLEEP(N)` commands against the baseline to determine the minimum detectable delay at the current network latency

### 6.3 Attack Graph Visualization & Trajectory Export

**Motivation.** The system already records an 18-field `ExploitTrajectoryNode` per round with state transitions, primitive activations, endpoint discoveries, and HTTP status code evolution. This structured data is a near-complete attack graph — but it is currently only serialized to JSON. For academic evaluation and competition demonstration, we need standard-format visual attack graphs.

**Planned implementation:**
- Export the `exploit_trajectory.json` to **Mermaid.js** flowchart format for direct embedding in Markdown reports
- Generate **Graphviz DOT** files with color-coded edges (red=failed attempt, yellow=partial progress, green=state advancement, gold=flag capture)
- Support **ATT&CK Navigator** layer export — map each primitive activation to its closest ATT&CK Technique ID (e.g., `ssti_execution` → T1059, `credential_dump` → T1003)
- Build an optional **React-based trajectory viewer** that animates the state machine progression round-by-round, showing which primitives were activated, which endpoints were discovered, and where the attack chain stalled
- Integrate this as a `--visualize` flag on the CLI: `python cli.py exploit ... --visualize` produces `reports/attack_graph.html`

### 6.4 Cross-Target Primitive Transfer & Few-Shot Warm-Start

**Motivation.** The current Consolidator writes generalized lessons to ChromaDB after each task, and the next task's Planner retrieves them via metadata-filtered vector search. However, the retrieval quality depends heavily on CWE tag alignment — a Planner attacking a Jinja2 SSTI target will not retrieve lessons from a Velocity SSTI target unless the CWE tags match exactly. We need a mechanism for **cross-template-engine** and **cross-CWE** primitive transfer.

**Planned implementation:**
- Build a **Primitive Embedding Space** where exploit primitives are embedded not by their CWE ID but by their structural properties (injection vector, parser interaction, output channel)
- Implement **few-shot warm-start**: before the first Planner round, inject the top-K most structurally similar successful trajectory fragments from ChromaDB as concrete few-shot examples
- Add a **Primitive Generalization Score** metric: `(# targets where learned primitive was successfully reused) / (total targets attempted)`

---

## 7. Citation

```bibtex
@software{co-redteam2025,
  title     = {Co-RedTeam: LLM-Driven Autonomous Exploit Reasoning via
               Constrained Agency and Incremental Capability Accumulation},
  year      = {2025},
  note      = {National University Student Information Security Competition (CISCN)},
  keywords  = {LLM agents, autonomous exploitation, exploit state machine,
               side-effect scoring, constrained agency, dual-model reflexion}
}
```

---

*Co-RedTeam — where every side-effect is a signal, every signal accumulates momentum, and no viable attack path is abandoned without proof.*
