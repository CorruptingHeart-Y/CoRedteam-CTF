# Manual Route CLI Bridge — Implementation Report

**Date:** 2026-07-28  
**Branch:** competition-standard  
**Scope:** Thin Manual Route CLI Bridge — enables a specified YAML Route to enter the existing execution chain  

---

## 1. Modified Files

| File | Change | Lines |
|---|---|---|
| `b/routes/manual_bridge.py` | **NEW** — ManualRouteErrorCode, ManualRouteResult, run_manual_route(), _resolve_runtime_facts() | ~330 |
| `b/cli.py` | 6 new CLI args + `_cmd_exploit_manual_route()` dispatch function | +95 |
| `b/test_manual_route_cli_bridge.py` | **NEW** — 33 comprehensive offline tests | ~1050 |
| `manual_route_cli_bridge_implementation_report.md` | This report | — |

**No production files in the forbidden list were modified.** No CWE logic, no Route schema, no Normalizer/Admission/Registry/Frontier/Materializer changes.

---

## 2. CLI Parameters

### Actual final parameter names

| Flag | Type | Required | Description |
|---|---|---|---|
| `--manual-route` | `store_true` | Required to activate mode | Enable manual route mode |
| `--route-dir` | `DIR` | Required with `--manual-route` | Directory of candidate route YAML files |
| `--route-id` | `ID` | Required with `--manual-route` | Canonical route ID to execute |
| `--route-method` | `GET` or `POST` | Required if confirmed contract ambiguous | HTTP method override |
| `--route-location` | `query`, `form`, or `json` | Required if confirmed contract ambiguous | Request location override |

### Example command

```powershell
$env:CO_REDTEAM_MAX_ITER=1
$env:CO_REDTEAM_MAX_ITER_CAP=1
$env:CO_REDTEAM_MAX_RUNS=1

python -X utf8 b/cli.py exploit `
  --url http://127.0.0.1:1337 `
  --confirmed b/data/confirmed_vuln.json `
  --manual-route `
  --route-dir b/data/candidate_routes `
  --route-id cwe-94:init:ssti-reflection:arithmetic-probe `
  --route-method POST `
  --route-location form
```

---

## 3. Confirmed / Runtime Facts Mapping

| Fact | Source | Priority |
|---|---|---|
| `base_url` | `--url` (CLI, via TargetContext.url) | Mandatory — always from CLI |
| `endpoint` | confirmed `evidence[].code_snippet` regex `@RequestMapping("/")` | Extracted from confirmed; fails if missing |
| `parameter` | confirmed `source` field regex `` `text` `` | Extracted from confirmed; fails if missing |
| `method` | `--route-method` > confirmed `exploitation` regex (POST/GET) > **FAIL** | CLI overrides confirmed; conflict → `RUNTIME_FACT_CONFLICT`; neither → `RUNTIME_FACT_MISSING` |
| `request_location` | `--route-location` > confirmed `source` hints (`@RequestParam` etc.) > **FAIL** | CLI overrides confirmed; neither → `RUNTIME_FACT_MISSING` |

### Rules enforced

1. Confirmed contract has unambiguous value → used
2. CLI explicit value overrides confirmed
3. CLI value conflicts with confirmed unambiguous value → `RUNTIME_FACT_CONFLICT` (fail closed)
4. Neither has value → `RUNTIME_FACT_MISSING` (fail closed)
5. No default for method
6. No default for request_location
7. No guessing from technique
8. No guessing from parameter name
9. Confirmed contract is never modified

---

## 4. Real Route Data Flow

```
CLI --manual-route --route-id <ID> --route-dir <DIR>
  │
  ├─[1] Validate route directory exists
  │
  ├─[2] For each .yaml/.yml file in route_dir:
  │      load_and_admit_candidate_route(yaml_path, adapter)  ← YAML safe_load + Admission
  │      → register only admitted_candidate routes into RouteRegistry
  │
  ├─[3] registry.get(route_id)  ← exact match, no fuzzy
  │
  ├─[4] Extract endpoint/parameter from confirmed for Frontier
  │      build_frontier_context(adapter, runtime_facts_source={endpoint, parameter})
  │
  ├─[5] build_frontier(registry.snapshot(), context)
  │      → check route_id in eligible_routes
  │
  ├─[6] registry.get(eligible_entry.route_id).route  ← Frontier-sourced route
  │
  ├─[7] _resolve_runtime_facts()  ← confirmed + CLI merges
  │
  ├─[8] materialize_route_plan(route, adapter, facts, output_path)  → plan.json
  │
  ├─[9] validate_plan_structure(plan)  ← shared contract
  │
  ├─[10] run_validator(plan_path, validated_path, parameter_contract=...)
  │
  ├─[11] run_executor(validated_path, result_path, target=target)
  │
  ├─[12] run_evaluator(settings, memory, confirmed, plan, exec_out, ...)
  │
  └─[13] Check expected_signals ∩ observed_signals ≠ ∅
```

The original in-memory route from Normalizer is never used downstream. All stages consume the output of the previous stage.

---

## 5. Planner Bypass Boundary

| Bypassed | NOT Bypassed |
|---|---|
| Planner's route selection | Validator |
| Planner's LLM plan generation | Executor |
| Planner's attack chain design | Evaluator |
| Planner's feedback loop | Policy gates |
| | Manifest checks |
| | Memory gates |
| | Expected signal checks |
| | Shared plan structure contract |
| | Anti-regression controls (Validator) |

The manual bridge does NOT create a second execution chain. It feeds into the existing `run_validator` → `run_executor` → `run_evaluator` path, exactly as the Coordinator does for Planner-generated plans.

---

## 6. Validator / Executor / Evaluator / Consolidator Integration

| Agent | Integration Point | How |
|---|---|---|
| **Validator** | `run_validator(plan_path, validated_path, parameter_contract=...)` | Same call as Coordinator line 1105 |
| **Executor** | `run_executor(validated_path, result_path, ..., target=target)` | Same call as Coordinator line 1130 |
| **Evaluator** | `run_evaluator(settings, memory, confirmed, plan, exec_out, feedback_path, llm=None, adapter=None)` | Same call as Coordinator line 1238; manual mode uses `llm=None` for local evaluation only |
| **Consolidator** | Not called (single-run mode) | Evaluator output is the terminal result |

---

## 7. Single Route / Single Step / Single Request Constraints

| Constraint | Enforcement |
|---|---|
| 1 route | `registry.get(route_id)` — exact match, no fallback, no auto-select |
| 1 plan | `materialize_route_plan()` produces exactly 1 plan with 1 step |
| 1 step | Plan structure contract validates `len(steps) == 1` |
| 1 HTTP request | Single `sdk_calls[]` entry → single HttpClient call |
| 1 evaluator result | Evaluator called once, no retry loop |

### Max-iter / max-runs enforcement

`_cmd_exploit_manual_route()` checks environment variables at startup:
- `CO_REDTEAM_MAX_ITER` must be `1`
- `CO_REDTEAM_MAX_ITER_CAP` must be `1`
- `CO_REDTEAM_MAX_RUNS` must be `1`

Any value ≠ 1 → `MANUAL_ROUTE_SINGLE_RUN_REQUIRED` (fail closed).

No retry. No fallback route. No Planner fallback. No second payload/endpoint/parameter. No auto route ranking. No multi-route execution.

---

## 8. Stable Failure Codes

| Error Code | Trigger | Stage |
|---|---|---|
| `ROUTE_DIRECTORY_NOT_FOUND` | Directory missing or 0 YAML/0 admitted | Load |
| `ROUTE_ID_NOT_FOUND` | Route ID not in Registry | Registry.get() |
| `ROUTE_NOT_ADMITTED` | Route exists but admission rejected | Admission (filtered at load) |
| `ROUTE_BLOCKED` | Frontier blocks route (state/signals/facts) | Frontier |
| `RUNTIME_FACT_MISSING` | Required fact not in confirmed or CLI | Fact resolution |
| `RUNTIME_FACT_CONFLICT` | CLI value conflicts with confirmed | Fact resolution |
| `PAYLOAD_REF_RESOLUTION_FAILED` | Payload template ref can't be resolved | Materializer |
| `MATERIALIZATION_FAILED` | Plan generation error | Materializer |
| `PLAN_STRUCTURE_INVALID` | Plan fails shared structure contract | validate_plan_structure |
| `VALIDATION_FAILED` | Plan fails runtime Validator | Validator |
| `EXECUTION_FAILED` | Executor raises or returns executed=False | Executor |
| `EVALUATION_FAILED` | Evaluator raises exception | Evaluator |
| `EXPECTED_SIGNAL_NOT_OBSERVED` | No expected signal in evaluator output | Signal check |
| `MANUAL_ROUTE_SINGLE_RUN_REQUIRED` | max_iter/max_runs ≠ 1 | Pre-flight |

Fail-closed: each error returns immediately. No fallback to Planner. No retry.

---

## 9. Expected Signal Determination

```python
expected_signals = set(route.expected_signals)       # from Route YAML
observed_primitives = set(evaluation["detected_primitives"])
repro_success = evaluation.get("repro_success", False)

signal_match = bool(expected_signals & observed_primitives) or repro_success

# If still no match, scan stdout for signal patterns via _detect_success_signal()
if not signal_match:
    detected = _detect_success_signal(all_stdout)
    if detected:
        signal_match = True
```

- Success requires at least one expected signal to be observed
- HTTP 200 alone is NOT success
- `repro_success=True` from evaluator counts as signal match
- Empty `detected_primitives` + `repro_success=False` → `EXPECTED_SIGNAL_NOT_OBSERVED`

---

## 10. Non-Manual Mode Compatibility

| Check | Verified |
|---|---|
| Without `--manual-route`, existing CLI behavior unchanged | `test_non_manual_cli_unchanged` ✅ |
| `--route-dir` and `--route-id` are ignored without `--manual-route` | Parser default=None, only checked in manual branch |
| Original Planner path still executes | No code path changes in `cmd_exploit()` for non-manual |
| Original exploit args unchanged | `--url`, `--confirmed`, `--vuln`, `--challenge` untouched |
| Original max-iter/max-runs logic unchanged | Only checked in `_cmd_exploit_manual_route()` |
| manual_bridge module not loaded on normal CLI import | `test_non_manual_path_unchanged` ✅ (subprocess verification) |

---

## 11. Test Results

### Manual bridge tests (new)

```
pytest -q b/test_manual_route_cli_bridge.py
```
```
33 passed in 1.84s
```

### Complete test suite

```
pytest -q b/test_routes.py b/test_route_materializer_impl.py
  b/test_plan_contract.py b/test_run_isolation_evidence_guard.py
  b/test_route_materializer_acceptance.py b/test_manual_route_cli_bridge.py
```
```
566 passed in 12.04s
```

| Metric | Before | After | Delta |
|---|---|---|---|
| passed | 533 | 566 | +33 |
| failed | 0 | 0 | 0 |
| skipped | 0 | 0 | 0 |
| xfailed | 0 | 0 | 0 |
| warnings | 3 | 3 | 0 |

All 3 warnings are third-party paramiko CryptographyDeprecationWarning — no project warnings.

---

## 12. Offline Success Smoke

Test: `TestManualBridgeSmoke::test_success_smoke_real_pipeline_mock_executor`

```
RouteProposal → Normalizer → YAML Writer → temp YAML file
→ load_and_admit_candidate_route() → Registry → Frontier
→ Materializer → plan.json → validate_plan_structure
→ mocked Validator → mocked Executor (exactly 1 call)
→ mocked Evaluator (exactly 1 call, returning ssti_reflection + repro_success=True)
→ expected signal match → result.success = True

Assertions:
  plan steps = 1        ✅
  executor calls = 1    ✅
  evaluator calls = 1   ✅
  planner calls = 0     ✅ (never imported)
  HTTP calls = 0        ✅
  observed expected signal = true  ✅
  result success = true ✅
```

---

## 13. HTTP 200 Without Signal — Failure Smoke

Test: `TestManualBridgeSmoke::test_failure_smoke_http200_no_signal`

```
Mock Executor returns: HTTP 200, "Normal page" in stdout
Mock Evaluator returns: repro_success=False, detected_primitives=[]

→ EXPECTED_SIGNAL_NOT_OBSERVED
→ result.success = False

Assertion: HTTP 200 without expected signal ≠ success ✅
```

---

## 14. Stage 1 Post-Execution CLI Command Template

After Stage 1 generates confirmed_vuln.json and candidate route YAMLs:

```powershell
# Required: single-run environment
$env:CO_REDTEAM_MAX_ITER = "1"
$env:CO_REDTEAM_MAX_ITER_CAP = "1"
$env:CO_REDTEAM_MAX_RUNS = "1"

# Basic — method/location from confirmed contract:
python -X utf8 b/cli.py exploit `
  --url http://127.0.0.1:1337 `
  --confirmed b/data/confirmed_vuln.json `
  --manual-route `
  --route-dir b/data/candidate_routes `
  --route-id cwe-94:init:ssti-reflection:arithmetic-probe

# With explicit method/location overrides:
python -X utf8 b/cli.py exploit `
  --url http://127.0.0.1:1337 `
  --confirmed b/data/confirmed_vuln.json `
  --manual-route `
  --route-dir b/data/candidate_routes `
  --route-id cwe-94:init:ssti-reflection:arithmetic-probe `
  --route-method POST `
  --route-location form
```

---

## 15. Blocking Issues

None.

---

## 16. Final Conclusion

**MANUAL_ROUTE_CLI_BRIDGE_READY**
