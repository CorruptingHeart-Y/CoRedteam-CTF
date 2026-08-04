# Materializer Final Pipeline Fix Report

**Date:** 2026-07-28  
**Branch:** competition-standard  
**Scope:** Fix 3 Codex REVIEW_REJECTED test reliability issues — no CWE/Route/Schema/Stage-1 changes  

---

## 1. Modified Files

| File | Change |
|---|---|
| `b/test_route_materializer_impl.py` | Removed `except ImportError: pass` bypass in executor test; split counters for `run_executor` + `_run_step` |
| `b/test_route_materializer_acceptance.py` | Rewrote smoke test with real YAML→Admission→Registry→Frontier→Materializer data flow + fail-fast side-effect counters |
| `ds_materializer_final_pipeline_fix_report.md` | This report |

**No production files were modified.** No CLI, no Stage 1, no HTTP, no exploit execution.

---

## 2. Executor ImportError Bypass — Fixed

**File:** `b/test_route_materializer_impl.py`  
**Test:** `TestNonInterference::test_materializer_does_not_call_executor_interface`

### Before (REVIEW_REJECTED)

```python
try:
    import agents.executor
except ImportError:
    pass          # ← SILENT BYPASS: test passes even if import fails
else:
    monkeypatch.setattr(...)
```

### After

```python
import agents.executor  # MUST succeed — no except, no pass

executor_calls = {"run_executor": 0, "run_step": 0}

def _fail_run_executor(*a, **kw):
    executor_calls["run_executor"] += 1
    raise AssertionError(...)

def _fail_run_step(*a, **kw):
    executor_calls["run_step"] += 1
    raise AssertionError(...)

monkeypatch.setattr("agents.executor.run_executor", _fail_run_executor)
monkeypatch.setattr("agents.executor._run_step", _fail_run_step)

# ... run Materializer ...

assert executor_calls["run_executor"] == 0
assert executor_calls["run_step"] == 0
```

- `except ImportError: pass` — **deleted**
- Import failure → **test fails**
- Two independent counters for each entry point
- Both asserted == 0 after Materializer completes

---

## 3. Real YAML → Admission → Registry → Frontier → Materializer Data Flow

**File:** `b/test_route_materializer_acceptance.py`  
**Test:** `TestOfflineReleaseSmoke::test_full_pipeline_uses_yaml_loaded_admitted_frontier_route` (new name)

### Before (REVIEW_REJECTED)

```python
# Admission used original in-memory route (bypassed YAML file)
decision = admit_route(route, adapter)       # ← route from memory

# Materializer used original in-memory route (bypassed Frontier output)
materialized = materialize_route_plan(route, ...)  # ← same route from memory
```

### After (real object flow)

```
RouteProposal (CWE-1336)
  → Normalizer → canonical CWE-94 route
  → YAML Writer → temp .yaml file on disk
  → load_and_admit_candidate_route(yaml_path, adapter)  ← reads file, safe_load, parses, admits
  → Registry.register_decision(decision, yaml_path)
  → Frontier.build_frontier(registry.snapshot(), context)
  → eligible_entry = frontier.eligible_routes[0]
  → registered = registry.get(eligible_entry.route_id)  ← lookup via Registry, NOT memory
  → frontier_route = registered.route
  → Materializer(frontier_route, ...)                    ← Frontier route, NOT original
  → plan.json → validate_plan_structure → controlled validate_plan
```

### Explicit identity assertions

| Assertion | Verified |
|---|---|
| YAML file exists on disk | `yaml_path.is_file() == True` |
| Safe-loaded object comes from YAML file | `load_and_admit_candidate_route(yaml_path, ...)` |
| Admission input is safe-loaded YAML | Same call chain |
| Registry object from Admission output | `registry.register_decision(decision, yaml_path)` |
| Materializer input is Frontier eligible entry route | `registry.get(eligible_entry.route_id).route` |
| plan `route_id` == Frontier route `canonical_id` | `assert ==` |
| plan `payload_template_ref` == Frontier route | `assert ==` |
| plan `steps == 1` | `assert len(plan["steps"]) == 1` |
| `schema_version == 1.1.0` | Checked in YAML text |
| Admission status == `admitted_candidate` | `assert decision.status == ADMITTED_CANDIDATE` |
| Registry size == 1 | `assert len(registry) == 1` |
| Frontier eligible == 1 | `assert len(frontier.eligible_routes) == 1` |
| Materializer success == True | `assert materialized.success` |
| Plan Structure passed == True | `assert struct.passed` |
| Runtime Validator passed == True | `assert validation["passed"] is True` |

---

## 4. Side-Effect Call Counters

### HTTP — `http_calls == 0`

| Entry Point | Patched | Required |
|---|---|---|
| `socket.socket.connect` | fail-fast | mandatory (stdlib) |
| `urllib.request.urlopen` | fail-fast | mandatory (stdlib) |
| `requests.request` | fail-fast (if importable) | optional |
| `httpx.request` | fail-fast (if importable) | optional |

**Patch failure on mandatory entries → test fails.** Optional third-party imports that are unavailable are silently skipped (only the patching, not the test).

### Executor — `executor_calls == 0`

| Entry Point | Patched |
|---|---|
| `agents.executor.run_executor` | fail-fast |
| `agents.executor._run_step` | fail-fast |

Import failure → test fails. No except clause.

### Verification Memory — `verif_writes == 0`

Patched methods (all 10 exist on the singleton):
`confirm`, `confirm_endpoint`, `confirm_injectable`, `add_accepted_field`, `add_rejected_field`, `add_blacklist`, `add_bypass`, `add_working_primitive`, `add_flag`, `_save`

Uses temp path with `reset_verification(path=..., clear_current_run=True)` for clean state.

### Trajectory Memory — `traj_writes == 0`

Patched methods (only those that actually exist):
`append`, `_save`

State tracking:
- `current_state` unchanged (`initial_state == "init"`)
- `node_count` unchanged

Uses temp path with `reset_trajectory(path=..., clear_current_run=True)` for clean state.

### Forbidden Imports — subprocess `returncode == 0`, `found_forbidden == []`

Checked modules:
`planner`, `coordinator`, `evaluator`, `consolidator`, `openai`, `anthropic`, `langchain`, `litellm`

Additional assertions:
- `subprocess.returncode == 0`
- `stderr` contains no `Traceback`
- `FORBIDDEN:` not in stdout

### Removed

All `assert True` placeholders — **deleted**. No `except Exception: pass`. No skip/xfail/warning-as-pass.

---

## 5. Targeted Test Results

```
pytest -q b/test_route_materializer_acceptance.py
```
```
5 passed, 3 warnings in 0.30s
```

```
pytest -q b/test_route_materializer_impl.py -k "executor or memory or trajectory or side_effect"
```
```
8 passed, 120 deselected, 3 warnings in 0.52s
```

---

## 6. Complete Test Suite Results

```
pytest -q \
  b/test_routes.py \
  b/test_route_materializer_impl.py \
  b/test_plan_contract.py \
  b/test_run_isolation_evidence_guard.py \
  b/test_route_materializer_acceptance.py
```
```
533 passed in 13.48s
```

| Metric | Count |
|---|---|
| passed | 533 |
| failed | 0 |
| skipped | 0 |
| xfailed | 0 |

---

## 7. Warnings (original sources)

All 3 warnings originate from the third-party `paramiko` library, not from project code:

```
D:\11\Lib\site-packages\paramiko\pkey.py:82
  CryptographyDeprecationWarning: TripleDES has been moved to
  cryptography.hazmat.decrepit.ciphers.algorithms.TripleDES
  and will be removed from this module in 48.0.0.

D:\11\Lib\site-packages\paramiko\transport.py:219
  CryptographyDeprecationWarning: Blowfish has been moved to
  cryptography.hazmat.decrepit.ciphers.algorithms.Blowfish
  and will be removed from this module in 45.0.0.

D:\11\Lib\site-packages\paramiko\transport.py:243
  CryptographyDeprecationWarning: TripleDES has been moved to
  cryptography.hazmat.decrepit.ciphers.algorithms.TripleDES
  and will be removed from this module in 48.0.0.
```

No project warnings. No deprecation from project code.

---

## 8. Blocking Issues

None.

---

## 9. Final Conclusion

**MATERIALIZER_PIPELINE_SMOKE_READY**
