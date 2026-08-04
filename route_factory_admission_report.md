# Route Factory v1.2 — Offline Route Admission Report

## Completion verdict

Route Admission v1 is implemented as a deterministic, read-only, offline gate from
`NormalizedRoute` or candidate YAML to `AdmissionDecision`. A successful decision
keeps the route at `activation.state=draft` and
`generation_status=candidate_only`; it does not select, execute, repair, or promote
the route.

Final focused regression result:

```text
212 passed in 1.31s
```

This preserves the 149-test Route Factory baseline and adds 63 Admission test
items. Docker, HTTP, LLM, target execution, and the exploit pipeline were not run.

## Modified files

```text
b/routes/admission.py       new strict parser, loader, and admission gate
b/routes/schema.py          immutable admission diagnostics and decisions
b/routes/__init__.py        lazy Admission API exports
b/test_routes.py            Admission and YAML safety tests
route_factory_admission_report.md
```

No five-layer Agent, Coordinator, state machine, PrimitiveRegistry,
PrimitiveTransitionGraph, TemplateManager, builtin YAML, or historical generated
YAML was modified.

## Public API and call chains

Direct admission:

```python
decision = admit_route(route, adapter)
```

```text
NormalizedRoute
→ to_plain()
→ normalized_route_from_plain()
→ strict dataclass reconstruction
→ deterministic invariant checks
→ AdmissionDecision
```

Candidate YAML admission:

```python
decision = load_and_admit_candidate_route(yaml_path, adapter)
```

```text
bounded UTF-8 read (maximum 256 KiB + 1 byte)
→ YAML token alias limit
→ yaml.safe_load()
→ top-level mapping and structure bounds
→ normalized_route_from_plain()
→ deterministic invariant checks
→ AdmissionDecision
```

## AdmissionDecision contract

The immutable schema is:

```python
@dataclass(frozen=True)
class AdmissionDiagnostic:
    code: AdmissionErrorCode
    field: str | None
    message: str

@dataclass(frozen=True)
class AdmissionDecision:
    accepted: bool
    status: str
    canonical_id: str | None
    diagnostics: tuple[AdmissionDiagnostic, ...]
    checked_invariants: tuple[str, ...]
    route: NormalizedRoute | None
```

Status is either `admitted_candidate` or `rejected`. A rejected decision does not
return a partially trusted route. Diagnostics expose stable codes and never
resolve or include raw payload content.

## Strict plain-object reconstruction

`normalized_route_from_plain()` requires the exact NormalizedRoute top-level
fields and explicitly validates each scalar, mapping, and list type. It does not:

- fill missing fields;
- convert strings to lists or booleans;
- remove unsupported keys;
- rewrite canonical IDs;
- change candidate activation;
- discard state-mutation declarations and continue.

Missing or wrong top-level schema fields return `SCHEMA_INVALID`. Nested contracts
with dedicated error codes, such as materialization and replay, retain those
specific codes.

## Admission rules

| Invariant | Admission v1 behavior | Stable rejection code |
|---|---|---|
| Schema | Exact fields and types; schema version must be `1.0.0` | `SCHEMA_INVALID` |
| Candidate state | Only `draft + route_factory + candidate_only` | `INVALID_CANDIDATE_STATE` |
| CWE | Reuses `SSTI_CWE_ALIASES`; YAML must store canonical `CWE-94` | `UNKNOWN_CWE`, `NON_CANONICAL_CWE` |
| Canonical ID | Recomputed with the existing `_canonical_id()` implementation | `CANONICAL_ID_MISMATCH` |
| Technique | Must remain in the current Normalizer technique set | `UNSUPPORTED_TECHNIQUE` |
| State | Delegates to `PrimitiveAdapter.state_exists()` | `UNKNOWN_STATE` |
| Primitive | Must exist and be a CWE entry primitive | `UNKNOWN_PRIMITIVE`, `UNSUPPORTED_PRIMITIVE` |
| Payload reference | Stable lowercase 16-hex SHA-256 ref, same primitive, resolvable | `LEGACY_PAYLOAD_REF_NOT_ADMITTED`, `MALFORMED_PAYLOAD_REF`, `PAYLOAD_PRIMITIVE_MISMATCH`, `UNKNOWN_PAYLOAD_TEMPLATE` |
| Expected signals | Non-empty, unique, and all supported by the primitive | `MISSING_EXPECTED_SIGNAL`, `DUPLICATE_EXPECTED_SIGNAL`, `PRIMITIVE_SIGNAL_MISMATCH` |
| Success | `match=any`; signals exactly equal the top-level signals | `UNSUPPORTED_SUCCESS_MATCH`, `SUCCESS_SIGNAL_MISMATCH` |
| Observability | At least one fully supported observable result | `NON_OBSERVABLE_ROUTE` |
| Materialization | Only the current `http_request` / `runtime_truths` declaration; refs equal | `UNSUPPORTED_MATERIALIZATION_TYPE`, `MATERIALIZATION_INCOMPLETE`, `MATERIALIZATION_REF_MISMATCH` |
| Runtime facts | Local temporary allowlist: `endpoint`, `parameter`, `method` | `MISSING_RUNTIME_FACTS`, `UNKNOWN_RUNTIME_FACT` |
| Requires state | Static `requires.current_state` must equal `current_state` | `REQUIRES_STATE_MISMATCH` |
| Replay | Exact mapping with boolean `enabled=false` and no extra policy | `UNSUPPORTED_REPLAY_POLICY` |
| Failure | Only `state_change=none` | `INVALID_FAILURE_STATE_CHANGE` |
| Success state mutation | Rejects `next_state`, `set_state`, `state_transition`, `advance_state`, and `unlock_state` | `ROUTE_ATTEMPTS_STATE_MUTATION` |

The runtime fact allowlist is local to `routes.admission` and explicitly documented
as a temporary Route Factory v1 contract, not a global RuntimeTruths source.

## YAML safety boundary

The loader uses `yaml.safe_load()` only. It rejects:

- files larger than 256 KiB using a bounded binary read;
- invalid UTF-8 or unreadable files;
- multiple YAML documents;
- Python object construction tags;
- non-mapping top-level values;
- more than 32 aliases;
- cyclic, excessively deep, or more than 10,000-node structures.

Stable codes are `YAML_LOAD_ERROR`, `YAML_TOP_LEVEL_NOT_MAPPING`,
`YAML_MULTIPLE_DOCUMENTS`, and `YAML_FILE_TOO_LARGE`.

## Accepted example

```text
accepted: true
status: admitted_candidate
canonical_id: cwe-94:init:ssti-reflection:arithmetic-probe
diagnostics: []
route.activation.state: draft
route.activation.source: route_factory
route.generation_status: candidate_only
```

The admitted route still contains only a stable reference such as:

```text
primitive:ssti_reflection:sha256:d095461aa3182fe4
```

It does not contain the referenced payload template.

## Rejected examples

Active candidate:

```text
accepted: false
status: rejected
error_codes: [INVALID_CANDIDATE_STATE]
route: null
```

Multiple YAML documents:

```text
accepted: false
status: rejected
error_codes: [YAML_MULTIPLE_DOCUMENTS]
route: null
```

Legacy payload index reference:

```text
accepted: false
status: rejected
error_codes: [LEGACY_PAYLOAD_REF_NOT_ADMITTED]
route: null
```

## Verification performed

```text
Baseline before Admission: 149 passed in 0.98s
Final full Route Factory suite: 212 passed in 1.31s
Python source compile smoke: passed
Admission import smoke: passed
Temporary candidate YAML write → safe load → admission: admitted_candidate
Temporary invalid multi-document YAML: YAML_MULTIPLE_DOCUMENTS
```

Tests cover every requested test name plus alias limits, activation source,
malformed references, replay type/extra fields, runtime allowlist locality,
requires-state consistency, schema version, immutable decisions, and safe-loader
source inspection.

## Explicitly deferred

Admission v1 does not evaluate current runtime state or RuntimeTruths values, route
attempt/completion history, runtime replay fingerprints, route ranking, fallback,
unlocking, Route Frontier eligibility, Planner selection, Validator plan contracts,
Executor materialization/execution, Evaluator observations, or physical HTTP
signals. `expression_evaluated` remains outside current primitive observable
signals and is not admitted as an expected signal.

## Worktree and Git summary

`b/routes/` and `b/test_routes.py` were already untracked, so ordinary `git diff`
does not provide a baseline for their contents. The pre-existing 23 deletions
under `target_codebase/cybench_web_challenges/2/` were left untouched. No commit or
push was performed.
