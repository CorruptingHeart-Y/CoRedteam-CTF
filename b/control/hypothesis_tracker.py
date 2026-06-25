"""HypothesisTracker — evidence-driven hypothesis rejection for exploit paths.

Tracks exploitation hypotheses across pipeline restarts and rejects those
that have accumulated enough evidence of failure. Drives forced exploration
when Planner is stuck on a dead exploitation path.

Key design decisions:
- Fingerprint is NOT derived from payload text — it comes from confirmed_vuln,
  distiller evidence, FSM stage, and detected primitive. This ensures that
  CRLF+memcached+pickle(raw) and CRLF+memcached+pickle(urlencoded) are
  recognized as the SAME hypothesis.
- Rejection requires: (1) MIN_ATTEMPTS reached, (2) zero successes,
  (3) ≥80% of failures at the SAME stage.
- Persisted to disk. Pipeline restart does not lose rejection state.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Literal


# ── Fingerprint generation ───────────────────────────────────────────

# Maps CWE IDs to normalized exploit vectors for fingerprint construction.
_CWE_VECTOR_MAP: dict[str, str] = {
    "CWE-502":  "deserialization",     # unsafe deserialization
    "CWE-1336": "ssti",                # template injection
    "CWE-94":   "code_injection",      # arbitrary code injection
    "CWE-89":   "sqli",               # SQL injection
    "CWE-918":  "ssrf",               # server-side request forgery
    "CWE-78":   "command_injection",   # OS command injection
    "CWE-22":   "path_traversal",      # path traversal
    "CWE-79":   "xss",                # cross-site scripting
    "CWE-611":  "xxe",                # XML external entity
}

# Maps technology keywords to normalized component names.
_COMPONENT_KEYWORDS: dict[str, str] = {
    "memcached":         "memcached",
    "memcache":          "memcached",
    "velocity":          "velocity",
    "jinja2":            "jinja2",
    "jinja":             "jinja2",
    "flask":             "flask",
    "django":            "django",
    "mysql":             "mysql",
    "postgresql":        "postgresql",
    "sqlite":            "sqlite",
    "redis":             "redis",
    "tomcat":            "tomcat",
    "spring":            "spring",
    "apache":            "apache",
    "nginx":             "nginx",
    "express":           "express",
    "laravel":           "laravel",
    "pickle":            "pickle",
    "pyyaml":            "pyyaml",
    "java":              "java",
    "python":            "python",
    "php":               "php",
}

# Maps attack delivery mechanism keywords to normalized vectors.
_VECTOR_KEYWORDS: dict[str, str] = {
    "crlf":        "crlf",
    "crlf_injection": "crlf",
    "\\r\\n":      "crlf",
    "%0d%0a":      "crlf",
    "session":     "crlf",       # session cookie injection = CRLF vector
    "cookie":      "crlf",       # cookie-based injection
    "header":      "header_injection",
    "ssti":        "ssti",
    "template":    "ssti",
    "sql":         "sqli",
    "union":       "sqli",
    "ssrf":        "ssrf",
    "xxe":         "xxe",
    "deserialization": "deserialization",
    "pickle":      "pickle_rce",
}

# Maps execution goals to normalized labels.
_GOAL_KEYWORDS: dict[str, str] = {
    "rce":            "rce",
    "exec":           "rce",
    "runtime.exec":   "rce",
    "os.system":      "rce",
    "command":        "rce",
    "flag":           "flag_exfil",
    "exfil":          "flag_exfil",
    "file_read":      "file_read",
    "/etc/passwd":    "file_read",
    "data_exfil":     "data_exfil",
    "reverse_shell":  "reverse_shell",
    "webshell":       "webshell",
}


def _resolve_keyword(text: str, mapping: dict[str, str]) -> str:
    """Match the longest keyword first to avoid partial matches."""
    text_lower = text.lower()
    for kw in sorted(mapping.keys(), key=len, reverse=True):
        if kw.lower() in text_lower:
            return mapping[kw]
    return ""



def _first_cwe(confirmed: dict[str, Any] | None) -> str:
    vulns = (confirmed or {}).get("vulnerabilities") or []
    for vuln in vulns:
        cwe = str((vuln or {}).get("cwe_id") or "").upper()
        if cwe:
            return cwe
    return ""


def _plan_text(plan: dict[str, Any] | None) -> str:
    if not plan:
        return ""
    parts: list[str] = []
    for st in plan.get("steps") or []:
        if isinstance(st, dict):
            parts.append(str(st.get("purpose") or ""))
            parts.append(str(st.get("command") or ""))
            parts.append(str(st.get("expected_outcome") or ""))
            parts.append(str(st.get("primitive") or ""))
    return "\n".join(parts).lower()


def canonicalize_strategy_id(
    strategy_id: str = "",
    confirmed: dict[str, Any] | None = None,
    plan: dict[str, Any] | None = None,
) -> str:
    """Normalize a concrete attempt into vector*component*technique.

    This is intentionally runtime-derived: YAML IDs can be coarse or generated,
    but rejection should attach to the attempted strategy family.
    """
    raw = (strategy_id or "").strip().lower().replace(".", "*")
    if raw.count("*") >= 2 and not plan:
        return raw

    text = " ".join([raw, _plan_text(plan)])
    cwe_id = _first_cwe(confirmed)

    if "cwe-1336" in text or "cwe_1336" in text or cwe_id in ("CWE-1336", "CWE-917", "CWE-94"):
        vector = "ssti"
    elif "crlf" in text or "%0d%0a" in text or "\\r\\n" in text:
        vector = "crlf"
    elif "sql" in text or cwe_id == "CWE-89":
        vector = "sqli"
    elif "ssrf" in text or cwe_id == "CWE-918":
        vector = "ssrf"
    elif cwe_id:
        vector = _CWE_VECTOR_MAP.get(cwe_id, cwe_id.lower().replace("-", "_"))
    else:
        vector = "unknown"

    if "velocity" in text or "#set" in text or "#evaluate" in text or "$class" in text:
        component = "velocity"
    elif "jinja" in text or "{{" in text or "__globals__" in text:
        component = "jinja2"
    elif "mako" in text:
        component = "mako"
    elif "memcached" in text or "memcache" in text:
        component = "memcached"
    elif "mysql" in text:
        component = "mysql"
    elif "postgres" in text:
        component = "postgresql"
    else:
        component = _resolve_keyword(text, _COMPONENT_KEYWORDS) or "generic"

    if "#evaluate" in text:
        technique = "evaluate_dynamic"
    elif "processbuilder" in text:
        technique = "process_builder_exec"
    elif any(k in text for k in ("runtime.exec", "getruntime", "forname", "getmethod", "invoke(")):
        technique = "reflection_exec"
    elif any(k in text for k in ("cat /flag", "/flag", "/etc/passwd", "file_read", "readfile")):
        technique = "file_read"
    elif any(k in text for k in ("$class", "getclass", "config", "self.__init__", "__subclasses__")):
        technique = "object_access"
    elif any(k in text for k in ("7*7", "49", "arithmetic", "probe")):
        technique = "arithmetic_probe"
    elif any(k in text for k in ("exec", "rce", "whoami", " id", "uid=")):
        technique = "exec"
    else:
        technique = "unknown"

    return f"{vector}*{component}*{technique}"


def build_attempted_strategy(
    confirmed: dict[str, Any] | None,
    plan: dict[str, Any] | None,
    source: str = "planner",
) -> dict[str, Any]:
    template_selection = (plan or {}).get("template_selection") or {}
    matched = template_selection.get("matched_strategy_ids") or []
    available = template_selection.get("available_strategy_ids") or []
    yaml_strategy_id = ""
    if isinstance(available, list) and available:
        yaml_strategy_id = str(available[0])
    elif isinstance(matched, list) and matched:
        yaml_strategy_id = str(matched[0])

    cwe_id = _first_cwe(confirmed)
    canonical = canonicalize_strategy_id(yaml_strategy_id, confirmed=confirmed, plan=plan)
    return {
        "strategy_id": yaml_strategy_id,
        "canonical_strategy_id": canonical,
        "source": source,
        "surface": {
            "cwe": cwe_id,
            "endpoint": "/",
            "param": "",
        },
        "template_selection_status": template_selection.get("status", ""),
        "matched_strategy_ids": matched if isinstance(matched, list) else [],
        "available_strategy_ids": available if isinstance(available, list) else [],
    }
def generate_fingerprint(
    confirmed: dict[str, Any],
    fsm_progression: str = "",
    fsm_next_target: str = "",
    distilled: dict[str, Any] | None = None,
    last_plan: dict[str, Any] | None = None,
) -> str:
    """Generate a normalized hypothesis fingerprint from system-side signals.

    NEVER uses payload text or command strings. Derived exclusively from:
      - confirmed_vuln (CWE, technology, description)
      - FSM state (which progression, which stage)
      - distiller output (detected capabilities)

    Returns a fingerprint like: "crlf*memcached*pickle_rce"
    """
    vulns = confirmed.get("vulnerabilities") or [{}]
    vuln = vulns[0] if vulns else {}

    cwe_id = str(vuln.get("cwe_id", "") or "").upper()
    title = vuln.get("title", "") or ""
    description = vuln.get("description", "") or ""
    vuln_type = vuln.get("vuln_type", "") or ""
    source = vuln.get("source", {}) or {}
    source_code = source.get("code", "") if isinstance(source, dict) else ""

    # Source code is the richest signal — scan it first for component/vector
    source_text = f"{source_code} {title} {description}".lower()

    # ── 1. Resolve vector (how is the payload delivered?) ──
    vector = ""
    # Check confirmed vuln source code for delivery mechanism hints
    if "crlf" in source_text or "\\r\\n" in source_text or "%0d%0a" in source_text:
        vector = "crlf"
    elif "cookie" in source_text and ("session" in source_text or "pickle" in source_text):
        vector = "crlf"

    if not vector:
        # Fall back to FSM progression for vector hints
        if fsm_progression == "memcached_injection":
            vector = "crlf"
        elif fsm_progression == "ssti":
            vector = "ssti"
        elif fsm_progression == "sqli":
            vector = "sqli"

    if not vector:
        vector = _resolve_keyword(source_text, _VECTOR_KEYWORDS)
    if not vector:
        vector = _resolve_keyword(description, _VECTOR_KEYWORDS)
    if not vector:
        vector = "unknown"

    # ── 2. Resolve component (what technology is targeted?) ──
    component = ""
    # Source code is best for component identification
    if "memcached" in source_text or "memcache" in source_text:
        component = "memcached"
    elif "pickle" in source_text:
        # pickle implies python deserialization; check if memcached is involved
        if "memcached" in source_text or "memcache" in source_text:
            component = "memcached"
        else:
            component = "python"

    if not component:
        component = _resolve_keyword(source_text, _COMPONENT_KEYWORDS)
    if not component:
        component = _resolve_keyword(description, _COMPONENT_KEYWORDS)
    if not component:
        # Infer from CWE
        if "CWE-502" in cwe_id:
            component = "python"  # pickle/yaml unsafe deserialization
        elif "CWE-1336" in cwe_id or "CWE-94" in cwe_id:
            component = "velocity"
        elif "CWE-89" in cwe_id:
            component = "mysql"

    if not component:
        component = "unknown"

    # ── 3. Resolve execution goal ──
    goal = ""
    # From vuln type or description
    if "rce" in vuln_type.lower() or "remote code" in description.lower():
        goal = "rce"
    elif "flag" in description.lower() or "exfil" in description.lower():
        goal = "flag_exfil"

    if not goal:
        goal = _resolve_keyword(description, _GOAL_KEYWORDS)

    # From source code: what does the exploit try to achieve?
    if not goal and source_code:
        if "exec(" in source_code or "system(" in source_code or "Runtime" in source_code:
            goal = "rce"
        elif "cat /flag" in source_code or "flag" in source_code.lower():
            goal = "flag_exfil"
        elif "open(" in source_code and "read" in source_code:
            goal = "file_read"

    if not goal:
        # Infer from CWE
        if "CWE-502" in cwe_id:
            goal = "rce"  # deserialization → RCE is the standard chain
        elif "CWE-1336" in cwe_id:
            goal = "rce"
        elif "CWE-89" in cwe_id:
            goal = "data_exfil"

    if not goal:
        goal = "unknown"

    # ── 4. Assemble normalized fingerprint ──
    fingerprint = f"{vector}*{component}*{goal}"

    # Special case: CRLF injection targeting memcached with pickle payload
    # Normalize all variants to the canonical form
    if vector == "crlf" and ("memcached" in component or "pickle" in source_text):
        fingerprint = "crlf*memcached*pickle_rce"
    elif vector == "crlf" and component == "memcached":
        fingerprint = "crlf*memcached*pickle_rce"

    # SSTI normalization
    if vector == "ssti" and "velocity" in source_text:
        fingerprint = "ssti*velocity*exec"
    elif vector == "ssti" and "jinja" in source_text:
        fingerprint = "ssti*jinja2*exec"

    # SQLi normalization
    if vector == "sqli":
        if "mysql" in source_text or "mysql" in component:
            fingerprint = "sqli*mysql*data_exfil"

    return fingerprint


# ── Failure stage from distiller ─────────────────────────────────────

def resolve_failure_stage(
    distilled: dict[str, Any] | None,
    fsm_next_target: str = "",
    step_results: list[dict[str, Any]] | None = None,
) -> str:
    """Determine which exploitation stage failed this round.

    Priority order (most specific first):
      1. distiller capability signals (which cap was NOT achieved)
      2. FSM next_target (what we were trying to achieve)
      3. HTTP status code heuristics
    """
    if distilled:
        caps = distilled.get("capabilities", {})
        # Walk the progression from payload_delivery upward
        # The first NOT-True capability is the failure stage
        for stage in ("payload_delivery", "reflection", "crlf_injection",
                       "memcached_command", "deserialization", "template_eval",
                       "breakout", "object_access", "method_call", "classloader",
                       "exec", "file_read", "flag_exfil"):
            val = caps.get(stage)
            if val is False:
                return stage
            if val is not True:
                # Not yet achieved → this is the failure boundary
                return stage

    # Fall back to FSM next_target
    if fsm_next_target:
        return fsm_next_target

    # Fall back to HTTP status heuristics from step_results
    if step_results:
        all_stdout = " ".join(
            str((r.get("result") or {}).get("stdout") or "") for r in step_results
        )
        if "500" in all_stdout:
            return "deserialization"  # 500 often = pickle/memcached error
        if "404" in all_stdout or "NotFound" in all_stdout:
            return "file_read"  # flag file not found
        if "302" in all_stdout:
            return "reflection"  # redirect — no useful response

    return "payload_delivery"


# ── Hypothesis data class ────────────────────────────────────────────

@dataclass
class Hypothesis:
    """A single exploitation hypothesis tracked across execution rounds."""

    fingerprint: str  # normalized identifier, e.g. "crlf*memcached*pickle_rce"

    attempts: int = 0
    successes: int = 0

    # Track which stages failed and how many times
    failure_stages: Counter = field(default_factory=Counter)

    # Last evidence snippets (truncated, for debugging)
    last_evidence: list[str] = field(default_factory=list)

    first_seen: str = ""
    last_seen: str = ""

    # Set when hypothesis crosses rejection threshold
    rejected: bool = False
    rejected_at: str = ""
    rejected_reason: str = ""
    migrated_from: list[str] = field(default_factory=list)
    migration_version: int = 0

    # ── Extended runtime state (persisted with Hypothesis) ──
    consecutive_failures: int = 0
    failure_classes: Counter = field(default_factory=Counter)
    last_attempt_round: int | None = None
    last_positive_evidence_round: int | None = None
    last_outcome: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.failure_stages, dict):
            self.failure_stages = Counter(self.failure_stages)
        now = datetime.now(timezone.utc).isoformat()
        if not self.first_seen:
            self.first_seen = now
        if not self.last_seen:
            self.last_seen = now

    @property
    def dominant_failure_stage(self) -> str:
        """The failure stage with the highest count."""
        if not self.failure_stages:
            return "unknown"
        return self.failure_stages.most_common(1)[0][0]

    @property
    def dominant_failure_count(self) -> int:
        """Count of failures at the dominant stage."""
        if not self.failure_stages:
            return 0
        return self.failure_stages.most_common(1)[0][1]

    @property
    def dominant_failure_ratio(self) -> float:
        """Ratio of failures concentrated at the dominant failure stage."""
        total = sum(self.failure_stages.values())
        if total == 0:
            return 0.0
        return self.dominant_failure_count / total

    @property
    def rejection_ratio(self) -> float:
        """Overall failure ratio: failed_attempts / total_attempts."""
        if self.attempts == 0:
            return 0.0
        return (self.attempts - self.successes) / self.attempts

    @property
    def is_rejected(self) -> bool:
        return self.rejected

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "attempts": self.attempts,
            "successes": self.successes,
            "failure_stages": dict(self.failure_stages),
            "last_evidence": self.last_evidence[-5:],
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "rejected": self.rejected,
            "rejected_at": self.rejected_at,
            "rejected_reason": self.rejected_reason,
            "migrated_from": self.migrated_from,
            "migration_version": self.migration_version,
            "consecutive_failures": self.consecutive_failures,
            "failure_classes": dict(self.failure_classes),
            "last_attempt_round": self.last_attempt_round,
            "last_positive_evidence_round": self.last_positive_evidence_round,
            "last_outcome": self.last_outcome,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Hypothesis":
        return cls(
            fingerprint=data["fingerprint"],
            attempts=data.get("attempts", 0),
            successes=data.get("successes", 0),
            failure_stages=Counter(data.get("failure_stages", {})),
            last_evidence=data.get("last_evidence", []),
            first_seen=data.get("first_seen", ""),
            last_seen=data.get("last_seen", ""),
            rejected=data.get("rejected", False),
            rejected_at=data.get("rejected_at", ""),
            rejected_reason=data.get("rejected_reason", ""),
            migrated_from=data.get("migrated_from", []),
            migration_version=data.get("migration_version", 0),
            consecutive_failures=data.get("consecutive_failures", 0),
            failure_classes=Counter(data.get("failure_classes", {})),
            last_attempt_round=data.get("last_attempt_round"),
            last_positive_evidence_round=data.get("last_positive_evidence_round"),
            last_outcome=data.get("last_outcome"),
        )


# ── HypothesisTracker ────────────────────────────────────────────────

# Rejection thresholds
MIN_ATTEMPTS = 5            # must have at least this many attempts
DOMINANT_FAILURE_RATIO = 0.8  # ≥80% of failures at same stage
MAX_EVIDENCE_SNIPPETS = 5     # keep last N evidence snippets

StrategyHealthDecision = Literal["ALLOW", "DEGRADE", "REJECT", "HARD_REJECT"]


@dataclass
class StrategyHealth:
    """Quantified runtime judgement for a strategy only, never the surface."""

    strategy_id: str
    canonical_strategy_id: str
    matched_fingerprint: str = ""
    scope: str = "strategy_only"
    attempts: int = 0
    successes: int = 0
    failures: int = 0
    failure_rate: float = 0.0
    success_rate: float = 0.0
    dominant_failure_stage: str = "unknown"
    dominant_failure_count: int = 0
    dominant_failure_ratio: float = 0.0
    score: float = 1.0
    decision: StrategyHealthDecision = "ALLOW"
    budget: int = 1
    reason: str = ""
    surface_still_valid: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy_id": self.strategy_id,
            "canonical_strategy_id": self.canonical_strategy_id,
            "matched_fingerprint": self.matched_fingerprint,
            "scope": self.scope,
            "attempts": self.attempts,
            "successes": self.successes,
            "failures": self.failures,
            "failure_rate": self.failure_rate,
            "success_rate": self.success_rate,
            "dominant_failure_stage": self.dominant_failure_stage,
            "dominant_failure_count": self.dominant_failure_count,
            "dominant_failure_ratio": self.dominant_failure_ratio,
            "score": self.score,
            "decision": self.decision,
            "budget": self.budget,
            "reason": self.reason,
            "surface_still_valid": self.surface_still_valid,
        }

class HypothesisTracker:
    """Persistent tracker for exploitation hypotheses.

    Survives pipeline restarts. Writes to b/control/rejected_hypotheses.json.
    """

    def __init__(self, storage_path: Path | str | None = None) -> None:
        if storage_path is None:
            storage_path = Path(__file__).resolve().parent / "rejected_hypotheses.json"
        self._path = Path(storage_path)
        self._alias_path = self._path.parent / "legacy_alias_map.json"
        self._hypotheses: dict[str, Hypothesis] = {}
        self._load()

    # ── persistence ──────────────────────────────────────────────────

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            for fp, h_data in data.get("hypotheses", {}).items():
                self._hypotheses[fp] = Hypothesis.from_dict(h_data)
            if self._apply_legacy_alias_migration():
                self._save()
        except (json.JSONDecodeError, KeyError):
            self._hypotheses = {}

    def _apply_legacy_alias_migration(self) -> bool:
        if not self._alias_path.exists():
            return False
        try:
            alias_map = json.loads(self._alias_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return False
        if not isinstance(alias_map, dict):
            return False

        changed = False
        for old_key, canonical_id in alias_map.items():
            old_key = str(old_key or "").strip()
            canonical_id = str(canonical_id or "").strip()
            if not old_key or not canonical_id or old_key == canonical_id:
                continue
            old = self._hypotheses.get(old_key)
            if old is None:
                continue
            target = self._hypotheses.get(canonical_id)
            if target is None:
                target = Hypothesis(fingerprint=canonical_id)
                self._hypotheses[canonical_id] = target

            target.attempts += old.attempts
            target.successes += old.successes
            target.failure_stages.update(old.failure_stages)
            target.last_evidence = (target.last_evidence + old.last_evidence)[-MAX_EVIDENCE_SNIPPETS:]
            if not target.first_seen or (old.first_seen and old.first_seen < target.first_seen):
                target.first_seen = old.first_seen
            if old.last_seen and old.last_seen > target.last_seen:
                target.last_seen = old.last_seen
            target.rejected = target.rejected or old.rejected
            if old.rejected_at and (not target.rejected_at or old.rejected_at > target.rejected_at):
                target.rejected_at = old.rejected_at
            if old.rejected_reason and not target.rejected_reason:
                target.rejected_reason = old.rejected_reason
            migrated = set(target.migrated_from or [])
            migrated.add(old_key)
            migrated.update(old.migrated_from or [])
            target.migrated_from = sorted(migrated)
            target.migration_version = max(target.migration_version, 1)
            del self._hypotheses[old_key]
            changed = True
        return changed

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, Any] = {
            "version": 1,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "hypotheses": {
                fp: h.to_dict() for fp, h in self._hypotheses.items()
            },
        }
        self._path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    # ── recording ────────────────────────────────────────────────────

    def record_attempt(
        self,
        fingerprint: str,
        success: bool,
        failure_stage: str = "",
        evidence: str = "",
        failure_class: str = "",
        round_number: int | None = None,
        outcome: str = "",
    ) -> Hypothesis:
        """Record an execution attempt against a hypothesis.

        Creates the hypothesis on first encounter. Updates failure stage
        tracking. Checks rejection thresholds and marks rejected if met.
        """
        if fingerprint not in self._hypotheses:
            self._hypotheses[fingerprint] = Hypothesis(fingerprint=fingerprint)

        h = self._hypotheses[fingerprint]
        h.attempts += 1
        h.last_seen = datetime.now(timezone.utc).isoformat()
        h.last_outcome = outcome or ("positive_evidence" if success else "no_positive_evidence")
        if round_number is not None:
            h.last_attempt_round = round_number

        if success:
            h.successes += 1
            h.consecutive_failures = 0
            h.last_positive_evidence_round = round_number
        else:
            h.consecutive_failures += 1
            if failure_stage:
                h.failure_stages[failure_stage] += 1
            if failure_class:
                h.failure_classes[failure_class] += 1
            if evidence:
                h.last_evidence.append(evidence[:300])
                if len(h.last_evidence) > MAX_EVIDENCE_SNIPPETS:
                    h.last_evidence = h.last_evidence[-MAX_EVIDENCE_SNIPPETS:]

        # ── Check rejection thresholds ──
        if not h.rejected and not success:
            if (h.attempts >= MIN_ATTEMPTS
                    and h.successes == 0
                    and h.dominant_failure_ratio >= DOMINANT_FAILURE_RATIO):
                h.rejected = True
                h.rejected_at = datetime.now(timezone.utc).isoformat()
                h.rejected_reason = (
                    f"Hypothesis REJECTED: {h.attempts} attempts, 0 successes. "
                    f"Dominant failure stage: {h.dominant_failure_stage} "
                    f"({h.dominant_failure_count}/{sum(h.failure_stages.values())} = "
                    f"{h.dominant_failure_ratio:.0%}). "
                    f"Exploitation path is falsified — forced exploration required."
                )
                print(f"\n[hypothesis_tracker] 🔴 {h.rejected_reason}")

        self._save()
        return h

    def record_success(self, fingerprint: str, evidence: str = "") -> Hypothesis:
        """Record a successful exploitation — instantly un-rejects the hypothesis."""
        if fingerprint not in self._hypotheses:
            self._hypotheses[fingerprint] = Hypothesis(fingerprint=fingerprint)

        h = self._hypotheses[fingerprint]
        h.attempts += 1
        h.successes += 1
        h.last_seen = datetime.now(timezone.utc).isoformat()
        if evidence:
            h.last_evidence.append(evidence[:300])

        # Success clears rejection
        if h.rejected:
            h.rejected = False
            h.rejected_at = ""
            h.rejected_reason = ""
            print(f"[hypothesis_tracker] ✅ Hypothesis {fingerprint} un-rejected by success")

        self._save()
        return h

    # ── querying ─────────────────────────────────────────────────────

    def get(self, fingerprint: str) -> Hypothesis | None:
        return self._hypotheses.get(fingerprint)
    def evaluate_strategy_health(
        self,
        strategy_id: str,
        aliases: Iterable[str] | None = None,
    ) -> StrategyHealth:
        """Return quantified health for an exact canonical strategy id.

        aliases is accepted for backward-compatible callers, but is ignored by
        design. Legacy keys must be migrated through legacy_alias_map.json first.
        """
        canonical = (strategy_id or "").strip()
        matched = self._hypotheses.get(canonical) if canonical else None

        if matched is None:
            return StrategyHealth(
                strategy_id=canonical,
                canonical_strategy_id=canonical,
                reason="no_runtime_history",
                budget=1,
            )

        attempts = matched.attempts
        successes = matched.successes
        failures = max(attempts - successes, 0)
        failure_rate = failures / attempts if attempts else 0.0
        success_rate = successes / attempts if attempts else 0.0
        dominant_ratio = matched.dominant_failure_ratio
        score = max(0.0, min(1.0, 1.0 - 0.60 * failure_rate - 0.25 * dominant_ratio + 0.70 * success_rate))

        decision: StrategyHealthDecision = "ALLOW"
        budget = 1
        reason = "healthy_or_unproven"
        if attempts >= 10 and successes == 0 and dominant_ratio >= DOMINANT_FAILURE_RATIO:
            decision = "HARD_REJECT"
            budget = 0
            reason = "repeated_zero_success_dominant_failure"
        elif matched.rejected or (attempts >= MIN_ATTEMPTS and successes == 0 and dominant_ratio >= DOMINANT_FAILURE_RATIO):
            decision = "REJECT"
            budget = 0
            reason = "empirically_rejected_strategy"
        elif matched.consecutive_failures >= 3 and successes == 0:
            decision = "DEGRADE"
            budget = 1
            reason = "consecutive_no_positive_evidence"
        elif attempts >= 3 and successes == 0 and failure_rate >= 0.67:
            decision = "DEGRADE"
            budget = 1
            reason = "low_yield_strategy"

        return StrategyHealth(
            strategy_id=canonical,
            canonical_strategy_id=canonical,
            matched_fingerprint=canonical,
            attempts=attempts,
            successes=successes,
            failures=failures,
            failure_rate=failure_rate,
            success_rate=success_rate,
            dominant_failure_stage=matched.dominant_failure_stage,
            dominant_failure_count=matched.dominant_failure_count,
            dominant_failure_ratio=dominant_ratio,
            score=score,
            decision=decision,
            budget=budget,
            reason=reason,
            surface_still_valid=True,
        )

    def get_rejected(self) -> dict[str, Hypothesis]:
        """Return all currently rejected hypotheses."""
        return {fp: h for fp, h in self._hypotheses.items() if h.is_rejected}

    def get_rejected_strategy_ids(self) -> set[str]:
        """Return rejected canonical strategy ids by exact persisted key only."""
        return {fp for fp, h in self._hypotheses.items() if h.is_rejected}
    def get_all(self) -> dict[str, Hypothesis]:
        return dict(self._hypotheses)

    def is_rejected(self, fingerprint: str) -> bool:
        h = self._hypotheses.get(fingerprint)
        return h is not None and h.is_rejected

    def is_semantically_rejected(
        self,
        candidate_fingerprint: str,
        plan: dict[str, Any] | None = None,
    ) -> tuple[bool, str]:
        """Check if a candidate fingerprint (or plan) matches any rejected hypothesis.

        Does semantic normalization: even if the fingerprint string differs,
        checks whether the underlying vector*component*goal matches a rejected
        hypothesis.

        Returns (is_rejected: bool, matched_fingerprint: str).
        """
        # Direct match
        if self.is_rejected(candidate_fingerprint):
            return True, candidate_fingerprint

        # Parse candidate into parts for semantic comparison
        candidate_parts = candidate_fingerprint.split("*")
        if len(candidate_parts) < 3:
            return False, ""

        cand_vector, cand_component, cand_goal = candidate_parts[0], candidate_parts[1], candidate_parts[2]

        for fp, h in self._hypotheses.items():
            if not h.is_rejected:
                continue
            fp_parts = fp.split("*")
            if len(fp_parts) < 3:
                continue
            fp_vector, fp_component, fp_goal = fp_parts[0], fp_parts[1], fp_parts[2]

            # Same vector + component = same exploitation surface
            # Even if goal differs slightly, it's the same hypothesis
            if cand_vector == fp_vector and cand_component == fp_component:
                return True, fp

            # Cross-normalization: crlf+memcached variants
            if cand_vector == "crlf" and fp_vector == "crlf":
                if cand_component == "memcached" or fp_component == "memcached":
                    return True, fp

        return False, ""

    # ── feedback injection ────────────────────────────────────────────

    def build_rejection_feedback(self, fingerprint: str) -> str:
        """Build the [HYPOTHESIS_REJECTED] feedback block for Planner injection."""
        h = self._hypotheses.get(fingerprint)
        if not h or not h.is_rejected:
            return ""

        return (
            "\n\n"
            "╔══════════════════════════════════════════════════════════════╗\n"
            "║  🔴 [HYPOTHESIS_REJECTED] — Exploitation path FALSIFIED     ║\n"
            "╚══════════════════════════════════════════════════════════════╝\n"
            f"\n  Hypothesis: {h.fingerprint}\n"
            f"  Attempts:   {h.attempts}\n"
            f"  Successes:  {h.successes}\n"
            f"  Dominant Failure Stage: {h.dominant_failure_stage} "
            f"({h.dominant_failure_count}/{sum(h.failure_stages.values())} failures)\n"
            f"  Rejected at: {h.rejected_at}\n"
            f"\n  This hypothesis has been FALSIFIED by accumulated evidence.\n"
            f"  Do NOT generate variants of this path.\n"
            f"  Payload mutations are FORBIDDEN:\n"
            f"    - NO encoding variants (raw/urlencoded/base64)\n"
            f"    - NO cookie format tweaks\n"
            f"    - NO path guessing\n"
            f"    - NO header adjustments\n"
            f"\n"
            f"  You MUST explore a fundamentally DIFFERENT exploitation surface.\n"
            f"  Acceptable alternatives:\n"
            f"    - Switch from CRLF injection to SSTI\n"
            f"    - Switch from CRLF injection to SSRF\n"
            f"    - Switch from CRLF injection to SQL injection\n"
            f"    - Switch from memcached to direct application logic exploitation\n"
            f"\n"
            f"  Generate a plan targeting a DIFFERENT attack vector entirely.\n"
        )

    # ── stats ─────────────────────────────────────────────────────────

    def get_stats(self) -> dict[str, Any]:
        rejected = self.get_rejected()
        return {
            "total_hypotheses": len(self._hypotheses),
            "rejected_count": len(rejected),
            "rejected_fingerprints": list(rejected.keys()),
            "active_hypotheses": len(self._hypotheses) - len(rejected),
        }


# ── Singleton ────────────────────────────────────────────────────────

_tracker: HypothesisTracker | None = None


def get_hypothesis_tracker(
    storage_path: Path | str | None = None,
) -> HypothesisTracker:
    global _tracker
    if _tracker is None:
        _tracker = HypothesisTracker(storage_path)
    return _tracker


def reset_hypothesis_tracker() -> None:
    global _tracker
    _tracker = None
