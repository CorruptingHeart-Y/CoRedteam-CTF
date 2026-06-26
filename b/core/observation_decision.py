"""ObservationDecision — single deterministic source of truth for post-execution outcome.

All consumers (Evidence Ledger, StrategyHealth, CLI milestone, failure counter,
Consolidator) MUST consume ONLY this decision. No LLM evaluator primitives are
used to create, promote, demote, or duplicate-write signals.

Design contract:
  - Deterministic observer checks actual HTTP response bodies against the route's
    expected_signals contract.
  - LLM evaluator's detected_primitives / summary / confidence are explanatory
    text only — they never create evidence.
  - evidence_key = (run_id, surface_key, execution_fingerprint, signal_id)
  - is_new_evidence is True only when this exact evidence_key has never been
    written to the Evidence Ledger.
  - is_new_state_transition is True only when the confirmed signal represents
    genuine progression (first time this signal is confirmed on this surface in
    this run).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ═══════════════════════════════════════════════════════════════════════════════
# Deterministic signal observers — no LLM, no confidence, no heuristics
# ═══════════════════════════════════════════════════════════════════════════════

def _deterministic_check_arithmetic_reflection(
    payload: str, response_bodies: list[str],
) -> bool:
    """Check if an arithmetic expression in the payload is reflected as its
    computed result in any HTTP response body.

    Example: payload="#set($x=7*7)$x" → response contains "49" → True
    """
    if not payload or not response_bodies:
        return False
    # Find arithmetic expression: number operator number
    m = re.search(r'(\d+)\s*([*+\-/])\s*(\d+)', str(payload))
    if not m:
        return False
    try:
        a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
        if op == '*':
            result = a * b
        elif op == '+':
            result = a + b
        elif op == '-':
            result = a - b
        elif op == '/':
            if b == 0:
                return False
            result = a // b
        else:
            return False
    except (ValueError, ZeroDivisionError):
        return False
    expected = str(result)
    for body in response_bodies:
        if expected in str(body or ""):
            return True
    return False


def _deterministic_check_template_directive(
    payload: str, response_bodies: list[str],
) -> bool:
    """Check if a template directive was parsed (not echoed literally).

    Heuristic: if response contains template-processed markers but not the
    raw directive string, the template engine parsed the injection.
    """
    if not payload or not response_bodies:
        return False
    # Look for known template directive patterns
    directive_patterns = [
        r'#(?:set|if|foreach|evaluate|macro)\s*\(',
        r'\$\{.*\}',
        r'\{\{.*\}\}',
        r'%\s*if\b',
    ]
    has_directive = any(re.search(p, str(payload)) for p in directive_patterns)
    if not has_directive:
        return False
    # Check that response does NOT contain the raw directive verbatim
    # (which would mean it wasn't processed), but DOES contain something
    # that looks like processed output
    raw_directive = str(payload).strip()
    for body in response_bodies:
        body_str = str(body or "")
        if raw_directive in body_str:
            continue  # echoed literally — not processed
        # If response is non-empty and doesn't echo the directive, it was parsed
        if len(body_str.strip()) > 10:
            return True
    return False


def _deterministic_check_command_execution(
    payload: str, response_bodies: list[str],
) -> bool:
    """Check for command execution output markers in response bodies."""
    if not response_bodies:
        return False
    indicators = ["uid=", "gid=", "root:", "bin/", "/etc/", "www-data"]
    for body in response_bodies:
        body_str = str(body or "").lower()
        if any(indicator.lower() in body_str for indicator in indicators):
            return True
    return False


def _deterministic_check_file_read(
    payload: str, response_bodies: list[str],
) -> bool:
    """Check for file content indicators in response bodies."""
    if not response_bodies:
        return False
    content_indicators = [
        "root:x:", "daemon:x:", "/etc/passwd", "flag{", "FLAG{",
        "BEGIN RSA", "BEGIN OPENSSH",
    ]
    for body in response_bodies:
        body_str = str(body or "")
        if any(indicator in body_str for indicator in content_indicators):
            return True
    return False


def _deterministic_check_oob_callback(
    payload: str, response_bodies: list[str],
) -> bool:
    """Check for OOB callback confirmation in step output.

    OOB callbacks are typically detected via the OOB server log, not HTTP
    response bodies. We check for explicit marker strings in the response.
    """
    if not response_bodies:
        return False
    for body in response_bodies:
        body_str = str(body or "")
        if "OOB_RECEIVED" in body_str or "callback received" in body_str.lower():
            return True
    return False


def _deterministic_check_object_access(
    payload: str, response_bodies: list[str],
) -> bool:
    """Check if object access / class enumeration succeeded.

    Indicators: Java class names in response, or characteristic reflection output.
    """
    if not response_bodies:
        return False
    class_indicators = [
        "java.lang.", "class ", "@", "Field", "Method",
        "java.util.", "java.io.",
    ]
    for body in response_bodies:
        body_str = str(body or "")
        # Multiple class indicators = likely successful object access
        hits = sum(1 for ind in class_indicators if ind in body_str)
        if hits >= 2:
            return True
    return False


# Observer registry: signal_id → deterministic check function
_DETERMINISTIC_OBSERVERS: dict[str, callable] = {
    "arithmetic_reflection_confirmed": _deterministic_check_arithmetic_reflection,
    "template_directive_parsed": _deterministic_check_template_directive,
    "command_execution_confirmed": _deterministic_check_command_execution,
    "file_read_confirmed": _deterministic_check_file_read,
    "oob_callback_received": _deterministic_check_oob_callback,
    "object_access_confirmed": _deterministic_check_object_access,
}


# ═══════════════════════════════════════════════════════════════════════════════
# Signal→primitive name mapping (for diagnostic output only)
# ═══════════════════════════════════════════════════════════════════════════════

SIGNAL_TO_PRIMITIVE: dict[str, str] = {
    "arithmetic_reflection_confirmed": "ssti_arithmetic",
    "template_directive_parsed": "template_injection",
    "command_execution_confirmed": "command_execution",
    "file_read_confirmed": "arbitrary_file_read",
    "oob_callback_received": "oob_callback",
    "object_access_confirmed": "object_access",
}


# ═══════════════════════════════════════════════════════════════════════════════
# ObservationDecision
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ObservationDecision:
    """Single deterministic outcome for one execution round.

    Created once after Executor completes. All downstream modules MUST
    consume this decision rather than independently interpreting exec_out
    or LLM evaluator output.
    """

    request_sent: bool
    observation_status: str  # positive_evidence | no_positive_evidence | request_not_sent | observation_unknown
    matched_signal_ids: list[str] = field(default_factory=list)
    failure_class: str | None = None
    surface_key: str = ""
    execution_fingerprint: str = ""
    evidence_keys: list[str] = field(default_factory=list)
    is_new_evidence: bool = False
    is_new_state_transition: bool = False
    selected_strategy_id: str = ""
    payload: str = ""
    response_bodies: list[str] = field(default_factory=list)
    diagnostic_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_sent": self.request_sent,
            "observation_status": self.observation_status,
            "matched_signal_ids": list(self.matched_signal_ids),
            "failure_class": self.failure_class,
            "surface_key": self.surface_key,
            "execution_fingerprint": self.execution_fingerprint,
            "evidence_keys": list(self.evidence_keys),
            "is_new_evidence": self.is_new_evidence,
            "is_new_state_transition": self.is_new_state_transition,
            "selected_strategy_id": self.selected_strategy_id,
            "diagnostic_notes": list(self.diagnostic_notes),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Factory function
# ═══════════════════════════════════════════════════════════════════════════════

def _make_evidence_key(
    run_id: str,
    surface_key: str,
    execution_fingerprint: str,
    signal_id: str,
) -> str:
    """Stable evidence key for dedup."""
    raw = f"{run_id}|{surface_key}|{execution_fingerprint}|{signal_id}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def make_observation_decision(
    *,
    exec_out: dict[str, Any],
    expected_signals: list[str],
    run_id: str,
    surface_key: str,
    selected_strategy_id: str = "",
    evidence_ledger_path: Path | None = None,
) -> ObservationDecision:
    """Create the single ObservationDecision for this execution round.

    Deterministic observer contract:
      1. Extract actual request from MaterializedExecutionRecord.
      2. Extract actual HTTP response bodies from step_results.
      3. For each expected_signal, run the deterministic observer.
      4. Check evidence ledger for dedup.
      5. Determine is_new_state_transition.

    LLM evaluator output (detected_primitives, confidence, summary) is
    deliberately ignored by this function.
    """
    diagnostic: list[str] = []

    # ── Step 1: Extract request_sent ──
    step_results = exec_out.get("step_results") or []
    materialized = exec_out.get("materialized_execution_record") if isinstance(exec_out, dict) else None
    if not isinstance(materialized, dict):
        materialized = {}

    if not step_results:
        return ObservationDecision(
            request_sent=False,
            observation_status="request_not_sent",
            failure_class=None,
            surface_key=surface_key,
            execution_fingerprint="",
            diagnostic_notes=["no step_results in exec_out"],
        )

    request_sent = bool(materialized.get("request_sent"))
    if not request_sent:
        # Check step-level records
        for sr in step_results:
            mr = sr.get("materialized_execution_record") if isinstance(sr, dict) else None
            if isinstance(mr, dict) and mr.get("request_sent"):
                request_sent = True
                materialized = mr
                break

    if not request_sent:
        return ObservationDecision(
            request_sent=False,
            observation_status="request_not_sent",
            failure_class=None,
            surface_key=surface_key,
            execution_fingerprint=str(materialized.get("execution_fingerprint") or ""),
            diagnostic_notes=["no request was sent in any step"],
        )

    # ── Step 2: Extract execution_fingerprint and payload ──
    execution_fingerprint = str(materialized.get("execution_fingerprint") or "")
    payload = ""
    normalized_body = materialized.get("normalized_request_body") or {}
    if isinstance(normalized_body, dict):
        for v in normalized_body.values():
            payload = str(v)
            break

    # ── Step 3: Collect all HTTP response bodies ──
    response_bodies: list[str] = []
    for sr in step_results:
        http_resps = sr.get("http_responses") if isinstance(sr, dict) else None
        if isinstance(http_resps, list):
            for resp in http_resps:
                if isinstance(resp, dict):
                    body = resp.get("response_body") or ""
                    if body:
                        response_bodies.append(str(body))

    if not expected_signals:
        return ObservationDecision(
            request_sent=True,
            observation_status="observation_unknown",
            failure_class=None,
            surface_key=surface_key,
            execution_fingerprint=execution_fingerprint,
            selected_strategy_id=selected_strategy_id,
            payload=payload,
            response_bodies=response_bodies,
            diagnostic_notes=["no expected_signals defined for this route"],
        )

    # ── Step 4: Run deterministic observers ──
    matched_signal_ids: list[str] = []
    for sig in expected_signals:
        observer = _DETERMINISTIC_OBSERVERS.get(str(sig).lower())
        if observer is None:
            diagnostic.append(f"no deterministic observer for signal: {sig}")
            continue
        try:
            if observer(payload, response_bodies):
                matched_signal_ids.append(str(sig))
                diagnostic.append(f"deterministic observer CONFIRMED: {sig}")
        except Exception as exc:
            diagnostic.append(f"deterministic observer ERROR for {sig}: {exc}")

    # ── Step 5: Determine observation_status ──
    if matched_signal_ids:
        observation_status = "positive_evidence"
        failure_class = None
    else:
        observation_status = "no_positive_evidence"
        failure_class = "expected_signal_missing"

    # ── Step 6: Build evidence_keys and check is_new_evidence ──
    evidence_keys: list[str] = []
    is_new_evidence = False
    is_new_state_transition = False

    if matched_signal_ids and evidence_ledger_path is not None:
        from core.evidence_ledger import evidence_exists, has_signal_on_surface

        for sig in matched_signal_ids:
            ek = _make_evidence_key(run_id, surface_key, execution_fingerprint, sig)
            evidence_keys.append(ek)
            if not evidence_exists(evidence_ledger_path, ek):
                is_new_evidence = True
                # Check if this signal is genuinely new for this surface in this run
                if not has_signal_on_surface(evidence_ledger_path, run_id, surface_key, sig):
                    is_new_state_transition = True

    return ObservationDecision(
        request_sent=True,
        observation_status=observation_status,
        matched_signal_ids=matched_signal_ids,
        failure_class=failure_class,
        surface_key=surface_key,
        execution_fingerprint=execution_fingerprint,
        evidence_keys=evidence_keys,
        is_new_evidence=is_new_evidence,
        is_new_state_transition=is_new_state_transition,
        selected_strategy_id=selected_strategy_id,
        payload=payload,
        response_bodies=response_bodies,
        diagnostic_notes=diagnostic,
    )
