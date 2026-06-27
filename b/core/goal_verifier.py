"""Deterministic Goal Verifier — scans current-round execution results for flags.

Evidence sources (ALLOWED — only current execution_result):
  - step_results[*].chain_output._last_response_text
  - step_results[*].chain_output._http_responses[*].response_body
  - step_results[*].http_responses[*].response_body

Excluded sources (NEVER scanned):
  - Planner rationale / plan JSON payload / body / code
  - feedback / memory / history workspace files
  - LLM analysis / Evaluator claims
"""

from __future__ import annotations

import hashlib
import re
from typing import Any


# ── Configurable flag patterns ──────────────────────────────────────────
# Ordered by specificity: earlier patterns match first.
_FLAG_PATTERNS: list[re.Pattern] = [
    re.compile(r"HTB\{[^}]+\}"),
    re.compile(r"flag\{[^}]+\}", re.IGNORECASE),
    re.compile(r"CTF\{[^}]+\}"),
    # Generic: any {alphanum_underscore} pattern that looks like a flag
    re.compile(r"[A-Za-z0-9_]+\{[A-Za-z0-9_!@#$%^&*()\-+=[\]|;:',.<>?/]+\}"),
]

# ── Anti-echo: fields in sent requests that must NOT contain the flag ───
_SENT_FIELDS = ("body", "query", "data", "params", "payload", "command")


def _hash_evidence(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def verify_goal(
    exec_out: dict[str, Any],
    plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Deterministically scan execution results for captured flags.

    Args:
        exec_out: The execution_result dict from run_executor.
        plan: Optional—only used to extract the sent payload for anti-echo.

    Returns a verification dict (see module docstring for schema).
    """
    result: dict[str, Any] = {
        "verified": False,
        "artifact_type": "",
        "artifact": "",
        "step_id": None,
        "source_kind": "",
        "method": "",
        "url": "",
        "status_code": None,
        "evidence_sha256": "",
        "verifier_version": "goal-verifier-v1",
        "exclusion_reason": "",
    }

    step_results = exec_out.get("step_results") or []
    if not step_results:
        result["exclusion_reason"] = "no step_results in execution output"
        return result

    # ── Collect sent payloads for anti-echo ───────────────────────────
    sent_texts: list[str] = []
    if plan:
        for st in (plan.get("steps") or []):
            if not isinstance(st, dict):
                continue
            # sdk_calls dict form
            sdk_calls = st.get("sdk_calls") or []
            if isinstance(sdk_calls, list):
                for sc in sdk_calls:
                    if isinstance(sc, dict):
                        for field in _SENT_FIELDS:
                            val = sc.get(field)
                            if isinstance(val, str):
                                sent_texts.append(val)
                            elif isinstance(val, dict):
                                sent_texts.append(str(val))
                    elif isinstance(sc, str):
                        sent_texts.append(sc)
            # command field
            cmd = st.get("command") or ""
            if isinstance(cmd, str) and cmd.strip():
                sent_texts.append(cmd)

    # ── Scan execution results ───────────────────────────────────────
    for r in step_results:
        if not isinstance(r, dict):
            continue
        step_id = r.get("step_id")

        # Source A: chain_output._last_response_text
        chain = r.get("chain_output")
        if isinstance(chain, dict):
            lrt = chain.get("_last_response_text") or ""
            if isinstance(lrt, str) and lrt.strip():
                match = _match_flag(lrt, sent_texts)
                if match:
                    result.update({
                        "verified": True,
                        "artifact_type": "flag",
                        "artifact": match,
                        "step_id": step_id,
                        "source_kind": "chain_response_body",
                        "evidence_sha256": _hash_evidence(lrt[:2000]),
                    })
                    _enrich_http_meta(result, chain, r)
                    return result

            # Source B: chain_output._http_responses[*].response_body
            http_resps = chain.get("_http_responses") or []
            if isinstance(http_resps, list):
                for h in http_resps:
                    if isinstance(h, dict):
                        resp_body = h.get("response_body") or ""
                        if isinstance(resp_body, str) and resp_body.strip():
                            match = _match_flag(resp_body, sent_texts)
                            if match:
                                result.update({
                                    "verified": True,
                                    "artifact_type": "flag",
                                    "artifact": match,
                                    "step_id": step_id,
                                    "source_kind": "http_response_body",
                                    "method": h.get("method", ""),
                                    "url": h.get("url", ""),
                                    "status_code": h.get("status_code"),
                                    "evidence_sha256": _hash_evidence(resp_body[:2000]),
                                })
                                return result

        # Source C: step-level http_responses[*].response_body
        http_resps = r.get("http_responses") or []
        if isinstance(http_resps, list):
            for h in http_resps:
                if isinstance(h, dict):
                    resp_body = h.get("response_body") or ""
                    if isinstance(resp_body, str) and resp_body.strip():
                        match = _match_flag(resp_body, sent_texts)
                        if match:
                            result.update({
                                "verified": True,
                                "artifact_type": "flag",
                                "artifact": match,
                                "step_id": step_id,
                                "source_kind": "http_response_body",
                                "method": h.get("method", ""),
                                "url": h.get("url", ""),
                                "status_code": h.get("status_code"),
                                "evidence_sha256": _hash_evidence(resp_body[:2000]),
                            })
                            return result

    result["exclusion_reason"] = "no flag pattern matched in any response body"
    return result


def _match_flag(text: str, sent_texts: list[str]) -> str:
    """Return the first flag match in *text* that is NOT an echo of a sent payload.

    Anti-echo guard: if the candidate flag string appears verbatim in any sent
    payload text (body/query/params/command), reject it.
    """
    for pat in _FLAG_PATTERNS:
        for m in pat.finditer(text):
            candidate = m.group(0)
            # Anti-echo check
            if any(candidate in sent for sent in sent_texts):
                continue
            return candidate
    return ""


def _enrich_http_meta(
    result: dict[str, Any],
    chain: dict[str, Any],
    step: dict[str, Any],
) -> None:
    """Pull method/url/status_code from chain or step metadata."""
    # Try chain._http_responses first
    for h in (chain.get("_http_responses") or []):
        if isinstance(h, dict):
            result["method"] = h.get("method", "")
            result["url"] = h.get("url", "")
            result["status_code"] = h.get("status_code")
            return
    # Fallback: step-level http_responses
    for h in (step.get("http_responses") or []):
        if isinstance(h, dict):
            result["method"] = h.get("method", "")
            result["url"] = h.get("url", "")
            result["status_code"] = h.get("status_code")
            return
