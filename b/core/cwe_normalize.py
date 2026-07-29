"""Shared CWE Field Normalizer.

Pure function for normalizing the ``cwe`` / ``cwe_id`` field in vulnerability
dictionaries.  All consumers that read a CWE identifier from a vulnerability
record MUST use this function — never access ``"cwe"`` or ``"cwe_id"`` directly.

Rules (fail-closed):
    1. Both ``cwe_id`` and ``cwe`` present and equal → ok, return the value.
    2. Only ``cwe_id`` present → ok, return ``cwe_id``.
    3. Only ``cwe`` present → ok, return ``cwe`` (treat as canonical).
    4. Both present but differ → **fail closed** (ambiguous source).
    5. Neither present → **fail closed** (missing required field).

This module is side-effect free.  It does NOT import any LLM client, networking
component, or file-system consumer.  It belongs to the Stage 1 contract output
boundary and the shared contract parser layer.
"""

from __future__ import annotations

from typing import Any


class CweNormalizeError(ValueError):
    """Raised when CWE field normalization fails (ambiguous or missing)."""


def normalize_cwe_field(vuln: dict[str, Any]) -> str:
    """Normalize the CWE field from *vuln* and return the canonical value.

    Returns the CWE string (e.g. ``"CWE-94"``).  Raises :exc:`CweNormalizeError`
    on ambiguity or missing data.

    This function does NOT modify *vuln* — callers that need to persist the
    normalized value should store the return value under ``cwe_id``.
    """
    has_cwe_id = "cwe_id" in vuln
    has_cwe = "cwe" in vuln

    raw_cwe_id = vuln.get("cwe_id")
    raw_cwe = vuln.get("cwe")

    # ---- neither present → fail closed ----
    if not has_cwe_id and not has_cwe:
        raise CweNormalizeError(
            "CWE_NORMALIZE_MISSING: vulnerability record has neither "
            "'cwe_id' nor 'cwe' field"
        )

    # ---- only cwe_id present ----
    if has_cwe_id and not has_cwe:
        if not isinstance(raw_cwe_id, str) or not raw_cwe_id.strip():
            raise CweNormalizeError(
                f"CWE_NORMALIZE_EMPTY: 'cwe_id' is present but empty: {raw_cwe_id!r}"
            )
        return raw_cwe_id.strip()

    # ---- only cwe present ----
    if has_cwe and not has_cwe_id:
        if not isinstance(raw_cwe, str) or not raw_cwe.strip():
            raise CweNormalizeError(
                f"CWE_NORMALIZE_EMPTY: 'cwe' is present but empty: {raw_cwe!r}"
            )
        return raw_cwe.strip()

    # ---- both present ----
    cwe_id_val = raw_cwe_id.strip() if isinstance(raw_cwe_id, str) else str(raw_cwe_id)
    cwe_val = raw_cwe.strip() if isinstance(raw_cwe, str) else str(raw_cwe)

    # Both empty → fail closed
    if not cwe_id_val and not cwe_val:
        raise CweNormalizeError(
            "CWE_NORMALIZE_BOTH_EMPTY: both 'cwe_id' and 'cwe' are empty"
        )

    # One empty, use the other
    if not cwe_id_val:
        return cwe_val
    if not cwe_val:
        return cwe_id_val

    # Compare case-insensitively (CWE identifiers are case-insensitive)
    if cwe_id_val.upper() == cwe_val.upper():
        return cwe_id_val

    # Both non-empty and differ → fail closed
    raise CweNormalizeError(
        f"CWE_NORMALIZE_CONFLICT: 'cwe_id'={cwe_id_val!r} != 'cwe'={cwe_val!r}. "
        f"Cannot determine canonical CWE."
    )


def apply_cwe_normalization(vulns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize CWE fields across a list of vulnerability dicts.

    For each entry, resolves ``cwe``/``cwe_id`` into a single ``cwe_id`` field.
    Returns a new list (does not mutate the input).  Raises
    :exc:`CweNormalizeError` on the first entry that fails.
    """
    result: list[dict[str, Any]] = []
    for i, v in enumerate(vulns):
        canonical = normalize_cwe_field(v)
        entry = {**v, "cwe_id": canonical}
        result.append(entry)
    return result
