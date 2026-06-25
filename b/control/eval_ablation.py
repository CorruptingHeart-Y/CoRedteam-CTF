"""
Evaluator Prompt Ablation Study — minimally invasive experiment framework.

Usage:
    Set env var CO_REDTEAM_ABLATION to one of:
      EXP_A  — strip confirmed_vuln from Evaluator prompt
      EXP_B  — strip plan from Evaluator prompt
      EXP_C  — replace REJECTED_HYPOTHESES with permanently-banned text
      (unset) — normal operation, no-op

Output:
    Each experiment run writes a record to:
      b/workspace/ablation_{mode}_{timestamp}.json
"""

from __future__ import annotations

import copy
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Experiment mode ──────────────────────────────────────────────────
_ABLATION_MODE = os.getenv("CO_REDTEAM_ABLATION", "").strip().upper()
_VALID_MODES = {"EXP_BASE", "EXP_A", "EXP_B", "EXP_C"}
_MODE = _ABLATION_MODE if _ABLATION_MODE in _VALID_MODES else ""

# ── Output directory ─────────────────────────────────────────────────
_OUTPUT_DIR = Path(__file__).resolve().parents[1] / "workspace"

# ═══════════════════════════════════════════════════════════════════════
# STRONG REJECTION TEXT (EXP_C)
# ═══════════════════════════════════════════════════════════════════════
_STRONG_REJECTION = """
【🚫 PERMANENTLY BANNED ATTACK PATHS — 系统级禁令】

The following attack paths are permanently banned.
Do NOT recommend, mutate, improve, retry, or suggest variants of them.
These paths have been decisively proven to NOT exist on the current target.

If all candidate exploit paths known to you are in the banned list,
output the exact string PATH_BANNED in your guidance, hypothesis,
next_required_action, and feedback_for_planner fields.

Banned paths:
{banned_items}

【HARD CONSTRAINT — 违反此规则的输出将被废弃】
"""


def _build_strong_rejection() -> str:
    """Build the EXP_C strong rejection text using current tracker data."""
    from control.hypothesis_tracker import get_hypothesis_tracker

    tracker = get_hypothesis_tracker()
    rejected = tracker.get_rejected()
    if not rejected:
        return ""

    items = []
    for fp, h in rejected.items():
        items.append(
            f"  🚫 {fp} — {h.attempts} attempts, {h.successes} successes, "
            f"{h.dominant_failure_count} failures at stage [{h.dominant_failure_stage}]"
        )
    return _STRONG_REJECTION.format(banned_items="\n".join(items))


# ═══════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════

def get_mode() -> str:
    """Return current ablation mode, or '' for normal operation."""
    return _MODE


def apply_ablation(
    mode: str,
    confirmed: dict[str, Any],
    plan: dict[str, Any],
    pre_detection_note: str,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Apply ablation transform to Evaluator inputs.

    Returns (confirmed_out, plan_out, pre_detection_note_out) — copies
    of the originals, mutated per experiment mode.
    """
    if not mode:
        return confirmed, plan, pre_detection_note

    _confirmed = copy.deepcopy(confirmed)
    _plan = copy.deepcopy(plan) if plan else {}
    _note = pre_detection_note

    if mode == "EXP_BASE":
        print("[ablation] EXP_BASE: recording baseline — no input mutation")
    elif mode == "EXP_A":
        _confirmed = {"_ablation": "EXP_A — confirmed_vuln removed"}  # type: ignore[assignment]
        print("[ablation] EXP_A: confirmed_vuln stripped from Evaluator prompt")

    elif mode == "EXP_B":
        _plan = {"_ablation": "EXP_B — plan removed"}  # type: ignore[assignment]
        print("[ablation] EXP_B: plan stripped from Evaluator prompt")

    elif mode == "EXP_C":
        strong = _build_strong_rejection()
        if strong:
            _note = strong
            print("[ablation] EXP_C: REJECTED_HYPOTHESES replaced with STRONG ban text")
            print(f"[ablation] EXP_C ban text length: {len(strong)} chars")
        else:
            print("[ablation] EXP_C: no rejected hypotheses to ban (tracker empty)")

    return _confirmed, _plan, _note


def record_ablation(
    mode: str,
    system_prompt: str,
    user_msg: str,
    llm_output: dict[str, Any] | None,
    metadata: dict[str, Any] | None = None,
) -> Path | None:
    """Record full experiment data to disk. Returns path or None.

    Saves: mode, timestamp, full system prompt, full user message,
    full LLM output, extraction of the 4 key fields, optional metadata.
    """
    if not mode:
        return None

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    _OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = _OUTPUT_DIR / f"ablation_{mode.lower()}_{ts}.json"

    key_fields: dict[str, Any] = {}
    if llm_output:
        for field in ("guidance", "hypothesis", "next_required_action", "feedback_for_planner"):
            if field == "guidance":
                key_fields[field] = (llm_output.get("analysis") or {}).get("guidance", "")
            else:
                key_fields[field] = llm_output.get(field, "")

    record: dict[str, Any] = {
        "experiment": {
            "mode": mode,
            "timestamp_utc": ts,
            "description": {
                "EXP_BASE": "baseline — no input mutation, record only",
                "EXP_A": "confirmed_vuln removed from Evaluator prompt",
                "EXP_B": "plan removed from Evaluator prompt",
                "EXP_C": "REJECTED_HYPOTHESES replaced with PERMANENTLY BANNED text",
            }.get(mode, ""),
        },
        "input": {
            "system_prompt": system_prompt,
            "system_prompt_len_chars": len(system_prompt),
            "user_message": user_msg,
            "user_message_len_chars": len(user_msg),
        },
        "output": {
            "full": llm_output,
            "key_fields": key_fields,
        },
        "metadata": metadata or {},
    }

    out_path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[ablation] 📝 experiment record saved: {out_path}")
    return out_path


def summarize() -> str:
    """Return a human-readable summary of current experiment configuration."""
    if not _MODE:
        return "ablation: OFF (normal Evaluator operation)"
    return (
        f"ablation: {_MODE} ACTIVE — "
        + {
            "EXP_BASE": "baseline — record only, no mutation",
            "EXP_A": "confirmed_vuln stripped",
            "EXP_B": "plan stripped",
            "EXP_C": "REJECTED_HYPOTHESES → STRONG ban text",
        }.get(_MODE, "unknown")
    )
