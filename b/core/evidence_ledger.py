"""Evidence Ledger — per-run confirmed capability signals.

Only deterministic code (Distiller, Coordinator) writes signals.
Never LLM inference. Reset on each new pipeline run (new run_id).

Consumed by TemplateManager.select_templates_for_target() to gate
strategy eligibility via requires_signals.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

LEDGER_FILENAME = "evidence_ledger.json"


def load_confirmed_signals(workspace: Path) -> set[str]:
    """Return the set of signal_id values confirmed in the current run."""
    path = workspace / LEDGER_FILENAME
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return set()
    return {s["signal_id"] for s in data.get("signals", [])}


def write_signals(workspace: Path, new_signals: list[dict]) -> None:
    """Append one or more signals to the current run's ledger."""
    if not new_signals:
        return
    path = workspace / LEDGER_FILENAME
    data: dict = {"run_id": "", "signals": []}
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    for sig in new_signals:
        sig.setdefault("observed_at", datetime.now(timezone.utc).isoformat())
        data["signals"].append(sig)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def reset_ledger(workspace: Path, run_id: str = "") -> None:
    """Reset the ledger for a new pipeline run."""
    path = workspace / LEDGER_FILENAME
    data = {"run_id": run_id, "signals": []}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[evidence_ledger] reset for run={run_id}")


def has_signal(workspace: Path, signal_id: str) -> bool:
    return signal_id in load_confirmed_signals(workspace)


def evidence_exists(workspace: Path, evidence_key: str) -> bool:
    """Check if an exact evidence_key has already been written to the ledger."""
    path = workspace / LEDGER_FILENAME
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False
    existing_keys = {
        s.get("evidence_key", "")
        for s in data.get("signals", [])
    }
    return evidence_key in existing_keys


def has_signal_on_surface(
    workspace: Path,
    run_id: str,
    surface_key: str,
    signal_id: str,
) -> bool:
    """Check if a signal has been confirmed on this surface in this run.

    Used to determine is_new_state_transition — True only when the signal
    has never been seen on this surface before.
    """
    path = workspace / LEDGER_FILENAME
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False
    for s in data.get("signals", []):
        if (
            s.get("signal_id") == signal_id
            and s.get("run_id") == run_id
            and s.get("surface_key") == surface_key
        ):
            return True
    return False


def write_signals_deduped(
    workspace: Path,
    new_signals: list[dict],
) -> tuple[int, int]:
    """Write signals with evidence_key dedup.

    Returns (written_count, skipped_duplicate_count).
    Each signal dict must include: signal_id, run_id, evidence_key, surface_key.
    """
    if not new_signals:
        return 0, 0

    path = workspace / LEDGER_FILENAME
    data: dict = {"run_id": "", "signals": []}
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass

    existing_keys = {
        s.get("evidence_key", "")
        for s in data.get("signals", [])
    }

    written = 0
    skipped = 0
    for sig in new_signals:
        ek = sig.get("evidence_key", "")
        if ek and ek in existing_keys:
            skipped += 1
            continue
        sig.setdefault("observed_at", datetime.now(timezone.utc).isoformat())
        data["signals"].append(sig)
        if ek:
            existing_keys.add(ek)
        written += 1

    if written:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    return written, skipped
