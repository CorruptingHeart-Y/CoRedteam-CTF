from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


TRUSTED_SELECTION_FILENAME = "trusted_template_selection.json"


def compute_selection_hash(selection: dict[str, Any]) -> str:
    payload = {
        "run_id": selection.get("run_id", ""),
        "round": selection.get("round", 0),
        "status": selection.get("status", ""),
        "allowed_canonical_strategy_ids": sorted(selection.get("allowed_canonical_strategy_ids") or []),
        "rejected_canonical_strategy_ids": sorted(selection.get("rejected_canonical_strategy_ids") or []),
        "non_executable_templates": selection.get("non_executable_templates") or [],
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def build_trusted_selection(
    *,
    run_id: str,
    round_index: int,
    template_selection: dict[str, Any],
) -> dict[str, Any]:
    allowed_ids = sorted(set(template_selection.get("available_strategy_ids") or []))
    rejected_ids = sorted(set(template_selection.get("rejected_strategy_ids") or []))
    matched_ids = sorted(set(template_selection.get("matched_strategy_ids") or []))
    status = str(template_selection.get("status", "") or "")
    if status == "AVAILABLE_STRATEGY" and not allowed_ids:
        status = "ALL_MATCHED_STRATEGIES_REJECTED" if matched_ids or rejected_ids else "NO_MATCHED_TEMPLATE"

    trusted = {
        "run_id": run_id,
        "round": round_index,
        "status": status,
        "allowed_canonical_strategy_ids": allowed_ids,
        "rejected_canonical_strategy_ids": rejected_ids,
        "strategy_health": template_selection.get("strategy_health") or {},
        "strategy_descriptors": template_selection.get("strategy_descriptors") or {},
        "template_health": template_selection.get("template_health") or {},
        "migration_report": template_selection.get("migration_report") or [],
        "non_executable_templates": template_selection.get("non_executable_templates") or [],
    }
    trusted["selection_hash"] = compute_selection_hash(trusted)
    return trusted


def write_trusted_selection(path: Path, trusted: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(trusted, ensure_ascii=False, indent=2), encoding="utf-8")


def read_trusted_selection(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_plan_against_trusted_selection(
    plan: dict[str, Any],
    trusted: dict[str, Any],
) -> tuple[bool, list[str]]:
    errors: list[str] = []
    expected_hash = compute_selection_hash(trusted)
    if trusted.get("selection_hash") != expected_hash:
        errors.append("TRUSTED_SELECTION_TAMPERED: selection_hash does not match trusted content")

    status = trusted.get("status")
    if status == "NO_MATCHED_TEMPLATE":
        errors.append("NO_MATCHED_TEMPLATE: automatic generic bootstrap execution is disabled")
    elif status == "ALL_MATCHED_STRATEGIES_REJECTED":
        errors.append("NO_AVAILABLE_STRATEGY_FOR_SURFACE: all matched strategies are rejected")

    if plan.get("trusted_run_id") != trusted.get("run_id"):
        errors.append("TRUSTED_SELECTION_MISMATCH: run_id mismatch")
    if plan.get("trusted_round") != trusted.get("round"):
        errors.append("TRUSTED_SELECTION_MISMATCH: round mismatch")
    if plan.get("trusted_selection_hash") != trusted.get("selection_hash"):
        errors.append("TRUSTED_SELECTION_MISMATCH: selection_hash mismatch")

    selected = str(plan.get("selected_canonical_strategy_id") or "").strip()
    if not selected:
        errors.append("STRATEGY_ID_MISSING: selected_canonical_strategy_id is required")
    else:
        allowed = set(trusted.get("allowed_canonical_strategy_ids") or [])
        if selected not in allowed:
            errors.append(
                f"STRATEGY_ID_NOT_ALLOWED: selected_canonical_strategy_id={selected} "
                "is not in trusted allowed_canonical_strategy_ids"
            )

    return len(errors) == 0, errors
