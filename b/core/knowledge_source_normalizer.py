from __future__ import annotations

from typing import Any, Iterable


VERIFIED_FACT = "VERIFIED_FACT"
HARD_CONSTRAINT = "HARD_CONSTRAINT"
VERIFIED_STRATEGY = "VERIFIED_STRATEGY"
STRATEGY_OPTION = "STRATEGY_OPTION"
CANDIDATE_HINT = "CANDIDATE_HINT"
REFERENCE = "REFERENCE"

FACT_AUTHORITY = "FACT"
CONSTRAINT_AUTHORITY = "HARD CONSTRAINT"
STRATEGY_AUTHORITY = "STRATEGY"
REFERENCE_AUTHORITY = "REFERENCE"

_AUTHORITY_BY_TYPE = {
    VERIFIED_FACT: FACT_AUTHORITY,
    HARD_CONSTRAINT: CONSTRAINT_AUTHORITY,
    VERIFIED_STRATEGY: STRATEGY_AUTHORITY,
    STRATEGY_OPTION: STRATEGY_AUTHORITY,
    CANDIDATE_HINT: REFERENCE_AUTHORITY,
    REFERENCE: REFERENCE_AUTHORITY,
}


def normalize_knowledge_source(
    *,
    source: str,
    content: Any,
    metadata: dict[str, Any] | None = None,
    knowledge_type: str | None = None,
) -> dict[str, Any]:
    """Classify one upstream item before it reaches Context Authority."""
    normalized_metadata = dict(metadata or {})
    resolved_type = knowledge_type or _infer_knowledge_type(
        source,
        content,
        normalized_metadata,
    )
    if resolved_type not in _AUTHORITY_BY_TYPE:
        raise ValueError(f"unsupported knowledge_type: {resolved_type}")

    normalized_content = (
        _candidate_hint(content, normalized_metadata)
        if resolved_type == CANDIDATE_HINT
        else content
    )
    return {
        "source": str(source or "unknown"),
        "knowledge_type": resolved_type,
        "authority_level": _AUTHORITY_BY_TYPE[resolved_type],
        "content": normalized_content,
        "metadata": normalized_metadata,
    }


def group_knowledge_by_authority(
    sources: Iterable[dict[str, Any]],
) -> dict[str, tuple[Any, ...]]:
    """Return content grouped in the existing four-level authority model."""
    grouped: dict[str, list[Any]] = {
        FACT_AUTHORITY: [],
        CONSTRAINT_AUTHORITY: [],
        STRATEGY_AUTHORITY: [],
        REFERENCE_AUTHORITY: [],
    }
    for item in sources:
        authority = str(item.get("authority_level") or "")
        if authority not in grouped:
            raise ValueError(f"unsupported authority_level: {authority}")
        content = item.get("content")
        if content not in (None, "", {}, [], ()):
            grouped[authority].append(content)
    return {key: tuple(values) for key, values in grouped.items()}


def _infer_knowledge_type(
    source: str,
    content: Any,
    metadata: dict[str, Any],
) -> str:
    source_name = str(source or "").strip().lower()
    generation_status = str(
        metadata.get("generation_status")
        or _mapping_value(content, "generation_status")
        or ""
    ).strip().lower()
    generated_by = str(
        metadata.get("generated_by")
        or _mapping_value(content, "generated_by")
        or ""
    ).strip().lower()

    if generation_status == "candidate_only" or generated_by == "route_factory":
        return CANDIDATE_HINT
    if source_name in {"route_factory", "route_knowledge_provider"}:
        return CANDIDATE_HINT
    if source_name in {"evaluator", "verification_memory", "verified_state"}:
        return VERIFIED_FACT
    if source_name in {
        "primitive_transition_graph",
        "state_restriction",
        "transition_restriction",
    }:
        return HARD_CONSTRAINT
    if source_name in {"evaluator_strategy", "planner_strategy_option"}:
        return STRATEGY_OPTION
    if source_name == "consolidator" or generated_by == "consolidator":
        return (
            VERIFIED_STRATEGY
            if _is_validated_consolidator_source(metadata)
            else CANDIDATE_HINT
        )
    return REFERENCE


def _is_validated_consolidator_source(metadata: dict[str, Any]) -> bool:
    tags = {str(tag).strip().lower() for tag in metadata.get("tags", [])}
    if "consolidator_reviewed:false" in tags:
        return False
    if "consolidator_reviewed:true" in tags:
        return True
    if metadata.get("validated") is True or metadata.get("success_trajectory") is True:
        return True
    return str(
        metadata.get("validation_status")
        or metadata.get("trajectory_status")
        or metadata.get("historical_outcome")
        or ""
    ).strip().lower() in {"validated", "verified", "approved", "success"}


def _candidate_hint(content: Any, metadata: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(content, dict):
        return {"candidate": f"{str(content).strip()} exploration hint"}

    candidate = str(
        content.get("target_primitive")
        or content.get("primitive")
        or content.get("strategy_class")
        or content.get("technique")
        or content.get("candidate")
        or ""
    ).strip()
    hint: dict[str, Any] = {}
    if candidate:
        hint["candidate"] = f"{candidate} exploration hint"
    expected_signals = content.get("expected_signals")
    if isinstance(expected_signals, (list, tuple)) and expected_signals:
        hint["expected_signals"] = list(expected_signals)
    cwe = content.get("cwe") or content.get("cwe_id")
    if cwe:
        hint["cwe"] = cwe
    status = (
        content.get("route_status")
        or content.get("generation_status")
        or metadata.get("generation_status")
    )
    if status:
        hint["generation_status"] = status
    return hint or {"candidate": "unclassified exploration hint"}


def _mapping_value(content: Any, key: str) -> Any:
    if not isinstance(content, dict):
        return None
    if key in content:
        return content.get(key)
    metadata = content.get("metadata")
    if isinstance(metadata, dict):
        return metadata.get(key)
    return None
