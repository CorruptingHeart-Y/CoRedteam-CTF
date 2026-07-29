from __future__ import annotations

import re

from routes.primitive_adapter import PrimitiveAdapter
from routes.schema import (
    Activation,
    FailurePolicy,
    MaterializationDeclaration,
    NormalizationError,
    NormalizationErrorCode,
    NormalizationResult,
    NormalizedRoute,
    ReplayPolicy,
    RouteProposal,
    RouteRequirements,
    SuccessCriteria,
)


SCHEMA_VERSION = "1.1.0"
SSTI_CWE_ALIASES = {
    "CWE-94": "CWE-94",
    "CWE-917": "CWE-94",
    "CWE-1336": "CWE-94",
}
SUPPORTED_TECHNIQUES = (
    "arithmetic_probe",
    "syntax_probe",
    "reflection_probe",
)


def _normalize_technique(value: str) -> str:
    return re.sub(r"[\s-]+", "_", value.strip().lower())


def _unique_nonempty(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value.strip() for value in values if value.strip()))


def _safe_id_part(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _canonical_id(
    cwe_id: str,
    current_state: str,
    target_primitive: str,
    technique: str,
) -> str:
    return ":".join(
        _safe_id_part(value)
        for value in (cwe_id, current_state, target_primitive, technique)
    )


def normalize_route_proposal(
    proposal: RouteProposal,
    adapter: PrimitiveAdapter,
) -> NormalizationResult:
    errors: list[NormalizationError] = []

    source_cwe = proposal.cwe_id.strip().upper()
    canonical_cwe = SSTI_CWE_ALIASES.get(source_cwe)
    if canonical_cwe is None:
        errors.append(
            NormalizationError(NormalizationErrorCode.UNKNOWN_CWE, "cwe_id", proposal.cwe_id)
        )

    current_state = proposal.current_state.strip()
    if not adapter.state_exists(current_state):
        errors.append(
            NormalizationError(
                NormalizationErrorCode.UNKNOWN_STATE,
                "current_state",
                proposal.current_state,
            )
        )

    target_primitive = proposal.target_primitive.strip()
    primitive_exists = adapter.primitive_exists(target_primitive)
    if not primitive_exists:
        errors.append(
            NormalizationError(
                NormalizationErrorCode.UNKNOWN_PRIMITIVE,
                "target_primitive",
                proposal.target_primitive,
            )
        )
    elif canonical_cwe is not None and target_primitive not in adapter.get_entry_primitives(canonical_cwe):
        errors.append(
            NormalizationError(
                NormalizationErrorCode.UNSUPPORTED_PRIMITIVE,
                "target_primitive",
                target_primitive,
            )
        )

    technique = _normalize_technique(proposal.technique)
    if technique not in SUPPORTED_TECHNIQUES:
        errors.append(
            NormalizationError(
                NormalizationErrorCode.UNSUPPORTED_TECHNIQUE,
                "technique",
                proposal.technique,
            )
        )

    runtime_facts = _unique_nonempty(proposal.required_runtime_facts)
    if not runtime_facts:
        errors.append(
            NormalizationError(
                NormalizationErrorCode.MISSING_RUNTIME_FACTS,
                "required_runtime_facts",
            )
        )

    required_signals = _unique_nonempty(proposal.required_signals)
    # required_signals may legitimately be empty for first-stage probes;
    # that is not an error.  They express pre-execution preconditions,
    # *not* the signals the route expects to observe afterwards.

    expected_signals = _unique_nonempty(proposal.expected_signals)
    if not expected_signals:
        errors.append(
            NormalizationError(
                NormalizationErrorCode.MISSING_EXPECTED_SIGNAL,
                "expected_signals",
            )
        )
    elif primitive_exists:
        supported_signals = set(adapter.get_observable_signals(target_primitive))
        mismatched_signals = tuple(
            signal for signal in expected_signals if signal not in supported_signals
        )
        if mismatched_signals:
            errors.append(
                NormalizationError(
                    NormalizationErrorCode.PRIMITIVE_SIGNAL_MISMATCH,
                    "expected_signals",
                    mismatched_signals,
                )
            )

    payload_template_ref = proposal.payload_template_ref.strip()
    if primitive_exists:
        payload_template_index = adapter.resolve_payload_template_ref(
            target_primitive,
            payload_template_ref,
        )
        if payload_template_index is None:
            errors.append(
                NormalizationError(
                    NormalizationErrorCode.UNKNOWN_PAYLOAD_TEMPLATE,
                    "payload_template_ref",
                    proposal.payload_template_ref,
                )
            )
        else:
            payload_template_ref = adapter.get_payload_template_refs(target_primitive)[
                payload_template_index
            ]

    if errors:
        return NormalizationResult(errors=tuple(errors))

    assert canonical_cwe is not None
    metadata = dict(proposal.metadata)
    metadata.update(
        {
            "generated_by": "route_factory",
            "source_cwe": source_cwe,
            "canonical_cwe": canonical_cwe,
        }
    )
    route = NormalizedRoute(
        schema_version=SCHEMA_VERSION,
        canonical_id=_canonical_id(
            canonical_cwe,
            current_state,
            target_primitive,
            technique,
        ),
        cwe_id=canonical_cwe,
        current_state=current_state,
        technique=technique,
        metadata=metadata,
        activation=Activation(),
        requires=RouteRequirements(
            current_state=current_state,
            runtime_facts=runtime_facts,
            signals=required_signals,
        ),
        target_primitive=target_primitive,
        payload_template_ref=payload_template_ref,
        expected_signals=expected_signals,
        materialization=MaterializationDeclaration(
            type="http_request",
            method_from="runtime_truths",
            endpoint_from="runtime_truths",
            parameter_from="runtime_truths",
            payload_template_ref=payload_template_ref,
        ),
        success=SuccessCriteria(match="any", expected_signals=expected_signals),
        failure=FailurePolicy(),
        replay=ReplayPolicy(),
        generation_status="candidate_only",
    )
    return NormalizationResult(route=route)
