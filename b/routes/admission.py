from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path

import yaml
from yaml.composer import ComposerError
from yaml.tokens import AliasToken

from routes.normalizer import (
    SCHEMA_VERSION,
    SSTI_CWE_ALIASES,
    SUPPORTED_TECHNIQUES,
    _canonical_id,
)
from routes.primitive_adapter import PrimitiveAdapter
from routes.schema import (
    Activation,
    AdmissionDecision,
    AdmissionDiagnostic,
    AdmissionErrorCode,
    FailurePolicy,
    MaterializationDeclaration,
    NormalizedRoute,
    ReplayPolicy,
    RouteParseResult,
    RouteRequirements,
    SuccessCriteria,
)


ADMITTED_CANDIDATE = "admitted_candidate"
REJECTED = "rejected"
MAX_YAML_FILE_SIZE = 256 * 1024
MAX_YAML_ALIASES = 32
MAX_YAML_DEPTH = 32
MAX_YAML_NODES = 10_000

# Temporary Route Factory v1 static contract. This is intentionally local to
# admission and is not a new global RuntimeTruths fact source.
ROUTE_FACTORY_V1_RUNTIME_FACTS = frozenset(("endpoint", "parameter", "method"))

_TOP_LEVEL_FIELDS = (
    "schema_version",
    "canonical_id",
    "cwe_id",
    "current_state",
    "technique",
    "metadata",
    "activation",
    "requires",
    "target_primitive",
    "payload_template_ref",
    "expected_signals",
    "materialization",
    "success",
    "failure",
    "replay",
    "generation_status",
)
_SUCCESS_STATE_MUTATION_FIELDS = frozenset(
    ("next_state", "set_state", "state_transition", "advance_state", "unlock_state")
)
_LEGACY_PAYLOAD_REF = re.compile(r"^primitive:([^:]+):([0-9]+)$")
_STABLE_PAYLOAD_REF = re.compile(
    r"^primitive:([^:]+):sha256:([0-9a-f]{16})$"
)


def _diagnostic(
    code: AdmissionErrorCode,
    field: str | None,
    message: str,
) -> AdmissionDiagnostic:
    return AdmissionDiagnostic(code=code, field=field, message=message)


def _parse_error(
    code: AdmissionErrorCode,
    field: str | None,
    message: str,
) -> RouteParseResult:
    return RouteParseResult(diagnostics=(_diagnostic(code, field, message),))


def _is_plain_tree(value: object, ancestors: set[int] | None = None) -> bool:
    if value is None or type(value) in (str, int, float, bool):
        return True
    if ancestors is None:
        ancestors = set()
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in ancestors or not all(isinstance(key, str) for key in value):
            return False
        ancestors.add(identity)
        valid = all(_is_plain_tree(item, ancestors) for item in value.values())
        ancestors.remove(identity)
        return valid
    if isinstance(value, list):
        identity = id(value)
        if identity in ancestors:
            return False
        ancestors.add(identity)
        valid = all(_is_plain_tree(item, ancestors) for item in value)
        ancestors.remove(identity)
        return valid
    return False


def _mapping_with_keys(
    data: Mapping[str, object],
    field: str,
    required: frozenset[str],
    error_code: AdmissionErrorCode = AdmissionErrorCode.SCHEMA_INVALID,
) -> tuple[Mapping[str, object] | None, RouteParseResult | None]:
    value = data.get(field)
    if not isinstance(value, Mapping):
        return None, _parse_error(error_code, field, f"{field} must be a mapping")
    keys = set(value)
    if keys != required or not all(isinstance(key, str) for key in value):
        return None, _parse_error(
            error_code,
            field,
            f"{field} fields do not match the supported schema",
        )
    return value, None


def _string_list(
    value: object,
    field: str,
) -> tuple[tuple[str, ...] | None, RouteParseResult | None]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return None, _parse_error(
            AdmissionErrorCode.SCHEMA_INVALID,
            field,
            f"{field} must be a list of strings",
        )
    return tuple(value), None


def normalized_route_from_plain(
    data: Mapping[str, object],
) -> RouteParseResult:
    if not isinstance(data, Mapping):
        return _parse_error(
            AdmissionErrorCode.YAML_TOP_LEVEL_NOT_MAPPING,
            None,
            "candidate route must be a top-level mapping",
        )

    keys = set(data)
    if keys != set(_TOP_LEVEL_FIELDS) or not all(isinstance(key, str) for key in data):
        return _parse_error(
            AdmissionErrorCode.SCHEMA_INVALID,
            None,
            "top-level fields do not match the normalized route schema",
        )

    string_fields = (
        "schema_version",
        "canonical_id",
        "cwe_id",
        "current_state",
        "technique",
        "target_primitive",
        "payload_template_ref",
        "generation_status",
    )
    for field in string_fields:
        if not isinstance(data[field], str):
            return _parse_error(
                AdmissionErrorCode.SCHEMA_INVALID,
                field,
                f"{field} must be a string",
            )

    metadata = data["metadata"]
    if not isinstance(metadata, Mapping) or not _is_plain_tree(metadata):
        return _parse_error(
            AdmissionErrorCode.SCHEMA_INVALID,
            "metadata",
            "metadata must contain only plain string-keyed values",
        )

    activation, error = _mapping_with_keys(
        data,
        "activation",
        frozenset(("state", "source")),
    )
    if error is not None:
        return error
    assert activation is not None
    if not isinstance(activation["state"], str) or not isinstance(
        activation["source"], str
    ):
        return _parse_error(
            AdmissionErrorCode.SCHEMA_INVALID,
            "activation",
            "activation fields must be strings",
        )

    requires, error = _mapping_with_keys(
        data,
        "requires",
        frozenset(("current_state", "runtime_facts", "signals")),
    )
    if error is not None:
        return error
    assert requires is not None
    if not isinstance(requires["current_state"], str):
        return _parse_error(
            AdmissionErrorCode.SCHEMA_INVALID,
            "requires.current_state",
            "requires.current_state must be a string",
        )
    runtime_facts, error = _string_list(
        requires["runtime_facts"],
        "requires.runtime_facts",
    )
    if error is not None:
        return error
    assert runtime_facts is not None

    requires_signals, error = _string_list(
        requires["signals"],
        "requires.signals",
    )
    if error is not None:
        return error
    assert requires_signals is not None

    expected_signals, error = _string_list(
        data["expected_signals"],
        "expected_signals",
    )
    if error is not None:
        return error
    assert expected_signals is not None

    materialization, error = _mapping_with_keys(
        data,
        "materialization",
        frozenset(
            (
                "type",
                "method_from",
                "endpoint_from",
                "parameter_from",
                "payload_template_ref",
            )
        ),
        AdmissionErrorCode.MATERIALIZATION_INCOMPLETE,
    )
    if error is not None:
        return error
    assert materialization is not None
    if not all(isinstance(value, str) for value in materialization.values()):
        return _parse_error(
            AdmissionErrorCode.MATERIALIZATION_INCOMPLETE,
            "materialization",
            "materialization fields must be strings",
        )

    success_value = data["success"]
    if not isinstance(success_value, Mapping):
        return _parse_error(
            AdmissionErrorCode.SCHEMA_INVALID,
            "success",
            "success must be a mapping",
        )
    if set(success_value) & _SUCCESS_STATE_MUTATION_FIELDS:
        return _parse_error(
            AdmissionErrorCode.ROUTE_ATTEMPTS_STATE_MUTATION,
            "success",
            "route success declaration may not mutate global state",
        )
    if set(success_value) != {"match", "expected_signals"}:
        return _parse_error(
            AdmissionErrorCode.SCHEMA_INVALID,
            "success",
            "success fields do not match the supported schema",
        )
    if not isinstance(success_value["match"], str):
        return _parse_error(
            AdmissionErrorCode.SCHEMA_INVALID,
            "success.match",
            "success.match must be a string",
        )
    success_signals, error = _string_list(
        success_value["expected_signals"],
        "success.expected_signals",
    )
    if error is not None:
        return error
    assert success_signals is not None

    failure, error = _mapping_with_keys(
        data,
        "failure",
        frozenset(("state_change",)),
        AdmissionErrorCode.INVALID_FAILURE_STATE_CHANGE,
    )
    if error is not None:
        return error
    assert failure is not None
    if not isinstance(failure["state_change"], str):
        return _parse_error(
            AdmissionErrorCode.INVALID_FAILURE_STATE_CHANGE,
            "failure.state_change",
            "failure.state_change must be a string",
        )

    replay, error = _mapping_with_keys(
        data,
        "replay",
        frozenset(("enabled",)),
        AdmissionErrorCode.UNSUPPORTED_REPLAY_POLICY,
    )
    if error is not None:
        return error
    assert replay is not None
    if type(replay["enabled"]) is not bool:
        return _parse_error(
            AdmissionErrorCode.UNSUPPORTED_REPLAY_POLICY,
            "replay.enabled",
            "replay.enabled must be a boolean",
        )

    try:
        route = NormalizedRoute(
            schema_version=data["schema_version"],
            canonical_id=data["canonical_id"],
            cwe_id=data["cwe_id"],
            current_state=data["current_state"],
            technique=data["technique"],
            metadata=dict(metadata),
            activation=Activation(
                state=activation["state"],
                source=activation["source"],
            ),
            requires=RouteRequirements(
                current_state=requires["current_state"],
                runtime_facts=runtime_facts,
                signals=requires_signals,
            ),
            target_primitive=data["target_primitive"],
            payload_template_ref=data["payload_template_ref"],
            expected_signals=expected_signals,
            materialization=MaterializationDeclaration(
                type=materialization["type"],
                method_from=materialization["method_from"],
                endpoint_from=materialization["endpoint_from"],
                parameter_from=materialization["parameter_from"],
                payload_template_ref=materialization["payload_template_ref"],
            ),
            success=SuccessCriteria(
                match=success_value["match"],
                expected_signals=success_signals,
            ),
            failure=FailurePolicy(state_change=failure["state_change"]),
            replay=ReplayPolicy(enabled=replay["enabled"]),
            generation_status=data["generation_status"],
        )
    except (TypeError, ValueError) as exc:
        return _parse_error(
            AdmissionErrorCode.SCHEMA_INVALID,
            None,
            f"normalized route construction failed: {exc}",
        )
    return RouteParseResult(route=route)


def _rejected_decision(
    diagnostics: tuple[AdmissionDiagnostic, ...],
    checked_invariants: tuple[str, ...],
    canonical_id: str | None = None,
) -> AdmissionDecision:
    return AdmissionDecision(
        accepted=False,
        status=REJECTED,
        canonical_id=canonical_id,
        diagnostics=diagnostics,
        checked_invariants=checked_invariants,
        route=None,
    )


def _admit_parsed_route(
    route: NormalizedRoute,
    adapter: PrimitiveAdapter,
) -> AdmissionDecision:
    diagnostics: list[AdmissionDiagnostic] = []
    checked: list[str] = []

    checked.append("schema")
    if route.schema_version != SCHEMA_VERSION:
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.SCHEMA_INVALID,
                "schema_version",
                "schema_version is not supported",
            )
        )

    checked.append("candidate_state")
    if (
        route.activation.state != "draft"
        or route.activation.source != "route_factory"
        or route.generation_status != "candidate_only"
    ):
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.INVALID_CANDIDATE_STATE,
                "activation",
                "route must remain a route_factory draft candidate",
            )
        )

    checked.append("cwe")
    source_cwe = route.cwe_id.strip().upper()
    canonical_cwe = SSTI_CWE_ALIASES.get(source_cwe)
    if canonical_cwe is None:
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.UNKNOWN_CWE,
                "cwe_id",
                "route CWE is not supported",
            )
        )
    elif route.cwe_id != canonical_cwe:
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.NON_CANONICAL_CWE,
                "cwe_id",
                "candidate YAML must store the canonical CWE",
            )
        )

    checked.append("canonical_id")
    if canonical_cwe is not None:
        expected_canonical_id = _canonical_id(
            canonical_cwe,
            route.current_state,
            route.target_primitive,
            route.technique,
        )
        if route.canonical_id != expected_canonical_id:
            diagnostics.append(
                _diagnostic(
                    AdmissionErrorCode.CANONICAL_ID_MISMATCH,
                    "canonical_id",
                    "canonical_id does not match the route fields",
                )
            )

    checked.append("technique")
    if route.technique not in SUPPORTED_TECHNIQUES:
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.UNSUPPORTED_TECHNIQUE,
                "technique",
                "route technique is not supported",
            )
        )

    checked.append("state")
    if not adapter.state_exists(route.current_state):
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.UNKNOWN_STATE,
                "current_state",
                "route current_state is not known",
            )
        )

    checked.append("primitive")
    primitive_exists = adapter.primitive_exists(route.target_primitive)
    if not primitive_exists:
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.UNKNOWN_PRIMITIVE,
                "target_primitive",
                "target primitive is not registered",
            )
        )
    elif canonical_cwe is not None and route.target_primitive not in adapter.get_entry_primitives(
        canonical_cwe
    ):
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.UNSUPPORTED_PRIMITIVE,
                "target_primitive",
                "target primitive is not an entry primitive for this CWE",
            )
        )

    checked.append("payload_template_ref")
    legacy_match = _LEGACY_PAYLOAD_REF.fullmatch(route.payload_template_ref)
    stable_match = _STABLE_PAYLOAD_REF.fullmatch(route.payload_template_ref)
    if legacy_match is not None:
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.LEGACY_PAYLOAD_REF_NOT_ADMITTED,
                "payload_template_ref",
                "legacy payload index references are not admitted",
            )
        )
    elif stable_match is None:
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.MALFORMED_PAYLOAD_REF,
                "payload_template_ref",
                "payload template reference must use the stable sha256 form",
            )
        )
    elif stable_match.group(1) != route.target_primitive:
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.PAYLOAD_PRIMITIVE_MISMATCH,
                "payload_template_ref",
                "payload reference primitive does not match target_primitive",
            )
        )
    elif adapter.resolve_payload_template_ref(
        route.target_primitive,
        route.payload_template_ref,
    ) is None:
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.UNKNOWN_PAYLOAD_TEMPLATE,
                "payload_template_ref",
                "stable payload template reference is not registered",
            )
        )

    checked.append("expected_signals")
    signals = route.expected_signals
    missing_signals = not signals or any(not signal.strip() for signal in signals)
    duplicate_signals = len(signals) != len(set(signals))
    if missing_signals:
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.MISSING_EXPECTED_SIGNAL,
                "expected_signals",
                "expected_signals must contain non-empty signal names",
            )
        )
    if duplicate_signals:
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.DUPLICATE_EXPECTED_SIGNAL,
                "expected_signals",
                "expected_signals may not contain duplicates",
            )
        )

    mismatched_signals: tuple[str, ...] = ()
    if primitive_exists:
        supported_signals = set(adapter.get_observable_signals(route.target_primitive))
        mismatched_signals = tuple(
            signal for signal in signals if signal not in supported_signals
        )
        if mismatched_signals:
            diagnostics.append(
                _diagnostic(
                    AdmissionErrorCode.PRIMITIVE_SIGNAL_MISMATCH,
                    "expected_signals",
                    "one or more expected signals are not observable for the primitive",
                )
            )
    if route.success.expected_signals != signals:
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.SUCCESS_SIGNAL_MISMATCH,
                "success.expected_signals",
                "success signals must exactly match top-level expected_signals",
            )
        )
    if route.success.match != "any":
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.UNSUPPORTED_SUCCESS_MATCH,
                "success.match",
                "only success.match=any is supported",
            )
        )

    checked.append("observability")
    if missing_signals or mismatched_signals or not primitive_exists:
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.NON_OBSERVABLE_ROUTE,
                "expected_signals",
                "route does not have a fully supported observable result",
            )
        )

    checked.append("materialization")
    if route.materialization.type != "http_request":
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.UNSUPPORTED_MATERIALIZATION_TYPE,
                "materialization.type",
                "materialization type is not supported",
            )
        )
    if any(
        value != "runtime_truths"
        for value in (
            route.materialization.method_from,
            route.materialization.endpoint_from,
            route.materialization.parameter_from,
        )
    ):
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.MATERIALIZATION_INCOMPLETE,
                "materialization",
                "materialization sources must use runtime_truths",
            )
        )
    if route.materialization.payload_template_ref != route.payload_template_ref:
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.MATERIALIZATION_REF_MISMATCH,
                "materialization.payload_template_ref",
                "materialization payload reference must match the top-level reference",
            )
        )

    checked.append("runtime_facts")
    runtime_facts = route.requires.runtime_facts
    if not runtime_facts:
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.MISSING_RUNTIME_FACTS,
                "requires.runtime_facts",
                "at least one runtime fact is required",
            )
        )
    if any(fact not in ROUTE_FACTORY_V1_RUNTIME_FACTS for fact in runtime_facts):
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.UNKNOWN_RUNTIME_FACT,
                "requires.runtime_facts",
                "route requires an unsupported runtime fact",
            )
        )
    if route.requires.current_state != route.current_state:
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.REQUIRES_STATE_MISMATCH,
                "requires.current_state",
                "requires.current_state must match current_state",
            )
        )

    checked.append("required_signals")
    required_signals = route.requires.signals
    duplicate_required = len(required_signals) != len(set(required_signals))
    if duplicate_required:
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.DUPLICATE_REQUIRED_SIGNAL,
                "requires.signals",
                "requires.signals may not contain duplicate signal names",
            )
        )
    has_empty_required = required_signals and any(
        not signal.strip() for signal in required_signals
    )
    if has_empty_required:
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.MISSING_REQUIRED_SIGNALS,
                "requires.signals",
                "requires.signals must contain non-empty signal names",
            )
        )
    if primitive_exists:
        supported_requirement = set(
            adapter.get_supported_requirement_signals(route.target_primitive)
        )
        unknown_required = tuple(
            signal
            for signal in required_signals
            if signal not in supported_requirement
        )
        if unknown_required:
            diagnostics.append(
                _diagnostic(
                    AdmissionErrorCode.UNKNOWN_REQUIRED_SIGNAL,
                    "requires.signals",
                    "one or more required signals are not recognised for the target primitive",
                )
            )

    checked.append("replay")
    if route.replay.enabled is not False:
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.UNSUPPORTED_REPLAY_POLICY,
                "replay.enabled",
                "Route Admission v1 only permits replay.enabled=false",
            )
        )

    checked.append("failure")
    if route.failure.state_change != "none":
        diagnostics.append(
            _diagnostic(
                AdmissionErrorCode.INVALID_FAILURE_STATE_CHANGE,
                "failure.state_change",
                "route failure declaration may not change global state",
            )
        )

    checked.append("success_state_immutability")

    accepted = not diagnostics
    return AdmissionDecision(
        accepted=accepted,
        status=ADMITTED_CANDIDATE if accepted else REJECTED,
        canonical_id=route.canonical_id,
        diagnostics=tuple(diagnostics),
        checked_invariants=tuple(checked),
        route=route if accepted else None,
    )


def admit_route(
    route: NormalizedRoute,
    adapter: PrimitiveAdapter,
) -> AdmissionDecision:
    try:
        plain = route.to_plain()
    except (AttributeError, RecursionError, TypeError, ValueError) as exc:
        return _rejected_decision(
            (
                _diagnostic(
                    AdmissionErrorCode.SCHEMA_INVALID,
                    None,
                    f"route could not be converted to the normalized schema: {exc}",
                ),
            ),
            ("schema",),
        )

    parse_result = normalized_route_from_plain(plain)
    if not parse_result.ok or parse_result.route is None:
        return _rejected_decision(
            parse_result.diagnostics,
            ("schema",),
            route.canonical_id if isinstance(route.canonical_id, str) else None,
        )
    return _admit_parsed_route(parse_result.route, adapter)


def _yaml_structure_is_bounded(value: object) -> bool:
    visited_nodes = 0

    def visit(item: object, depth: int, ancestors: set[int]) -> bool:
        nonlocal visited_nodes
        visited_nodes += 1
        if visited_nodes > MAX_YAML_NODES or depth > MAX_YAML_DEPTH:
            return False
        if isinstance(item, Mapping):
            identity = id(item)
            if identity in ancestors:
                return False
            ancestors.add(identity)
            valid = all(
                visit(key, depth + 1, ancestors)
                and visit(child, depth + 1, ancestors)
                for key, child in item.items()
            )
            ancestors.remove(identity)
            return valid
        if isinstance(item, list):
            identity = id(item)
            if identity in ancestors:
                return False
            ancestors.add(identity)
            valid = all(visit(child, depth + 1, ancestors) for child in item)
            ancestors.remove(identity)
            return valid
        return True

    return visit(value, 0, set())


def load_and_admit_candidate_route(
    yaml_path: Path,
    adapter: PrimitiveAdapter,
) -> AdmissionDecision:
    path = Path(yaml_path)
    try:
        with path.open("rb") as yaml_file:
            yaml_bytes = yaml_file.read(MAX_YAML_FILE_SIZE + 1)
        if len(yaml_bytes) > MAX_YAML_FILE_SIZE:
            return _rejected_decision(
                (
                    _diagnostic(
                        AdmissionErrorCode.YAML_FILE_TOO_LARGE,
                        None,
                        "candidate YAML exceeds the Route Admission size limit",
                    ),
                ),
                ("yaml_safe_load",),
            )
        yaml_text = yaml_bytes.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        return _rejected_decision(
            (
                _diagnostic(
                    AdmissionErrorCode.YAML_LOAD_ERROR,
                    None,
                    f"candidate YAML could not be read: {exc}",
                ),
            ),
            ("yaml_safe_load",),
        )

    try:
        alias_count = sum(
            isinstance(token, AliasToken)
            for token in yaml.scan(yaml_text, Loader=yaml.SafeLoader)
        )
        if alias_count > MAX_YAML_ALIASES:
            return _rejected_decision(
                (
                    _diagnostic(
                        AdmissionErrorCode.YAML_LOAD_ERROR,
                        None,
                        "candidate YAML contains too many aliases",
                    ),
                ),
                ("yaml_safe_load",),
            )
        data = yaml.safe_load(yaml_text)
    except ComposerError as exc:
        code = (
            AdmissionErrorCode.YAML_MULTIPLE_DOCUMENTS
            if "single document" in str(exc).lower()
            else AdmissionErrorCode.YAML_LOAD_ERROR
        )
        return _rejected_decision(
            (_diagnostic(code, None, "candidate YAML document structure is invalid"),),
            ("yaml_safe_load",),
        )
    except yaml.YAMLError:
        return _rejected_decision(
            (
                _diagnostic(
                    AdmissionErrorCode.YAML_LOAD_ERROR,
                    None,
                    "candidate YAML could not be safely loaded",
                ),
            ),
            ("yaml_safe_load",),
        )

    if not isinstance(data, Mapping):
        return _rejected_decision(
            (
                _diagnostic(
                    AdmissionErrorCode.YAML_TOP_LEVEL_NOT_MAPPING,
                    None,
                    "candidate YAML top level must be a mapping",
                ),
            ),
            ("yaml_safe_load",),
        )
    if not _yaml_structure_is_bounded(data):
        return _rejected_decision(
            (
                _diagnostic(
                    AdmissionErrorCode.YAML_LOAD_ERROR,
                    None,
                    "candidate YAML structure exceeds admission limits",
                ),
            ),
            ("yaml_safe_load",),
        )

    canonical_id = data.get("canonical_id")
    canonical_id = canonical_id if isinstance(canonical_id, str) else None
    parse_result = normalized_route_from_plain(data)
    if not parse_result.ok or parse_result.route is None:
        return _rejected_decision(
            parse_result.diagnostics,
            ("yaml_safe_load", "schema"),
            canonical_id,
        )
    return _admit_parsed_route(parse_result.route, adapter)
