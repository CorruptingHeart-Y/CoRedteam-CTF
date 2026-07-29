from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping


class NormalizationErrorCode(str, Enum):
    UNKNOWN_CWE = "UNKNOWN_CWE"
    UNKNOWN_STATE = "UNKNOWN_STATE"
    UNKNOWN_PRIMITIVE = "UNKNOWN_PRIMITIVE"
    UNSUPPORTED_PRIMITIVE = "UNSUPPORTED_PRIMITIVE"
    UNKNOWN_PAYLOAD_TEMPLATE = "UNKNOWN_PAYLOAD_TEMPLATE"
    MISSING_EXPECTED_SIGNAL = "MISSING_EXPECTED_SIGNAL"
    PRIMITIVE_SIGNAL_MISMATCH = "PRIMITIVE_SIGNAL_MISMATCH"
    MISSING_RUNTIME_FACTS = "MISSING_RUNTIME_FACTS"
    UNSUPPORTED_TECHNIQUE = "UNSUPPORTED_TECHNIQUE"


class AdmissionErrorCode(str, Enum):
    SCHEMA_INVALID = "SCHEMA_INVALID"
    INVALID_CANDIDATE_STATE = "INVALID_CANDIDATE_STATE"
    CANONICAL_ID_MISMATCH = "CANONICAL_ID_MISMATCH"
    UNKNOWN_CWE = "UNKNOWN_CWE"
    NON_CANONICAL_CWE = "NON_CANONICAL_CWE"
    UNKNOWN_STATE = "UNKNOWN_STATE"
    UNKNOWN_PRIMITIVE = "UNKNOWN_PRIMITIVE"
    UNSUPPORTED_PRIMITIVE = "UNSUPPORTED_PRIMITIVE"
    UNSUPPORTED_TECHNIQUE = "UNSUPPORTED_TECHNIQUE"
    LEGACY_PAYLOAD_REF_NOT_ADMITTED = "LEGACY_PAYLOAD_REF_NOT_ADMITTED"
    MALFORMED_PAYLOAD_REF = "MALFORMED_PAYLOAD_REF"
    UNKNOWN_PAYLOAD_TEMPLATE = "UNKNOWN_PAYLOAD_TEMPLATE"
    PAYLOAD_PRIMITIVE_MISMATCH = "PAYLOAD_PRIMITIVE_MISMATCH"
    MISSING_EXPECTED_SIGNAL = "MISSING_EXPECTED_SIGNAL"
    DUPLICATE_EXPECTED_SIGNAL = "DUPLICATE_EXPECTED_SIGNAL"
    PRIMITIVE_SIGNAL_MISMATCH = "PRIMITIVE_SIGNAL_MISMATCH"
    SUCCESS_SIGNAL_MISMATCH = "SUCCESS_SIGNAL_MISMATCH"
    NON_OBSERVABLE_ROUTE = "NON_OBSERVABLE_ROUTE"
    UNSUPPORTED_SUCCESS_MATCH = "UNSUPPORTED_SUCCESS_MATCH"
    MATERIALIZATION_INCOMPLETE = "MATERIALIZATION_INCOMPLETE"
    MATERIALIZATION_REF_MISMATCH = "MATERIALIZATION_REF_MISMATCH"
    UNSUPPORTED_MATERIALIZATION_TYPE = "UNSUPPORTED_MATERIALIZATION_TYPE"
    MISSING_RUNTIME_FACTS = "MISSING_RUNTIME_FACTS"
    UNKNOWN_RUNTIME_FACT = "UNKNOWN_RUNTIME_FACT"
    REQUIRES_STATE_MISMATCH = "REQUIRES_STATE_MISMATCH"
    UNSUPPORTED_REPLAY_POLICY = "UNSUPPORTED_REPLAY_POLICY"
    INVALID_FAILURE_STATE_CHANGE = "INVALID_FAILURE_STATE_CHANGE"
    ROUTE_ATTEMPTS_STATE_MUTATION = "ROUTE_ATTEMPTS_STATE_MUTATION"
    YAML_LOAD_ERROR = "YAML_LOAD_ERROR"
    YAML_TOP_LEVEL_NOT_MAPPING = "YAML_TOP_LEVEL_NOT_MAPPING"
    YAML_MULTIPLE_DOCUMENTS = "YAML_MULTIPLE_DOCUMENTS"
    YAML_FILE_TOO_LARGE = "YAML_FILE_TOO_LARGE"
    UNKNOWN_REQUIRED_SIGNAL = "UNKNOWN_REQUIRED_SIGNAL"
    DUPLICATE_REQUIRED_SIGNAL = "DUPLICATE_REQUIRED_SIGNAL"
    MISSING_REQUIRED_SIGNALS = "MISSING_REQUIRED_SIGNALS"


class RegistryErrorCode(str, Enum):
    DUPLICATE_ROUTE = "DUPLICATE_ROUTE"
    CONFLICTING_ROUTE_DEFINITION = "CONFLICTING_ROUTE_DEFINITION"
    ROUTE_NOT_ADMITTED = "ROUTE_NOT_ADMITTED"
    ADMISSION_ROUTE_MISSING = "ADMISSION_ROUTE_MISSING"
    INVALID_ADMISSION_STATUS = "INVALID_ADMISSION_STATUS"
    REGISTRY_DIRECTORY_NOT_FOUND = "REGISTRY_DIRECTORY_NOT_FOUND"
    REGISTRY_PATH_NOT_DIRECTORY = "REGISTRY_PATH_NOT_DIRECTORY"
    UNSAFE_REGISTRY_PATH = "UNSAFE_REGISTRY_PATH"
    REGISTRY_FILE_REJECTED = "REGISTRY_FILE_REJECTED"


class FrontierDiagnosticCode(str, Enum):
    STATE_REQUIREMENT_UNSATISFIED = "STATE_REQUIREMENT_UNSATISFIED"
    MISSING_REQUIRED_SIGNALS = "MISSING_REQUIRED_SIGNALS"
    MISSING_RUNTIME_FACT = "MISSING_RUNTIME_FACT"


def _string_tuple(values: tuple[str, ...], field_name: str) -> tuple[str, ...]:
    if not isinstance(values, tuple) or not all(isinstance(value, str) for value in values):
        raise TypeError(f"{field_name} must be a tuple of strings")
    return values


def _to_plain_value(value: Any) -> object:
    if is_dataclass(value) and not isinstance(value, type):
        return {
            item.name: _to_plain_value(getattr(value, item.name))
            for item in fields(value)
        }
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("plain mapping keys must be strings")
        return {key: _to_plain_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_plain_value(item) for item in value]
    if isinstance(value, Enum):
        return _to_plain_value(value.value)
    if value is None or type(value) in (str, int, float, bool):
        return value
    raise TypeError(f"unsupported plain value type: {type(value).__name__}")


def _freeze_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _freeze_value(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_value(item) for item in value)
    return value


@dataclass(frozen=True)
class RouteProposal:
    cwe_id: str
    current_state: str
    target_primitive: str
    technique: str
    required_runtime_facts: tuple[str, ...]
    payload_template_ref: str
    expected_signals: tuple[str, ...]
    required_signals: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name in (
            "cwe_id",
            "current_state",
            "target_primitive",
            "technique",
            "payload_template_ref",
        ):
            if not isinstance(getattr(self, field_name), str):
                raise TypeError(f"{field_name} must be a string")
        _string_tuple(self.required_runtime_facts, "required_runtime_facts")
        _string_tuple(self.expected_signals, "expected_signals")
        _string_tuple(self.required_signals, "required_signals")
        if not isinstance(self.metadata, Mapping):
            raise TypeError("metadata must be a mapping")
        if not all(isinstance(key, str) for key in self.metadata):
            raise TypeError("metadata keys must be strings")
        object.__setattr__(self, "metadata", _freeze_value(self.metadata))


@dataclass(frozen=True)
class Activation:
    state: str = "draft"
    source: str = "route_factory"


@dataclass(frozen=True)
class RouteRequirements:
    current_state: str
    runtime_facts: tuple[str, ...]
    signals: tuple[str, ...] = ()


@dataclass(frozen=True)
class MaterializationDeclaration:
    type: str
    method_from: str
    endpoint_from: str
    parameter_from: str
    payload_template_ref: str


@dataclass(frozen=True)
class SuccessCriteria:
    match: str
    expected_signals: tuple[str, ...]


@dataclass(frozen=True)
class FailurePolicy:
    state_change: str = "none"


@dataclass(frozen=True)
class ReplayPolicy:
    enabled: bool = False


@dataclass(frozen=True)
class NormalizedRoute:
    schema_version: str
    canonical_id: str
    cwe_id: str
    current_state: str
    technique: str
    metadata: Mapping[str, Any]
    activation: Activation
    requires: RouteRequirements
    target_primitive: str
    payload_template_ref: str
    expected_signals: tuple[str, ...]
    materialization: MaterializationDeclaration
    success: SuccessCriteria
    failure: FailurePolicy
    replay: ReplayPolicy
    generation_status: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", _freeze_value(self.metadata))

    def to_plain(self) -> dict[str, object]:
        plain = _to_plain_value(self)
        assert isinstance(plain, dict)
        return plain


@dataclass(frozen=True)
class NormalizationError:
    code: NormalizationErrorCode
    field: str
    value: Any = None


@dataclass(frozen=True)
class NormalizationResult:
    route: NormalizedRoute | None = None
    errors: tuple[NormalizationError, ...] = ()

    @property
    def ok(self) -> bool:
        return self.route is not None and not self.errors


@dataclass(frozen=True)
class AdmissionDiagnostic:
    code: AdmissionErrorCode
    field: str | None
    message: str


@dataclass(frozen=True)
class AdmissionDecision:
    accepted: bool
    status: str
    canonical_id: str | None
    diagnostics: tuple[AdmissionDiagnostic, ...]
    checked_invariants: tuple[str, ...]
    route: NormalizedRoute | None


@dataclass(frozen=True)
class RouteParseResult:
    route: NormalizedRoute | None = None
    diagnostics: tuple[AdmissionDiagnostic, ...] = ()

    @property
    def ok(self) -> bool:
        return self.route is not None and not self.diagnostics


@dataclass(frozen=True)
class RegisteredRoute:
    canonical_id: str
    route: NormalizedRoute
    source_path: str | None
    route_fingerprint: str

    def to_plain(self) -> dict[str, object]:
        plain = _to_plain_value(self)
        assert isinstance(plain, dict)
        return plain


@dataclass(frozen=True)
class RegistryDiagnostic:
    code: RegistryErrorCode
    source_path: str | None
    canonical_id: str | None
    message: str
    admission_code: AdmissionErrorCode | None = None

    def to_plain(self) -> dict[str, object]:
        plain = _to_plain_value(self)
        assert isinstance(plain, dict)
        return plain


@dataclass(frozen=True)
class RegistryRegistrationResult:
    registered: bool
    duplicate: bool
    conflict: bool
    registered_route: RegisteredRoute | None
    diagnostics: tuple[RegistryDiagnostic, ...]

    def to_plain(self) -> dict[str, object]:
        plain = _to_plain_value(self)
        assert isinstance(plain, dict)
        return plain


@dataclass(frozen=True)
class RegistryLoadResult:
    files_discovered: int
    files_admitted: int
    routes_registered: int
    rejected: int
    duplicates: int
    conflicts: int
    diagnostics: tuple[RegistryDiagnostic, ...]

    def to_plain(self) -> dict[str, object]:
        plain = _to_plain_value(self)
        assert isinstance(plain, dict)
        return plain


@dataclass(frozen=True)
class RouteRegistrySnapshot:
    routes: tuple[RegisteredRoute, ...]
    diagnostics: tuple[RegistryDiagnostic, ...]

    def to_plain(self) -> dict[str, object]:
        plain = _to_plain_value(self)
        assert isinstance(plain, dict)
        return plain


@dataclass(frozen=True)
class FrontierContext:
    current_state: str
    confirmed_signals: tuple[str, ...]
    runtime_facts: Mapping[str, object]

    def __post_init__(self) -> None:
        if not isinstance(self.current_state, str):
            raise TypeError("current_state must be a string")
        _string_tuple(self.confirmed_signals, "confirmed_signals")
        if not isinstance(self.runtime_facts, Mapping):
            raise TypeError("runtime_facts must be a mapping")

        confirmed_signals = tuple(sorted(set(self.confirmed_signals)))
        runtime_facts = _freeze_value(
            {key: self.runtime_facts[key] for key in sorted(self.runtime_facts)}
        )
        _to_plain_value(runtime_facts)

        object.__setattr__(self, "confirmed_signals", confirmed_signals)
        object.__setattr__(self, "runtime_facts", runtime_facts)

    def to_plain(self) -> dict[str, object]:
        plain = _to_plain_value(self)
        assert isinstance(plain, dict)
        return plain


@dataclass(frozen=True)
class FrontierEntry:
    route_id: str
    status: str
    diagnostics: tuple[str, ...]

    def to_plain(self) -> dict[str, object]:
        plain = _to_plain_value(self)
        assert isinstance(plain, dict)
        return plain


@dataclass(frozen=True)
class RouteFrontier:
    eligible_routes: tuple[FrontierEntry, ...]
    blocked_routes: tuple[FrontierEntry, ...]
    context_fingerprint: str

    def to_plain(self) -> dict[str, object]:
        plain = _to_plain_value(self)
        assert isinstance(plain, dict)
        return plain
