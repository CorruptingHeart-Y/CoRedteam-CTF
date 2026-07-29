from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit, urlunsplit

from routes.admission import ADMITTED_CANDIDATE, admit_route
from routes.primitive_adapter import PrimitiveAdapter
from routes.registry import route_fingerprint
from routes.schema import AdmissionErrorCode, NormalizedRoute
from core.plan_contract import validate_plan_structure


class MaterializationErrorCode(str, Enum):
    ROUTE_NOT_ADMITTED = "ROUTE_NOT_ADMITTED"
    INVALID_ROUTE_STATE = "INVALID_ROUTE_STATE"
    RUNTIME_FACT_MISSING = "RUNTIME_FACT_MISSING"
    UNSUPPORTED_HTTP_METHOD = "UNSUPPORTED_HTTP_METHOD"
    UNSUPPORTED_REQUEST_LOCATION = "UNSUPPORTED_REQUEST_LOCATION"
    PAYLOAD_REF_RESOLUTION_FAILED = "PAYLOAD_REF_RESOLUTION_FAILED"
    INVALID_TARGET_URL = "INVALID_TARGET_URL"
    PLAN_CONTRACT_INVALID = "PLAN_CONTRACT_INVALID"
    OUTPUT_FILE_EXISTS = "OUTPUT_FILE_EXISTS"
    UNSAFE_OUTPUT_PATH = "UNSAFE_OUTPUT_PATH"
    WRITE_FAILED = "WRITE_FAILED"


@dataclass(frozen=True)
class MaterializationDiagnostic:
    code: MaterializationErrorCode
    field: str | None
    message: str


@dataclass(frozen=True)
class MaterializationResult:
    success: bool
    route_id: str | None
    plan_path: str | None
    payload_template_ref: str | None
    resolved_endpoint: str | None
    resolved_parameter: str | None
    resolved_method: str | None
    request_location: str | None
    diagnostics: tuple[MaterializationDiagnostic, ...]

    @property
    def error_codes(self) -> tuple[MaterializationErrorCode, ...]:
        return tuple(item.code for item in self.diagnostics)


_REQUIRED_RUNTIME_FACTS = (
    "base_url",
    "endpoint",
    "parameter",
    "method",
    "request_location",
)
_SUPPORTED_METHODS = frozenset({"GET", "POST"})
_SUPPORTED_REQUEST_LOCATIONS = frozenset({"query", "form", "json"})
_STABLE_PAYLOAD_REF = re.compile(
    r"^primitive:([A-Za-z0-9_-]+):sha256:([0-9a-f]{16})$"
)
_PAYLOAD_ADMISSION_CODES = frozenset(
    {
        AdmissionErrorCode.LEGACY_PAYLOAD_REF_NOT_ADMITTED,
        AdmissionErrorCode.MALFORMED_PAYLOAD_REF,
        AdmissionErrorCode.UNKNOWN_PAYLOAD_TEMPLATE,
        AdmissionErrorCode.PAYLOAD_PRIMITIVE_MISMATCH,
        AdmissionErrorCode.MATERIALIZATION_REF_MISMATCH,
    }
)


def _failure(
    *,
    route_id: str | None,
    payload_template_ref: str | None,
    diagnostics: tuple[MaterializationDiagnostic, ...],
    endpoint: str | None = None,
    parameter: str | None = None,
    method: str | None = None,
    request_location: str | None = None,
) -> MaterializationResult:
    return MaterializationResult(
        success=False,
        route_id=route_id,
        plan_path=None,
        payload_template_ref=payload_template_ref,
        resolved_endpoint=endpoint,
        resolved_parameter=parameter,
        resolved_method=method,
        request_location=request_location,
        diagnostics=diagnostics,
    )


def _normalize_runtime_facts(
    runtime_facts: Mapping[str, object],
) -> tuple[dict[str, str] | None, tuple[MaterializationDiagnostic, ...]]:
    if not isinstance(runtime_facts, Mapping):
        return None, (
            MaterializationDiagnostic(
                MaterializationErrorCode.RUNTIME_FACT_MISSING,
                "runtime_facts",
                "runtime_facts must be a mapping with explicit string values",
            ),
        )

    normalized: dict[str, str] = {}
    diagnostics: list[MaterializationDiagnostic] = []
    for field_name in _REQUIRED_RUNTIME_FACTS:
        value = runtime_facts.get(field_name)
        if not isinstance(value, str) or not value.strip():
            diagnostics.append(
                MaterializationDiagnostic(
                    MaterializationErrorCode.RUNTIME_FACT_MISSING,
                    field_name,
                    f"runtime fact {field_name} is required",
                )
            )
            continue
        normalized[field_name] = value.strip()

    if diagnostics:
        return None, tuple(diagnostics)

    normalized["method"] = normalized["method"].upper()
    normalized["request_location"] = normalized["request_location"].lower()
    if normalized["method"] not in _SUPPORTED_METHODS:
        diagnostics.append(
            MaterializationDiagnostic(
                MaterializationErrorCode.UNSUPPORTED_HTTP_METHOD,
                "method",
                "method must be GET or POST",
            )
        )
    if normalized["request_location"] not in _SUPPORTED_REQUEST_LOCATIONS:
        diagnostics.append(
            MaterializationDiagnostic(
                MaterializationErrorCode.UNSUPPORTED_REQUEST_LOCATION,
                "request_location",
                "request_location must be query, form, or json",
            )
        )
    return (None, tuple(diagnostics)) if diagnostics else (normalized, ())


def _resolve_target(base_url: str, endpoint: str) -> tuple[str, str] | None:
    try:
        base = urlsplit(base_url)
        parsed_endpoint = urlsplit(endpoint)
        _ = base.port
    except (TypeError, ValueError):
        return None

    if (
        base.scheme.lower() not in {"http", "https"}
        or not base.netloc
        or not base.hostname
        or base.username is not None
        or base.password is not None
        or base.query
        or base.fragment
        or base.path not in ("", "/")
    ):
        return None
    if (
        parsed_endpoint.scheme
        or parsed_endpoint.netloc
        or parsed_endpoint.query
        or parsed_endpoint.fragment
        or endpoint.startswith("//")
        or "\\" in endpoint
        or any(ord(character) < 32 for character in endpoint)
    ):
        return None

    normalized_endpoint = "/" + parsed_endpoint.path.lstrip("/")
    origin = urlunsplit((base.scheme.lower(), base.netloc, "", "", ""))
    resolved_url = f"{origin}{normalized_endpoint}"
    resolved = urlsplit(resolved_url)
    if (resolved.scheme, resolved.netloc) != (base.scheme.lower(), base.netloc):
        return None
    return origin, normalized_endpoint


def _resolve_payload(route: NormalizedRoute, adapter: PrimitiveAdapter) -> str | None:
    match = _STABLE_PAYLOAD_REF.fullmatch(route.payload_template_ref)
    if match is None or match.group(1) != route.target_primitive:
        return None
    index = adapter.resolve_payload_template_ref(
        route.target_primitive,
        route.payload_template_ref,
    )
    if index is None:
        return None

    primitive = adapter._registry.get(route.target_primitive)
    if primitive is None or index >= len(primitive.payload_templates):
        return None
    return primitive.payload_templates[index]


def _build_sdk_call(
    *,
    method: str,
    endpoint: str,
    parameter: str,
    request_location: str,
    payload: str,
) -> dict[str, object] | None:
    # The current Executor only consumes query for GET and body for POST.
    if method == "GET" and request_location != "query":
        return None
    if method == "POST" and request_location == "query":
        return None

    call: dict[str, object] = {
        "primitive": f"HttpClient.{method.lower()}",
        "target": endpoint,
        "query": None,
        "body": None,
    }
    if request_location == "query":
        call["query"] = {parameter: payload}
    else:
        call["body"] = {parameter: payload}
        call["body_format"] = request_location
    return call


def _build_plan(
    route: NormalizedRoute,
    *,
    facts: Mapping[str, str],
    origin: str,
    endpoint: str,
    payload: str,
) -> dict[str, object] | None:
    sdk_call = _build_sdk_call(
        method=facts["method"],
        endpoint=endpoint,
        parameter=facts["parameter"],
        request_location=facts["request_location"],
        payload=payload,
    )
    if sdk_call is None:
        return None

    fingerprint = route_fingerprint(route)
    identity = json.dumps(
        {
            "route_fingerprint": fingerprint,
            "base_url": origin,
            "endpoint": endpoint,
            "parameter": facts["parameter"],
            "method": facts["method"],
            "request_location": facts["request_location"],
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    plan_id = f"route-{hashlib.sha256(identity).hexdigest()[:24]}"

    metadata = {
        "source": "route_factory",
        "route_id": route.canonical_id,
        "route_fingerprint": fingerprint,
        "target_primitive": route.target_primitive,
        "payload_template_ref": route.payload_template_ref,
        "expected_signals": list(route.expected_signals),
        "cwe_id": route.cwe_id,
        "technique": route.technique,
        "current_state": route.current_state,
        "request_location": facts["request_location"],
        "resolved_url": f"{origin}{endpoint}",
    }
    step = {
        "id": 1,
        "status": "PLANNED",
        "type": "python",
        "imports": [],
        "sdk_calls": [sdk_call],
        "purpose": route.technique,
        "expected_outcome": ", ".join(route.expected_signals),
        "depends_on": None,
        "on_failure": "BLOCK_AND_DEBUG",
        "target_primitive": route.target_primitive,
        "why_this_step_advances_state": (
            f"Observe the declared signals for {route.target_primitive}."
        ),
        "why_this_payload_is_a_mutation": (
            "Use the payload template selected by the admitted route."
        ),
        "why_this_is_not_regression": (
            f"Remain on the admitted route at state {route.current_state}."
        ),
        "why_this_primitive_advances_chain": (
            f"Exercise the admitted primitive {route.target_primitive}."
        ),
    }
    return {
        "version": 1,
        "plan_id": plan_id,
        "vuln_summary": f"{route.cwe_id}: {route.technique}",
        "rationale": f"Offline materialization of admitted route {route.canonical_id}",
        "chain_design": "single_step_route_materialization",
        "history_state": {"current_state": route.current_state},
        "primitive_context": {
            "current_primitive": route.target_primitive,
            "target_primitive": route.target_primitive,
            "transition_edge": route.current_state,
            "fallback_primitive": None,
        },
        "target_context": {"base_url": origin},
        "metadata": metadata,
        "steps": [step],
        "platform": "offline",
    }


def _plan_contract_is_valid(plan: Mapping[str, object]) -> bool:
    """Compatibility wrapper — pure delegate to the shared structural contract.

    The Materializer no longer maintains a second, divergent contract.  This
    wrapper exists solely for backward compatibility with existing callers and
    tests; it delegates 100% to
    :func:`b.core.plan_contract.validate_plan_structure`.

    A ``True`` return means ONLY ``PLAN_STRUCTURE_VALID`` — i.e. the plan's
    static JSON structure satisfies the runtime Validator's structural input
    contract.  It does NOT mean the runtime Validator will accept the plan,
    because runtime acceptance additionally depends on Manifest, policy,
    trajectory, Verification Memory, anti-regression and current-state gates.
    """
    return validate_plan_structure(plan).passed


def _resolve_output_path(output_path: Path) -> Path:
    path = Path(output_path)
    if not path.name or any(part == ".." for part in path.parts):
        raise ValueError("output path may not contain path traversal")
    resolved = path.resolve(strict=False)
    if resolved.exists() and resolved.is_dir():
        raise ValueError("output path must identify a file")
    return resolved


def _atomic_write_text(destination: Path, content: str, overwrite: bool) -> None:
    if destination.exists() and not overwrite:
        raise FileExistsError(destination)

    temp_path: Path | None = None
    reserved_destination = False
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temp_file:
            temp_path = Path(temp_file.name)
            temp_file.write(content)
            temp_file.flush()
            os.fsync(temp_file.fileno())
        if not overwrite:
            reservation = os.open(
                destination,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            )
            os.close(reservation)
            reserved_destination = True
        os.replace(temp_path, destination)
        temp_path = None
        reserved_destination = False
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        if reserved_destination:
            destination.unlink(missing_ok=True)


def materialize_route_plan(
    route: NormalizedRoute,
    *,
    adapter: PrimitiveAdapter,
    runtime_facts: Mapping[str, object],
    output_path: Path,
    overwrite: bool = False,
) -> MaterializationResult:
    route_id = route.canonical_id if isinstance(route, NormalizedRoute) else None
    payload_ref = route.payload_template_ref if isinstance(route, NormalizedRoute) else None
    if not isinstance(route, NormalizedRoute):
        return _failure(
            route_id=None,
            payload_template_ref=None,
            diagnostics=(MaterializationDiagnostic(MaterializationErrorCode.ROUTE_NOT_ADMITTED, "route", "route must be a NormalizedRoute"),),
        )

    if route.activation.state != "draft" or route.activation.source != "route_factory" or route.generation_status != "candidate_only":
        return _failure(
            route_id=route_id,
            payload_template_ref=payload_ref,
            diagnostics=(MaterializationDiagnostic(MaterializationErrorCode.INVALID_ROUTE_STATE, "route", "route must remain draft, route_factory, and candidate_only"),),
        )

    decision = admit_route(route, adapter)
    if not decision.accepted or decision.status != ADMITTED_CANDIDATE:
        code = MaterializationErrorCode.PAYLOAD_REF_RESOLUTION_FAILED if any(item.code in _PAYLOAD_ADMISSION_CODES for item in decision.diagnostics) else MaterializationErrorCode.ROUTE_NOT_ADMITTED
        return _failure(
            route_id=route_id,
            payload_template_ref=payload_ref,
            diagnostics=(MaterializationDiagnostic(code, "payload_template_ref" if code == MaterializationErrorCode.PAYLOAD_REF_RESOLUTION_FAILED else "route", "route did not pass the existing Admission contract"),),
        )

    facts, fact_diagnostics = _normalize_runtime_facts(runtime_facts)
    if fact_diagnostics:
        return _failure(route_id=route_id, payload_template_ref=payload_ref, diagnostics=fact_diagnostics)
    assert facts is not None

    target = _resolve_target(facts["base_url"], facts["endpoint"])
    if target is None:
        return _failure(
            route_id=route_id, payload_template_ref=payload_ref,
            diagnostics=(MaterializationDiagnostic(MaterializationErrorCode.INVALID_TARGET_URL, "base_url/endpoint", "base_url and endpoint must resolve to one http(s) origin"),),
            parameter=facts["parameter"], method=facts["method"], request_location=facts["request_location"],
        )
    origin, endpoint = target

    payload = _resolve_payload(route, adapter)
    if payload is None:
        return _failure(
            route_id=route_id, payload_template_ref=payload_ref,
            diagnostics=(MaterializationDiagnostic(MaterializationErrorCode.PAYLOAD_REF_RESOLUTION_FAILED, "payload_template_ref", "stable payload reference could not be resolved"),),
            endpoint=endpoint, parameter=facts["parameter"], method=facts["method"], request_location=facts["request_location"],
        )

    plan = _build_plan(route, facts=facts, origin=origin, endpoint=endpoint, payload=payload)
    if plan is None or not _plan_contract_is_valid(plan):
        return _failure(
            route_id=route_id, payload_template_ref=payload_ref,
            diagnostics=(MaterializationDiagnostic(MaterializationErrorCode.PLAN_CONTRACT_INVALID, "method/request_location", "method and request_location are not executable by the current plan contract"),),
            endpoint=endpoint, parameter=facts["parameter"], method=facts["method"], request_location=facts["request_location"],
        )

    try:
        destination = _resolve_output_path(output_path)
    except (OSError, TypeError, ValueError) as exc:
        return _failure(
            route_id=route_id, payload_template_ref=payload_ref,
            diagnostics=(MaterializationDiagnostic(MaterializationErrorCode.UNSAFE_OUTPUT_PATH, "output_path", str(exc)),),
            endpoint=endpoint, parameter=facts["parameter"], method=facts["method"], request_location=facts["request_location"],
        )

    content = json.dumps(plan, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if destination.exists() and not overwrite:
        return _failure(
            route_id=route_id, payload_template_ref=payload_ref,
            diagnostics=(MaterializationDiagnostic(MaterializationErrorCode.OUTPUT_FILE_EXISTS, "output_path", "output file already exists"),),
            endpoint=endpoint, parameter=facts["parameter"], method=facts["method"], request_location=facts["request_location"],
        )

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_text(destination, content, overwrite=overwrite)
    except FileExistsError:
        return _failure(
            route_id=route_id, payload_template_ref=payload_ref,
            diagnostics=(MaterializationDiagnostic(MaterializationErrorCode.OUTPUT_FILE_EXISTS, "output_path", "output file already exists"),),
            endpoint=endpoint, parameter=facts["parameter"], method=facts["method"], request_location=facts["request_location"],
        )
    except OSError:
        return _failure(
            route_id=route_id, payload_template_ref=payload_ref,
            diagnostics=(MaterializationDiagnostic(MaterializationErrorCode.WRITE_FAILED, "output_path", "plan file could not be written"),),
            endpoint=endpoint, parameter=facts["parameter"], method=facts["method"], request_location=facts["request_location"],
        )

    return MaterializationResult(
        success=True, route_id=route_id, plan_path=str(destination), payload_template_ref=payload_ref,
        resolved_endpoint=endpoint, resolved_parameter=facts["parameter"], resolved_method=facts["method"],
        request_location=facts["request_location"], diagnostics=(),
    )
