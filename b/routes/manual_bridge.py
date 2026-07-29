"""Manual Route CLI Bridge 鈥?thin bridge from YAML route to execution chain.

Routes a single specified candidate YAML route through:
  safe load 鈫?Admission 鈫?Registry 鈫?Frontier 鈫?Materializer
  鈫?Validator 鈫?Executor 鈫?Evaluator

Bypasses ONLY Planner's route selection and LLM plan generation.
Does NOT bypass: Validator, Executor, Evaluator, policy, Manifest,
Memory gate, or expected signal checks.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import parse_qsl, urlsplit

from routes.admission import (
    ADMITTED_CANDIDATE,
    load_and_admit_candidate_route,
)
from routes.context_adapter import build_frontier_context
from routes.frontier import build_frontier
from routes.materializer import (
    MaterializationErrorCode,
    materialize_route_plan,
)
from routes.primitive_adapter import PrimitiveAdapter
from routes.registry import RouteRegistry
from routes.schema import FrontierContext, NormalizedRoute
from core.plan_contract import validate_plan_structure


class ManualRouteErrorCode(str, Enum):
    ROUTE_DIRECTORY_NOT_FOUND = "ROUTE_DIRECTORY_NOT_FOUND"
    ROUTE_ID_NOT_FOUND = "ROUTE_ID_NOT_FOUND"
    ROUTE_NOT_ADMITTED = "ROUTE_NOT_ADMITTED"
    ROUTE_BLOCKED = "ROUTE_BLOCKED"
    RUNTIME_FACT_MISSING = "RUNTIME_FACT_MISSING"
    RUNTIME_FACT_CONFLICT = "RUNTIME_FACT_CONFLICT"
    PAYLOAD_REF_RESOLUTION_FAILED = "PAYLOAD_REF_RESOLUTION_FAILED"
    MATERIALIZATION_FAILED = "MATERIALIZATION_FAILED"
    PLAN_STRUCTURE_INVALID = "PLAN_STRUCTURE_INVALID"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    EVALUATION_FAILED = "EVALUATION_FAILED"
    EXPECTED_SIGNAL_NOT_OBSERVED = "EXPECTED_SIGNAL_NOT_OBSERVED"
    MANUAL_ROUTE_SINGLE_RUN_REQUIRED = "MANUAL_ROUTE_SINGLE_RUN_REQUIRED"


@dataclass(frozen=True)
class ManualRouteResult:
    success: bool
    error_code: ManualRouteErrorCode | None
    route_id: str | None
    plan: dict[str, Any] | None
    exec_out: dict[str, Any] | None
    evaluation: dict[str, Any] | None
    diagnostics: tuple[str, ...]
    failure_record: dict[str, Any] | None = None



@dataclass(frozen=True)
class ManualRouteBatchResult:
    success: bool
    selected_result: ManualRouteResult | None
    failure_records: tuple[dict[str, Any], ...]
    attempted_route_ids: tuple[str, ...]
    diagnostics: tuple[str, ...]

def _failure(
    code: ManualRouteErrorCode,
    detail: str,
    route_id: str | None = None,
    failure_record: dict[str, Any] | None = None,
) -> ManualRouteResult:
    return ManualRouteResult(
        success=False,
        error_code=code,
        route_id=route_id,
        plan=None,
        exec_out=None,
        evaluation=None,
        diagnostics=(detail,),
        failure_record=failure_record,
    )






def _admitted_route_ids(
    route_dir: Path,
    adapter: PrimitiveAdapter,
) -> tuple[str, ...]:
    registry = RouteRegistry(adapter=adapter)
    load_result = registry.load_directory(route_dir)
    if load_result.routes_registered == 0:
        return ()
    return tuple(route.canonical_id for route in registry.list_all())

def _materialization_failure_record(
    *,
    route_id: str | None,
    error_code: MaterializationErrorCode | None,
    diagnostics: list[str],
) -> dict[str, Any]:
    """Structured route failure event for callers that iterate candidates."""
    reason = "contract_unavailable"
    if error_code == MaterializationErrorCode.RUNTIME_FACT_MISSING:
        reason = "runtime_fact_missing"
    elif error_code == MaterializationErrorCode.PAYLOAD_REF_RESOLUTION_FAILED:
        reason = "payload_ref_resolution_failed"
    elif error_code == MaterializationErrorCode.INVALID_ROUTE_STATE:
        reason = "invalid_route_state"
    return {
        "route_id": route_id,
        "stage": "materialization",
        "reason": reason,
        "error_code": error_code.value if error_code else None,
        "diagnostics": diagnostics,
    }

# 鈹€鈹€ Runtime fact extraction from confirmed contract 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€


_CONFIRMED_TEXT_FIELDS = (
    "vulnerabilities",
    "request_facts",
    "endpoint",
    "path",
    "route",
    "parameter",
    "parameter_name",
    "parameters",
    "method",
    "methods",
    "request_location",
    "locations",
    "source",
    "sink",
    "evidence",
    "flow",
    "code",
    "code_snippet",
    "description",
    "exploitation",
    "exploit_example",
    "attack_vector",
    "request_example",
)
_ENDPOINT_FIELDS = ("vulnerabilities", "request_facts", "endpoint", "path", "route")
_PARAMETER_FIELDS = (
    "vulnerabilities",
    "request_facts",
    "parameter",
    "parameter_name",
    "parameters",
)
_METHOD_FIELD = ("vulnerabilities", "request_facts", "method")
_METHODS_FIELD = ("vulnerabilities", "request_facts", "methods")
_LOCATION_FIELD = ("vulnerabilities", "request_facts", "request_location")
_LOCATIONS_FIELD = ("vulnerabilities", "request_facts", "locations")
_REQUEST_EXAMPLE_FIELDS = (
    "vulnerabilities",
    "attack_vector",
    "exploit_example",
    "request_example",
    "code",
    "code_snippet",
    "description",
)
_EVIDENCE_TEXT_FIELDS = (
    "vulnerabilities",
    "source",
    "sink",
    "evidence",
    "flow",
    "code",
    "code_snippet",
    "description",
    "exploitation",
)
_REQUEST_LINE_RE = re.compile(
    r"^\s*(?P<method>GET|POST|PUT|DELETE|PATCH)\s+(?P<target>\S+)"
    r"(?:\s+HTTP/\d+(?:\.\d+)?)?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_ROUTE_ANNOTATION_RE = re.compile(
    r"@(?P<annotation>RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)"
    r"\s*\((?P<arguments>[^)]*)\)",
    re.DOTALL,
)
_ROUTE_PATH_NAMED_RE = re.compile(r'(?:value|path)\s*=\s*(["\'])([^"\']+)\1')
_ROUTE_PATH_POSITIONAL_RE = re.compile(r'^\s*(["\'])([^"\']+)\1')
_REQUEST_MAPPING_METHOD_RE = re.compile(
    r"\bRequestMethod\s*\.\s*(GET|POST|PUT|DELETE|PATCH)\b",
    re.IGNORECASE,
)
_REQUEST_PARAM_ANNOTATION_RE = re.compile(
    r"@RequestParam\s*\((?P<arguments>[^)]*)\)",
    re.DOTALL,
)
_REQUEST_PARAM_NAMED_RE = re.compile(
    r"(?:name|value)\s*=\s*([\"'])([A-Za-z_][\w.\-\[\]]*)\1",
)
_REQUEST_PARAM_POSITIONAL_RE = re.compile(
    r"^\s*([\"'])([A-Za-z_][\w.\-\[\]]*)\1",
)
_LEGACY_PARAMETER_RE = re.compile(
    r"\b(?:parameter_name|parameter|param)\b\s*"
    r"(?:name\s*)?(?:[:=]\s*)?[\x60\"']([A-Za-z_][\w.\-\[\]]*)[\x60\"']",
    re.IGNORECASE,
)
_PARAMETER_NAME_RE = re.compile(r"^[A-Za-z_][\w.\-\[\]]*$")
_FORM_URLENCODED_RE = re.compile(
    r"^\s*Content-Type\s*:\s*application/x-www-form-urlencoded\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_JSON_CONTENT_TYPE_RE = re.compile(
    r"^\s*Content-Type\s*:\s*application/(?:[A-Za-z0-9.+-]+\+)?json\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_METHOD_TOKEN_RE = re.compile(r"\b(GET|POST|PUT|DELETE|PATCH)\b", re.IGNORECASE)
_QUERY_LOCATION_RE = re.compile(r"\bquery(?:\s+string)?\b", re.IGNORECASE)
_FORM_LOCATION_RE = re.compile(
    r"\bform(?:-urlencoded)?\b|application/x-www-form-urlencoded|(?:^|\s)data\s*=",
    re.IGNORECASE,
)
_JSON_LOCATION_RE = re.compile(
    r"application/(?:[A-Za-z0-9.+-]+\+)?json\b|\bjson\s+(?:request\s+)?body\b",
    re.IGNORECASE,
)
_ALLOWED_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH")
_ALLOWED_LOCATIONS = ("query", "form", "json")


def _collect_text_nodes(
    value: Any,
    allowed_fields: tuple[str, ...] = _CONFIRMED_TEXT_FIELDS,
) -> tuple[str, ...]:
    """Collect strings from explicit confirmed-contract fields only."""
    ordered_fields = tuple(dict.fromkeys(allowed_fields))
    collected: list[str] = []
    active_containers: set[int] = set()

    def visit(node: Any) -> None:
        if isinstance(node, str):
            collected.append(node)
            return
        if isinstance(node, Mapping):
            container_id = id(node)
            if container_id in active_containers:
                return
            active_containers.add(container_id)
            try:
                for field in ordered_fields:
                    if field in node:
                        visit(node[field])
            finally:
                active_containers.remove(container_id)
            return
        if isinstance(node, (list, tuple)):
            container_id = id(node)
            if container_id in active_containers:
                return
            active_containers.add(container_id)
            try:
                for child in node:
                    visit(child)
            finally:
                active_containers.remove(container_id)

    visit(value)
    return tuple(collected)


def _normalize_parameter_candidate(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not _PARAMETER_NAME_RE.fullmatch(candidate):
        return None
    return candidate


def _normalize_endpoint_candidate(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None

    parsed = urlsplit(candidate)
    if parsed.scheme.lower() in {"http", "https"} and parsed.netloc:
        path = parsed.path or "/"
    else:
        path = candidate.split("?", 1)[0].split("#", 1)[0]

    if not path.startswith("/") or any(ch.isspace() for ch in path):
        return None
    return path


def _select_unique_candidate(fact_name: str, candidates: list[str]) -> str | None:
    unique = list(dict.fromkeys(candidates))
    if len(unique) > 1:
        raise _FactError(
            ManualRouteErrorCode.RUNTIME_FACT_CONFLICT,
            f"{fact_name}: confirmed sources disagree: {unique}",
        )
    return unique[0] if unique else None


def _select_allowed_candidate(
    fact_name: str,
    groups: list[set[str]],
    *,
    preferred: str | None,
    allowed_values: tuple[str, ...],
) -> str | None:
    nonempty = [group for group in groups if group]
    for index, group in enumerate(nonempty):
        for other in nonempty[index + 1:]:
            if group.isdisjoint(other):
                ordered_group = [value for value in allowed_values if value in group]
                ordered_other = [value for value in allowed_values if value in other]
                raise _FactError(
                    ManualRouteErrorCode.RUNTIME_FACT_CONFLICT,
                    f"{fact_name}: confirmed sources disagree: "
                    f"{ordered_group} versus {ordered_other}",
                )

    allowed = set().union(*nonempty) if nonempty else set()
    if not allowed:
        return None

    ordered = [value for value in allowed_values if value in allowed]
    if preferred is not None:
        if preferred not in allowed:
            confirmed_detail = ordered[0] if len(ordered) == 1 else ordered
            raise _FactError(
                ManualRouteErrorCode.RUNTIME_FACT_CONFLICT,
                f"{fact_name}: CLI says {preferred}, confirmed says {confirmed_detail}",
            )
        return preferred
    return ordered[0] if len(ordered) == 1 else None


def _extract_endpoint_from_confirmed(confirmed: Any) -> str | None:
    """Extract one unambiguous normalized endpoint from confirmed facts."""
    candidates: list[str] = []

    def add_candidate(raw_value: Any) -> None:
        endpoint = _normalize_endpoint_candidate(raw_value)
        if endpoint is not None:
            candidates.append(endpoint)

    for text in _collect_text_nodes(confirmed, _ENDPOINT_FIELDS):
        add_candidate(text)
    for text in _collect_text_nodes(confirmed, _REQUEST_EXAMPLE_FIELDS):
        for match in _REQUEST_LINE_RE.finditer(text):
            add_candidate(match.group("target"))
    for text in _collect_text_nodes(confirmed, _EVIDENCE_TEXT_FIELDS):
        for annotation in _ROUTE_ANNOTATION_RE.finditer(text):
            arguments = annotation.group("arguments")
            named = _ROUTE_PATH_NAMED_RE.search(arguments)
            positional = _ROUTE_PATH_POSITIONAL_RE.match(arguments)
            if named is not None:
                add_candidate(named.group(2))
            elif positional is not None:
                add_candidate(positional.group(2))

    return _select_unique_candidate("endpoint", candidates)


def _parameter_candidates_from_text(text: str) -> list[str]:
    candidates: list[str] = []
    for annotation in _REQUEST_PARAM_ANNOTATION_RE.finditer(text):
        arguments = annotation.group("arguments")
        named = [match.group(2) for match in _REQUEST_PARAM_NAMED_RE.finditer(arguments)]
        if named:
            candidates.extend(named)
            continue
        positional = _REQUEST_PARAM_POSITIONAL_RE.match(arguments)
        if positional is not None:
            candidates.append(positional.group(2))

    candidates.extend(match.group(1) for match in _LEGACY_PARAMETER_RE.finditer(text))
    return candidates


def _parameter_candidates_from_request_example(text: str) -> list[str]:
    candidates: list[str] = []
    for match in _REQUEST_LINE_RE.finditer(text):
        query = urlsplit(match.group("target")).query
        candidates.extend(name for name, _ in parse_qsl(query, keep_blank_values=True))

    normalized = text.replace("\r\n", "\n")
    if _FORM_URLENCODED_RE.search(normalized) and "\n\n" in normalized:
        body = normalized.split("\n\n", 1)[1].strip()
        candidates.extend(name for name, _ in parse_qsl(body, keep_blank_values=True))
    return candidates


def _extract_parameter_from_confirmed(confirmed: Any) -> str | None:
    """Extract one unambiguous parameter from structured and textual facts."""
    candidates: list[str] = []
    for text in _collect_text_nodes(confirmed, _PARAMETER_FIELDS):
        candidate = _normalize_parameter_candidate(text)
        if candidate is not None:
            candidates.append(candidate)
    for text in _collect_text_nodes(confirmed, _EVIDENCE_TEXT_FIELDS):
        candidates.extend(_parameter_candidates_from_text(text))
    for text in _collect_text_nodes(confirmed, _REQUEST_EXAMPLE_FIELDS):
        candidates.extend(_parameter_candidates_from_request_example(text))

    normalized = [
        candidate
        for value in candidates
        if (candidate := _normalize_parameter_candidate(value)) is not None
    ]
    return _select_unique_candidate("parameter", normalized)


def _normalize_method_candidate(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip().upper()
    return candidate if candidate in _ALLOWED_METHODS else None


def _method_candidates_from_text(text: str) -> set[str]:
    candidates = {match.group(1).upper() for match in _METHOD_TOKEN_RE.finditer(text)}
    for annotation in _ROUTE_ANNOTATION_RE.finditer(text):
        annotation_name = annotation.group("annotation")
        if annotation_name != "RequestMapping":
            mapped = annotation_name.removesuffix("Mapping").upper()
            if mapped in _ALLOWED_METHODS:
                candidates.add(mapped)
        else:
            candidates.update(
                match.group(1).upper()
                for match in _REQUEST_MAPPING_METHOD_RE.finditer(
                    annotation.group("arguments")
                )
            )
    return candidates


def _extract_method_from_confirmed(
    confirmed: Any,
    *,
    preferred: str | None = None,
) -> str | None:
    """Extract an HTTP method, retaining explicit allowed sets for CLI choice."""
    normalized_preferred = _normalize_method_candidate(preferred)
    if preferred is not None and normalized_preferred is None:
        raise _FactError(
            ManualRouteErrorCode.RUNTIME_FACT_CONFLICT,
            f"method: unsupported CLI value {preferred!r}",
        )

    groups: list[set[str]] = []
    for text in _collect_text_nodes(confirmed, _METHOD_FIELD):
        candidate = _normalize_method_candidate(text)
        if candidate is not None:
            groups.append({candidate})

    plural = {
        candidate
        for text in _collect_text_nodes(confirmed, _METHODS_FIELD)
        if (candidate := _normalize_method_candidate(text)) is not None
    }
    if plural:
        groups.append(plural)

    text_fields = tuple(dict.fromkeys(_EVIDENCE_TEXT_FIELDS + _REQUEST_EXAMPLE_FIELDS))
    for text in _collect_text_nodes(confirmed, text_fields):
        candidates = _method_candidates_from_text(text)
        if candidates:
            groups.append(candidates)

    return _select_allowed_candidate(
        "method",
        groups,
        preferred=normalized_preferred,
        allowed_values=_ALLOWED_METHODS,
    )


def _normalize_location_candidate(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower()
    return candidate if candidate in _ALLOWED_LOCATIONS else None


def _request_body(text: str) -> str | None:
    normalized = text.replace("\r\n", "\n")
    if "\n\n" not in normalized:
        return None
    body = normalized.split("\n\n", 1)[1].strip()
    return body or None


def _location_candidates_from_text(text: str) -> set[str]:
    candidates: set[str] = set()
    lowered = text.lower()
    if "@requestparam" in lowered:
        candidates.update(("query", "form"))
    if _QUERY_LOCATION_RE.search(text):
        candidates.add("query")
    if _FORM_LOCATION_RE.search(text):
        candidates.add("form")
    if _JSON_LOCATION_RE.search(text):
        candidates.add("json")

    for request_line in _REQUEST_LINE_RE.finditer(text):
        if (
            request_line.group("method").upper() == "GET"
            and urlsplit(request_line.group("target")).query
        ):
            candidates.add("query")

    body = _request_body(text)
    if _FORM_URLENCODED_RE.search(text):
        candidates.add("form")
    if _JSON_CONTENT_TYPE_RE.search(text):
        candidates.add("json")
    elif body is not None and body[:1] in {"{", "["}:
        try:
            json.loads(body)
        except (TypeError, ValueError):
            pass
        else:
            candidates.add("json")
    return candidates


def _extract_location_from_confirmed(
    confirmed: Any,
    *,
    preferred: str | None = None,
) -> str | None:
    """Extract request location without guessing from method or CWE."""
    normalized_preferred = _normalize_location_candidate(preferred)
    if preferred is not None and normalized_preferred is None:
        raise _FactError(
            ManualRouteErrorCode.RUNTIME_FACT_CONFLICT,
            f"request_location: unsupported CLI value {preferred!r}",
        )

    groups: list[set[str]] = []
    for text in _collect_text_nodes(confirmed, _LOCATION_FIELD):
        candidate = _normalize_location_candidate(text)
        if candidate is not None:
            groups.append({candidate})

    plural = {
        candidate
        for text in _collect_text_nodes(confirmed, _LOCATIONS_FIELD)
        if (candidate := _normalize_location_candidate(text)) is not None
    }
    if plural:
        groups.append(plural)

    text_fields = tuple(dict.fromkeys(_EVIDENCE_TEXT_FIELDS + _REQUEST_EXAMPLE_FIELDS))
    for text in _collect_text_nodes(confirmed, text_fields):
        candidates = _location_candidates_from_text(text)
        if candidates:
            groups.append(candidates)

    return _select_allowed_candidate(
        "request_location",
        groups,
        preferred=normalized_preferred,
        allowed_values=_ALLOWED_LOCATIONS,
    )


def _resolve_runtime_facts(
    *,
    target_url: str,
    confirmed: dict[str, Any],
    cli_method: str | None = None,
    cli_location: str | None = None,
) -> dict[str, str]:
    """Resolve runtime facts from confirmed contract + CLI overrides.

    Rules:
      - confirmed value used if available and unambiguous
      - CLI explicit value overrides confirmed
      - CLI value conflicts with confirmed unambiguous value 鈫?RUNTIME_FACT_CONFLICT
      - Neither has value 鈫?RUNTIME_FACT_MISSING
      - No guessing; no defaults for method or location
    """
    facts: dict[str, str] = {}

    # base_url 鈥?always from --url
    facts["base_url"] = target_url

    # endpoint 鈥?from confirmed
    endpoint = _extract_endpoint_from_confirmed(confirmed)
    if not endpoint:
        raise _FactError(ManualRouteErrorCode.RUNTIME_FACT_MISSING, "endpoint")
    facts["endpoint"] = endpoint

    # parameter 鈥?from confirmed
    parameter = _extract_parameter_from_confirmed(confirmed)
    if not parameter:
        raise _FactError(ManualRouteErrorCode.RUNTIME_FACT_MISSING, "parameter")
    facts["parameter"] = parameter

    # method 鈥?CLI selects one value from the confirmed allowed set.
    method = _extract_method_from_confirmed(confirmed, preferred=cli_method)
    if method is None and cli_method is not None:
        method = _normalize_method_candidate(cli_method)
    if method is None:
        raise _FactError(ManualRouteErrorCode.RUNTIME_FACT_MISSING, "method")
    facts["method"] = method

    # request_location 鈥?CLI selects one value from the confirmed allowed set.
    request_location = _extract_location_from_confirmed(
        confirmed,
        preferred=cli_location,
    )
    if request_location is None and cli_location is not None:
        request_location = _normalize_location_candidate(cli_location)
    if request_location is None:
        raise _FactError(
            ManualRouteErrorCode.RUNTIME_FACT_MISSING,
            "request_location",
        )
    facts["request_location"] = request_location
    return facts


class _ManualEvaluationMemory:
    """Discard evaluator memory patches in isolated manual single-run mode."""

    def apply_evaluator_patch(self, patch: dict[str, Any]) -> None:
        return None

class _FactError(Exception):
    def __init__(self, code: ManualRouteErrorCode, fact_name: str):
        self.code = code
        self.fact_name = fact_name
        super().__init__(f"[{code.value}] {fact_name}")


# 鈹€鈹€ Main orchestrator 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€




def run_manual_route_candidates(
    *,
    route_dir: Path,
    confirmed: dict[str, Any],
    target: Any,
    settings: Any,
    workspace_dir: Path,
    adapter: PrimitiveAdapter | None = None,
    route_ids: Iterable[str] | None = None,
    cli_method: str | None = None,
    cli_location: str | None = None,
) -> ManualRouteBatchResult:
    """Try candidate routes, skipping materialization-only failures.

    Manual routes remain hypothesis verification: this helper does not build a
    plan itself. It delegates every candidate to the existing full bridge and
    only treats materialization failures as non-terminal candidate misses.
    """
    if adapter is None:
        adapter = PrimitiveAdapter()

    candidates = tuple(route_ids) if route_ids is not None else _admitted_route_ids(route_dir, adapter)
    if not candidates:
        return ManualRouteBatchResult(
            success=False,
            selected_result=None,
            failure_records=(),
            attempted_route_ids=(),
            diagnostics=("no admitted candidate routes available",),
        )

    failure_records: list[dict[str, Any]] = []
    attempted: list[str] = []
    last_result: ManualRouteResult | None = None
    for candidate_id in candidates:
        attempted.append(candidate_id)
        result = run_manual_route(
            route_dir=route_dir,
            route_id=candidate_id,
            confirmed=confirmed,
            target=target,
            settings=settings,
            workspace_dir=workspace_dir,
            adapter=adapter,
            cli_method=cli_method,
            cli_location=cli_location,
        )
        last_result = result
        if result.success:
            return ManualRouteBatchResult(
                success=True,
                selected_result=result,
                failure_records=tuple(failure_records),
                attempted_route_ids=tuple(attempted),
                diagnostics=(),
            )
        if (
            result.failure_record
            and result.failure_record.get("stage") == "materialization"
        ):
            failure_records.append(result.failure_record)
            continue
        return ManualRouteBatchResult(
            success=False,
            selected_result=result,
            failure_records=tuple(failure_records),
            attempted_route_ids=tuple(attempted),
            diagnostics=result.diagnostics,
        )

    return ManualRouteBatchResult(
        success=False,
        selected_result=last_result,
        failure_records=tuple(failure_records),
        attempted_route_ids=tuple(attempted),
        diagnostics=("all candidate routes failed during materialization",),
    )

def run_manual_route(
    *,
    route_dir: Path,
    route_id: str,
    confirmed: dict[str, Any],
    target: Any,  # TargetContext
    settings: Any,  # Settings
    workspace_dir: Path,
    adapter: PrimitiveAdapter | None = None,
    cli_method: str | None = None,
    cli_location: str | None = None,
) -> ManualRouteResult:
    """Execute a single manually-specified route through the full execution chain.

    Data flow:
      YAML safe load 鈫?Admission 鈫?Registry 鈫?Frontier 鈫?Materializer
      鈫?Validator 鈫?Executor 鈫?Evaluator 鈫?expected signal check
    """
    if adapter is None:
        adapter = PrimitiveAdapter()

    ws = Path(workspace_dir)
    ws.mkdir(parents=True, exist_ok=True)

    # 鈹€鈹€ 0. Validate route directory 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
    rd = Path(route_dir)
    if not rd.is_dir():
        return _failure(
            ManualRouteErrorCode.ROUTE_DIRECTORY_NOT_FOUND,
            f"route directory does not exist: {rd}",
        )

    # 鈹€鈹€ 1. Load and admit candidate YAML routes 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
    registry = RouteRegistry(adapter=adapter)
    yaml_files = sorted(
        p for p in rd.iterdir()
        if p.suffix.lower() in {".yaml", ".yml"} and p.is_file()
    )
    if not yaml_files:
        return _failure(
            ManualRouteErrorCode.ROUTE_DIRECTORY_NOT_FOUND,
            f"no YAML files found in route directory: {rd}",
        )

    admitted_count = 0
    for yaml_path in yaml_files:
        decision = load_and_admit_candidate_route(yaml_path, adapter)
        if decision.accepted and decision.status == ADMITTED_CANDIDATE:
            reg_result = registry.register_decision(decision, yaml_path)
            if reg_result.registered:
                admitted_count += 1
    if admitted_count == 0:
        return _failure(
            ManualRouteErrorCode.ROUTE_DIRECTORY_NOT_FOUND,
            f"no routes admitted from directory: {rd}",
        )

    # 鈹€鈹€ 2. Find target route by exact ID 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
    registered = registry.get(route_id)
    if registered is None:
        available = [r.canonical_id for r in registry.list_all()]
        return _failure(
            ManualRouteErrorCode.ROUTE_ID_NOT_FOUND,
            f"route_id={route_id!r} not found. Available: {available}",
        )

    # 鈹€鈹€ 3. Build Frontier context 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
    from memory.exploit_trajectory import get_trajectory, reset_trajectory
    from memory.verification_memory import get_verification, reset_verification

    # Use isolated memory for manual single-run
    reset_verification(ws / "verification_memory.json", clear_current_run=True)
    reset_trajectory(ws / "exploit_trajectory.json", clear_current_run=True)

    # Resolve the complete normalized facts before Frontier. The same object is
    # passed to Materializer; later stages must not rebuild it.
    try:
        runtime_facts = _resolve_runtime_facts(
            target_url=target.url,
            confirmed=confirmed,
            cli_method=cli_method,
            cli_location=cli_location,
        )
    except _FactError as e:
        return _failure(e.code, str(e), route_id=route_id)

    frontier_ctx = build_frontier_context(
        adapter,
        verification_memory=get_verification(ws / "verification_memory.json"),
        trajectory=get_trajectory(ws / "exploit_trajectory.json"),
        runtime_facts_source=runtime_facts,
    )

    # 鈹€鈹€ 4. Frontier eligibility check 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
    frontier = build_frontier(registry.snapshot(), frontier_ctx)
    blocked_ids = {e.route_id for e in frontier.blocked_routes}
    if route_id in blocked_ids:
        diagnostics: list[str] = []
        for entry in frontier.blocked_routes:
            if entry.route_id == route_id:
                diagnostics.extend(entry.diagnostics)
        return _failure(
            ManualRouteErrorCode.ROUTE_BLOCKED,
            f"route {route_id!r} is blocked by Frontier: {diagnostics}",
            route_id=route_id,
        )

    eligible_ids = {e.route_id for e in frontier.eligible_routes}
    if route_id not in eligible_ids:
        return _failure(
            ManualRouteErrorCode.ROUTE_BLOCKED,
            f"route {route_id!r} is neither eligible nor blocked",
            route_id=route_id,
        )

    # 鈹€鈹€ 5. Get route from Frontier via Registry 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
    eligible_entry = next(
        e for e in frontier.eligible_routes if e.route_id == route_id
    )
    frontier_registered = registry.get(eligible_entry.route_id)
    if frontier_registered is None:
        return _failure(
            ManualRouteErrorCode.ROUTE_ID_NOT_FOUND,
            f"eligible route {eligible_entry.route_id!r} not found in registry",
            route_id=route_id,
        )
    route: NormalizedRoute = frontier_registered.route

    # 鈹€鈹€ 7. Materialize route 鈫?plan.json 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
    plan_path = ws / "plan.json"
    materialized = materialize_route_plan(
        route,
        adapter=adapter,
        runtime_facts=runtime_facts,
        output_path=plan_path,
        overwrite=True,
    )
    if not materialized.success:
        error_msgs = [d.message for d in materialized.diagnostics]
        error_code = materialized.error_codes[0] if materialized.error_codes else None
        bridge_code = _map_materialization_error(error_code)
        failure_record = _materialization_failure_record(
            route_id=route.canonical_id,
            error_code=error_code,
            diagnostics=error_msgs,
        )
        return _failure(
            bridge_code,
            f"materialization failed: {error_msgs}",
            route_id=route.canonical_id,
            failure_record=failure_record,
        )

    plan = json.loads(plan_path.read_text(encoding="utf-8"))

    # 鈹€鈹€ 7b. Plan structure contract 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
    struct = validate_plan_structure(plan)
    if not struct.passed:
        return _failure(
            ManualRouteErrorCode.PLAN_STRUCTURE_INVALID,
            f"plan structure invalid: {struct.diagnostics}",
            route_id=route.canonical_id,
        )

    # 鈹€鈹€ 8. Validator 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
    from agents.validator import run_validator

    validated_path = ws / "validated_plan.json"
    parameter_contract = {
        "parameters": [{
            "name": runtime_facts["parameter"],
            "accepted_locations": [runtime_facts["request_location"]],
        }],
        "endpoint": runtime_facts["endpoint"],
        "method": runtime_facts["method"],
    }
    validation = run_validator(
        plan_path,
        validated_path,
        parameter_contract=parameter_contract,
    )
    val = validation.get("validation", {})
    if not val.get("passed"):
        errors = val.get("errors", [])
        return _failure(
            ManualRouteErrorCode.VALIDATION_FAILED,
            f"validation failed: {errors}",
            route_id=route.canonical_id,
        )

    # 鈹€鈹€ 9. Executor 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
    from agents.executor import run_executor

    exec_path = ws / "execution_result.json"
    try:
        exec_out = run_executor(
            validated_path=validated_path,
            result_path=exec_path,
            workdir=settings.project_root,
            timeout_sec=settings.docker_timeout,
            docker_image=settings.docker_image,
            target=target,
        )
    except Exception as e:
        return _failure(
            ManualRouteErrorCode.EXECUTION_FAILED,
            f"executor raised: {e}",
            route_id=route.canonical_id,
        )

    if not exec_out.get("executed"):
        return _failure(
            ManualRouteErrorCode.EXECUTION_FAILED,
            f"executor did not complete: {exec_out.get('reason', exec_out.get('error', 'unknown'))}",
            route_id=route.canonical_id,
        )

    # 鈹€鈹€ 10. Evaluator 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
    from agents.evaluator import run_evaluator
    from core.settings import Settings

    feedback_path = ws / "feedback.json"
    try:
        evaluation = run_evaluator(
            settings=settings if isinstance(settings, Settings) else settings,
            memory=_ManualEvaluationMemory(),
            confirmed=confirmed,
            plan=plan,
            exec_out=exec_out,
            feedback_path=feedback_path,
            llm=None,  # Manual mode: local evaluation only
            adapter=None,
        )
    except Exception as e:
        return _failure(
            ManualRouteErrorCode.EVALUATION_FAILED,
            f"evaluator raised: {e}",
            route_id=route.canonical_id,
        )

    # 鈹€鈹€ 11. Expected signal check 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
    expected_signals = set(route.expected_signals)
    observed_primitives = set(evaluation.get("detected_primitives", []))
    repro_success = evaluation.get("repro_success", False)

    # If route.success.match == "any": observed 鈭?expected non-empty 鈫?success
    signal_match = bool(expected_signals & observed_primitives) or repro_success

    # Deeper check: scan stdout for expected signal patterns
    if not signal_match:
        from agents.evaluator import _detect_success_signal
        step_results = exec_out.get("step_results", [])
        all_stdout = " ".join(
            (sr.get("result") or {}).get("stdout", "")
            for sr in step_results
        )
        detected = _detect_success_signal(all_stdout)
        if detected:
            signal_match = True

    # Velocity SSTI arithmetic probe: #set($x=7*7)$x 鈫?49
    # This confirms the SSTI primitive only. It must not be promoted to
    # exploit completion unless GoalVerifier/strong chain evidence later proves it.
    arithmetic_signal_match = False
    if not signal_match and "arithmetic_result_in_response" in expected_signals:
        plan_payloads: list[str] = []
        for st in (plan.get("steps") or []):
            for call in (st.get("sdk_calls") or []):
                for loc in ("query", "body"):
                    params = call.get(loc)
                    if isinstance(params, dict):
                        plan_payloads.extend(str(v) for v in params.values())
        expected_values: set[str] = set()
        for payload in plan_payloads:
            m = re.search(r"#set\(\$x\s*=\s*(\d+)\s*\*\s*(\d+)\s*\)\s*\$x", payload)
            if m:
                expected_values.add(str(int(m.group(1)) * int(m.group(2))))
        if expected_values:
            step_results = exec_out.get("step_results", [])
            parts: list[str] = []
            for sr in step_results:
                parts.append((sr.get("result") or {}).get("stdout", ""))
                co = sr.get("chain_output") or {}
                parts.append(str(co.get("_stdout", "")))
                parts.append(str(co.get("_last_response_text", "")))
            observed_text = " ".join(parts)
            arithmetic_signal_match = any(value in observed_text for value in expected_values)
            signal_match = arithmetic_signal_match

    primitive_confirmed = bool(expected_signals & observed_primitives) or arithmetic_signal_match
    flag_found = bool(evaluation.get("flag_found"))
    if not flag_found:
        from agents.evaluator import _detect_flag
        step_results = exec_out.get("step_results", [])
        scan_parts: list[str] = []
        for sr in step_results:
            scan_parts.append((sr.get("result") or {}).get("stdout", ""))
            co = sr.get("chain_output") or {}
            scan_parts.append(str(co.get("_stdout", "")))
            scan_parts.append(str(co.get("_last_response_text", "")))
        flag_found = bool(_detect_flag(" ".join(scan_parts)))
    exploit_completed = bool(evaluation.get("exploit_completed") or (repro_success and flag_found))
    if primitive_confirmed:
        evaluation["primitive_confirmed"] = True
    evaluation["flag_found"] = flag_found
    evaluation["exploit_completed"] = exploit_completed
    if arithmetic_signal_match and not exploit_completed and not flag_found:
        evaluation["repro_success"] = False
        repro_success = False
        evaluation.setdefault("failure_analysis", {})
        evaluation["failure_analysis"].setdefault("type", "primitive_only")
        evaluation["failure_analysis"].setdefault(
            "detail",
            "arithmetic_result_in_response confirms SSTI primitive, not exploit completion",
        )
        evaluation.setdefault("possible_next_direction", ["processbuilder", "scriptengine"])

    if not signal_match:
        return _failure(
            ManualRouteErrorCode.EXPECTED_SIGNAL_NOT_OBSERVED,
            f"expected signals {sorted(expected_signals)} not observed. "
            f"Observed primitives: {sorted(observed_primitives)}. "
            f"repro_success={repro_success}",
            route_id=route.canonical_id,
        )

    return ManualRouteResult(
        success=True,
        error_code=None,
        route_id=route.canonical_id,
        plan=plan,
        exec_out=exec_out,
        evaluation=evaluation,
        diagnostics=(),
    )


def _map_materialization_error(
    code: MaterializationErrorCode | None,
) -> ManualRouteErrorCode:
    """Map MaterializationErrorCode to ManualRouteErrorCode."""
    if code is None:
        return ManualRouteErrorCode.MATERIALIZATION_FAILED
    mapping = {
        MaterializationErrorCode.RUNTIME_FACT_MISSING: ManualRouteErrorCode.RUNTIME_FACT_MISSING,
        MaterializationErrorCode.PAYLOAD_REF_RESOLUTION_FAILED: ManualRouteErrorCode.PAYLOAD_REF_RESOLUTION_FAILED,
    }
    return mapping.get(code, ManualRouteErrorCode.MATERIALIZATION_FAILED)

