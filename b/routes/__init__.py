from routes.normalizer import normalize_route_proposal
from routes.primitive_adapter import PrimitiveAdapter
from routes.schema import (
    Activation,
    AdmissionDecision,
    AdmissionDiagnostic,
    AdmissionErrorCode,
    FailurePolicy,
    FrontierContext,
    FrontierDiagnosticCode,
    FrontierEntry,
    MaterializationDeclaration,
    NormalizationError,
    NormalizationErrorCode,
    NormalizationResult,
    NormalizedRoute,
    ReplayPolicy,
    RegisteredRoute,
    RegistryDiagnostic,
    RegistryErrorCode,
    RegistryLoadResult,
    RegistryRegistrationResult,
    RouteParseResult,
    RouteProposal,
    RouteRegistrySnapshot,
    RouteFrontier,
    RouteRequirements,
    SuccessCriteria,
)

_LAZY_EXPORTS = {
    "ADMITTED_CANDIDATE": ("routes.admission", "ADMITTED_CANDIDATE"),
    "DUPLICATE_ROUTE_ID": ("routes.factory", "DUPLICATE_ROUTE_ID"),
    "GenerationDiagnostic": ("routes.factory", "GenerationDiagnostic"),
    "GenerationReport": ("routes.factory", "GenerationReport"),
    "MaterializationDiagnostic": (
        "routes.materializer",
        "MaterializationDiagnostic",
    ),
    "MaterializationErrorCode": (
        "routes.materializer",
        "MaterializationErrorCode",
    ),
    "MaterializationResult": ("routes.materializer", "MaterializationResult"),
    "MAX_YAML_FILE_SIZE": ("routes.admission", "MAX_YAML_FILE_SIZE"),
    "ROUTE_FACTORY_V1_RUNTIME_FACTS": (
        "routes.admission",
        "ROUTE_FACTORY_V1_RUNTIME_FACTS",
    ),
    "RouteRegistry": ("routes.registry", "RouteRegistry"),
    "RuntimeFactAdaptation": (
        "routes.context_adapter",
        "RuntimeFactAdaptation",
    ),
    "RuntimeFactAdapter": ("routes.context_adapter", "RuntimeFactAdapter"),
    "WriteError": ("routes.writer", "WriteError"),
    "WriteErrorCode": ("routes.writer", "WriteErrorCode"),
    "WriteResult": ("routes.writer", "WriteResult"),
    "YamlPreview": ("routes.factory", "YamlPreview"),
    "admit_route": ("routes.admission", "admit_route"),
    "build_frontier": ("routes.frontier", "build_frontier"),
    "build_frontier_context": (
        "routes.context_adapter",
        "build_frontier_context",
    ),
    "candidate_route_filename": ("routes.writer", "candidate_route_filename"),
    "generate_candidate_routes": ("routes.factory", "generate_candidate_routes"),
    "load_and_admit_candidate_route": (
        "routes.admission",
        "load_and_admit_candidate_route",
    ),
    "materialize_route_plan": (
        "routes.materializer",
        "materialize_route_plan",
    ),
    "normalized_route_from_plain": (
        "routes.admission",
        "normalized_route_from_plain",
    ),
    "context_fingerprint": ("routes.frontier", "context_fingerprint"),
    "route_fingerprint": ("routes.registry", "route_fingerprint"),
    "render_candidate_route_yaml": ("routes.writer", "render_candidate_route_yaml"),
    "write_candidate_route": ("routes.writer", "write_candidate_route"),
}


def __getattr__(name: str):
    module_name, attribute_name = _LAZY_EXPORTS.get(name, (None, None))
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module

    value = getattr(import_module(module_name), attribute_name)
    globals()[name] = value
    return value


__all__ = [
    "ADMITTED_CANDIDATE",
    "Activation",
    "AdmissionDecision",
    "AdmissionDiagnostic",
    "AdmissionErrorCode",
    "FailurePolicy",
    "FrontierContext",
    "FrontierDiagnosticCode",
    "FrontierEntry",
    "DUPLICATE_ROUTE_ID",
    "GenerationDiagnostic",
    "GenerationReport",
    "MaterializationDeclaration",
    "MaterializationDiagnostic",
    "MaterializationErrorCode",
    "MaterializationResult",
    "MAX_YAML_FILE_SIZE",
    "NormalizationError",
    "NormalizationErrorCode",
    "NormalizationResult",
    "NormalizedRoute",
    "PrimitiveAdapter",
    "ReplayPolicy",
    "RegisteredRoute",
    "RegistryDiagnostic",
    "RegistryErrorCode",
    "RegistryLoadResult",
    "RegistryRegistrationResult",
    "ROUTE_FACTORY_V1_RUNTIME_FACTS",
    "RouteParseResult",
    "RouteProposal",
    "RouteRegistry",
    "RouteRegistrySnapshot",
    "RouteFrontier",
    "RouteRequirements",
    "RuntimeFactAdaptation",
    "RuntimeFactAdapter",
    "SuccessCriteria",
    "WriteError",
    "WriteErrorCode",
    "WriteResult",
    "YamlPreview",
    "admit_route",
    "build_frontier",
    "build_frontier_context",
    "candidate_route_filename",
    "generate_candidate_routes",
    "load_and_admit_candidate_route",
    "materialize_route_plan",
    "normalize_route_proposal",
    "normalized_route_from_plain",
    "context_fingerprint",
    "render_candidate_route_yaml",
    "route_fingerprint",
    "write_candidate_route",
]
