"""Runtime capability manifest for deterministic execution interfaces.

This registry describes execution adapters only.  It does not participate in
route selection, primitive resolution, FSM transitions, or YAML admission.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class CapabilitySpec:
    capability_id: str
    adapter: str
    required_modules: tuple[str, ...]
    allowed_calls: tuple[str, ...]
    runtime_requirements: Mapping[str, Any]
    available: bool = True

    def to_manifest(self) -> dict[str, Any]:
        return {
            "id": self.capability_id,
            "adapter": self.adapter,
            "required_modules": list(self.required_modules),
            "allowed_calls": list(self.allowed_calls),
            "runtime_requirements": dict(self.runtime_requirements),
            "available": self.available,
        }


@dataclass(frozen=True)
class CapabilityDecision:
    allowed: bool
    code: str
    capability_id: str | None = None
    detail: str = ""


class CapabilityRegistry:
    """In-memory, fail-closed registry for execution capabilities."""

    def __init__(self, capabilities: Iterable[CapabilitySpec] = ()) -> None:
        self._by_id: dict[str, CapabilitySpec] = {}
        self._by_adapter: dict[str, CapabilitySpec] = {}
        self._by_call: dict[str, CapabilitySpec] = {}
        for capability in capabilities:
            self.register(capability)

    def register(self, capability: CapabilitySpec) -> None:
        capability_id = capability.capability_id.strip().lower()
        adapter = capability.adapter.strip()
        if not capability_id or not adapter or not capability.allowed_calls:
            raise ValueError("capability id, adapter, and allowed_calls are required")
        if capability_id in self._by_id or adapter in self._by_adapter:
            raise ValueError(f"duplicate capability registration: {capability_id}")
        for call in capability.allowed_calls:
            if call in self._by_call:
                raise ValueError(f"duplicate capability call registration: {call}")
        self._by_id[capability_id] = capability
        self._by_adapter[adapter] = capability
        for call in capability.allowed_calls:
            self._by_call[call] = capability

    def get(self, capability_id: str) -> CapabilitySpec | None:
        return self._by_id.get(str(capability_id).strip().lower())

    def for_adapter(self, adapter: str) -> CapabilitySpec | None:
        return self._by_adapter.get(str(adapter).strip())

    def for_call(self, call: str) -> CapabilitySpec | None:
        return self._by_call.get(str(call).strip().rstrip("("))

    def allowed_calls(self) -> tuple[str, ...]:
        return tuple(sorted(self._by_call))

    def manifest(self) -> tuple[dict[str, Any], ...]:
        return tuple(
            self._by_id[key].to_manifest() for key in sorted(self._by_id)
        )

    def validate(
        self,
        *,
        capability_id: str | None = None,
        adapter: str | None = None,
        call: str | None = None,
        required_modules: Iterable[str] = (),
    ) -> CapabilityDecision:
        spec = None
        if capability_id:
            spec = self.get(capability_id)
        elif adapter:
            spec = self.for_adapter(adapter)
        elif call:
            spec = self.for_call(call)
        if spec is None:
            return CapabilityDecision(False, "CAPABILITY_NOT_REGISTERED")
        if not spec.available:
            return CapabilityDecision(
                False, "CAPABILITY_UNAVAILABLE", spec.capability_id
            )
        if adapter and adapter != spec.adapter:
            return CapabilityDecision(
                False, "CAPABILITY_ADAPTER_MISMATCH", spec.capability_id
            )
        normalized_call = str(call or "").strip().rstrip("(")
        if normalized_call and normalized_call not in spec.allowed_calls:
            return CapabilityDecision(
                False, "CAPABILITY_CALL_NOT_ALLOWED", spec.capability_id
            )
        declared_modules = {str(module).strip() for module in required_modules}
        unavailable = declared_modules.difference(spec.required_modules)
        if unavailable:
            return CapabilityDecision(
                False,
                "CAPABILITY_DEPENDENCY_UNAVAILABLE",
                spec.capability_id,
                ",".join(sorted(unavailable)),
            )
        return CapabilityDecision(True, "CAPABILITY_AVAILABLE", spec.capability_id)


CAPABILITY_REGISTRY = CapabilityRegistry((
    CapabilitySpec(
        capability_id="http_client",
        adapter="HttpClient",
        required_modules=("requests", "urllib3"),
        allowed_calls=(
            "HttpClient.get",
            "HttpClient.post",
            "HttpClient.raw_request",
            "HttpClient.last_response",
        ),
        runtime_requirements={"protocols": ["http", "https"]},
    ),
    CapabilitySpec(
        capability_id="grpc_client",
        adapter="GrpcClient",
        required_modules=("grpc", "google.protobuf", "grpc_reflection"),
        allowed_calls=("GrpcClient.call",),
        runtime_requirements={
            "protocol": "grpc",
            "transport": "http2",
            "serialization": "protobuf",
            "service_reflection": True,
        },
    ),
))


def get_capability_registry() -> CapabilityRegistry:
    return CAPABILITY_REGISTRY


def is_capability_available(
    capability: str | Mapping[str, Any],
    registry: CapabilityRegistry | None = None,
    *,
    available_commands: Iterable[str] = (),
    available_modules: Iterable[str] | None = None,
) -> bool:
    """Query the runtime manifest without creating a second capability source."""
    registry = registry or get_capability_registry()
    if isinstance(capability, Mapping):
        kind = str(
            capability.get("kind")
            or capability.get("capability")
            or capability.get("id")
            or ""
        ).strip().lower()
        name = str(capability.get("name") or capability.get("value") or "").strip()
        raw = f"{kind}:{name}" if name else kind
    else:
        raw = str(capability).strip()

    spec = registry.get(raw) or registry.for_adapter(raw) or registry.for_call(raw)
    if spec is not None:
        return spec.available

    kind, separator, name = raw.partition(":")
    kind = kind.strip().lower()
    name = name.strip()
    if kind == "shell_command":
        commands = {
            str(command).strip().lower()
            for command in available_commands
            if str(command).strip()
        }
        return name.lower() in commands if separator else bool(commands)
    if kind == "python_module":
        if available_modules is None:
            modules = {
                module
                for item in registry.manifest()
                if item["available"]
                for module in item["required_modules"]
            }
        else:
            modules = {str(module).strip() for module in available_modules}
        return name in modules if separator else bool(modules)
    return False


__all__ = [
    "CapabilityDecision",
    "CapabilityRegistry",
    "CapabilitySpec",
    "CAPABILITY_REGISTRY",
    "get_capability_registry",
    "is_capability_available",
]
