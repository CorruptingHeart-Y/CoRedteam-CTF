"""Pure validation for Planner execution-interface declarations."""

from __future__ import annotations

from typing import Any

from core.capability_registry import CapabilityRegistry, get_capability_registry


def validate_capability_contract(
    plan: dict[str, Any],
    registry: CapabilityRegistry | None = None,
) -> list[str]:
    registry = registry or get_capability_registry()
    errors: list[str] = []
    declarations = [("plan", plan)]
    primitive_context = plan.get("primitive_context")
    if isinstance(primitive_context, dict):
        declarations.append(("primitive_context", primitive_context))
    declarations.extend(
        (f"steps[{idx}]", step)
        for idx, step in enumerate(plan.get("steps") or [])
        if isinstance(step, dict)
    )

    declared_capabilities: set[str] = set()
    observed_capabilities: set[str] = set()
    for label, declaration in declarations:
        interface = declaration.get("execution_interface")
        if interface is None:
            continue
        if not isinstance(interface, dict) or not isinstance(interface.get("adapter"), str):
            errors.append(f"[CAPABILITY_CONTRACT_INVALID] {label}.execution_interface.adapter")
            continue
        adapter_id = interface["adapter"].strip()
        decision = registry.validate(capability_id=adapter_id)
        if not decision.allowed:
            errors.append(
                f"[{decision.code}] {label}.execution_interface.adapter={adapter_id}"
            )
            continue
        declared_capabilities.add(decision.capability_id or adapter_id)

    for idx, step in enumerate(plan.get("steps") or []):
        if not isinstance(step, dict):
            continue
        for call_idx, call in enumerate(step.get("sdk_calls") or []):
            call_name = call.get("primitive", "") if isinstance(call, dict) else str(call)
            decision = registry.validate(call=call_name)
            if not decision.allowed:
                errors.append(
                    f"[{decision.code}] steps[{idx}].sdk_calls[{call_idx}]={call_name}"
                )
                continue
            capability_id = decision.capability_id or ""
            observed_capabilities.add(capability_id)
            if declared_capabilities and capability_id not in declared_capabilities:
                errors.append(
                    f"[CAPABILITY_ADAPTER_MISMATCH] steps[{idx}].sdk_calls[{call_idx}]={call_name}"
                )
            if capability_id == "grpc_client" and isinstance(call, dict):
                for field in ("target", "service", "method", "payload"):
                    if call.get(field) in (None, ""):
                        errors.append(
                            f"[CAPABILITY_CONTRACT_INVALID] steps[{idx}].sdk_calls[{call_idx}].{field}"
                        )
                if not isinstance(call.get("payload"), dict):
                    errors.append(
                        f"[CAPABILITY_CONTRACT_INVALID] steps[{idx}].sdk_calls[{call_idx}].payload"
                    )
                if not isinstance(call.get("metadata", {}), dict):
                    errors.append(
                        f"[CAPABILITY_CONTRACT_INVALID] steps[{idx}].sdk_calls[{call_idx}].metadata"
                    )
    if "grpc_client" in observed_capabilities and "grpc_client" not in declared_capabilities:
        errors.append("[CAPABILITY_DECLARATION_REQUIRED] grpc_client")
    if "grpc_client" in declared_capabilities and "grpc_client" not in observed_capabilities:
        errors.append("[CAPABILITY_CALL_REQUIRED] GrpcClient.call")
    return errors


__all__ = ["validate_capability_contract"]
