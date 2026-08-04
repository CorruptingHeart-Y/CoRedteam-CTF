"""Capability gate for executable technique memory."""

from __future__ import annotations

import ast
import re
import shlex
import sys
from copy import deepcopy
from typing import Any

from core.capability_registry import (
    CapabilityDecision,
    CapabilityRegistry,
    get_capability_registry,
    is_capability_available,
)


def _declared_capabilities(tech: dict[str, Any]) -> list[str]:
    declared: list[str] = []
    capability_id = tech.get("capability_id")
    if isinstance(capability_id, str) and capability_id.strip():
        declared.append(capability_id.strip())
    capabilities = tech.get("capabilities")
    if isinstance(capabilities, list):
        declared.extend(
            item.strip() for item in capabilities
            if isinstance(item, str) and item.strip()
        )
    interface = tech.get("execution_interface")
    if isinstance(interface, dict):
        adapter = interface.get("adapter")
        if isinstance(adapter, str) and adapter.strip():
            declared.append(adapter.strip())
    return list(dict.fromkeys(declared))


_EXECUTABLE_TEXT_FIELDS = (
    "content", "command", "executable_patch", "payload_template", "template",
)


def _tech_text(tech: dict[str, Any]) -> str:
    return "\n".join(
        value
        for field in _EXECUTABLE_TEXT_FIELDS
        if isinstance((value := tech.get(field)), str) and value.strip()
    )


def _inferred_capabilities(tech: dict[str, Any]) -> list[str]:
    """Infer only concrete runtime requirements from executable tech fields."""
    text = _tech_text(tech)
    inferred: list[str] = []
    if re.search(r"\bGrpcClient\b", text):
        inferred.append("grpc_client")
    if re.search(r"\bHttpClient\b", text):
        inferred.append("http_client")

    tech_type = str(tech.get("type") or "").strip().lower()
    if tech_type == "command":
        command = tech.get("content") or tech.get("command") or ""
        try:
            parts = shlex.split(command)
        except ValueError:
            parts = []
        if parts:
            tool = parts[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
            inferred.append(f"shell_command:{tool}")

    python_source = tech.get("executable_patch")
    if not isinstance(python_source, str) and tech_type in {"python", "script", "code"}:
        python_source = tech.get("content")
    if isinstance(python_source, str) and python_source.strip():
        try:
            tree = ast.parse(python_source)
        except SyntaxError:
            inferred.append("python_module:__invalid_syntax__")
        else:
            for node in ast.walk(tree):
                modules = []
                if isinstance(node, ast.Import):
                    modules = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    modules = [node.module]
                for module in modules:
                    root = module.split(".", 1)[0]
                    if root not in sys.stdlib_module_names and root != "redteam_sdk":
                        inferred.append(f"python_module:{module}")
    return list(dict.fromkeys(inferred))


def _strategy_pattern(tech: dict[str, Any], codes: list[str]) -> dict[str, Any]:
    return {
        "name": tech.get("vulnerability") or tech.get("name") or "capability strategy",
        "description": tech.get("description", ""),
        "pattern": tech.get("strategy") or tech.get("description") or "Executable technique requires unavailable runtime capability.",
        "type": "strategy",
        "source": "consolidator_capability_gate",
        "non_executable": True,
        "capability_diagnostics": codes,
        "cwe_ids": tech.get("cwe_ids", []),
        "tags": tech.get("tags", []),
    }


def gate_executable_tech_memory(
    memory_patch: dict[str, Any],
    registry: CapabilityRegistry | None = None,
) -> dict[str, Any]:
    """Downgrade techniques whose execution capability cannot be proven."""
    registry = registry or get_capability_registry()
    gated = deepcopy(memory_patch)
    techs = gated.get("techs") or []
    if not isinstance(techs, list):
        gated["techs"] = []
        return gated

    executable: list[dict[str, Any]] = []
    downgraded: list[dict[str, Any]] = []
    for tech in techs:
        if not isinstance(tech, dict):
            continue
        declared = list(dict.fromkeys(_declared_capabilities(tech) + _inferred_capabilities(tech)))
        required_modules = tech.get("required_modules") or []
        if not isinstance(required_modules, list):
            required_modules = [str(required_modules)]
        decisions: list[CapabilityDecision] = []
        for capability_id in declared:
            if capability_id.startswith("shell_command:"):
                allowed = is_capability_available(capability_id, registry)
                decisions.append(CapabilityDecision(
                    allowed,
                    "CAPABILITY_AVAILABLE" if allowed else "CAPABILITY_TOOL_UNAVAILABLE",
                    capability_id,
                ))
            elif capability_id.startswith("python_module:"):
                allowed = is_capability_available(capability_id, registry)
                decisions.append(CapabilityDecision(
                    allowed,
                    "CAPABILITY_AVAILABLE" if allowed else "CAPABILITY_MODULE_UNAVAILABLE",
                    capability_id,
                ))
            else:
                decisions.append(registry.validate(
                    capability_id=capability_id, required_modules=required_modules,
                ))
        if decisions and all(decision.allowed for decision in decisions):
            executable.append(tech)
            continue
        codes = [decision.code for decision in decisions] or [
            "CAPABILITY_NOT_REGISTERED"
        ]
        downgraded.append(_strategy_pattern(tech, codes))

    gated["techs"] = executable
    if downgraded:
        patterns = gated.get("patterns") or []
        gated["patterns"] = list(patterns) + downgraded
        # Explicit YAML operations can bypass the filtered tech list.
        gated["yaml_operations"] = []
    return gated


__all__ = ["gate_executable_tech_memory"]
