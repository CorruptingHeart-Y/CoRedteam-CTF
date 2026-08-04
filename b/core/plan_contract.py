"""Shared Plan Structural Contract.

Pure-function structural validation for plan JSON, extracted from the real
runtime Validator (``b/agents/validator.py::validate_plan``).  Both the runtime
Validator and the offline Route Materializer call :func:`validate_plan_structure`
so there is exactly one definition of "the plan's static structure is legal".

This module is deliberately side-effect free and depends only on the Python
standard library.  It does NOT import ``coordinator``, ``memory``, any LLM
client, or any networking component, and it does NOT consult the Runtime
Manifest, sandbox policy, trajectory, Verification Memory, or
AntiRegressionController.

A passing result means ONLY::

    PLAN_STRUCTURE_VALID

i.e. the plan's static JSON shape satisfies the Validator's structural input
contract.  It does NOT mean the runtime Validator will accept the plan —
runtime acceptance additionally requires Manifest, policy, trajectory,
Verification Memory, anti-regression and other current-state gates.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


# ═══════════════════════════════════════════════════════════════════
# Result types — immutable, stable, not reliant on English messages
# ═══════════════════════════════════════════════════════════════════


class PlanStructureErrorCode(str, Enum):
    """Stable, machine-readable structural error codes."""

    VERSION_INVALID = "VERSION_INVALID"
    STEPS_NOT_LIST = "STEPS_NOT_LIST"
    STEPS_EMPTY = "STEPS_EMPTY"
    STEP_NOT_DICT = "STEP_NOT_DICT"
    MIXED_PROTOCOL = "MIXED_PROTOCOL"
    STEP_TYPE_INVALID = "STEP_TYPE_INVALID"
    EMPTY_STEP = "EMPTY_STEP"
    IMPORTS_NOT_LIST = "IMPORTS_NOT_LIST"
    IMPORTS_INVALID_ELEMENT = "IMPORTS_INVALID_ELEMENT"
    PRIMITIVE_CONTEXT_INVALID = "PRIMITIVE_CONTEXT_INVALID"
    TARGET_PRIMITIVE_INVALID = "TARGET_PRIMITIVE_INVALID"
    SDK_PRIMITIVE_INVALID = "SDK_PRIMITIVE_INVALID"
    SDK_CALL_INVALID = "SDK_CALL_INVALID"
    SDK_TARGET_INVALID = "SDK_TARGET_INVALID"
    REQUEST_CONTAINER_INVALID = "REQUEST_CONTAINER_INVALID"


@dataclass(frozen=True)
class PlanStructureDiagnostic:
    code: PlanStructureErrorCode
    field: str | None
    message: str


@dataclass(frozen=True)
class PlanStructureResult:
    passed: bool
    diagnostics: tuple[PlanStructureDiagnostic, ...]

    @property
    def error_codes(self) -> tuple[PlanStructureErrorCode, ...]:
        return tuple(d.code for d in self.diagnostics)


# ═══════════════════════════════════════════════════════════════════
# Internal helpers — mirror validator._vtext semantics, no globals
# ═══════════════════════════════════════════════════════════════════

_VALID_STEP_TYPES = frozenset({"python", "shell"})


def _text(value: Any) -> str:
    """None-safe text normalization, matching validator._vtext."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _is_non_empty_list(value: Any) -> bool:
    return isinstance(value, list) and len(value) > 0


def _diag(
    code: PlanStructureErrorCode, field: str, message: str
) -> PlanStructureDiagnostic:
    return PlanStructureDiagnostic(code, field, message)


# ═══════════════════════════════════════════════════════════════════
# Per-step structural checks
# ═══════════════════════════════════════════════════════════════════


def _validate_step(st: Any, idx: int, diags: list[PlanStructureDiagnostic]) -> None:
    # Non-dict steps must be rejected structurally — the real Validator
    # calls st.get() unconditionally and would crash on a non-Mapping step.
    # The shared contract prevents that crash before the plan reaches the
    # runtime Validator.
    if not isinstance(st, Mapping):
        diags.append(_diag(
            PlanStructureErrorCode.STEP_NOT_DICT,
            f"steps[{idx}]",
            f"each step must be a JSON object (dict), got {type(st).__name__}",
        ))
        return

    label = f"steps[{idx}]"
    step_type = st.get("type")
    sdk_calls = st.get("sdk_calls")
    is_ast_mode = _is_non_empty_list(sdk_calls)

    if (
        not isinstance(step_type, str)
        or not step_type.strip()
        or step_type not in _VALID_STEP_TYPES
    ):
        diags.append(_diag(
            PlanStructureErrorCode.STEP_TYPE_INVALID,
            f"{label}.type",
            f"step[{idx}].type missing or invalid",
        ))

    # ── Mixed protocol: AST mode (sdk_calls present) + non-empty command ──
    # Faithful to validator.validate_plan lines ~929-937.
    if is_ast_mode:
        cmd = _text(st.get("command")).strip()
        if cmd:
            diags.append(_diag(
                PlanStructureErrorCode.MIXED_PROTOCOL,
                f"{label}.command",
                "sdk_calls and command must not coexist; AST mode forbids command",
            ))

    # ── Legacy mode (no sdk_calls): step type + non-empty payload ──
    # Faithful to validator._validate_step (type + at-least-one-of rule).
    if not is_ast_mode:
        cmd = _text(st.get("command")).strip()
        code = st.get("code")
        has_cmd = bool(cmd)
        has_code = isinstance(code, str) and bool(code.strip())
        has_sdk = _is_non_empty_list(sdk_calls)
        if not (has_cmd or has_code or has_sdk):
            diags.append(_diag(
                PlanStructureErrorCode.EMPTY_STEP,
                label,
                "step must declare at least one of command / code / sdk_calls",
            ))

    # ── imports: type-only structural check (when present) ──
    imports = st.get("imports")
    if imports is not None:
        if not isinstance(imports, list):
            diags.append(_diag(
                PlanStructureErrorCode.IMPORTS_NOT_LIST,
                f"{label}.imports",
                "`imports` must be an array when present",
            ))
        else:
            for imp in imports:
                if not isinstance(imp, str):
                    diags.append(_diag(
                        PlanStructureErrorCode.IMPORTS_INVALID_ELEMENT,
                        f"{label}.imports",
                        f"`imports` elements must be strings, got {type(imp).__name__}",
                    ))
                    break

    # ── target_primitive: type-only (presence is a runtime warning gate) ──
    tp = st.get("target_primitive")
    if tp is not None and not isinstance(tp, str):
        diags.append(_diag(
            PlanStructureErrorCode.TARGET_PRIMITIVE_INVALID,
            f"{label}.target_primitive",
            "`target_primitive` must be a string when present",
        ))

    # ── AST sdk_calls: structural type checks on the dict form ──
    if is_ast_mode:
        for cidx, call in enumerate(sdk_calls):
            if not isinstance(call, Mapping):
                diags.append(_diag(
                    PlanStructureErrorCode.SDK_CALL_INVALID,
                    f"{label}.sdk_calls[{cidx}]",
                    f"step[{idx}].sdk_calls[{cidx}] must be an object",
                ))
                continue
            field_prefix = f"{label}.sdk_calls[{cidx}]"

            primitive = call.get("primitive")
            if not isinstance(primitive, str) or not primitive.strip():
                diags.append(_diag(
                    PlanStructureErrorCode.SDK_PRIMITIVE_INVALID,
                    f"{field_prefix}.primitive",
                    "sdk_call `primitive` must be a non-empty string",
                ))

            target = call.get("target")
            if target is not None and not isinstance(target, str):
                diags.append(_diag(
                    PlanStructureErrorCode.SDK_TARGET_INVALID,
                    f"{field_prefix}.target",
                    "sdk_call `target` must be a string when present",
                ))

            for container in ("query", "body"):
                val = call.get(container)
                if val is not None and not isinstance(val, Mapping):
                    diags.append(_diag(
                        PlanStructureErrorCode.REQUEST_CONTAINER_INVALID,
                        f"{field_prefix}.{container}",
                        f"sdk_call `{container}` must be an object or null when present",
                    ))


# ═══════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════


def validate_plan_structure(plan: Mapping[str, Any]) -> PlanStructureResult:
    """Validate the static structural contract of a plan.

    Returns a :class:`PlanStructureResult` with deterministic diagnostic
    ordering.  ``passed`` is True iff the plan satisfies every static
    structural rule the runtime Validator enforces before its dynamic gates.

    This function reads no global state and performs no I/O.
    """
    if not isinstance(plan, Mapping):
        return PlanStructureResult(
            False,
            (_diag(
                PlanStructureErrorCode.STEPS_NOT_LIST,
                "plan",
                "plan must be a JSON object",
            ),),
        )

    diags: list[PlanStructureDiagnostic] = []

    # ── version ── (validator.validate_plan: version must be integer 1)
    if plan.get("version") != 1:
        diags.append(_diag(
            PlanStructureErrorCode.VERSION_INVALID,
            "version",
            "top-level field `version` must be integer 1",
        ))

    # ── steps ── (validator.validate_plan: steps must be a non-empty array)
    steps = plan.get("steps")
    if not isinstance(steps, list):
        diags.append(_diag(
            PlanStructureErrorCode.STEPS_NOT_LIST,
            "steps",
            "`steps` must be an array",
        ))
    elif not steps:
        diags.append(_diag(
            PlanStructureErrorCode.STEPS_EMPTY,
            "steps",
            "`steps` must be a non-empty array",
        ))
    else:
        for idx, st in enumerate(steps):
            _validate_step(st, idx, diags)

    # ── primitive_context: type-only (presence is a runtime warning gate) ──
    pctx = plan.get("primitive_context")
    if pctx is not None and not isinstance(pctx, Mapping):
        diags.append(_diag(
            PlanStructureErrorCode.PRIMITIVE_CONTEXT_INVALID,
            "primitive_context",
            "`primitive_context` must be an object when present",
        ))

    return PlanStructureResult(not diags, tuple(diags))


__all__ = [
    "PlanStructureErrorCode",
    "PlanStructureDiagnostic",
    "PlanStructureResult",
    "validate_plan_structure",
]
