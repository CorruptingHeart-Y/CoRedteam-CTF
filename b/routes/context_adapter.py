from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from routes.primitive_adapter import PrimitiveAdapter
from routes.schema import FrontierContext


METHOD_RUNTIME_FACT_DEFERRED = "METHOD_RUNTIME_FACT_DEFERRED"
_REFLECTION_PRIMITIVE_ID = "ssti_reflection"


@dataclass(frozen=True)
class RuntimeFactAdaptation:
    runtime_facts: Mapping[str, object]
    deferred: tuple[str, ...]

    def __post_init__(self) -> None:
        frozen = FrontierContext(
            current_state="init",
            confirmed_signals=(),
            runtime_facts=self.runtime_facts,
        ).runtime_facts
        object.__setattr__(self, "runtime_facts", frozen)

    def to_plain(self) -> dict[str, object]:
        return {
            "runtime_facts": FrontierContext(
                current_state="init",
                confirmed_signals=(),
                runtime_facts=self.runtime_facts,
            ).to_plain()["runtime_facts"],
            "deferred": list(self.deferred),
        }


class RuntimeFactAdapter:
    @staticmethod
    def adapt(
        verification_memory: object,
        runtime_facts_source: Mapping[str, object] | None = None,
    ) -> RuntimeFactAdaptation:
        runtime_facts: dict[str, object] = {}

        injectable_endpoints = verification_memory.get_fact(
            "injectable_endpoints",
            (),
        )
        if isinstance(injectable_endpoints, (list, tuple)):
            endpoints = tuple(
                value
                for value in injectable_endpoints
                if isinstance(value, str) and value
            )
            if endpoints:
                runtime_facts["endpoint"] = endpoints

        injectable_params = verification_memory.get_fact("injectable_params", {})
        if isinstance(injectable_params, Mapping):
            parameters = {
                endpoint: tuple(
                    parameter
                    for parameter in values
                    if isinstance(parameter, str) and parameter
                )
                for endpoint, values in injectable_params.items()
                if isinstance(endpoint, str) and isinstance(values, (list, tuple))
            }
            parameters = {
                endpoint: values
                for endpoint, values in parameters.items()
                if values
            }
            if parameters:
                runtime_facts["parameter"] = parameters

        if runtime_facts_source is not None:
            for key, value in runtime_facts_source.items():
                if value is not None:
                    runtime_facts[key] = value

        deferred = (
            ()
            if "method" in runtime_facts
            else (METHOD_RUNTIME_FACT_DEFERRED,)
        )
        return RuntimeFactAdaptation(
            runtime_facts=runtime_facts,
            deferred=deferred,
        )


def _confirmed_signals(
    verification_memory: object,
    adapter: PrimitiveAdapter,
) -> tuple[str, ...]:
    confirmed: set[str] = set()
    working_primitives = verification_memory.get_fact("working_primitives", ())

    if isinstance(working_primitives, (list, tuple)):
        for item in working_primitives:
            primitive_id: str | None = None
            confidence = 0.0
            if isinstance(item, str):
                primitive_id = item
                confidence = 0.7
            elif isinstance(item, Mapping):
                raw_id = item.get("primitive_id")
                raw_confidence = item.get("confidence", 0.0)
                if isinstance(raw_id, str):
                    primitive_id = raw_id
                if type(raw_confidence) in (int, float):
                    confidence = float(raw_confidence)
            if primitive_id and confidence >= 0.5:
                confirmed.update(
                    adapter.get_supported_requirement_signals(primitive_id)
                )

    if verification_memory.get_fact("reflection_confirmed", False) is True:
        signal = adapter.get_confirmation_signal(_REFLECTION_PRIMITIVE_ID)
        if signal:
            confirmed.add(signal)

    return tuple(sorted(confirmed))


def build_frontier_context(
    adapter: PrimitiveAdapter,
    *,
    trajectory: object | None = None,
    verification_memory: object | None = None,
    runtime_facts_source: Mapping[str, object] | None = None,
) -> FrontierContext:
    if trajectory is None:
        from memory.exploit_trajectory import get_trajectory

        trajectory = get_trajectory()
    if verification_memory is None:
        from memory.verification_memory import get_verification

        verification_memory = get_verification()

    adaptation = RuntimeFactAdapter.adapt(
        verification_memory,
        runtime_facts_source,
    )
    return FrontierContext(
        current_state=trajectory.get_current_state(),
        confirmed_signals=_confirmed_signals(verification_memory, adapter),
        runtime_facts=adaptation.runtime_facts,
    )
