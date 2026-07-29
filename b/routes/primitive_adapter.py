from __future__ import annotations

import hashlib
import re

from memory.exploit_primitives import PrimitiveRegistry
from memory.exploit_trajectory import VALID_STATES
from memory.primitive_transition_graph import PrimitiveTransitionGraph


class PrimitiveAdapter:
    """Read-only view over the existing primitive and state fact sources."""

    def __init__(
        self,
        registry: PrimitiveRegistry | None = None,
        transition_graph: PrimitiveTransitionGraph | None = None,
    ) -> None:
        self._registry = registry or PrimitiveRegistry()
        self._transition_graph = transition_graph or PrimitiveTransitionGraph(self._registry)

    def primitive_exists(self, primitive_id: str) -> bool:
        return self._registry.get(primitive_id) is not None

    def get_observable_signals(self, primitive_id: str) -> tuple[str, ...]:
        primitive = self._registry.get(primitive_id)
        return tuple(primitive.observable_signals) if primitive else ()

    def get_payload_template_refs(self, primitive_id: str) -> tuple[str, ...]:
        primitive = self._registry.get(primitive_id)
        if primitive is None:
            return ()
        return tuple(
            self._stable_payload_template_ref(primitive_id, template)
            for template in primitive.payload_templates
        )

    def payload_template_exists(self, primitive_id: str, template_ref: str) -> bool:
        return self.resolve_payload_template_ref(primitive_id, template_ref) is not None

    def resolve_payload_template_ref(
        self,
        primitive_id: str,
        template_ref: str,
    ) -> int | None:
        primitive = self._registry.get(primitive_id)
        if primitive is None:
            return None

        legacy_match = re.fullmatch(
            rf"primitive:{re.escape(primitive_id)}:([0-9]+)",
            template_ref,
        )
        if legacy_match:
            index = int(legacy_match.group(1))
            return index if index < len(primitive.payload_templates) else None

        stable_match = re.fullmatch(
            rf"primitive:{re.escape(primitive_id)}:sha256:([0-9a-f]{{16}})",
            template_ref,
        )
        if stable_match:
            fingerprint = stable_match.group(1)
            for index, template in enumerate(primitive.payload_templates):
                if self._payload_fingerprint(template) == fingerprint:
                    # Duplicate payload strings are semantically identical; the
                    # stable reference resolves to their first matching position.
                    return index
        return None

    @staticmethod
    def _payload_fingerprint(template: str) -> str:
        return hashlib.sha256(template.encode("utf-8")).hexdigest()[:16]

    @classmethod
    def _stable_payload_template_ref(cls, primitive_id: str, template: str) -> str:
        return f"primitive:{primitive_id}:sha256:{cls._payload_fingerprint(template)}"

    def state_exists(self, state: str) -> bool:
        return state in VALID_STATES

    def transition_exists(self, source_primitive: str, target_primitive: str) -> bool:
        return target_primitive in tuple(
            self._transition_graph.get_next_primitives(source_primitive)
        )

    def get_entry_primitives(self, cwe_id: str) -> tuple[str, ...]:
        return tuple(self._transition_graph.get_entry_primitives([cwe_id]))

    def get_confirmation_signal(self, primitive_id: str) -> str | None:
        """Return the evidence_requirements / confirmation signal name for a primitive.

        Reads the ``confirmation`` field from the canonical
        ``INJECTION_PRIMITIVES`` / ``POST_EXPLOITATION_PRIMITIVES`` /
        ``OOB_PRIMITIVES`` definitions (exposed via ``ExploitPrimitive``).
        Returns ``None`` when the primitive is unknown or its confirmation
        is empty.
        """
        primitive = self._registry.get(primitive_id)
        if primitive is None:
            return None
        return primitive.evidence_requirements or None

    def get_supported_requirement_signals(
        self,
        primitive_id: str,
    ) -> tuple[str, ...]:
        """Return the set of signal names that a route targeting *primitive_id*
        may declare in ``requires.signals``.

        The returned tuple is built dynamically from the existing
        ``ExploitPrimitive`` fields:

        * ``observable_signals`` — signals the primitive can produce
        * ``evidence_requirements`` — the confirmation signal (if non-empty)

        No signal names are hard-coded or aliased inside the routes package.
        """
        primitive = self._registry.get(primitive_id)
        if primitive is None:
            return ()
        supported = list(primitive.observable_signals)
        confirmation = primitive.evidence_requirements
        if confirmation and confirmation not in supported:
            supported.append(confirmation)
        return tuple(supported)
