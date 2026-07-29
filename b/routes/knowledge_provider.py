"""Payload-free, advisory knowledge derived from manual route YAML."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml

from memory.primitive_transition_graph import (
    PrimitiveTransitionGraph,
    get_transition_graph,
)


_KNOWN_OUTCOMES = frozenset({"success", "failure", "mixed", "unknown"})


@dataclass(frozen=True)
class RouteKnowledge:
    """Planner-safe metadata for one route hypothesis.

    This type intentionally has no payload, request, materialization, or step
    fields. Adding one would turn advisory knowledge into an execution contract.
    """

    cwe: str
    primitive: str
    route_state: str
    possible_transitions: tuple[str, ...]
    expected_signals: tuple[str, ...]
    strategy_class: str
    route_status: str
    historical_outcome: str

    def to_plain(self) -> dict[str, Any]:
        return {
            "cwe": self.cwe,
            "primitive": self.primitive,
            "route_state": self.route_state,
            "possible_transitions": list(self.possible_transitions),
            "expected_signals": list(self.expected_signals),
            "strategy_class": self.strategy_class,
            "route_status": self.route_status,
            "historical_outcome": self.historical_outcome,
        }


class RouteKnowledgeProvider:
    """Read manual route hypotheses as non-executable Planner knowledge."""

    def __init__(
        self,
        route_root: Path | None = None,
        transition_graph: PrimitiveTransitionGraph | None = None,
    ) -> None:
        self.route_root = (
            route_root
            or Path(__file__).resolve().parents[1] / "data" / "manual_routes"
        )
        # Reuse the authoritative graph; do not maintain a second transition source.
        self._transition_graph = transition_graph or get_transition_graph()

    def collect(self, cwe_ids: Iterable[str] | None = None) -> list[RouteKnowledge]:
        wanted = {cwe.strip().upper() for cwe in (cwe_ids or []) if cwe}
        wanted_entry_primitives = set(
            self._transition_graph.get_entry_primitives(sorted(wanted))
        )
        if not self.route_root.exists():
            return []

        knowledge: list[RouteKnowledge] = []
        yaml_paths = sorted(self.route_root.rglob("*.yml"))
        yaml_paths += sorted(self.route_root.rglob("*.yaml"))
        for yaml_path in yaml_paths:
            doc = self._load_route(yaml_path)
            if not doc:
                continue

            cwe = str(doc.get("cwe_id") or "").strip().upper()
            primitive = str(doc.get("target_primitive") or "").strip()
            if not cwe or not primitive:
                continue
            # CWE aliases (for example CWE-917 and CWE-94) share an entry
            # primitive in the authoritative transition graph.
            if wanted and cwe not in wanted and primitive not in wanted_entry_primitives:
                continue

            activation = doc.get("activation")
            activation_state = (
                str(activation.get("state") or "").strip()
                if isinstance(activation, dict)
                else ""
            )
            route_status = (
                str(doc.get("generation_status") or "").strip()
                or activation_state
                or "candidate_only"
            )

            metadata = doc.get("metadata")
            declared_strategy_class = (
                str(metadata.get("strategy_class") or "").strip()
                if isinstance(metadata, dict)
                else ""
            )
            strategy_class = (
                declared_strategy_class
                or str(doc.get("technique") or "").strip()
                or primitive
            )

            outcome = str(doc.get("historical_outcome") or "unknown").strip().lower()
            if outcome not in _KNOWN_OUTCOMES:
                outcome = "unknown"

            knowledge.append(
                RouteKnowledge(
                    cwe=cwe,
                    primitive=primitive,
                    route_state=str(doc.get("current_state") or "unknown").strip(),
                    possible_transitions=tuple(
                        self._transition_graph.get_next_primitives(primitive)
                    ),
                    expected_signals=tuple(
                        self._string_list(doc.get("expected_signals"))
                    ),
                    strategy_class=strategy_class,
                    route_status=route_status,
                    historical_outcome=outcome,
                )
            )
        return knowledge

    def for_confirmed(self, confirmed: dict[str, Any]) -> list[RouteKnowledge]:
        cwe_ids = [
            str(v.get("cwe_id") or v.get("cwe") or "")
            for v in (confirmed.get("vulnerabilities") or [])
            if isinstance(v, dict)
        ]
        return self.collect(cwe_ids)

    def build_planner_context(self, confirmed: dict[str, Any]) -> str:
        knowledge = self.for_confirmed(confirmed)
        if not knowledge:
            return ""

        lines = [
            "【Route Intelligence Block — advisory prior only】",
            "Authority: advisory_only; execution_authority: none.",
            "Use route transitions and expected signals to rank objectives",
            "against confirmed facts and evaluator feedback.",
            "Candidate-only routes must never be copied into execution steps.",
            "The LLM Planner remains the sole plan decision-maker.",
        ]
        for item in knowledge:
            plain = item.to_plain()
            lines.append(
                f"- primitive={plain['primitive']}; "
                f"route_state={plain['route_state']}; "
                f"possible_transitions={plain['possible_transitions']}; "
                f"expected_signals={plain['expected_signals']}; "
                f"strategy_class={plain['strategy_class']}; "
                f"route_status={plain['route_status']}; "
                f"historical_outcome={plain['historical_outcome']}"
            )
        return "\n".join(lines)

    @staticmethod
    def _string_list(value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        return [str(item).strip() for item in value if str(item).strip()]

    @staticmethod
    def _load_route(path: Path) -> dict[str, Any] | None:
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return None
        if len(raw.encode("utf-8")) > 256 * 1024:
            return None
        try:
            loaded = yaml.safe_load(raw)
        except yaml.YAMLError:
            return None
        return loaded if isinstance(loaded, dict) else None


def build_route_knowledge_context(
    confirmed: dict[str, Any],
    route_root: Path | None = None,
    transition_graph: PrimitiveTransitionGraph | None = None,
) -> str:
    """Build the payload-free Route Intelligence Block for Planner."""

    return RouteKnowledgeProvider(route_root, transition_graph).build_planner_context(
        confirmed
    )
