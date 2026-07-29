from __future__ import annotations

import hashlib
import json

from routes.schema import (
    FrontierContext,
    FrontierDiagnosticCode,
    FrontierEntry,
    RouteFrontier,
    RouteRegistrySnapshot,
)


ELIGIBLE = "eligible"
BLOCKED = "blocked"


def context_fingerprint(context: FrontierContext) -> str:
    canonical_json = json.dumps(
        context.to_plain(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical_json).hexdigest()


def build_frontier(
    registry_snapshot: RouteRegistrySnapshot,
    context: FrontierContext,
) -> RouteFrontier:
    eligible: list[FrontierEntry] = []
    blocked: list[FrontierEntry] = []
    confirmed_signals = frozenset(context.confirmed_signals)
    runtime_fact_keys = frozenset(context.runtime_facts)

    for registered in sorted(
        registry_snapshot.routes,
        key=lambda item: item.canonical_id,
    ):
        route = registered.route
        diagnostics: list[str] = []

        if route.requires.current_state != context.current_state:
            diagnostics.append(
                FrontierDiagnosticCode.STATE_REQUIREMENT_UNSATISFIED.value
            )

        if not set(route.requires.signals).issubset(confirmed_signals):
            diagnostics.append(
                FrontierDiagnosticCode.MISSING_REQUIRED_SIGNALS.value
            )

        if not set(route.requires.runtime_facts).issubset(runtime_fact_keys):
            diagnostics.append(FrontierDiagnosticCode.MISSING_RUNTIME_FACT.value)

        status = BLOCKED if diagnostics else ELIGIBLE
        entry = FrontierEntry(
            route_id=registered.canonical_id,
            status=status,
            diagnostics=tuple(diagnostics),
        )
        (blocked if diagnostics else eligible).append(entry)

    return RouteFrontier(
        eligible_routes=tuple(eligible),
        blocked_routes=tuple(blocked),
        context_fingerprint=context_fingerprint(context),
    )
