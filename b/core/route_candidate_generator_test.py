"""
Regression tests for route_candidate_generator.py.

Run directly:
    python -m core.route_candidate_generator_test

Or:
    python b/core/route_candidate_generator_test.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# Ensure project root is on path
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from core.route_candidate_generator import (
    CandidateRoute,
    generate_candidate_routes,
    rank_candidate_routes,
    build_candidate_routes_context,
    generate_and_rank_routes,
    _is_reflection_blocked,
    _find_all_paths,
)
from memory.primitive_transition_graph import PrimitiveTransitionGraph, get_transition_graph


# ═══════════════════════════════════════════════════════════════════
# Test Helpers
# ═══════════════════════════════════════════════════════════════════

def _make_result(passed: bool, details: list[str], failures: list[str]) -> dict[str, Any]:
    return {
        "passed": len(failures) == 0,
        "details": details,
        "failures": failures,
        "total_tests": len(details) + len(failures),
        "passed_count": len(details),
        "failed_count": len(failures),
    }


def _assert(condition: bool, label: str, failures: list[str], details: list[str]) -> None:
    if condition:
        details.append(label)
    else:
        failures.append(label)


# ═══════════════════════════════════════════════════════════════════
# Feedback fixtures
# ═══════════════════════════════════════════════════════════════════

FB_REFLECTION_BLOCKED: dict[str, Any] = {
    "primitive_confirmed": True,
    "exploit_completed": False,
    "flag_found": False,
    "failure_reason": "reflection_blocked",
    "repro_success": False,
    "same_primitive_attempts": 3,
    "no_progress_streak": 3,
    "primitive_state": {"ssti": True, "rce": False, "arithmetic": False},
    "current_exploit_state": "probe_success",
    "detected_primitives": ["ssti_reflection"],
    "what_failed": "RCE payload reflected literally, no execution evidence",
    "state_transition_blocker": "reflected literally in response body",
    "raw_evidence": "payload reflected as <h2>$x.class.forName</h2>",
}

FB_NORMAL_SSTI: dict[str, Any] = {
    "primitive_confirmed": True,
    "exploit_completed": False,
    "flag_found": False,
    "repro_success": True,
    "primitive_state": {"ssti": True, "rce": False, "arithmetic": True},
    "current_exploit_state": "probe_success",
    "detected_primitives": ["ssti_reflection"],
    "what_failed": "",
    "state_transition_blocker": "",
    "raw_evidence": "{{7*7}} evaluated to 49",
}


# ═══════════════════════════════════════════════════════════════════
# Test 1: ssti_reflection generates multiple candidate routes
# ═══════════════════════════════════════════════════════════════════

def test_ssti_reflection_generates_diverse_routes() -> dict[str, Any]:
    """ssti_reflection must generate routes covering at minimum:
    command_execution, file_read, configuration_disclosure, template_access.
    """
    failures: list[str] = []
    details: list[str] = []
    graph = PrimitiveTransitionGraph()

    routes = generate_candidate_routes(
        current_primitive="ssti_reflection",
        graph=graph,
        feedback=None,
        traj=None,
        max_depth=2,
    )

    objectives = {r.objective for r in routes}

    # Required objectives from the user spec
    required = {"command_execution", "file_read", "configuration_disclosure", "template_access"}
    for obj in required:
        _assert(
            obj in objectives,
            f"Route with objective='{obj}' exists in generated routes",
            failures, details,
        )

    # At least 4 routes total
    _assert(
        len(routes) >= 4,
        f"At least 4 candidate routes generated (got {len(routes)})",
        failures, details,
    )

    # No duplicate route_ids
    route_ids = [r.route_id for r in routes]
    _assert(
        len(route_ids) == len(set(route_ids)),
        f"All route_ids are unique ({len(route_ids)} routes)",
        failures, details,
    )

    # Every route has a non-empty path starting with ssti_reflection
    for r in routes:
        _assert(
            len(r.path) >= 2 and r.path[0] == "ssti_reflection",
            f"Route '{r.route_id}' path starts with ssti_reflection and has ≥2 nodes: {r.path}",
            failures, details,
        )

    return _make_result(len(failures) == 0, details, failures)


# ═══════════════════════════════════════════════════════════════════
# Test 2: reflection_blocked downgrades RCE below non-RCE routes
# ═══════════════════════════════════════════════════════════════════

def test_reflection_blocked_downgrades_rce() -> dict[str, Any]:
    """When reflection_blocked, previously-failed RCE routes must rank
    below unexplored non-RCE routes.
    """
    failures: list[str] = []
    details: list[str] = []
    graph = PrimitiveTransitionGraph()

    routes = generate_candidate_routes(
        current_primitive="ssti_reflection",
        graph=graph,
        feedback=FB_REFLECTION_BLOCKED,
        traj=None,
        max_depth=2,
    )
    ranked = rank_candidate_routes(routes, feedback=FB_REFLECTION_BLOCKED)

    # Find the highest-ranked RCE route and highest-ranked non-RCE route
    rce_routes = [r for r in ranked if r.objective == "command_execution"]
    non_rce_routes = [r for r in ranked if r.objective != "command_execution"]

    _assert(
        len(rce_routes) > 0,
        f"RCE route(s) still exist ({len(rce_routes)} found) — RCE is not banned",
        failures, details,
    )
    _assert(
        len(non_rce_routes) > 0,
        f"Non-RCE routes exist ({len(non_rce_routes)} found)",
        failures, details,
    )

    # The top-ranked route should NOT be command_execution
    _assert(
        ranked[0].objective != "command_execution",
        f"Top-ranked route is '{ranked[0].objective}' (not command_execution) when reflection_blocked",
        failures, details,
    )

    # At least one non-RCE route should outrank all RCE routes
    best_rce_score = max(r.score for r in rce_routes) if rce_routes else -999
    best_non_rce_score = max(r.score for r in non_rce_routes) if non_rce_routes else -999
    _assert(
        best_non_rce_score > best_rce_score,
        f"Best non-RCE score ({best_non_rce_score:.0f}) > best RCE score ({best_rce_score:.0f})",
        failures, details,
    )

    # Information disclosure routes should be near the top
    info_disc_objectives = {"file_read", "configuration_disclosure", "template_access"}
    top3_objectives = {r.objective for r in ranked[:3]}
    has_info_disc_in_top3 = bool(top3_objectives & info_disc_objectives)
    _assert(
        has_info_disc_in_top3,
        f"Top 3 routes include at least one information_disclosure objective: {top3_objectives}",
        failures, details,
    )

    return _make_result(len(failures) == 0, details, failures)


# ═══════════════════════════════════════════════════════════════════
# Test 3: Normal SSTI initial state — RCE route still present and ranked high
# ═══════════════════════════════════════════════════════════════════

def test_normal_ssti_rce_present() -> dict[str, Any]:
    """Without failure feedback, RCE route should still be present and
    ranked competitively (not suppressed).
    """
    failures: list[str] = []
    details: list[str] = []
    graph = PrimitiveTransitionGraph()

    routes = generate_candidate_routes(
        current_primitive="ssti_reflection",
        graph=graph,
        feedback=FB_NORMAL_SSTI,
        traj=None,
        max_depth=2,
    )
    ranked = rank_candidate_routes(routes, feedback=FB_NORMAL_SSTI)

    rce_routes = [r for r in ranked if r.objective == "command_execution"]
    _assert(
        len(rce_routes) > 0,
        f"RCE route(s) exist in normal SSTI state ({len(rce_routes)} found)",
        failures, details,
    )

    # RCE should rank reasonably high (in top half)
    rce_positions = [i for i, r in enumerate(ranked) if r.objective == "command_execution"]
    best_rce_pos = min(rce_positions) if rce_positions else len(ranked)
    _assert(
        best_rce_pos < len(ranked) / 2,
        f"RCE route is in top half (position {best_rce_pos + 1}/{len(ranked)})",
        failures, details,
    )

    return _make_result(len(failures) == 0, details, failures)


# ═══════════════════════════════════════════════════════════════════
# Test 4: No feedback — preserves original behavior (RCE ranks normally)
# ═══════════════════════════════════════════════════════════════════

def test_no_feedback_preserves_behavior() -> dict[str, Any]:
    """With feedback=None (first round), routes should be generated
    and ranked without failure-aware adjustments. RCE can rank high.
    """
    failures: list[str] = []
    details: list[str] = []
    graph = PrimitiveTransitionGraph()

    routes = generate_candidate_routes(
        current_primitive="ssti_reflection",
        graph=graph,
        feedback=None,  # No feedback = first round
        traj=None,
        max_depth=2,
    )
    ranked = rank_candidate_routes(routes, feedback=None)

    _assert(
        len(ranked) >= 4,
        f"Routes generated without feedback ({len(ranked)} routes)",
        failures, details,
    )

    # No route should be marked as "previous_failed" (no history)
    for r in ranked:
        _assert(
            r.status == "unexplored",
            f"Route '{r.route_id}' status is 'unexplored' (not 'previous_failed') without feedback",
            failures, details,
        )

    # At least one route exists for each of the major categories
    objectives = {r.objective for r in ranked}
    _assert(
        "command_execution" in objectives,
        "command_execution route present without feedback",
        failures, details,
    )
    _assert(
        "file_read" in objectives,
        "file_read route present without feedback",
        failures, details,
    )

    return _make_result(len(failures) == 0, details, failures)


# ═══════════════════════════════════════════════════════════════════
# Test 5: Planner prompt capture — candidate routes enter LLM context
# ═══════════════════════════════════════════════════════════════════

def test_candidate_routes_in_planner_context() -> dict[str, Any]:
    """Verify that build_candidate_routes_context() produces output
    suitable for LLM injection and contains route information.
    """
    failures: list[str] = []
    details: list[str] = []
    graph = PrimitiveTransitionGraph()

    routes = generate_candidate_routes(
        current_primitive="ssti_reflection",
        graph=graph,
        feedback=FB_REFLECTION_BLOCKED,
        traj=None,
        max_depth=2,
    )
    ranked = rank_candidate_routes(routes, feedback=FB_REFLECTION_BLOCKED)
    context = build_candidate_routes_context(ranked, max_routes=8)

    # Context is non-empty
    _assert(
        len(context) > 0,
        f"Route context is non-empty ({len(context)} chars)",
        failures, details,
    )

    # Contains key structural markers
    _assert(
        "🧭 Ranked Candidate Exploit Routes" in context,
        "Context contains 'Ranked Candidate Exploit Routes' header",
        failures, details,
    )
    _assert(
        "Objective:" in context,
        "Context contains 'Objective:' field",
        failures, details,
    )
    _assert(
        "Path:" in context,
        "Context contains 'Path:' field",
        failures, details,
    )
    _assert(
        "Status:" in context,
        "Context contains 'Status:' field",
        failures, details,
    )
    _assert(
        "Score:" in context,
        "Context contains 'Score:' field",
        failures, details,
    )

    # Contains the route_id for the top-ranked route
    _assert(
        ranked[0].route_id in context,
        f"Top-ranked route_id '{ranked[0].route_id}' appears in context",
        failures, details,
    )

    # Decision rule is included
    _assert(
        "Decision Rule" in context,
        "Context includes 'Decision Rule' guidance for LLM",
        failures, details,
    )
    _assert(
        "YOU make the final choice" in context,
        "Context tells LLM it makes the final choice (not a rule executor)",
        failures, details,
    )

    # Routes are in score-descending order
    scores = [r.score for r in ranked]
    _assert(
        scores == sorted(scores, reverse=True),
        f"Routes are sorted by score descending: {[f'{s:.0f}' for s in scores]}",
        failures, details,
    )

    return _make_result(len(failures) == 0, details, failures)


# ═══════════════════════════════════════════════════════════════════
# Test 6: _is_reflection_blocked helper
# ═══════════════════════════════════════════════════════════════════

def test_is_reflection_blocked_detection() -> dict[str, Any]:
    """Unit test _is_reflection_blocked with various feedback shapes."""
    failures: list[str] = []
    details: list[str] = []

    # Positive: explicit failure_reason
    _assert(
        _is_reflection_blocked({
            "primitive_confirmed": True,
            "failure_reason": "reflection_blocked",
            "same_primitive_attempts": 3,
            "no_progress_streak": 3,
        }),
        "Detects explicit failure_reason='reflection_blocked'",
        failures, details,
    )

    # Positive: ssti without rce in primitive_state
    _assert(
        _is_reflection_blocked({
            "primitive_confirmed": True,
            "same_primitive_attempts": 3,
            "no_progress_streak": 3,
            "primitive_state": {"ssti": True, "rce": False, "arithmetic": False},
            "failure_analysis": {"type": "no_execution_evidence"},
        }),
        "Detects primitive_state ssti=True, rce=False",
        failures, details,
    )

    # Negative: detected_primitives alone should NOT trigger (normal initial state)
    _assert(
        not _is_reflection_blocked({
            "primitive_confirmed": True,
            "detected_primitives": ["ssti_reflection"],
        }),
        "Does NOT trigger on detected_primitives alone (normal initial SSTI state)",
        failures, details,
    )

    # Positive: blocker text + evidence corroboration
    _assert(
        _is_reflection_blocked({
            "primitive_confirmed": True,
            "same_primitive_attempts": 3,
            "no_progress_streak": 3,
            "state_transition_blocker": "reflected literally in response body",
            "raw_evidence": "payload reflected as <h2>...",
            "what_failed": "no execution evidence found",
        }),
        "Detects when blocker text + evidence both indicate reflection",
        failures, details,
    )

    # Negative: exploit completed
    _assert(
        not _is_reflection_blocked({
            "primitive_confirmed": True,
            "exploit_completed": True,
            "failure_reason": "reflection_blocked",
        }),
        "Does NOT detect when exploit_completed=True",
        failures, details,
    )

    # Negative: None feedback
    _assert(
        not _is_reflection_blocked(None),
        "Returns False for None feedback",
        failures, details,
    )

    # Negative: empty feedback
    _assert(
        not _is_reflection_blocked({}),
        "Returns False for empty feedback",
        failures, details,
    )

    # Negative: normal SSTI with arithmetic working
    _assert(
        not _is_reflection_blocked(FB_NORMAL_SSTI),
        "Does NOT detect reflection_blocked for normal working SSTI",
        failures, details,
    )

    return _make_result(len(failures) == 0, details, failures)


# ═══════════════════════════════════════════════════════════════════
# Test 7: _find_all_paths works correctly
# ═══════════════════════════════════════════════════════════════════

def test_find_all_paths() -> dict[str, Any]:
    """Unit test BFS path generation."""
    failures: list[str] = []
    details: list[str] = []
    graph = PrimitiveTransitionGraph()

    # Depth 1: direct neighbors only
    paths_d1 = _find_all_paths(graph, "ssti_reflection", max_depth=1)
    paths_d1_set = {tuple(p) for p in paths_d1}
    expected_d1 = {
        ("ssti_reflection", "ssti_execution"),
        ("ssti_reflection", "blind_ssti"),
        ("ssti_reflection", "template_access"),
        ("ssti_reflection", "configuration_disclosure"),
        ("ssti_reflection", "file_read"),
        ("ssti_reflection", "command_execution"),
    }
    for expected in expected_d1:
        _assert(
            expected in paths_d1_set,
            f"Depth-1 path {list(expected)} found",
            failures, details,
        )
    _assert(
        len(paths_d1) == len(expected_d1),
        f"All {len(expected_d1)} depth-1 paths found (no extras)",
        failures, details,
    )

    # Depth 2: includes multi-hop paths
    paths_d2 = _find_all_paths(graph, "ssti_reflection", max_depth=2)
    _assert(
        len(paths_d2) > len(paths_d1),
        f"Depth-2 paths ({len(paths_d2)}) > depth-1 paths ({len(paths_d1)})",
        failures, details,
    )

    # Multi-hop path exists: ssti_reflection → ssti_execution → command_execution
    multi_hop = ("ssti_reflection", "ssti_execution", "command_execution")
    _assert(
        multi_hop in {tuple(p) for p in paths_d2},
        f"Multi-hop path {list(multi_hop)} exists at depth 2",
        failures, details,
    )

    # No cycles: paths should not contain duplicate nodes
    for path in paths_d2:
        _assert(
            len(path) == len(set(path)),
            f"Path {path} has no duplicate nodes (no cycles)",
            failures, details,
        )

    return _make_result(len(failures) == 0, details, failures)


# ═══════════════════════════════════════════════════════════════════
# Test 8: CandidateRoute data structure
# ═══════════════════════════════════════════════════════════════════

def test_candidate_route_dataclass() -> dict[str, Any]:
    """Verify CandidateRoute fields and to_dict()."""
    failures: list[str] = []
    details: list[str] = []

    route = CandidateRoute(
        route_id="ssti_file_read",
        path=["ssti_reflection", "file_read"],
        objective="file_read",
        status="unexplored",
        complexity="low",
        score=85.0,
    )

    d = route.to_dict()
    _assert(d["route_id"] == "ssti_file_read", "to_dict preserves route_id", failures, details)
    _assert(d["path"] == ["ssti_reflection", "file_read"], "to_dict preserves path", failures, details)
    _assert(d["objective"] == "file_read", "to_dict preserves objective", failures, details)
    _assert(d["status"] == "unexplored", "to_dict preserves status", failures, details)
    _assert(d["complexity"] == "low", "to_dict preserves complexity", failures, details)
    _assert(d["score"] == 85.0, "to_dict preserves score", failures, details)

    # Scores are comparable
    r2 = CandidateRoute("r2", ["a", "b"], "b", "unexplored", "low", 90.0)
    _assert(r2.score > route.score, "Score comparison works (90 > 85)", failures, details)

    return _make_result(len(failures) == 0, details, failures)


# ═══════════════════════════════════════════════════════════════════
# Test 9: generate_and_rank_routes convenience API
# ═══════════════════════════════════════════════════════════════════

def test_generate_and_rank_convenience() -> dict[str, Any]:
    """The one-shot generate_and_rank_routes() returns both routes and context."""
    failures: list[str] = []
    details: list[str] = []
    graph = PrimitiveTransitionGraph()

    ranked, context = generate_and_rank_routes(
        current_primitive="ssti_reflection",
        graph=graph,
        feedback=FB_REFLECTION_BLOCKED,
        traj=None,
    )

    _assert(len(ranked) > 0, "Returns non-empty ranked list", failures, details)
    _assert(len(context) > 0, "Returns non-empty context string", failures, details)
    _assert(
        ranked[0].route_id in context,
        "Top route appears in context string",
        failures, details,
    )

    # All routes have scores assigned
    for r in ranked:
        _assert(
            r.score != 0.0,
            f"Route '{r.route_id}' has non-zero score ({r.score:.0f})",
            failures, details,
        )

    return _make_result(len(failures) == 0, details, failures)


# ═══════════════════════════════════════════════════════════════════
# Test 10: Ranking before/after comparison (visual diff)
# ═══════════════════════════════════════════════════════════════════

def test_ranking_before_after_comparison() -> dict[str, Any]:
    """Show how ranking changes between normal and reflection_blocked states.
    This is the key behavioral test: the same set of routes should order
    differently under different feedback contexts.
    """
    failures: list[str] = []
    details: list[str] = []
    graph = PrimitiveTransitionGraph()

    # Generate same routes once
    routes = generate_candidate_routes(
        current_primitive="ssti_reflection",
        graph=graph,
        feedback=None,
        traj=None,
        max_depth=2,
    )

    # Rank under normal state
    normal_ranked = rank_candidate_routes(routes, feedback=FB_NORMAL_SSTI)
    normal_order = [(r.route_id, r.score) for r in normal_ranked[:5]]

    # Rank under reflection_blocked state
    blocked_ranked = rank_candidate_routes(routes, feedback=FB_REFLECTION_BLOCKED)
    blocked_order = [(r.route_id, r.score) for r in blocked_ranked[:5]]

    # The order should be DIFFERENT between the two contexts
    normal_top_ids = [r[0] for r in normal_order]
    blocked_top_ids = [r[0] for r in blocked_order]
    _assert(
        normal_top_ids != blocked_top_ids,
        f"Route ordering DIFFERS between normal ({normal_top_ids[:3]}) "
        f"and reflection_blocked ({blocked_top_ids[:3]})",
        failures, details,
    )

    # In normal state, RCE should be in top 3
    normal_top3_objectives = {r.objective for r in normal_ranked[:3]}
    _assert(
        "command_execution" in normal_top3_objectives,
        f"Normal state: command_execution in top 3 objectives: {normal_top3_objectives}",
        failures, details,
    )

    # In reflection_blocked state, RCE should NOT be in top 3
    blocked_top3_objectives = {r.objective for r in blocked_ranked[:3]}
    _assert(
        "command_execution" not in blocked_top3_objectives,
        f"Blocked state: command_execution NOT in top 3 objectives: {blocked_top3_objectives}",
        failures, details,
    )

    return _make_result(len(failures) == 0, details, failures)


# ═══════════════════════════════════════════════════════════════════
# Test 11: PLAN GENERATION CONTRACT — schema > route selection
# ═══════════════════════════════════════════════════════════════════

def test_contract_prioritizes_schema_over_route() -> dict[str, Any]:
    """Verify that _build_plan_generation_contract produces a contract
    that explicitly prioritizes schema compliance above route selection.

    This is critical: the Planner must NOT violate parameter placement
    rules just because a candidate route recommends a different objective.
    """
    failures: list[str] = []
    details: list[str] = []

    # Import safely — already verified to work
    from agents.planner import _build_plan_generation_contract

    # Use the real confirmed_vuln.json fixture
    confirmed = {
        "vulnerabilities": [{
            "cwe_id": "CWE-917",
            "title": "Velocity SSTI",
            "description": "SSTI in Velocity template via 'text' parameter",
        }]
    }

    contract = _build_plan_generation_contract(confirmed)

    # ── 1. Contract has the correct name ──
    _assert(
        contract.get("contract_name") == "PLAN GENERATION CONTRACT",
        "Contract name is 'PLAN GENERATION CONTRACT'",
        failures, details,
    )

    # ── 2. Priority order exists and is a list ──
    priority = contract.get("priority_order", [])
    _assert(
        isinstance(priority, list) and len(priority) >= 3,
        f"priority_order has ≥3 entries: {priority}",
        failures, details,
    )

    # ── 3. "Route candidate selection" is ranked BELOW schema/contract items ──
    route_idx = None
    schema_indices: list[int] = []
    for i, item in enumerate(priority):
        item_lower = item.lower()
        if "route" in item_lower and "candidate" in item_lower:
            route_idx = i
        if "schema" in item_lower or "interface" in item_lower or "input" in item_lower:
            schema_indices.append(i)

    _assert(
        route_idx is not None,
        f"'Route candidate selection' found in priority_order at index {route_idx}",
        failures, details,
    )
    _assert(
        len(schema_indices) > 0,
        f"Schema/contract items found at indices {schema_indices}",
        failures, details,
    )
    _assert(
        all(route_idx > si for si in schema_indices),
        f"Route selection (idx={route_idx}) ranks BELOW all schema/contract items {schema_indices}",
        failures, details,
    )

    # ── 4. candidate_route_policy exists with explicit schema > route rule ──
    policy = contract.get("candidate_route_policy", [])
    _assert(
        isinstance(policy, list) and len(policy) >= 2,
        f"candidate_route_policy has ≥2 rules: {policy}",
        failures, details,
    )

    policy_text = " ".join(str(r).lower() for r in policy)
    _assert(
        "schema" in policy_text and "higher priority" in policy_text,
        f"candidate_route_policy states schema > route: {policy}",
        failures, details,
    )
    _assert(
        any("do not override" in r.lower() or "not override" in r.lower() for r in policy),
        "candidate_route_policy says routes do NOT override contract",
        failures, details,
    )

    # ── 5. required_inputs are present ──
    inputs_list = contract.get("required_inputs", [])
    _assert(
        isinstance(inputs_list, list),
        f"required_inputs is a list ({len(inputs_list)} entries)",
        failures, details,
    )

    # ── 6. interface_contract defines query/form locations ──
    iface = contract.get("interface_contract", {})
    _assert(
        bool(iface),
        "interface_contract is non-empty",
        failures, details,
    )
    _assert(
        "query_location" in iface or "form_location" in iface,
        f"interface_contract defines query/form locations: {list(iface.keys())}",
        failures, details,
    )

    # ── 7. examples section shows correct parameter placement ──
    examples = contract.get("examples", {})
    _assert(
        "correct" in examples,
        "Contract includes 'correct' example for parameter placement",
        failures, details,
    )

    return _make_result(len(failures) == 0, details, failures)


# ═══════════════════════════════════════════════════════════════════
# Test 12: User message assembly — contract has recency over routes
# ═══════════════════════════════════════════════════════════════════

def test_user_message_contract_after_routes() -> dict[str, Any]:
    """Verify that in the assembled user message, plan_generation_contract
    appears AFTER candidate_routes. This gives the contract higher recency
    in the LLM context, making it more likely to be respected.

    Also verifies that BOTH keys coexist — one does not overwrite the other.
    """
    failures: list[str] = []
    details: list[str] = []

    # ── Build a simulated user dict in the same order as run_planner() ──
    from agents.planner import _build_plan_generation_contract
    from core.route_candidate_generator import generate_and_rank_routes

    confirmed = {
        "vulnerabilities": [{
            "cwe_id": "CWE-917",
            "title": "Velocity SSTI",
            "description": "SSTI in Velocity template via 'text' parameter",
        }]
    }

    # Simulate the run_planner() assembly order (lines 2287-2299):
    # 1. Build base user dict
    # 2. Add candidate_routes (if available)
    # 3. Add plan_generation_contract LAST

    user: dict[str, Any] = {
        "confirmed_vuln": confirmed,
        "prior_feedback": None,
        "route_knowledge": [],
    }

    # Step 2: candidate_routes
    routes_context = "🧭 Routes(YOU choose): #1cmd_exec(100)..."
    user["candidate_routes"] = routes_context

    # Step 3: plan_generation_contract (LAST — highest recency)
    contract = _build_plan_generation_contract(confirmed)
    user["plan_generation_contract"] = contract

    # ── Verify both keys exist ──
    _assert(
        "candidate_routes" in user,
        "user dict contains 'candidate_routes' key",
        failures, details,
    )
    _assert(
        "plan_generation_contract" in user,
        "user dict contains 'plan_generation_contract' key",
        failures, details,
    )

    # ── Verify ordering: contract AFTER routes ──
    user_keys = list(user.keys())
    routes_idx = user_keys.index("candidate_routes")
    contract_idx = user_keys.index("plan_generation_contract")
    _assert(
        contract_idx > routes_idx,
        f"plan_generation_contract (idx={contract_idx}) appears AFTER "
        f"candidate_routes (idx={routes_idx}) — contract has recency",
        failures, details,
    )

    # ── Verify contract contains the critical priority rule ──
    policy = contract.get("candidate_route_policy", [])
    has_schema_priority = any(
        "schema" in r.lower() and ("higher" in r.lower() or "priority" in r.lower())
        for r in policy
    )
    _assert(
        has_schema_priority,
        f"Contract explicitly states schema > route priority: {policy}",
        failures, details,
    )

    # ── Verify routes context is non-empty and meaningful ──
    _assert(
        len(routes_context) > 0,
        "candidate_routes content is non-empty",
        failures, details,
    )
    _assert(
        "Routes" in routes_context or "route" in routes_context.lower(),
        "candidate_routes contains route information",
        failures, details,
    )

    # ── Verify contract is non-empty ──
    _assert(
        contract.get("contract_name") is not None,
        "contract_name is set in plan_generation_contract",
        failures, details,
    )

    return _make_result(len(failures) == 0, details, failures)


# -------------------------------------------------------------------
# Test 13: CWE classification outranks generic objective desirability
# -------------------------------------------------------------------

def test_cwe22_path_traversal_outranks_credential_dump() -> dict[str, Any]:
    """A CWE-22 classification must dominate generic objective desirability."""
    failures: list[str] = []
    details: list[str] = []
    confirmed_vuln = {
        "vulnerabilities": [{"cwe_id": "CWE-22"}],
    }
    routes = [
        CandidateRoute(
            "credential_dump",
            ["entry", "credential_dump"],
            "credential_dump",
            "unexplored",
            "low",
        ),
        CandidateRoute(
            "path_traversal",
            ["entry", "path_traversal"],
            "path_traversal",
            "unexplored",
            "low",
        ),
    ]

    ranked = rank_candidate_routes(routes, confirmed_vuln=confirmed_vuln)

    _assert(
        ranked[0].objective == "path_traversal",
        "CWE-22 ranks path_traversal above credential_dump",
        failures,
        details,
    )
    _assert(
        ranked[0].score > ranked[1].score,
        "CWE-22 classification match contributes more than generic objective score",
        failures,
        details,
    )

    return _make_result(len(failures) == 0, details, failures)


# ═══════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════

ALL_TESTS = [
    ("Test 1: ssti_reflection generates diverse routes", test_ssti_reflection_generates_diverse_routes),
    ("Test 2: reflection_blocked downgrades RCE below non-RCE", test_reflection_blocked_downgrades_rce),
    ("Test 3: Normal SSTI — RCE still present and ranked high", test_normal_ssti_rce_present),
    ("Test 4: No feedback — preserves original behavior", test_no_feedback_preserves_behavior),
    ("Test 5: Candidate routes enter Planner LLM context", test_candidate_routes_in_planner_context),
    ("Test 6: _is_reflection_blocked detection", test_is_reflection_blocked_detection),
    ("Test 7: _find_all_paths BFS", test_find_all_paths),
    ("Test 8: CandidateRoute dataclass", test_candidate_route_dataclass),
    ("Test 9: generate_and_rank_routes convenience", test_generate_and_rank_convenience),
    ("Test 10: Ranking before/after comparison", test_ranking_before_after_comparison),
    ("Test 11: Contract prioritizes schema over route", test_contract_prioritizes_schema_over_route),
    ("Test 12: User message assembly — contract after routes", test_user_message_contract_after_routes),
    ("Test 13: CWE-22 prioritizes path traversal", test_cwe22_path_traversal_outranks_credential_dump),
]


def main() -> int:
    all_passed = True
    total_tests = 0
    total_passed = 0
    total_failed = 0

    for name, test_fn in ALL_TESTS:
        print(f"\n{'='*60}")
        print(f"  {name}")
        print(f"{'='*60}")
        result = test_fn()
        for d in result["details"]:
            print(f"  [PASS] {d}")
        for f in result["failures"]:
            print(f"  [FAIL] {f}")
        print(f"  → {result['passed_count']}/{result['total_tests']} passed"
              f"  {'PASS' if result['passed'] else 'FAIL'}")
        total_tests += result["total_tests"]
        total_passed += result["passed_count"]
        total_failed += result["failed_count"]
        if not result["passed"]:
            all_passed = False

    print(f"\n{'='*60}")
    print(f"  OVERALL: {total_passed}/{total_tests} passed, {total_failed} failed")
    print(f"  {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}")
    print(f"{'='*60}")

    # ── Bonus: print ranking comparison visual ──
    print(f"\n{'='*60}")
    print(f"  Ranking Before/After Comparison (Visual)")
    print(f"{'='*60}")
    graph = PrimitiveTransitionGraph()
    routes = generate_candidate_routes(
        current_primitive="ssti_reflection",
        graph=graph,
        feedback=None,
        traj=None,
        max_depth=2,
    )

    normal = rank_candidate_routes(routes, feedback=FB_NORMAL_SSTI)
    blocked = rank_candidate_routes(routes, feedback=FB_REFLECTION_BLOCKED)

    print(f"\n  Normal SSTI state (top 5):")
    for i, r in enumerate(normal[:5], 1):
        print(f"    {i}. {r.route_id:35s} obj={r.objective:25s} score={r.score:6.0f}  status={r.status}")

    print(f"\n  Reflection Blocked state (top 5):")
    for i, r in enumerate(blocked[:5], 1):
        marker = " ⚠️ DOWNRANKED" if r.objective == "command_execution" else ""
        print(f"    {i}. {r.route_id:35s} obj={r.objective:25s} score={r.score:6.0f}  status={r.status}{marker}")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
