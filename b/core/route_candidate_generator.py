"""
Route Candidate Generator — pure logic component between PrimitiveTransitionGraph and Planner.

Generates multi-step candidate exploit routes from the current primitive,
ranks them with failure-aware scoring, and formats them for LLM injection.

Design principle:
  PrimitiveTransitionGraph → Candidate Route Generator → Route Ranking → Planner

The Planner still makes the final decision — this component only shapes the search space.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from memory.primitive_transition_graph import PrimitiveTransitionGraph, get_transition_graph
from memory.exploit_trajectory import ExploitTrajectoryMemory, get_trajectory


# ═══════════════════════════════════════════════════════════════════
# Data Structures
# ═══════════════════════════════════════════════════════════════════

@dataclass
class CandidateRoute:
    """A candidate exploit route from current primitive to an objective."""

    route_id: str
    path: list[str]               # ordered list of primitives, e.g. ["ssti_reflection", "file_read"]
    objective: str                 # terminal primitive — the goal of this route
    status: str                    # "unexplored" | "in_progress" | "previous_failed" | "completed"
    complexity: str                # "low" (1 hop) | "medium" (2 hops) | "high" (3+ hops)
    score: float = 0.0             # ranking score (higher = better); set by rank_candidate_routes()

    def to_dict(self) -> dict[str, Any]:
        return {
            "route_id": self.route_id,
            "path": self.path,
            "objective": self.objective,
            "status": self.status,
            "complexity": self.complexity,
            "score": self.score,
        }


# ═══════════════════════════════════════════════════════════════════
# Objective Classification
# ═══════════════════════════════════════════════════════════════════

# Primitives classified by exploit objective category
_ESCALATION_OBJECTIVES: set[str] = {
    "command_execution",
    "ssti_execution",
    "sql_union",
    "sql_stacked",
    "command_substitution",
    "blind_rce_oob",
}

_INFORMATION_DISCLOSURE_OBJECTIVES: set[str] = {
    "arbitrary_file_read",
    "file_read",
    "template_access",
    "configuration_disclosure",
    "credential_dump",
    "privilege_discovery",
    "filesystem_traversal",
    "xpath_injection",
    "ldap_injection",
}

_OOB_OBJECTIVES: set[str] = {
    "http_callback",
    "dns_exfiltration",
    "blind_ssti",
    "async_job_trigger",
}

# Base desirability score by objective type (0-100, higher = more desirable)
_BASE_OBJECTIVE_SCORES: dict[str, float] = {
    "command_execution": 90.0,
    "credential_dump": 85.0,
    "arbitrary_file_read": 70.0,
    "file_read": 70.0,
    "privilege_discovery": 60.0,
    "ssti_execution": 55.0,
    "sql_union": 50.0,
    "sql_stacked": 50.0,
    "command_substitution": 50.0,
    "filesystem_traversal": 45.0,
    "template_access": 40.0,
    "configuration_disclosure": 40.0,
    "blind_rce_oob": 40.0,
    "http_callback": 35.0,
    "dns_exfiltration": 35.0,
    "blind_ssti": 30.0,
    "async_job_trigger": 30.0,
    "deserialization_object_injection": 55.0,
    "xpath_injection": 40.0,
    "ldap_injection": 35.0,
}


def _is_escalation(obj: str) -> bool:
    return obj in _ESCALATION_OBJECTIVES


def _is_information_disclosure(obj: str) -> bool:
    return obj in _INFORMATION_DISCLOSURE_OBJECTIVES


def _is_oob(obj: str) -> bool:
    return obj in _OOB_OBJECTIVES


# ═══════════════════════════════════════════════════════════════════
# Path Generation (BFS)
# ═══════════════════════════════════════════════════════════════════

def _find_all_paths(
    graph: PrimitiveTransitionGraph,
    from_primitive: str,
    max_depth: int = 2,
) -> list[list[str]]:
    """BFS to find all paths from a primitive up to max_depth hops beyond it.

    Args:
        graph: The primitive transition graph.
        from_primitive: Starting primitive ID.
        max_depth: Maximum additional hops (1 = direct neighbors only).

    Returns:
        List of paths, each a list of primitive IDs starting with from_primitive.
        A path of length N has N-1 hops (edges).
    """
    paths: list[list[str]] = []

    # Queue: (current_node, path_so_far)
    queue: list[tuple[str, list[str]]] = [(from_primitive, [from_primitive])]

    while queue:
        current, path = queue.pop(0)

        # max_depth+1 because path includes the start node
        if len(path) > max_depth + 1:
            continue

        next_prims = graph.get_next_primitives(current)
        for next_p in next_prims:
            if next_p in path:  # avoid cycles
                continue
            new_path = path + [next_p]
            paths.append(new_path)
            if len(new_path) <= max_depth:
                queue.append((next_p, new_path))

    return paths


# ═══════════════════════════════════════════════════════════════════
# Status Detection
# ═══════════════════════════════════════════════════════════════════

def _detect_route_status(
    path: list[str],
    traj: ExploitTrajectoryMemory | None,
) -> str:
    """Determine the status of a candidate route based on trajectory history.

    Returns one of: "unexplored", "in_progress", "previous_failed", "completed"
    """
    if traj is None or not traj.nodes:
        return "unexplored"

    objective = path[-1]
    intermediate = set(path[1:-1])  # primitives between start and objective

    # Collect what's been tried and succeeded
    attempted_primitives: set[str] = set()
    succeeded_primitives: set[str] = set()
    failed_primitives: set[str] = set()

    for node in traj.nodes:
        dp = getattr(node, "detected_primitive", "")
        if dp:
            attempted_primitives.add(dp)
            if getattr(node, "success", False):
                succeeded_primitives.add(dp)
            else:
                failed_primitives.add(dp)

    # Check if the objective was already achieved
    if objective in succeeded_primitives:
        return "completed"

    # Check if the objective was attempted but failed
    if objective in failed_primitives:
        return "previous_failed"

    # Check if any intermediate primitive was attempted
    if intermediate & attempted_primitives:
        return "in_progress"

    # Check if the start primitive itself was attempted (everything starts somewhere)
    if attempted_primitives:
        return "in_progress"

    return "unexplored"


# ═══════════════════════════════════════════════════════════════════
# Route ID Generation
# ═══════════════════════════════════════════════════════════════════

def _make_route_id(path: list[str]) -> str:
    """Generate a unique, descriptive route ID from the full path."""
    # Use all nodes in path to guarantee uniqueness
    return "__".join(path)


def _make_complexity(hops: int) -> str:
    """Classify complexity by hop count."""
    if hops <= 1:
        return "low"
    elif hops == 2:
        return "medium"
    else:
        return "high"


# ═══════════════════════════════════════════════════════════════════
# Main API: generate_candidate_routes
# ═══════════════════════════════════════════════════════════════════

def generate_candidate_routes(
    current_primitive: str,
    graph: PrimitiveTransitionGraph | None = None,
    feedback: dict[str, Any] | None = None,
    traj: ExploitTrajectoryMemory | None = None,
    max_depth: int = 2,
) -> list[CandidateRoute]:
    """Generate all candidate exploit routes from the current primitive.

    Args:
        current_primitive: The currently confirmed primitive (e.g. "ssti_reflection").
        graph: The primitive transition graph. Uses singleton if None.
        feedback: Latest evaluator feedback dict (may be None for first round).
        traj: Exploit trajectory for status detection. Uses singleton if None.
        max_depth: Maximum hops to explore (1 = direct neighbors only).

    Returns:
        Unranked list of candidate routes. Call rank_candidate_routes() next.
    """
    if graph is None:
        graph = get_transition_graph()
    if traj is None:
        try:
            traj = get_trajectory()
        except Exception:
            traj = None

    # Deduplicate by path (list → tuple for hashing)
    seen_paths: set[tuple[str, ...]] = set()
    routes: list[CandidateRoute] = []

    all_paths = _find_all_paths(graph, current_primitive, max_depth=max_depth)

    for path in all_paths:
        path_tuple = tuple(path)
        if path_tuple in seen_paths:
            continue
        seen_paths.add(path_tuple)

        objective = path[-1]
        hops = len(path) - 1
        route_id = _make_route_id(path)
        status = _detect_route_status(path, traj)
        complexity = _make_complexity(hops)

        routes.append(CandidateRoute(
            route_id=route_id,
            path=path,
            objective=objective,
            status=status,
            complexity=complexity,
            score=0.0,  # will be set by rank_candidate_routes()
        ))

    return routes


# ═══════════════════════════════════════════════════════════════════
# Route Ranking
# ═══════════════════════════════════════════════════════════════════

def rank_candidate_routes(
    routes: list[CandidateRoute],
    feedback: dict[str, Any] | None = None,
) -> list[CandidateRoute]:
    """Score and rank candidate routes with failure-aware heuristics.

    Ranking principles:
    1. All legitimate objectives remain — RCE is never banned, only deprioritized.
    2. When reflection_blocked: information_disclosure > escalation.
    3. Unexplored routes are preferred over previously-failed ones.
    4. Shorter (lower complexity) paths are preferred all else equal.

    IMPORTANT: This function does NOT mutate the input list. It returns a NEW
    sorted list with updated scores. Callers can safely call it twice with
    different feedback dicts on the same route set.

    Args:
        routes: Unranked candidate routes from generate_candidate_routes().
        feedback: Evaluator feedback dict for failure-aware adjustments.

    Returns:
        NEW list of routes sorted by score descending.
    """
    if not routes:
        return []

    # ── Determine failure context ──
    is_reflection_blocked = _is_reflection_blocked(feedback)

    # Work on copies — do not mutate caller's routes
    scored: list[CandidateRoute] = []
    for route in routes:
        score = _compute_route_score(route, is_reflection_blocked)
        # Create a copy with the new score
        scored.append(CandidateRoute(
            route_id=route.route_id,
            path=list(route.path),
            objective=route.objective,
            status=route.status,
            complexity=route.complexity,
            score=score,
        ))

    # Sort descending by score, then by complexity (prefer simpler at equal score)
    scored.sort(key=lambda r: (r.score, _complexity_order(r.complexity)), reverse=True)
    return scored


def _is_reflection_blocked(feedback: dict[str, Any] | None) -> bool:
    """Detect whether the current exploit context is reflection-blocked.

    Requires strong signals — does NOT trigger on mere absence of execution.
    A normal initial SSTI state (reflection detected, no execution tried yet)
    is NOT reflection_blocked. Only triggers when execution has been attempted
    and explicitly blocked/reflected.
    """
    if not feedback or not isinstance(feedback, dict):
        return False

    if not feedback.get("primitive_confirmed"):
        return False
    if feedback.get("exploit_completed") or feedback.get("flag_found"):
        return False

    # ── Signal 1: Explicit failure_reason (strongest) ──
    failure_reason = str(feedback.get("failure_reason", "")).lower()
    if "reflection" in failure_reason and "blocked" in failure_reason:
        return True

    # ── Signal 2: primitive_state shows SSTI without RCE AND without arithmetic ──
    # Arithmetic working but execution blocked = reflection_blocked
    # Arithmetic NOT working = still probing, not definitively blocked
    ps = feedback.get("primitive_state", {})
    if isinstance(ps, dict):
        if ps.get("ssti") and not ps.get("rce") and not ps.get("arithmetic"):
            return True

    # ── Signal 3: multi-signal — explicit blocker text mentions reflection ──
    blocker = str(feedback.get("state_transition_blocker", "")).lower()
    what_failed = str(feedback.get("what_failed", "")).lower()
    reflection_keywords = ("reflected literally", "reflected as", "no execution")
    if any(kw in blocker or kw in what_failed for kw in reflection_keywords):
        # Need corroborating evidence — not just detected_primitives alone
        evidence = str(feedback.get("raw_evidence", "")).lower()
        if any(kw in evidence for kw in ("reflected", "no execution")):
            return True

    return False


def _complexity_order(complexity: str) -> int:
    """Map complexity label to numeric order (higher = preferred)."""
    return {"low": 3, "medium": 2, "high": 1}.get(complexity, 0)


def _compute_route_score(route: CandidateRoute, is_reflection_blocked: bool) -> float:
    """Compute a single route's score based on objective type, status, and context.

    Scoring formula:
      base = _BASE_OBJECTIVE_SCORES[objective] (default 25.0)
      - PATH_PENALTY: -10 per extra hop beyond 1
      + STATUS_BONUS/PENALTY
      + CONTEXT_ADJUSTMENT (reflection_blocked)

    Returns score as float. No floor/ceiling — raw values for comparison.
    """
    objective = route.objective
    base = _BASE_OBJECTIVE_SCORES.get(objective, 25.0)
    hops = len(route.path) - 1

    # ── Path length penalty ──
    path_penalty = max(0, (hops - 1)) * 10.0

    score = base - path_penalty

    # ── Status adjustments ──
    if route.status == "previous_failed":
        score -= 30.0
    elif route.status == "unexplored":
        score += 10.0
    elif route.status == "completed":
        score -= 50.0  # already done, don't repeat

    # ── Failure-aware context adjustments ──
    if is_reflection_blocked:
        if _is_escalation(objective):
            # Downgrade RCE/execution objectives when reflection is blocked
            score -= 40.0
        if _is_information_disclosure(objective):
            # Boost info-disclosure objectives — they don't need code execution
            score += 25.0
        if _is_oob(objective) and objective != "blind_ssti":
            # OOB channels are valid alternatives when in-band execution is blocked
            score += 10.0

    return score


# ═══════════════════════════════════════════════════════════════════
# LLM Context Formatting
# ═══════════════════════════════════════════════════════════════════

def build_candidate_routes_context(
    routes: list[CandidateRoute],
    max_routes: int = 8,
) -> str:
    """Format ranked candidate routes for injection into the Planner's LLM prompt.

    The output is designed to be scannable for an LLM — structured but not
    overly verbose. The Planner still makes the final decision.

    Args:
        routes: Ranked list of candidate routes (already scored and sorted).
        max_routes: Maximum number of routes to include (top-N by score).

    Returns:
        Formatted string ready for injection into the system prompt.
    """
    if not routes:
        return ""

    top_routes = routes[:max_routes]

    lines: list[str] = []
    lines.append("── 🧭 Ranked Candidate Exploit Routes ──")
    lines.append("")
    lines.append("Compare these routes before choosing your next step.")
    lines.append("Each route represents a complete exploit path from your current primitive.")
    lines.append("Higher-ranked routes are recommended based on exploit context and history.")
    lines.append("")

    for i, route in enumerate(top_routes, 1):
        status_marker = ""
        if route.status == "previous_failed":
            status_marker = " ⚠️ PREVIOUSLY FAILED — consider only if no unexplored alternatives"
        elif route.status == "unexplored":
            status_marker = " ✨ UNEXPLORED"
        elif route.status == "completed":
            status_marker = " ✓ ALREADY COMPLETED"

        path_str = " → ".join(route.path)
        lines.append(f"  Route #{i}: {route.route_id}")
        lines.append(f"    Path:        {path_str}")
        lines.append(f"    Objective:   {route.objective}")
        lines.append(f"    Complexity:  {route.complexity} ({len(route.path) - 1} hop(s))")
        lines.append(f"    Status:      {route.status}{status_marker}")
        lines.append(f"    Score:       {route.score:.0f}")
        lines.append("")

    lines.append("【Decision Rule】")
    lines.append("  • You are the Planner — YOU make the final choice among these routes.")
    lines.append("  • Higher score = more recommended given current context, NOT mandatory.")
    lines.append("  • If you have strong reason to deviate, explain your rationale.")
    lines.append("  • Do NOT blindly pick Route #1 — think about why it's ranked highest.")
    lines.append("  • Prefer unexplored routes over previously-failed ones.")
    lines.append("  • Once you choose a route, plan concrete steps along its path.")
    lines.append("")

    return "\n".join(lines)


def build_candidate_routes_context_compact(
    routes: list[CandidateRoute],
    max_routes: int = 6,
) -> str:
    """Build ultra-compact ranked route summary for budget-constrained prompts.

    Target: ~250-300 chars for max_routes=6. ONE line, no visual separators
    (──/═══/╔) that would trigger the budget splitter. Uses `|` as route
    delimiter to survive aggressive memory compaction.

    Format:
      🧭 Routes(YOU choose): #1 cmd_exec(100)ssti_reflection→cmd_exec|...
    """
    if not routes:
        return ""

    top_routes = routes[:max_routes]
    parts: list[str] = []
    for i, route in enumerate(top_routes, 1):
        path_compact = "→".join(route.path)
        icon = ""
        if route.status == "unexplored":
            icon = "✨"
        elif route.status == "previous_failed":
            icon = "⚠️"
        elif route.status == "completed":
            icon = "✓"
        parts.append(
            f"#{i}{route.objective}({route.score:.0f}){path_compact}{icon}"
        )

    header = "🧭 Routes(YOU choose): "
    return header + " | ".join(parts)


def build_candidate_routes_context_verbose(
    routes: list[CandidateRoute],
    max_routes: int = 8,
) -> str:
    """Build verbose multi-line candidate routes for non-budget-constrained use.
    This is the original format with per-route details and decision rules.
    """
    if not routes:
        return ""

    top_routes = routes[:max_routes]

    lines: list[str] = []
    lines.append("── 🧭 Ranked Candidate Exploit Routes ──")
    lines.append("")
    lines.append("Compare these routes before choosing your next step.")
    lines.append("Each route represents a complete exploit path from your current primitive.")
    lines.append("Higher-ranked routes are recommended based on exploit context and history.")
    lines.append("")

    for i, route in enumerate(top_routes, 1):
        status_marker = ""
        if route.status == "previous_failed":
            status_marker = " ⚠️ PREVIOUSLY FAILED — consider only if no unexplored alternatives"
        elif route.status == "unexplored":
            status_marker = " ✨ UNEXPLORED"
        elif route.status == "completed":
            status_marker = " ✓ ALREADY COMPLETED"

        path_str = " → ".join(route.path)
        lines.append(f"  Route #{i}: {route.route_id}")
        lines.append(f"    Path:        {path_str}")
        lines.append(f"    Objective:   {route.objective}")
        lines.append(f"    Complexity:  {route.complexity} ({len(route.path) - 1} hop(s))")
        lines.append(f"    Status:      {route.status}{status_marker}")
        lines.append(f"    Score:       {route.score:.0f}")
        lines.append("")

    lines.append("【Decision Rule】")
    lines.append("  • You are the Planner — YOU make the final choice among these routes.")
    lines.append("  • Higher score = more recommended given current context, NOT mandatory.")
    lines.append("  • If you have strong reason to deviate, explain your rationale.")
    lines.append("  • Do NOT blindly pick Route #1 — think about why it's ranked highest.")
    lines.append("  • Prefer unexplored routes over previously-failed ones.")
    lines.append("  • Once you choose a route, plan concrete steps along its path.")
    lines.append("")

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════
# High-Level Convenience API
# ═══════════════════════════════════════════════════════════════════

def generate_and_rank_routes(
    current_primitive: str,
    graph: PrimitiveTransitionGraph | None = None,
    feedback: dict[str, Any] | None = None,
    traj: ExploitTrajectoryMemory | None = None,
    max_depth: int = 2,
    max_routes: int = 8,
) -> tuple[list[CandidateRoute], str]:
    """One-shot: generate, rank, and format candidate routes.

    Args:
        current_primitive: The currently confirmed primitive.
        graph: Transition graph (singleton if None).
        feedback: Evaluator feedback (None = first round / no context).
        traj: Trajectory for status detection.
        max_depth: Max hops for path generation.
        max_routes: Max routes in formatted context.

    Returns:
        (ranked_routes, formatted_context_string)
    """
    routes = generate_candidate_routes(
        current_primitive=current_primitive,
        graph=graph,
        feedback=feedback,
        traj=traj,
        max_depth=max_depth,
    )
    ranked = rank_candidate_routes(routes, feedback=feedback)
    context = build_candidate_routes_context(ranked, max_routes=max_routes)
    return ranked, context


# ═══════════════════════════════════════════════════════════════════
# Backward Compatibility & Test Helpers
# ═══════════════════════════════════════════════════════════════════

# Alias for tests that import the verbose format
build_candidate_routes_context = build_candidate_routes_context_verbose


def _reset_for_testing() -> None:
    """Reset module-level state for test isolation. Not for production use."""
    pass
