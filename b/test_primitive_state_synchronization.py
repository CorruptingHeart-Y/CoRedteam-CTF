from __future__ import annotations

import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
B_DIR = ROOT / "b"
if str(B_DIR) not in sys.path:
    sys.path.insert(0, str(B_DIR))

from agents.planner import _build_exploit_transition_context
import coordinator
from memory.exploit_trajectory import ExploitTrajectoryMemory


def test_evaluator_current_primitive_reaches_next_planner_context(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    trajectory = ExploitTrajectoryMemory(tmp_path / "trajectory.json")
    trajectory.append(
        round_id=1,
        detected_primitive="ssti_reflection",
        primitive_confidence=1.0,
    )
    monkeypatch.setattr(coordinator, "get_trajectory", lambda: trajectory)

    coordinator._record_trajectory_entry(
        iteration=2,
        fb={
            "confirmed_primitives": ["ssti_reflection", "command_execution"],
            "current_primitive": "command_execution",
        },
        plan={"steps": []},
        exec_out={"step_results": []},
        step_results=[],
    )

    planner_context = _build_exploit_transition_context(trajectory)
    assert planner_context["current_primitive"] == "command_execution"
