"""Phase 2 shared types: planner, verification, execution, and evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional


# --- Planner output (stub until teammate implements planner) ---


@dataclass
class PlannedStep:
    """Single step from the planning agent (mock or real)."""

    step_id: str
    title: str
    description: str
    # Shell command to run inside the sandbox (e.g. python one-liner, pytest, curl to local service)
    command: str
    related_cwe: Optional[str] = None
    expected_signal: Optional[str] = None  # what success looks like for the evaluator


@dataclass
class PlannerOutput:
    """Full plan from the planning agent."""

    plan_id: str
    vulnerability_id: str
    steps: list[PlannedStep] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


# --- Verification ---

VerificationDecision = Literal["APPROVE", "REJECT", "NEEDS_REVISION"]


@dataclass
class VerificationResult:
    decision: VerificationDecision
    reason: str
    risk_notes: list[str] = field(default_factory=list)
    raw_json: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "risk_notes": self.risk_notes,
            "raw_json": self.raw_json,
        }


# --- Execution ---


@dataclass
class ExecutionResult:
    success: bool
    exit_code: Optional[int]
    stdout: str
    stderr: str
    error_message: Optional[str] = None
    docker_image: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "error_message": self.error_message,
            "docker_image": self.docker_image,
        }


# --- Evaluation ---


EvaluationDecision = Literal["SUCCESS", "PARTIAL_SUCCESS", "FAILED", "INCONCLUSIVE"]


@dataclass
class EvaluationResult:
    decision: EvaluationDecision
    confidence: float
    rationale: str
    evidence_summary: str
    suggested_next_action: Optional[str] = None
    raw_json: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "evidence_summary": self.evidence_summary,
            "suggested_next_action": self.suggested_next_action,
            "raw_json": self.raw_json,
        }
