"""Victory Screen -- hacker HUD terminal display for verified objective achievement.

Dark-terminal aesthetic: black background, neon-green accents, Rich Panel/Table/Layout.
No giant ASCII banners, no broken ++++ art.  Windows GBK-safe: ASCII-only icons.

Also writes workspace/success_summary.json (flag + metadata; NO payload content).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.table import Table
    from rich.columns import Columns
    from rich.layout import Layout
    from rich import box
    _RICH = True
except ImportError:
    _RICH = False

# ── Style constants ────────────────────────────────────────────────────
_G  = "bright_green"       # primary neon
_DG = "green"              # dim / secondary
_BG = "on black"           # background
_C  = "bright_cyan"        # accent
_Y  = "yellow"             # warn highlight
_M  = "dim green"          # muted

# ── Small ASCII trophy (compact, no deformation on narrow terminals) ───
_TROPHY = r"""
        .___.
       /     \
      |  [*]  |
       \     /
        `---`
    -- Co-RedTeam --
""".strip("\n")

# ── CRT scanline header / footer border ────────────────────────────────
_SCANLINE = "▬" * 78   # Windows GBK-safe?  Let's keep it ASCII
_HR = "=" * 78


def render_victory_screen(
    verification: dict[str, Any],
    target_info: dict[str, Any],
    plan: dict[str, Any] | None = None,
    step_results: list[dict] | None = None,
    runtime_sec: float = 0.0,
    workspace_dir: Path | None = None,
    challenge_name: str = "",
) -> None:
    """Display the hacker-HUD victory screen and write success_summary.json."""

    flag = verification.get("artifact", "???")
    step_id = verification.get("step_id", "?")
    source = verification.get("source_kind", "")
    method = verification.get("method", "")
    url = verification.get("url", "")
    status = verification.get("status_code")
    evidence_hash = verification.get("evidence_sha256", "")

    target_url = target_info.get("base_url", "unknown")
    target_name = target_info.get("app_name", challenge_name or "target")
    if not target_name or target_name == "target":
        target_name = target_url

    executed_steps = len(step_results) if step_results else 0

    # ── Write success_summary.json (before rendering) ──────────────────
    if workspace_dir:
        _write_success_summary(
            workspace_dir,
            verification=verification,
            target_url=target_url,
            plan_id=plan.get("plan_id", "") if plan else "",
            runtime_sec=runtime_sec,
            executed_steps=executed_steps,
        )

    if not _RICH:
        _print_plain_victory(flag, target_url, step_id, source, runtime_sec)
        return

    console = Console()
    console.clear()
    console.print()

    # ═══════════════════════════════════════════════════════════════════
    # TOP BANNER
    # ═══════════════════════════════════════════════════════════════════
    _render_top_banner(console)

    console.print()

    # ═══════════════════════════════════════════════════════════════════
    # VICTORY + REPORT  (two-column: left = mission+trophy, right = report)
    # ═══════════════════════════════════════════════════════════════════
    left = _build_left_with_trophy()
    right = _build_right_report(
        target_url, flag, method, url, status, step_id, source,
        evidence_hash, runtime_sec, executed_steps,
        verification.get("verifier_version", "goal-verifier-v1"),
    )
    console.print(Columns([left, right], equal=True, expand=True))
    console.print()

    # ═══════════════════════════════════════════════════════════════════
    # EXPLOIT CHAIN TABLE
    # ═══════════════════════════════════════════════════════════════════
    _render_exploit_chain(console, step_results, flag, step_id, source)

    console.print()

    # ═══════════════════════════════════════════════════════════════════
    # SYSTEM STATUS BAR
    # ═══════════════════════════════════════════════════════════════════
    _render_system_status(console, verification, runtime_sec, executed_steps)

    console.print()

    # ═══════════════════════════════════════════════════════════════════
    # FOOTER
    # ═══════════════════════════════════════════════════════════════════
    footer = Text("Co-RedTeam  //  Pipeline Terminated  //  Objective Verified", style=_M)
    console.print(footer, justify="center")
    console.print()


# ═══════════════════════════════════════════════════════════════════════
# SECTION RENDERERS
# ═══════════════════════════════════════════════════════════════════════

def _render_top_banner(console: Console) -> None:
    header = Panel(
        Text("Co-RedTeam  //  OPERATION COMPLETE          [[ SYSTEM COMPROMISED ]]",
             style=f"bold {_G}"),
        border_style=_G,
        box=box.HEAVY,
        padding=(0, 2),
    )
    console.print(header)


def _build_left_with_trophy() -> Panel:
    body = Text()
    body.append("VERIFIED OBJECTIVE ACHIEVED\n", style=f"bold {_G}")
    body.append("Co-RedTeam Victory\n", style=f"bold {_C}")
    body.append("\nTARGET NEUTRALIZED\n", style=_G)
    body.append("Mission objective complete\n\n", style=_M)
    body.append(_TROPHY + "\n", style=f"bold {_Y}")
    body.append("[LOCK] ACCESS GRANTED", style=_G)
    return Panel(body, title="[MISSION . TROPHY]", title_align="left",
                 border_style=_DG, box=box.SQUARE, padding=(1, 2))


def _build_right_report(
    target_url: str, flag: str, method: str, url: str,
    status: Any, step_id: Any, source: str,
    evidence_hash: str, runtime_sec: float, executed_steps: int,
    verifier_version: str,
) -> Panel:
    body = Text()
    def _kv(k: str, v: str, vstyle: str = _G) -> None:
        body.append(f"{k}: ", style=_M)
        body.append(f"{v}\n", style=vstyle)

    _kv("Target", target_url)
    _kv("Objective", "Flag captured")
    _kv("Flag", flag, vstyle=f"bold {_Y}")
    evidence_str = f"HTTP {status} {method} {url}"
    if len(evidence_str) > 45:
        evidence_str = evidence_str[:44] + "..."
    _kv("Evidence", f"{evidence_str} . step {step_id}")
    _kv("Verifier", verifier_version)
    _kv("Runtime", f"{runtime_sec:.1f}s . {executed_steps} steps")
    if evidence_hash:
        _kv("Hash", evidence_hash, vstyle=_DG)
    return Panel(body, title="[OBJECTIVE REPORT]", title_align="left",
                 border_style=_DG, box=box.SQUARE, padding=(1, 2))


def _render_exploit_chain(
    console: Console,
    step_results: list[dict] | None,
    flag: str,
    step_id: Any,
    source: str,
) -> None:
    steps_executed = len(step_results) if step_results else 0

    # Use a borderless table inside a Panel to avoid double-border nesting
    chain = Table(
        box=None,         # no inner border
        show_header=True,
        expand=True,
        padding=(0, 1),
    )
    chain.add_column("STATUS", style=f"bold {_G}", width=8, justify="center")
    chain.add_column("STAGE", style=f"bold {_DG}", width=14)
    chain.add_column("DETAIL", style=_G)

    chain.add_row("[OK]", "Planner", "Produced structured sdk_call / AST plan")
    chain.add_row("[OK]", "Validator", "Accepted AST request . contract compliant")
    chain.add_row("[OK]", "Executor", f"Executed {steps_executed} step(s) in sandbox")
    chain.add_row("[OK]", "Evaluator", "Execution completed without security violation")
    chain.add_row("[OK]", "GoalVerifier", f"Flag confirmed in {source} (step {step_id})")

    console.print(
        Panel(chain,
              title=f"[bold {_G}]EXPLOIT CHAIN [SUCCESS][/bold {_G}]",
              title_align="left", border_style=_DG, box=box.SQUARE, padding=(1, 2))
    )


def _render_system_status(
    console: Console,
    verification: dict[str, Any],
    runtime_sec: float,
    executed_steps: int,
) -> None:
    evidence_hash = verification.get("evidence_sha256", "")
    verifier_ver = verification.get("verifier_version", "goal-verifier-v1")

    # Build as two lines of key=value pairs
    line1 = Text()
    line1.append("Target lock: ", style=_M)
    line1.append("ACTIVE", style=f"bold {_G}")
    line1.append("    Evidence: ", style=_M)
    line1.append("VERIFIED", style=f"bold {_G}")
    line1.append("    Verifier: ", style=_M)
    line1.append(verifier_ver, style=_G)

    line2 = Text()
    line2.append("Exit code: ", style=_M)
    line2.append("0x0", style=f"bold {_G}")
    line2.append("    Pipeline: ", style=_M)
    line2.append("TERMINATED", style=_G)
    line2.append("    Trust: ", style=_M)
    line2.append("OBJECTIVE_VERIFIED", style=f"bold {_C}")

    body = Text()
    body.append(line1)
    body.append("\n")
    body.append(line2)
    if evidence_hash:
        body.append("\n")
        body.append("Evidence Hash: ", style=_M)
        body.append(evidence_hash, style=_DG)

    panel = Panel(
        body,
        title="[SYSTEM STATUS]",
        title_align="left",
        border_style=_DG,
        box=box.SQUARE,
        padding=(1, 2),
    )
    console.print(panel)


# ═══════════════════════════════════════════════════════════════════════
# FALLBACK  (no Rich installed)
# ═══════════════════════════════════════════════════════════════════════

def _print_plain_victory(
    flag: str, target_url: str, step_id: Any, source: str, runtime_sec: float,
) -> None:
    """Fallback when Rich is not installed."""
    print()
    print("=" * 64)
    print("    Co-RedTeam  //  OPERATION COMPLETE")
    print("    [[ SYSTEM COMPROMISED ]]")
    print("=" * 64)
    print(f"    VERIFIED OBJECTIVE ACHIEVED")
    print(f"    Target:    {target_url}")
    print(f"    Flag:      {flag}")
    print(f"    Evidence:  step {step_id} / {source}")
    print(f"    Runtime:   {runtime_sec:.1f}s")
    print("=" * 64)
    print()


# ═══════════════════════════════════════════════════════════════════════
# SUCCESS SUMMARY WRITER  (no payload / command / body)
# ═══════════════════════════════════════════════════════════════════════

def _write_success_summary(
    workspace_dir: Path,
    verification: dict[str, Any],
    target_url: str,
    plan_id: str,
    runtime_sec: float,
    executed_steps: int,
) -> None:
    """Write workspace/success_summary.json -- flag + metadata only."""
    summary = {
        "success": True,
        "verified_by": "goal-verifier-v1",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target_url": target_url,
        "plan_id": plan_id,
        "flag": verification.get("artifact", ""),
        "flag_sha256": verification.get("evidence_sha256", ""),
        "artifact_type": verification.get("artifact_type", ""),
        "step_id": verification.get("step_id"),
        "source_kind": verification.get("source_kind", ""),
        "method": verification.get("method", ""),
        "url": verification.get("url", ""),
        "status_code": verification.get("status_code"),
        "runtime_sec": runtime_sec,
        "executed_steps": executed_steps,
    }
    try:
        workspace_dir.mkdir(parents=True, exist_ok=True)
        path = workspace_dir / "success_summary.json"
        path.write_text(
            json.dumps(summary, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"[victory] success_summary written -> {path}")
    except OSError as e:
        print(f"[victory] WARNING: could not write success_summary.json: {e}")
