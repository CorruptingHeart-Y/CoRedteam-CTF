from __future__ import annotations

import os
from contextlib import contextmanager

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme


_THEME = Theme({
    "stage.planner":   "bold magenta",
    "stage.validator": "bold cyan",
    "stage.executor":  "bold yellow",
    "stage.evaluator": "bold green",
    "stage.cli":       "bold white",
    "stage.lock":      "bold red",
    "ok":              "bold green",
    "fail":            "bold red",
    "warn":            "yellow",
    "muted":           "grey50",
})


console = Console(theme=_THEME, highlight=False)


_VERBOSE = os.getenv("CO_REDTEAM_VERBOSE", "false").lower() in ("1", "true", "yes")


def is_verbose() -> bool:
    return _VERBOSE


def stage(name: str, message: str) -> None:
    """Emit a single-line stage update like '[Planner] 构建攻击链...'"""
    style = f"stage.{name.lower()}"
    console.print(f"[{style}]\\[{name}][/{style}] {message}")


def ok(message: str) -> None:
    console.print(f"[ok]✓[/ok] {message}")


def fail(message: str) -> None:
    console.print(f"[fail]✗[/fail] {message}")


def warn(message: str) -> None:
    console.print(f"[warn]![/warn] {message}")


def muted(message: str) -> None:
    console.print(f"[muted]{message}[/muted]")


def detail(message: str) -> None:
    """Verbose-only logging: prompt bodies, raw LLM exchanges, etc."""
    if _VERBOSE:
        console.print(f"[muted]  · {message}[/muted]")


def render_target_lock(target) -> None:
    """Print the target whitelist banner so the user sees what is locked."""
    body = Text()
    body.append("URL    ", style="muted")
    body.append(target.url + "\n", style="bold white")
    body.append("Host   ", style="muted")
    body.append(target.hostname + "\n", style="bold white")
    body.append("IP     ", style="muted")
    body.append(target.ip + "\n", style="bold white")
    body.append("Port   ", style="muted")
    body.append(str(target.port) + "\n", style="bold white")
    body.append("Scheme ", style="muted")
    body.append(target.scheme, style="bold white")
    console.print(
        Panel(
            body,
            title="[stage.lock]🔒 TARGET LOCKED — 仅此目标可被访问[/stage.lock]",
            border_style="stage.lock",
            padding=(0, 2),
        )
    )


def render_iteration_header(iteration: int, total: int) -> None:
    console.rule(f"[stage.cli]迭代 {iteration} / {total}[/stage.cli]")


def render_summary_table(rows: list[dict]) -> None:
    if not rows:
        return
    table = Table(title="复现成功记录", show_lines=False)
    table.add_column("迭代", justify="right")
    table.add_column("Plan ID")
    table.add_column("Confidence", justify="right")
    table.add_column("摘要")
    for r in rows:
        table.add_row(
            str(r.get("iteration", "?")),
            str(r.get("plan_id", "?")),
            f"{r.get('confidence', 0):.2f}",
            (r.get("summary") or "")[:80],
        )
    console.print(table)


def render_victory_banner(
    fb: dict,
    iteration: int,
    iter_budget: int,
    milestone_count: int,
    iter_history: list[dict],
    last_plan: dict,
    step_results: list[dict],
    confirmed: dict,
    challenge_name: str = "",
) -> None:
    """Print a high-impact OPERATION SUCCESSFUL banner with flag highlight."""
    import re
    import time

    # ── extract flag ────────────────────────────────────────────
    all_stdout = " ".join(
        (r.get("result") or {}).get("stdout", "") for r in step_results
    )
    flag_match = re.search(r'(?:flag|htb|ctf)\{[^}]+\}', all_stdout, re.IGNORECASE)
    flag_text = flag_match.group(0) if flag_match else ""

    # ── derive fields ───────────────────────────────────────────
    target_name = challenge_name or confirmed.get("target_context", {}).get("app_name", "unknown")
    vuln_id = last_plan.get("vulnerability_id") or ""
    cwe_id = last_plan.get("cwe_id", "")
    vector = (cwe_id + " " + vuln_id).strip() or "exploit"
    impact = (fb.get("analysis") or {}).get("what_happened", "flag_captured")[:50]
    confidence = fb.get("confidence", 1.0)
    summary = fb.get("summary", "")[:80]

    # ── metrics ─────────────────────────────────────────────────
    total_ok = sum(1 for r in step_results if (r.get("result") or {}).get("ok"))
    total_steps = len(step_results)
    history_ok = sum(e.get("ok_count", 0) for e in iter_history)

    console.print()  # blank line for separation
    console.print()  # blank line for separation

    # ── stats panel ─────────────────────────────────────────────
    stats_body = Text()
    stats_body.append(f"TARGET     ", style="muted")
    stats_body.append(f"{target_name}\n", style="bold white")
    stats_body.append(f"VECTOR     ", style="muted")
    stats_body.append(f"{vector}\n", style="bold white")
    stats_body.append(f"IMPACT     ", style="muted")
    stats_body.append(f"{impact}\n", style="bold white")
    stats_body.append(f"CONFIDENCE ", style="muted")
    stats_body.append(f"{confidence:.0%}\n", style="bold green")

    console.print(
        Panel(
            stats_body,
            title="[bold green]OPERATION SUCCESSFUL[/bold green]",
            border_style="bold green",
            padding=(1, 2),
            subtitle="[muted]Co-RedTeam[/muted]",
            subtitle_align="right",
        )
    )

    # ── FLAG ASCII art ──────────────────────────────────────────
    flag_ascii = Text()
    flag_ascii.append("""             ███████╗██╗      █████╗  ██████╗
             ██╔════╝██║     ██╔══██╗██╔════╝
             █████╗  ██║     ███████║██║  ███╗
             ██╔══╝  ██║     ██╔══██║██║   ██║
             ██║     ███████╗██║  ██║╚██████╔╝
             ╚═╝     ╚══════╝╚═╝  ╚═╝ ╚═════╝
""", style="bold green")
    console.print(flag_ascii)

    # ── flag highlight ──────────────────────────────────────────
    if flag_text:
        flag_panel = Panel(
            Text(flag_text, style="bold yellow"),
            border_style="yellow",
            padding=(0, 4),
        )
        console.print(flag_panel)
        console.print()

    # ── execution summary ───────────────────────────────────────
    summary_parts = [
        f"Iterations: {iteration}/{iter_budget}",
        f"Milestones: {milestone_count}",
        f"Steps this round: {total_ok}/{total_steps} ok",
        f"Total step OKs: {history_ok}",
        f"Summary: {summary}" if summary else "",
    ]
    console.print(Text(" · ".join(p for p in summary_parts if p), style="muted"))
    console.print()


def render_evaluator_feedback(fb: dict) -> None:
    """Print a highlighted Evaluator result panel — key signal for the operator."""
    from rich.text import Text as _Text

    success = fb.get("repro_success", False)
    confidence = fb.get("confidence", 0.0)
    summary = fb.get("summary", "")
    analysis = fb.get("analysis") or {}
    what = analysis.get("what_happened", "")
    guidance = analysis.get("guidance", "")
    should_continue = fb.get("should_continue", True)

    border = "bold green" if success else "bold red"
    icon   = "✅" if success else "❌"
    title  = f"{icon} Evaluator — {'SUCCESS' if success else 'FAILED'}  confidence={confidence:.2f}"

    body = _Text()
    if summary:
        body.append("Summary:  ", style="bold")
        body.append(summary[:200] + "\n", style="white")
    if what:
        body.append("What:     ", style="bold")
        body.append(what[:300] + "\n", style="grey82")
    if guidance:
        body.append("Guidance: ", style="bold yellow")
        body.append(guidance[:400] + "\n", style="yellow")
    body.append("Continue: ", style="bold")
    body.append(str(should_continue), style="cyan")

    console.print(
        Panel(body, title=f"[{border}]{title}[/{border}]",
              border_style=border, padding=(0, 2))
    )

    """Group noisy intermediate output under one collapsible header.

    In non-verbose mode, the inner prints from agents are suppressed;
    in verbose mode they're shown indented under the header.
    """
    stage(label, "运行中...")
    try:
        yield
    finally:
        pass
