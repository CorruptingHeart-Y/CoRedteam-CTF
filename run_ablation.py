"""
Co-RedTeam Evaluator Prompt Ablation Test
==========================================
Automated 4-experiment ablation study. Each experiment runs max_iter=3, max_runs=1.

Experiments:
  EXP_BASE — baseline (record only, no mutation)
  EXP_A    — strip confirmed_vuln from Evaluator prompt
  EXP_B    — strip plan from Evaluator prompt
  EXP_C    — replace REJECTED_HYPOTHESES with PERMANENTLY BANNED text

Output per experiment:
  b/workspace/ablation_{mode}_*.json  — full prompt + output record
  b/results/ablation/{mode}/          — consolidated results

Usage:
  python run_ablation.py --url http://172.29.80.1:9084
  python run_ablation.py --url http://172.29.80.1:9084 --modes EXP_BASE,EXP_C
  python run_ablation.py --url http://172.29.80.1:9084 --max-iter 3 --reset-between
"""

import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PHASE2_DIR = ROOT / "b"
WORKSPACE = PHASE2_DIR / "workspace"
RESULTS_DIR = PHASE2_DIR / "results" / "ablation"
REJECTED_PATH = PHASE2_DIR / "control" / "rejected_hypotheses.json"
REJECTED_BACKUP = PHASE2_DIR / "control" / "rejected_hypotheses.ablation_backup.json"

ALL_MODES = ["EXP_BASE", "EXP_A", "EXP_B", "EXP_C"]

MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-v4-flash")


def banner(text: str) -> None:
    print(f"\n{'='*70}")
    print(f"  {text}")
    print(f"{'='*70}\n")


def run_experiment(mode: str, url: str, max_iter: int = 3) -> dict:
    """Run a single ablation experiment. Returns summary dict."""
    banner(f"RUNNING {mode}  (model={MODEL})")

    start = time.time()
    env = os.environ.copy()
    env["CO_REDTEAM_ABLATION"] = mode
    env["CO_REDTEAM_MAX_ITER"] = str(max_iter)
    env["CO_REDTEAM_MAX_RUNS"] = "1"

    # Collect existing ablation files to detect new ones
    before_files = set(WORKSPACE.glob("ablation_*.json"))

    # Run pipeline — streaming output to console + log file
    cmd = [
        sys.executable, str(PHASE2_DIR / "cli.py"),
        "exploit",
        "--url", url,
        "--max-iter", str(max_iter),
        "--max-runs", "1",
    ]
    print(f"[ablation] CMD: {' '.join(cmd)}")
    print(f"[ablation] ENV: CO_REDTEAM_ABLATION={mode}\n")
    print("-" * 70)

    # Log file for full output
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    log_path = RESULTS_DIR / f"{mode}_{ts}_console.log"
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    full_output: list[str] = []
    iter_count = [0]  # mutable counter for nested function

    with open(log_path, "w", encoding="utf-8") as log_f:
        proc = subprocess.Popen(
            cmd,
            cwd=str(PHASE2_DIR),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding="utf-8",
            errors="replace",
        )

        for line in proc.stdout:  # type: ignore[union-attr]
            line = line.rstrip("\n").rstrip("\r")
            full_output.append(line)
            log_f.write(line + "\n")
            log_f.flush()

            # Progress markers
            if "==== Iteration" in line:
                iter_count[0] += 1
                print(f"\n{'─'*50}")
                print(f"  🔄 ITERATION {iter_count[0]}/{max_iter}")
                print(f"{'─'*50}")
            elif "[evaluator]" in line.lower():
                print(f"  📊 {line}")
            elif "[ablation]" in line.lower():
                print(f"  🔬 {line}")
            elif "[llm] DIAG" in line and "total_prompt" in line:
                print(f"  🤖 {line}")
            elif "REJECTED" in line:
                print(f"  🚫 {line}")
            elif "STEP_OK" in line:
                print(f"  ✅ {line}")
            elif "STEP_FAIL" in line:
                print(f"  ❌ {line[:200]}")
            elif "quota" in line.lower() or "exhausted" in line.lower():
                print(f"  ⚠️  {line}")
            # Don't print every line to avoid flooding — key lines only
            # But uncomment below for full verbosity:
            # else:
            #     print(f"     {line[:180]}")

        proc.wait(timeout=900)

    elapsed = time.time() - start

    # Find new ablation files
    after_files = set(WORKSPACE.glob("ablation_*.json"))
    new_files = after_files - before_files

    # Summarize
    joined_output = "\n".join(full_output)
    summary = {
        "mode": mode,
        "exit_code": proc.returncode,
        "elapsed_sec": round(elapsed, 1),
        "new_ablation_files": len(new_files),
        "ablation_paths": sorted(str(f) for f in new_files),
        "console_log": str(log_path),
        "stdout_last_2000": joined_output[-2000:] if joined_output else "",
        "stderr_last_500": "",
    }

    # Extract key fields from ablation records
    key_fields_by_mode = {}
    for fp in sorted(new_files):
        try:
            record = json.loads(fp.read_text(encoding="utf-8"))
            key_fields_by_mode[fp.name] = record.get("output", {}).get("key_fields", {})
        except Exception as e:
            key_fields_by_mode[fp.name] = {"_error": str(e)}

    summary["key_fields"] = key_fields_by_mode

    # Save summary
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    summary_path = RESULTS_DIR / f"{mode}_{ts}_summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    # Print quick results
    print(f"\n[ablation] {mode} DONE — exit={result.returncode}, elapsed={elapsed:.0f}s, "
          f"ablation_files={len(new_files)}")
    for fname, kf in key_fields_by_mode.items():
        guidance = kf.get("guidance", "")[:150]
        hypothesis = kf.get("hypothesis", "")[:150]
        print(f"  [{fname}]")
        print(f"    guidance:    {guidance}")
        print(f"    hypothesis:  {hypothesis}")

    return summary


def reset_state() -> None:
    """Restore rejected_hypotheses to pre-experiment state."""
    if REJECTED_BACKUP.exists():
        shutil.copy2(REJECTED_BACKUP, REJECTED_PATH)
        print("[ablation] 🔄 rejected_hypotheses restored from backup")


def backup_state() -> None:
    """Backup current rejected_hypotheses."""
    if REJECTED_PATH.exists():
        shutil.copy2(REJECTED_PATH, REJECTED_BACKUP)
        print("[ablation] 💾 rejected_hypotheses backed up")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Co-RedTeam Evaluator Prompt Ablation")
    parser.add_argument("--url", required=True, help="Target URL, e.g. http://172.29.80.1:9084")
    parser.add_argument("--max-iter", type=int, default=3, help="Max iterations per experiment")
    parser.add_argument("--modes", default="ALL",
                       help="Comma-separated modes, or ALL. Options: EXP_BASE,EXP_A,EXP_B,EXP_C")
    parser.add_argument("--reset-between", action="store_true",
                       help="Reset rejected_hypotheses between experiments")
    args = parser.parse_args()

    modes = ALL_MODES if args.modes.upper() == "ALL" else [
        m.strip().upper() for m in args.modes.split(",")
    ]
    modes = [m for m in modes if m in ALL_MODES]
    if not modes:
        print(f"ERROR: no valid modes. Choose from {ALL_MODES}")
        sys.exit(1)

    banner(f"Ablation Study — {len(modes)} experiments  (iter={args.max_iter})")
    print(f"  Modes:  {modes}")
    print(f"  URL:    {args.url}")
    print(f"  Model:  {MODEL}")
    print(f"  Reset:  {args.reset_between}")
    print(f"  Output: {RESULTS_DIR}/")

    backup_state()
    all_summaries = []

    for i, mode in enumerate(modes):
        if i > 0 and args.reset_between:
            reset_state()

        summary = run_experiment(mode, args.url, max_iter=args.max_iter)
        all_summaries.append(summary)

    # ═══════════════════════════════════════════════════════════════
    # FINAL COMPARISON TABLE
    # ═══════════════════════════════════════════════════════════════
    banner("COMPARISON TABLE")

    print(f"{'Mode':<12} {'guidance (first 120 chars)':<125}")
    print("-" * 137)
    for s in all_summaries:
        mode = s["mode"]
        kfs = s.get("key_fields", {})
        if kfs:
            # Get first ablation record's key fields
            first_kf = list(kfs.values())[0] if kfs else {}
            guidance = (first_kf.get("guidance") or "")[:120]
            hypothesis = (first_kf.get("hypothesis") or "")[:120]
        else:
            guidance = "(no ablation record)"
            hypothesis = "(no ablation record)"
        print(f"{mode:<12} {guidance:<125}")
        print(f"{'':12} hypothesis: {hypothesis}")
        print()

    # Check for PATH_BANNED
    print("\nPATH_BANNED occurrences:")
    for s in all_summaries:
        mode = s["mode"]
        kfs = s.get("key_fields", {})
        for fname, kf in kfs.items():
            for field in ("guidance", "hypothesis", "next_required_action", "feedback_for_planner"):
                val = (kf.get(field) or "")
                if "PATH_BANNED" in val:
                    print(f"  ✅ {mode}/{fname}.{field}")

    # Check for CRLF/pickle recommendations
    print("\nCRLF/pickle recommendations (BANNED fingerprints):")
    for s in all_summaries:
        mode = s["mode"]
        kfs = s.get("key_fields", {})
        for fname, kf in kfs.items():
            for field in ("guidance", "hypothesis", "feedback_for_planner"):
                val = (kf.get(field) or "").lower()
                if "crlf" in val or "pickle" in val:
                    print(f"  🚨 {mode}/{fname}.{field}: contains banned fingerprint")
                    excerpt = (kf.get(field) or "")[:200]
                    print(f"     '{excerpt}'")

    banner("ALL EXPERIMENTS COMPLETE")
    print(f"  Full results: {RESULTS_DIR}/")
    print(f"  Raw ablation: {WORKSPACE}/ablation_*.json")
    print(f"  Rejected backup: {REJECTED_BACKUP}")


if __name__ == "__main__":
    main()
