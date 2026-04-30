#!/usr/bin/env python3
"""
Benchmark Evaluator for Co-RedTeam Phase 1 (Vulnerability Discovery)

This script evaluates the performance of the vulnerability discovery engine
against a ground truth dataset in JSONL format.

Usage:
    python benchmark_evaluator.py [--dataset PATH] [--output PATH]

Output:
    - Precision, Recall, F1 Score per file and overall
    - Detailed comparison report
"""

import json
import os
import re
import sys
import argparse
from datetime import datetime
from typing import Any
from dataclasses import dataclass, field
from collections import defaultdict

from dotenv import load_dotenv

load_dotenv()

BLUE = "\033[94m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"


@dataclass
class GroundTruthVuln:
    cwe_id: str
    line_start: int
    line_end: int
    description: str


@dataclass
class DetectedVuln:
    cwe_id: str
    line_start: int | None = None
    line_end: int | None = None
    description: str = ""
    file_path: str = ""
    evidence: str = ""


@dataclass
class FileResult:
    file_path: str
    ground_truth: list[GroundTruthVuln] = field(default_factory=list)
    detected: list[DetectedVuln] = field(default_factory=list)
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0


def load_dataset(dataset_path: str) -> list[dict[str, Any]]:
    """Load JSONL dataset file."""
    samples = []
    with open(dataset_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def parse_ground_truth(sample: dict[str, Any]) -> list[GroundTruthVuln]:
    """Parse ground truth vulnerabilities from dataset sample."""
    vulns = []
    for gt in sample.get("ground_truth", []):
        vulns.append(GroundTruthVuln(
            cwe_id=gt["cwe_id"],
            line_start=gt.get("line_start", 0),
            line_end=gt.get("line_end", 0),
            description=gt.get("description", "")
        ))
    return vulns


def parse_llm_output(output: str) -> list[DetectedVuln]:
    """Parse LLM output to extract detected vulnerabilities."""
    detected = []
    
    try:
        match = re.search(r'\{.*\}', output, re.DOTALL)
        if not match:
            return detected
        
        json_str = match.group(0)
        data = json.loads(json_str)
        
        vulns = data.get("vulnerabilities", [])
        if not isinstance(vulns, list):
            vulns = [vulns] if vulns else []
        
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            
            cwe_id = vuln.get("cwe_id", vuln.get("cwe", ""))
            if not cwe_id:
                continue
            
            if not cwe_id.startswith("CWE-"):
                cwe_id = f"CWE-{cwe_id}"
            
            line_info = vuln.get("line", vuln.get("line_number", vuln.get("line_start", 0)))
            if isinstance(line_info, dict):
                line_start = line_info.get("start", line_info.get("from", 0))
                line_end = line_info.get("end", line_info.get("to", line_start))
            else:
                line_start = int(line_info) if line_info else 0
                line_end = line_start
            
            detected.append(DetectedVuln(
                cwe_id=cwe_id.upper(),
                line_start=line_start,
                line_end=line_end,
                description=vuln.get("description", vuln.get("title", "")),
                file_path=vuln.get("file", vuln.get("file_path", "")),
                evidence=vuln.get("evidence", vuln.get("code_snippet", ""))
            ))
    except json.JSONDecodeError as e:
        print(f"{YELLOW}[WARN] JSON parse error: {e}{RESET}")
    except Exception as e:
        print(f"{YELLOW}[WARN] Parse error: {e}{RESET}")
    
    return detected


def cwe_match(detected_cwe: str, ground_truth_cwe: str) -> bool:
    """Check if detected CWE matches ground truth CWE."""
    def normalize(cwe: str) -> str:
        cwe = cwe.upper().strip()
        cwe = re.sub(r'^CWE-?', '', cwe)
        return cwe
    
    return normalize(detected_cwe) == normalize(ground_truth_cwe)


def line_overlap(detected: DetectedVuln, gt: GroundTruthVuln, tolerance: int = 5) -> bool:
    """Check if detected vulnerability line overlaps with ground truth."""
    if not detected.line_start or not gt.line_start:
        return True
    
    detected_range = range(
        max(1, detected.line_start - tolerance),
        (detected.line_end or detected.line_start) + tolerance + 1
    )
    gt_range = range(gt.line_start, gt.line_end + 1)
    
    return bool(set(detected_range) & set(gt_range))


def evaluate_file(
    ground_truth: list[GroundTruthVuln],
    detected: list[DetectedVuln],
    line_tolerance: int = 5
) -> tuple[int, int, int, list[dict], list[dict], list[dict]]:
    """
    Evaluate detected vulnerabilities against ground truth.
    
    Returns:
        (true_positives, false_positives, false_negatives, tp_details, fp_details, fn_details)
    """
    true_positives = 0
    matched_gt = set()
    matched_detected = set()
    tp_details = []
    fp_details = []
    fn_details = []
    
    for i, det in enumerate(detected):
        found_match = False
        for j, gt in enumerate(ground_truth):
            if j in matched_gt:
                continue
            
            if cwe_match(det.cwe_id, gt.cwe_id) and line_overlap(det, gt, line_tolerance):
                true_positives += 1
                matched_gt.add(j)
                matched_detected.add(i)
                found_match = True
                tp_details.append({
                    "detected": {
                        "cwe_id": det.cwe_id,
                        "line": det.line_start,
                        "description": det.description[:100] if det.description else ""
                    },
                    "ground_truth": {
                        "cwe_id": gt.cwe_id,
                        "line_start": gt.line_start,
                        "line_end": gt.line_end,
                        "description": gt.description[:100] if gt.description else ""
                    }
                })
                break
        
        if not found_match:
            fp_details.append({
                "cwe_id": det.cwe_id,
                "line": det.line_start,
                "description": det.description[:100] if det.description else "",
                "evidence": det.evidence[:200] if det.evidence else ""
            })
    
    for j, gt in enumerate(ground_truth):
        if j not in matched_gt:
            fn_details.append({
                "cwe_id": gt.cwe_id,
                "line_start": gt.line_start,
                "line_end": gt.line_end,
                "description": gt.description[:100] if gt.description else ""
            })
    
    false_positives = len(detected) - true_positives
    false_negatives = len(ground_truth) - true_positives
    
    return true_positives, false_positives, false_negatives, tp_details, fp_details, fn_details


def calculate_metrics(tp: int, fp: int, fn: int) -> dict[str, float]:
    """Calculate Precision, Recall, and F1 Score."""
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    
    return {
        "precision": precision,
        "recall": recall,
        "f1_score": f1
    }


def run_analysis_on_file(file_path: str, mock_mode: bool = False) -> str:
    """
    Run Phase 1 analysis on a single file.
    
    In mock mode, returns a simulated output for testing.
    In real mode, calls the actual LLM analysis pipeline.
    """
    if mock_mode:
        return mock_analyze_file(file_path)
    
    try:
        from langchain_openai import ChatOpenAI
        from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage
        from vul_doc import VULN_TOOLS
        from code_browser import CODE_TOOLS
        
        DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY")
        
        llm = ChatOpenAI(
            model="deepseek-chat",
            api_key=DEEPSEEK_API_KEY,
            base_url="https://api.deepseek.com",
            temperature=0.1,
        )
        
        ALL_TOOLS = CODE_TOOLS + VULN_TOOLS
        llm_with_tools = llm.bind_tools(ALL_TOOLS)
        TOOL_MAP = {tool.name: tool for tool in ALL_TOOLS}
        
        sys_prompt = f"""你是一个高级安全分析智能体。分析以下文件并输出漏洞 JSON。

【核心禁令】：
1. 严禁想象：禁止虚构任何文件或代码。
2. 证据至上：每一条 'evidence' 必须来自真实代码。
3. 格式：输出纯 JSON 对象，严禁 Markdown 符号。

目标文件: {file_path}

输出格式：
{{
    "vulnerabilities": [
        {{
            "cwe_id": "CWE-XX",
            "line": 行号或 {{"start": X, "end": Y}},
            "description": "漏洞描述",
            "evidence": "相关代码片段"
        }}
    ]
}}
"""
        
        messages = [SystemMessage(content=sys_prompt)]
        messages.append(HumanMessage(content=f"请分析文件 {file_path} 并报告所有安全漏洞。"))
        
        step_count = 0
        MAX_STEPS = 15
        
        while True:
            res = llm_with_tools.invoke(messages)
            messages.append(res)
            if not res.tool_calls or step_count >= MAX_STEPS:
                break
            
            for tool_call in res.tool_calls:
                tool_fn = TOOL_MAP[tool_call['name']]
                tool_out = tool_fn.invoke(tool_call['args'])
                messages.append(ToolMessage(content=str(tool_out), tool_call_id=tool_call['id']))
            step_count += 1
        
        final_res = llm.invoke(messages + [HumanMessage(content="请输出最终漏洞 JSON 列表。")])
        return final_res.content
        
    except Exception as e:
        print(f"{RED}[ERROR] Analysis failed: {e}{RESET}")
        return '{"vulnerabilities": []}'


def mock_analyze_file(file_path: str) -> str:
    """Mock analysis for testing without LLM calls."""
    mock_results = {
        "target_codebase/financial_core_service.py": {
            "vulnerabilities": [
                {"cwe_id": "CWE-89", "line": 22, "description": "SQL Injection in query construction"},
                {"cwe_id": "CWE-78", "line": 38, "description": "Command Injection via template_path"},
                {"cwe_id": "CWE-918", "line": 48, "description": "SSRF via user-controlled URL"},
                {"cwe_id": "CWE-502", "line": 75, "description": "Insecure pickle deserialization"},
            ]
        },
        "b/Co-RedTeam/target_codebase/vuln_test.py": {
            "vulnerabilities": [
                {"cwe_id": "CWE-89", "line": 8, "description": "SQL Injection"},
                {"cwe_id": "CWE-22", "line": 14, "description": "Path Traversal"},
            ]
        },
        "b/Co-RedTeam/target_codebase/pwn_easy.c": {
            "vulnerabilities": [
                {"cwe_id": "CWE-120", "line": 16, "description": "Buffer Overflow"},
            ]
        }
    }
    
    for key, result in mock_results.items():
        if key in file_path or file_path.endswith(key.split("/")[-1]):
            return json.dumps(result)
    
    return '{"vulnerabilities": []}'


def print_report(results: list[FileResult], overall_metrics: dict[str, float], output_path: str | None = None):
    """Print evaluation report to console and optionally save to file."""
    lines = []
    
    lines.append(f"\n{BOLD}{CYAN}======================================================================{RESET}")
    lines.append(f"{BOLD}{CYAN}       Co-RedTeam Phase 1 Benchmark Evaluation Report{RESET}")
    lines.append(f"{BOLD}{CYAN}======================================================================{RESET}")
    lines.append(f"\n{YELLOW}Evaluation Time:{RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"{YELLOW}Total Files:{RESET} {len(results)}")
    
    total_tp = sum(r.true_positives for r in results)
    total_fp = sum(r.false_positives for r in results)
    total_fn = sum(r.false_negatives for r in results)
    total_gt = sum(len(r.ground_truth) for r in results)
    total_detected = sum(len(r.detected) for r in results)
    
    lines.append(f"\n{BOLD}{MAGENTA}----------------------------------------------------------------------{RESET}")
    lines.append(f"{BOLD}{MAGENTA}                      OVERALL RESULTS{RESET}")
    lines.append(f"{BOLD}{MAGENTA}----------------------------------------------------------------------{RESET}")
    
    lines.append(f"\n  {YELLOW}Ground Truth Vulnerabilities:{RESET} {total_gt}")
    lines.append(f"  {YELLOW}Detected Vulnerabilities:{RESET}    {total_detected}")
    lines.append(f"  {GREEN}True Positives (TP):{RESET}        {total_tp}")
    lines.append(f"  {RED}False Positives (FP):{RESET}       {total_fp}")
    lines.append(f"  {RED}False Negatives (FN):{RESET}       {total_fn}")
    
    lines.append(f"\n{BOLD}{GREEN}+==============================================================+{RESET}")
    lines.append(f"{BOLD}{GREEN}|  PRECISION: {overall_metrics['precision']:.2%}                                      |{RESET}")
    lines.append(f"{BOLD}{GREEN}|  RECALL:    {overall_metrics['recall']:.2%}                                      |{RESET}")
    lines.append(f"{BOLD}{GREEN}|  F1 SCORE:  {overall_metrics['f1_score']:.2%}                                      |{RESET}")
    lines.append(f"{BOLD}{GREEN}+==============================================================+{RESET}")
    
    for result in results:
        metrics = calculate_metrics(result.true_positives, result.false_positives, result.false_negatives)
        
        lines.append(f"\n{BOLD}{BLUE}----------------------------------------------------------------------{RESET}")
        lines.append(f"{BOLD}{BLUE}  FILE: {result.file_path}{RESET}")
        lines.append(f"{BOLD}{BLUE}----------------------------------------------------------------------{RESET}")
        
        lines.append(f"\n  {CYAN}Ground Truth ({len(result.ground_truth)} vulnerabilities):{RESET}")
        for gt in result.ground_truth:
            lines.append(f"    - {gt.cwe_id} (L{gt.line_start}-L{gt.line_end}): {gt.description[:60]}...")
        
        lines.append(f"\n  {CYAN}Detected ({len(result.detected)} vulnerabilities):{RESET}")
        for det in result.detected:
            lines.append(f"    - {det.cwe_id} (L{det.line_start}): {det.description[:60]}...")
        
        lines.append(f"\n  {GREEN}TP: {result.true_positives}{RESET} | {RED}FP: {result.false_positives}{RESET} | {RED}FN: {result.false_negatives}{RESET}")
        lines.append(f"  {YELLOW}Precision: {metrics['precision']:.2%} | Recall: {metrics['recall']:.2%} | F1: {metrics['f1_score']:.2%}{RESET}")
    
    report_text = "\n".join(lines)
    print(report_text)
    
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_text)
        print(f"\n{GREEN}[INFO] Report saved to: {output_path}{RESET}")


def main():
    parser = argparse.ArgumentParser(description="Co-RedTeam Phase 1 Benchmark Evaluator")
    parser.add_argument(
        "--dataset", "-d",
        default="benchmark_dataset.jsonl",
        help="Path to JSONL dataset file (default: benchmark_dataset.jsonl)"
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Path to save evaluation report (optional)"
    )
    parser.add_argument(
        "--mock", "-m",
        action="store_true",
        help="Run in mock mode (no LLM calls, use simulated results)"
    )
    parser.add_argument(
        "--tolerance", "-t",
        type=int,
        default=5,
        help="Line number tolerance for matching (default: 5)"
    )
    
    args = parser.parse_args()
    
    print(f"{BOLD}{YELLOW}======================================================================{RESET}")
    print(f"{BOLD}{YELLOW}  Co-RedTeam Benchmark Evaluator - Starting...{RESET}")
    print(f"{BOLD}{YELLOW}======================================================================{RESET}")
    print(f"\n{CYAN}Dataset:{RESET} {args.dataset}")
    print(f"{CYAN}Mode:{RESET} {'MOCK (simulated)' if args.mock else 'LIVE (real analysis)'}")
    print(f"{CYAN}Line Tolerance:{RESET} {args.tolerance}")
    
    if not os.path.exists(args.dataset):
        print(f"{RED}[ERROR] Dataset file not found: {args.dataset}{RESET}")
        sys.exit(1)
    
    samples = load_dataset(args.dataset)
    print(f"{GREEN}[INFO] Loaded {len(samples)} test samples{RESET}")
    
    results: list[FileResult] = []
    all_tp, all_fp, all_fn = 0, 0, 0
    
    for i, sample in enumerate(samples):
        file_path = sample["file_path"]
        print(f"\n{BOLD}{BLUE}[{i+1}/{len(samples)}] Analyzing: {file_path}{RESET}")
        
        ground_truth = parse_ground_truth(sample)
        
        llm_output = run_analysis_on_file(file_path, mock_mode=args.mock)
        detected = parse_llm_output(llm_output)
        
        tp, fp, fn, tp_details, fp_details, fn_details = evaluate_file(
            ground_truth, detected, args.tolerance
        )
        
        result = FileResult(
            file_path=file_path,
            ground_truth=ground_truth,
            detected=detected,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn
        )
        results.append(result)
        
        all_tp += tp
        all_fp += fp
        all_fn += fn
        
        print(f"  {GREEN}TP: {tp}{RESET} | {RED}FP: {fp}{RESET} | {RED}FN: {fn}{RESET}")
    
    overall_metrics = calculate_metrics(all_tp, all_fp, all_fn)
    
    print_report(results, overall_metrics, args.output)
    
    return overall_metrics


if __name__ == "__main__":
    main()
