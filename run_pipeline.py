#!/usr/bin/env python3
"""
Co-RedTeam 全局总控脚本 (Pipeline Orchestrator)

功能：
1. 启动 Phase 1 漏洞发现流程（main.py）
2. 自动捕获漏洞报告并格式化转换
3. 将数据桥接至 Phase 2 输入目录（b/data/confirmed_vuln.json）
4. 自动启动 Phase 2 动态利用流程（b/coordinator.py）

用法:
    python run_pipeline.py [--target TARGET_DIR] [--skip-phase1] [--mock]

参数:
    --target, -t    目标代码库路径（默认: target_codebase）
    --skip-phase1   跳过 Phase 1，直接使用已有的最新报告
    --mock          使用 Mock 模式运行（不调用 LLM）
    --dry-run       仅测试数据桥接，不实际执行 Phase 2
"""

import json
import os
import sys
import re
import shutil
import argparse
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Any

from dotenv import load_dotenv

load_dotenv()

ROOT = Path(__file__).resolve().parent
PHASE1_DIR = ROOT
PHASE2_DIR = ROOT / "b"
PHASE1_REPORTS_DIR = PHASE1_DIR / "reports"
PHASE2_DATA_DIR = PHASE2_DIR / "data"
PHASE2_CONFIRMED_PATH = PHASE2_DATA_DIR / "confirmed_vuln.json"

BLUE = "\033[94m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"
BOLD = "\033[1m"


def cleanup_for_new_target() -> None:
    """换题清理：只清除运行时产物，保留长期记忆（ChromaDB + memory/*.json）。"""
    print(f"\n{BOLD}{BLUE}{'─'*70}{RESET}")
    print(f"{BOLD}{BLUE}[Cleanup] 新目标检测 — 清理运行时产物（长期记忆保留）...{RESET}")
    print(f"{BOLD}{BLUE}{'─'*70}{RESET}")

    # 1. 删除 confirmed_vuln.json（题目专属）
    if PHASE2_CONFIRMED_PATH.exists():
        PHASE2_CONFIRMED_PATH.unlink()
        print(f"[Cleanup] [OK] 已删除 {PHASE2_CONFIRMED_PATH}")

    # 2. 清空 workspace（运行时产物）
    workspace_dir = PHASE2_DIR / "workspace"
    if workspace_dir.exists():
        shutil.rmtree(workspace_dir)
        workspace_dir.mkdir(parents=True, exist_ok=True)
        print(f"[Cleanup] [OK] 已清空 {workspace_dir}")

    # 3. 删除运行时轨迹文件（题目专属）
    for fname in ["exploit_trajectory.json", "verification_memory.json"]:
        fp = PHASE2_DIR / "memory" / fname
        if fp.exists():
            fp.unlink()
            print(f"[Cleanup] [OK] 已删除 {fp}")

    # 4. 清除 __pycache__
    for sub in [PHASE2_DIR / "memory", PHASE2_DIR / "control"]:
        for pycache in sub.glob("__pycache__"):
            if pycache.is_dir():
                shutil.rmtree(pycache)
                print(f"[Cleanup] [OK] 已清除 {pycache}")

    # 5. 确保 CWE 知识库存在（不删除重建，只有不存在时才初始化）
    chroma_dir = ROOT / "co_redteam_memory"
    if not chroma_dir.exists():
        print(f"[Cleanup] CWE 知识库不存在，正在初始化...")
        vul_doc_ini = ROOT / "vul_doc_ini.py"
        if vul_doc_ini.exists():
            print(f"[Cleanup] 运行 vul_doc_ini.py 初始化 CWE 知识库...")
        result = subprocess.run(
            [sys.executable, str(vul_doc_ini)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            print(f"[Cleanup] [OK] CWE 知识库初始化完成")
        else:
            stderr_tail = (result.stderr or "").strip()[-200:]
            print(f"[Cleanup] [WARN] vul_doc_ini.py 异常: {stderr_tail}")

    print(f"\n[Cleanup] 清理完成，环境已就绪\n")


def print_banner():
    print(f"\n{BOLD}{CYAN}{'='*70}{RESET}")
    print(f"{BOLD}{CYAN}   Co-RedTeam 全局流水线控制器 v1.0{RESET}")
    print(f"{BOLD}{CYAN}{'='*70}{RESET}")
    print(f"\n{YELLOW}[Pipeline] 项目根目录: {ROOT}{RESET}")
    print(f"[Pipeline] Phase 1 目录: {PHASE1_DIR}")
    print(f"[Pipeline] Phase 2 目录: {PHASE2_DIR}")


def find_latest_phase1_report() -> Path | None:
    """查找最新的 Phase 1 漏洞报告文件"""
    if not PHASE1_REPORTS_DIR.exists():
        return None
    
    reports = sorted(
        PHASE1_REPORTS_DIR.glob("vulnerability_proposal_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )
    
    return reports[0] if reports else None


def run_phase1(target_dir: str, mock_mode: bool = False) -> dict[str, Any]:
    """
    执行 Phase 1 漏洞发现流程
    返回解析后的漏洞报告字典
    """
    print(f"\n{BOLD}{YELLOW}{'─'*70}{RESET}")
    print(f"{BOLD}{YELLOW}[Phase 1] 启动漏洞发现引擎...{RESET}")
    print(f"{BOLD}{YELLOW}{'─'*70}{RESET}\n")
    
    if mock_mode:
        print(f"{YELLOW}[Phase 1] Mock 模式：使用预定义的模拟输出{RESET}")
        
        mock_report = {
            "vulnerabilities": [
                {
                    "cwe_id": "CWE-89",
                    "line": 22,
                    "description": "SQL Injection in get_transaction_history",
                    "evidence": "Line 21-22: query = f\"SELECT * FROM transactions WHERE user_id = {user_id}\"",
                    "file_path": str(ROOT / "target_codebase" / "financial_core_service.py"),
                },
                {
                    "cwe_id": "CWE-78",
                    "line": 38,
                    "description": "OS Command Injection in export_user_report",
                    "evidence": "Line 37-38: subprocess.run(f\"generate_pdf --input {full_path}...\", shell=True)",
                    "file_path": str(ROOT / "target_codebase" / "financial_core_service.py"),
                },
                {
                    "cwe_id": "CWE-918",
                    "line": 48,
                    "description": "SSRF in sync_exchange_rates via user-controlled URL",
                    "evidence": "Line 46-49: response = requests.get(provider_url, ...)",
                    "file_path": str(ROOT / "target_codebase" / "financial_core_service.py"),
                },
                {
                    "cwe_id": "CWE-502",
                    "line": 75,
                    "description": "Insecure Deserialization using pickle.loads()",
                    "evidence": "Line 74-75: prefs = pickle.loads(row['prefs'])",
                    "file_path": str(ROOT / "target_codebase" / "financial_core_service.py"),
                }
            ],
            "status": "ANALYSIS_COMPLETE",
            "timestamp": datetime.now().isoformat(),
            "_source": "mock"
        }
        
        return mock_report
    
    original_cwd = os.getcwd()
    
    try:
        os.chdir(PHASE1_DIR)
        
        sys.path.insert(0, str(PHASE1_DIR))
        
        from main import app, CoRedteamState
        
        initial_state: CoRedteamState = {
            "iteration_count": 0,
            "vulnerabilities": "",
            "critic_feedback": "",
            "messages": []
        }
        
        final_vulns = ""
        for output in app.stream(initial_state):
            if "Analysis" in output:
                final_vulns = output["Analysis"].get("vulnerabilities", final_vulns)
        
        if final_vulns:
            match = re.search(r'\{.*\}', final_vulns, re.DOTALL)
            clean_json = match.group(0) if match else final_vulns
            
            report_data = json.loads(clean_json)
            report_data["timestamp"] = datetime.now().isoformat()
            report_data["_source"] = "phase1_analysis"
            
            return report_data
        
        raise ValueError("Phase 1 未生成有效输出")
        
    except Exception as e:
        print(f"{RED}[Phase 1] 执行失败: {e}{RESET}")
        raise
    finally:
        os.chdir(original_cwd)
        if str(PHASE1_DIR) in sys.path:
            sys.path.remove(str(PHASE1_DIR))


def convert_phase1_to_phase2(phase1_report: dict[str, Any]) -> dict[str, Any]:
    """
    将 Phase 1 输出格式转换为 Phase 2 需要的 confirmed_vuln.json 格式
    
    Phase 1 格式:
    {
        "vulnerabilities": [
            {"cwe_id": "CWE-89", "line": 22, "description": "...", "evidence": "..."}
        ]
    }
    
    Phase 2 格式:
    {
        "vulnerabilities": [
            {
                "type": "SQL Injection",
                "cwe": "CWE-89",
                "severity": "HIGH",
                "location": "path/to/file.py",
                "function": "func_name",
                "evidence": "...",
                "source": "...",
                "sink": "...",
                "description": "..."
            }
        ],
        "status": "ANALYSIS_COMPLETE"
    }
    """
    CWE_TO_TYPE_MAP = {
        "CWE-89": "SQL Injection",
        "CWE-79": "Cross-Site Scripting (XSS)",
        "CWE-22": "Path Traversal",
        "CWE-78": "OS Command Injection",
        "CWE-502": "Insecure Deserialization",
        "CWE-639": "IDOR (Insecure Direct Object Reference)",
        "CWE-352": "CSRF (Cross-Site Request Forgery)",
        "CWE-434": "Unrestricted File Upload",
        "CWE-798": "Hard-coded Credentials",
        "CWE-862": "Missing Authorization",
        "CWE-917": "Server-Side Template Injection (SSTI)",
        "CWE-94": "Code Injection",
        "CWE-918": "Server-Side Request Forgery (SSRF)",
        "CWE-287": "Improper Authentication / Broken JWT",
        "CWE-327": "Weak Cryptographic Algorithm",
        "CWE-611": "XML External Entity (XXE)",
        "CWE-1321": "Prototype Pollution",
        "CWE-120": "Buffer Overflow",
        "CWE-190": "Integer Overflow",
        "CWE-416": "Use After Free",
        "CWE-200": "Sensitive Information Exposure",
        "CWE-362": "Race Condition",
    }
    
    SEVERITY_MAP = {
        "CRITICAL": ["CWE-94", "CWE-78", "CWE-502", "CWE-120"],
        "HIGH": ["CWE-89", "CWE-79", "CWE-22", "CWE-639", "CWE-862", "CWE-287", "CWE-917", "CWE-918"],
        "MEDIUM": ["CWE-352", "CWE-434", "CWE-798", "CWE-327", "CWE-611", "CWE-1321", "CWE-200"],
        "LOW": ["CWE-362", "CWE-190", "CWE-416"],
    }
    
    def get_severity(cwe_id: str) -> str:
        for severity, cwes in SEVERITY_MAP.items():
            if cwe_id in cwes:
                return severity
        return "MEDIUM"
    
    def get_type(cwe_id: str) -> str:
        return CWE_TO_TYPE_MAP.get(cwe_id, cwe_id.replace("CWE-", "Unknown-"))
    
    def extract_function_from_evidence(evidence: str) -> str:
        match = re.search(r'(?:def |function )(\w+)', evidence)
        return match.group(1) if match else "unknown"
    
    def extract_source_sink(evidence: str, description: str) -> tuple[str, str]:
        source_patterns = [r'(\w+)\s+(?:参数|input|用户输入)', r'(user(?:_|)id|username|request\.(?:args|form|params)\[(\w+)\])']
        sink_patterns = [r'(execute|query|loads|open|system|eval|exec|request)\s*\(', r'subprocess\.run']
        
        source = "未明确标注"
        sink = "未明确标注"
        
        for pattern in source_patterns:
            match = re.search(pattern, evidence, re.IGNORECASE)
            if match:
                try:
                    source = match.group(1) or match.group(0)
                except IndexError:
                    source = match.group(0)
                break
        
        for pattern in sink_patterns:
            match = re.search(pattern, evidence, re.IGNORECASE)
            if match:
                sink = match.group(0)
                break
        
        return source, sink
    
    phase2_vulns = []
    
    vulns = phase1_report.get("vulnerabilities", [])
    if isinstance(vulns, dict):
        vulns = [vulns]
    
    for i, vuln in enumerate(vulns):
        cwe_id = vuln.get("cwe_id", "UNKNOWN")
        line_num = vuln.get("line", vuln.get("line_start", 0))
        description = vuln.get("description", "")
        evidence_raw = vuln.get("evidence", "")
        file_path = vuln.get("file_path", "")
        
        if isinstance(evidence_raw, dict):
            evidence_text = evidence_raw.get("code_snippet", "")
            if not file_path:
                file_path = evidence_raw.get("file", "")
        else:
            evidence_text = str(evidence_raw)
        
        if file_path and file_path.startswith(str(ROOT)):
            try:
                rel_path = Path(file_path).relative_to(ROOT)
                location = str(rel_path)
            except ValueError:
                location = file_path
        else:
            location = file_path or f"unknown_file_{i+1}"
        
        source, sink = extract_source_sink(evidence_text, description)
        
        converted = {
            "id": vuln.get("id", f"VULN-{i+1:03d}"),
            "type": get_type(cwe_id),
            "cwe_id": cwe_id,
            "cwe": cwe_id,
            "title": vuln.get("title", ""),
            "severity": vuln.get("severity", get_severity(cwe_id)),
            "location": location,
            "function": extract_function_from_evidence(evidence_text),
            "evidence": evidence_raw,
            "source": vuln.get("source", source),
            "sink": vuln.get("sink", sink),
            "description": description,
            "attack_chain": vuln.get("attack_chain", ""),
            "data_flow": vuln.get("data_flow", ""),
        }
        
        phase2_vulns.append(converted)
    
    phase2_report = {
        "vulnerabilities": phase2_vulns,
        "status": "ANALYSIS_COMPLETE",
        "bridge_timestamp": datetime.now().isoformat(),
        "phase1_timestamp": phase1_report.get("timestamp", ""),
        "total_vulnerabilities": len(phase2_vulns),
    }
    
    return phase2_report


def extract_target_context(vulns: list[dict[str, Any]]) -> dict[str, Any]:
    """
    从漏洞证据中自动提取目标系统上下文信息
    """
    import re
    
    context: dict[str, Any] = {
        "base_url": os.getenv("CO_REDTEAM_TARGET_BASE", "http://host.docker.internal:9443"),
        "app_name": "目标应用",
        "os_hint": "linux",
    }
    
    app_names = set()
    
    for vuln in vulns:
        location = vuln.get("location", "")
        evidence = vuln.get("evidence", "")
        
        if isinstance(evidence, dict):
            file_path = evidence.get("file", "")
            code = evidence.get("code_snippet", "")
        else:
            file_path = ""
            code = str(evidence) if evidence else ""
        
        search_text = f"{location} {file_path} {code}"
        
        for pattern in [
            r"cybench_web_challenges/[^/]*?\[[^\]]*\]\s+(\w+)",
            r"target_codebase[/\\]cybench_web_challenges[/\\][^/\\]*?\[[^\]]*?\][/\\]?\s*(\w+)",
            r"([a-zA-Z][a-zA-Z0-9_-]{2,})[/\\]challenge[/\\]",
        ]:
            match = re.search(pattern, search_text)
            if match:
                app_names.add(match.group(1).strip())
        
        if re.search(r"\.js\b|node|npm|Node\.js|express", code or "", re.IGNORECASE):
            pass
        if re.search(r"\.py\b|flask|django|Jinja2|render_template", code or "", re.IGNORECASE):
            pass
        if re.search(r"\.php\b", code or "", re.IGNORECASE):
            pass
    
    if app_names:
        context["app_name"] = sorted(app_names)[0]
    
    routes = _scan_source_routes(vulns)
    if routes:
        context["discovered_routes"] = sorted(set(routes))
    
    return context


def _scan_source_routes(vulns: list[dict[str, Any]]) -> list[str]:
    """扫描漏洞引用的真实源文件，提取所有 @route 装饰器中的端点"""
    import re
    routes: list[str] = []
    seen_files: set[str] = set()
    route_re = re.compile(r"""@(\w+)\.route\(['\"](/[\w/<>-]*)['\"]""")
    
    for vuln in vulns:
        evidence = vuln.get("evidence", "")
        location = vuln.get("location", "")
        
        if isinstance(evidence, dict):
            source_file = evidence.get("file", "")
        else:
            source_file = location or ""
        
        if not source_file or source_file in seen_files:
            continue
        
        full_path = ROOT / source_file
        if not full_path.exists():
            continue
        
        seen_files.add(source_file)
        try:
            content = full_path.read_text(encoding="utf-8", errors="replace")
            for match in route_re.finditer(content):
                bp_name, ep = match.group(1), match.group(2)
                routes.append(f"@{bp_name}.route('{ep}')")
        except Exception:
            continue
        
        dir_path = full_path.parent
        for py_file in sorted(dir_path.glob("*.py")):
            py_path = str((ROOT / py_file).relative_to(ROOT) if py_file.is_relative_to(ROOT) else py_file)
            if py_path in seen_files:
                continue
            seen_files.add(py_path)
            try:
                content = py_file.read_text(encoding="utf-8", errors="replace")
                for match in route_re.finditer(content):
                    bp_name, ep = match.group(1), match.group(2)
                    routes.append(f"@{bp_name}.route('{ep}')")
            except Exception:
                continue
    
    return routes


def bridge_to_phase2(phase2_report: dict[str, Any]) -> Path:
    """
    将转换后的数据写入 Phase 2 的输入目录，并自动注入目标系统上下文
    返回写入的文件路径
    """
    print(f"\n{BOLD}{MAGENTA}{'─'*70}{RESET}")
    print(f"{BOLD}{MAGENTA}[Bridge] 数据桥接：Phase 1 → Phase 2{RESET}")
    print(f"{BOLD}{MAGENTA}{'─'*70}{RESET}")
    
    vulns = phase2_report.get("vulnerabilities", [])
    target_context = extract_target_context(vulns)
    phase2_report["target_context"] = target_context
    
    print(f"[Bridge] 目标系统识别: {target_context['app_name']}")
    print(f"[Bridge] 基础 URL: {target_context['base_url']}")
    
    PHASE2_DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    backup_path = None
    if PHASE2_CONFIRMED_PATH.exists():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"confirmed_vuln_backup_{timestamp}.json"
        backup_path = PHASE2_DATA_DIR / backup_name
        shutil.copy2(PHASE2_CONFIRMED_PATH, backup_path)
        print(f"[Bridge] 已备份原有文件 → {backup_name}")
    
    with open(PHASE2_CONFIRMED_PATH, 'w', encoding='utf-8') as f:
        json.dump(phase2_report, f, ensure_ascii=False, indent=4)
    
    print(f"[Bridge] [OK] 情报移交成功！已写入: {PHASE2_CONFIRMED_PATH}")
    print(f"[Bridge] 移交漏洞总数: {len(vulns)}")
    
    for vuln in vulns:
        severity_color = RED if vuln['severity'] == 'CRITICAL' else YELLOW if vuln['severity'] == 'HIGH' else GREEN
        print(f"  {severity_color}[{vuln['severity']}] {vuln['cwe']} - {vuln['type']}{RESET}")
        print(f"         Location: {vuln['location']}")
    
    return PHASE2_CONFIRMED_PATH


def run_phase2(mock_mode: bool = False, dry_run: bool = False) -> int:
    """
    执行 Phase 2 动态利用流程
    返回退出码
    """
    print(f"\n{BOLD}{YELLOW}{'─'*70}{RESET}")
    print(f"{BOLD}{YELLOW}[Phase 2] 启动动态利用引擎...{RESET}")
    print(f"{BOLD}{YELLOW}{'─'*70}{RESET}\n")
    
    if dry_run:
        print(f"{YELLOW}[Phase 2] Dry-run 模式：跳过实际执行{RESET}")
        print(f"[Phase 2] 输入文件已就绪: {PHASE2_CONFIRMED_PATH}")
        return 0
    
    coordinator_script = PHASE2_DIR / "coordinator.py"
    
    if not coordinator_script.exists():
        print(f"{RED}[Phase 2] 错误: coordinator.py 不存在于 {coordinator_script}{RESET}")
        return 1
    
    env = os.environ.copy()
    
    if mock_mode:
        env["CO_REDTEAM_MOCK_LLM"] = "true"
        print(f"[Phase 2] Mock 模式已启用")
    
    try:
        result = subprocess.run(
            [sys.executable, str(coordinator_script)],
            cwd=str(PHASE2_DIR),
            env=env,
            capture_output=False,
        )
        
        exit_code = result.returncode
        
        if exit_code == 0:
            print(f"\n{GREEN}[Phase 2] [OK] 动态利用完成，复现成功！{RESET}")
        elif exit_code == 2:
            print(f"\n{YELLOW}[Phase 2] [WARN] 评估建议终止迭代{RESET}")
        else:
            print(f"\n{RED}[Phase 2] [FAIL] 执行异常，退出码: {exit_code}{RESET}")
        
        return exit_code
        
    except Exception as e:
        print(f"{RED}[Phase 2] 执行失败: {e}{RESET}")
        return 1


def print_final_summary(
    phase1_success: bool,
    bridge_success: bool,
    phase2_exit_code: int,
    duration_sec: float,
):
    """打印最终汇总报告"""
    print(f"\n{BOLD}{CYAN}{'='*70}{RESET}")
    print(f"{BOLD}{CYAN}      Co-RedTeam 流水线执行摘要{RESET}")
    print(f"{BOLD}{CYAN}{'='*70}{RESET}\n")
    
    status_map = {
        ("Phase 1", phase1_success): (GREEN, "[OK] 完成") if phase1_success else (RED, "[FAIL] 失败"),
        ("Bridge", bridge_success): (GREEN, "[OK] 成功") if bridge_success else (RED, "[FAIL] 失败"),
        ("Phase 2", phase2_exit_code == 0): (GREEN, "[OK] 成功") if phase2_exit_code == 0 else (YELLOW, "[WARN] 退出码 {}".format(phase2_exit_code)),
    }
    
    for (name, success), (color, status) in status_map.items():
        print(f"  {color}{name:<12} {status}{RESET}")
    
    print(f"\n{YELLOW}Total Duration: {duration_sec:.2f} sec{RESET}")
    print(f"Report Location: {PHASE1_REPORTS_DIR}/")
    print(f"Intel File: {PHASE2_CONFIRMED_PATH}")
    print(f"Workspace: {PHASE2_DIR / 'workspace'}/")
    
    overall_status = "SUCCESS" if (phase1_success and bridge_success and phase2_exit_code == 0) else "PARTIAL" if (phase1_success and bridge_success) else "FAILED"
    
    if overall_status == "SUCCESS":
        print(f"\n{BOLD}{GREEN}[SUCCESS] All pipeline stages completed!{RESET}")
    elif overall_status == "PARTIAL":
        print(f"\n{BOLD}{YELLOW}[PARTIAL] Some stages completed, check logs above{RESET}")
    else:
        print(f"\n{BOLD}{RED}[FAILED] Pipeline execution failed, check error messages{RESET}")
    
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Co-RedTeam 全局流水线控制器 - 连接 Phase 1 和 Phase 2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python run_pipeline.py                     # 完整运行两个阶段
  python run_pipeline.py --mock              # Mock 模式（不调用 LLM）
  python run_pipeline.py --skip-phase1       # 跳过 Phase 1，使用已有报告
  python run_pipeline.py --dry-run           # 仅测试数据桥接
  python run_pipeline.py -t my_target/       # 指定目标代码库
"""
    )
    
    parser.add_argument(
        "--target", "-t",
        type=str,
        default=None,
        help="目标代码库路径（默认: target_codebase）"
    )
    parser.add_argument(
        "--skip-phase1",
        action="store_true",
        help="跳过 Phase 1，直接使用 reports/ 下最新的漏洞报告"
    )
    parser.add_argument(
        "--mock", "-m",
        action="store_true",
        help="Mock 模式：不调用 LLM API，使用模拟数据"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="仅测试数据桥接逻辑，不实际执行 Phase 2"
    )
    parser.add_argument(
        "--report",
        type=str,
        default=None,
        help="指定 Phase 1 报告文件路径（配合 --skip-phase1 使用）"
    )
    
    args = parser.parse_args()
    
    start_time = datetime.now()
    
    print_banner()
    
    phase1_success = False
    bridge_success = False
    phase2_exit_code = -1
    
    try:
        if args.skip_phase1:
            print(f"\n{YELLOW}[Pipeline] 跳过 Phase 1，加载已有报告...{RESET}")
            
            if args.report:
                report_path = Path(args.report)
            else:
                report_path = find_latest_phase1_report()
            
            if not report_path or not report_path.exists():
                print(f"{RED}[Pipeline] 错误: 未找到 Phase 1 报告文件{RESET}")
                print(f"[Pipeline] 提示: 请先运行 Phase 1 或指定 --report 参数")
                return 1
            
            print(f"[Pipeline] 加载报告: {report_path}")
            
            with open(report_path, 'r', encoding='utf-8') as f:
                phase1_report = json.load(f)
            
            phase1_success = True
            
        else:
            target_dir = args.target or "target_codebase"

            # Stage 1 入口：自动清理上一题记忆
            cleanup_for_new_target()

            try:
                phase1_report = run_phase1(target_dir, mock_mode=args.mock)
                phase1_success = True
                
                print(f"\n{GREEN}[Pipeline] [OK] Phase 1 完成检测到 {len(phase1_report.get('vulnerabilities', []))} 个漏洞{RESET}")
                
            except Exception as e:
                print(f"{RED}[Pipeline] Phase 1 失败: {e}{RESET}")
                if not args.mock:
                    print(f"{YELLOW}[Pipeline] 提示: 可尝试使用 --mock 模式进行测试{RESET}")
                return 1
        
        print(f"\n{CYAN}[Pipeline] 开始数据格式转换与桥接...{RESET}")
        
        phase2_report = convert_phase1_to_phase2(phase1_report)
        
        bridge_path = bridge_to_phase2(phase2_report)
        bridge_success = True
        
        print(f"\n{CYAN}[Pipeline] 情报移交成功，启动阶段二...{RESET}")
        
        phase2_exit_code = run_phase2(mock_mode=args.mock, dry_run=args.dry_run)
        
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}[Pipeline] 用户中断执行{RESET}")
        return 130
    
    except Exception as e:
        print(f"\n{RED}[Pipeline] 未预期的错误: {e}{RESET}")
        import traceback
        traceback.print_exc()
        return 1
    
    finally:
        duration = (datetime.now() - start_time).total_seconds()
        print_final_summary(phase1_success, bridge_success, phase2_exit_code, duration)
    
    return 0 if phase2_exit_code == 0 else phase2_exit_code


if __name__ == "__main__":
    sys.exit(main())
