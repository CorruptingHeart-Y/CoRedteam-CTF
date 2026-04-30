#!/usr/bin/env python3
"""
Co-RedTeam 完整演示脚本：SecurePay Platform 漏洞检测与修复

功能：
1. 启动 Phase 1 (漏洞发现) 扫描 target_codebase/secure_pay_platform/
2. 展示各 Agent 工作流程（Analysis → Critique → Evolution）
3. 自动生成修复代码并对比差异
4. 可选启动 Phase 2 (动态利用) 验证漏洞

用法:
    python demo_securepay.py --phase1          # 仅运行 Phase 1 漏洞发现
    python demo_securepay.py --full            # 完整运行 Phase 1 + Phase 2
    python demo_securepay.py --fix             # 生成修复代码
    python demo_securepay.py --compare         # 对比修复前后代码
    python demo_securepay.py --all             # 完整演示（发现+修复+对比）
"""

import os
import sys
import json
import shutil
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

ROOT = Path(__file__).resolve().parent
TARGET_DIR = ROOT / "target_codebase" / "secure_pay_platform"
REPORTS_DIR = ROOT / "reports"
FIXED_DIR = TARGET_DIR

BLUE = "\033[94m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"
BOLD = "\033[1m"


def print_banner():
    """打印演示横幅"""
    banner = f"""
{BOLD}{CYAN}
======================================================================
     Co-RedTeam 安全审计系统 v2.0 - 完整演示

     靶机项目: SecurePay Platform v2.1.0
     路径: target_codebase/secure_pay_platform/

     [Phase 1] Analysis Agent -> Critique Agent -> Evolution Agent
     [Phase 2] Planner -> Validator -> Executor -> Evaluator

======================================================================
{RESET}
"""
    print(banner)


def show_target_structure():
    """展示靶机项目结构"""
    print(f"\n{BOLD}{YELLOW}[Target Structure]{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")
    
    structure = """
target_codebase/secure_pay_platform/
├── app.py                    # [15个漏洞] 主应用入口
├── config.py                 # [硬编码凭证] 配置文件
├── requirements.txt          # Python依赖
├── ground_truth.json         # Ground Truth 数据集
│
├── models/
│   ├── __init__.py
│   ├── user.py               # [SQL注入] 用户模型
│   ├── transaction.py        # [SQL注入+IDOR] 交易模型
│   └── payment.py            # [弱加密] 支付处理器
│
├── utils/
│   ├── __init__.py
│   ├── serializer.py         # [反序列化] 序列化工具
│   └── template_engine.py    # [SSTI] 模板引擎
│
├── middleware/
│   ├── __init__.py
│   ├── cors.py               # [CORS配置错误]
│   └── csrf.py               # [CSRF保护缺失]
│
├── templates/
│   └── dashboard.html        # 前端模板
│
└── static/
    └── app.js                # 前端JavaScript
"""
    
    print(structure)
    
    vuln_summary = """
{BOLD}{RED}[Vulnerability Summary]{RESET}
{CYAN}{'='*60}{RESET}

{RED}CRITICAL (5):{RESET}
  - CWE-89  SQL Injection (app.py:73-74, :132-133)
  - CWE-78  OS Command Injection (app.py:253-268)
  - CWE-502 Insecure Deserialization (app.py:302-315)
  - CWE-917 Server-Side Template Injection (app.py:320-326)
  - CWE-798 Hardcoded Credentials (config.py)

{YELLOW}HIGH (6):{RESET}
  - CWE-918 SSRF (app.py:195-210, :349-368)
  - CWE-22  Path Traversal (app.py:217-225)
  - CWE-434 Unrestricted File Upload (app.py:233-241)
  - CWE-639 IDOR (app.py:101-102)
  - CWE-327 Weak Crypto Algorithm (app.py:82-84)
  - CWE-352 CSRF Protection Missing (middleware/csrf.py)

{GREEN}MEDIUM (4):{RESET}
  - CWE-79  Reflected XSS (app.py:333-341)
  - CWE-601 Open Redirect (app.py:344-346)
  - CWE-918 CORS Misconfiguration (middleware/cors.py)
  - CWE-328 Weak Hash Function (models/payment.py)
"""
    print(vuln_summary)


def run_phase1_detection():
    """运行 Phase 1 漏洞检测"""
    print(f"\n{BOLD}{CYAN}[Phase 1: Vulnerability Discovery]{RESET}")
    print(f"{CYAN}{'='*70}{RESET}\n")
    
    print(f"{YELLOW}[*] 目标目录:{RESET} {TARGET_DIR}")
    print(f"{YELLOW}[*] 报告输出:{RESET} {REPORTS_DIR}/")
    print()
    
    print(f"{BLUE}[Agent Workflow]{RESET}")
    print(f"  {GREEN}1. Analysis Agent{RESET}    - 使用 LLM + 工具链深度扫描代码")
    print(f"  {GREEN}2. Critique Agent{RESET}     - 交叉验证漏洞证据的真实性")
    print(f"  {GREEN}3. Evolution Agent{RESET}    - 提取经验写入长期记忆库")
    print()
    
    import subprocess
    
    cmd = [
        sys.executable,
        str(ROOT / "main.py"),
        "--target", str(TARGET_DIR),
        "--mock"
    ]
    
    print(f"{YELLOW}[执行命令]{RESET}")
    print(f"  {' '.join(cmd)}\n")
    
    try:
        result = subprocess.run(
            cmd,
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=300
        )
        
        print(f"{result.stdout}")
        
        if result.returncode != 0:
            print(f"{RED}[ERROR]{RESET} Phase 1 执行失败:")
            print(result.stderr[:500])
            return None
        
        return find_latest_report()
        
    except subprocess.TimeoutExpired:
        print(f"{RED}[TIMEOUT]{RESET} Phase 1 执行超时（>5分钟）")
        return None
    except Exception as e:
        print(f"{RED}[ERROR]{RESET} {e}")
        return None


def run_phase2_exploitation():
    """运行 Phase 2 动态利用"""
    print(f"\n{BOLD}{CYAN}[Phase 2: Dynamic Exploitation]{RESET}")
    print(f"{CYAN}{'='*70}{RESET}\n")
    
    print(f"{BLUE}[Agent Workflow]{RESET}")
    print(f"  {GREEN}1. Planner Agent{RESET}       - 制定攻击计划（检索历史经验）")
    print(f"  {GREEN}2. Validator Agent{RESET}      - 验证攻击可行性")
    print(f"  {GREEN}3. Executor Agent{RESET}       - 在 Docker 沙箱中执行攻击")
    print(f"  {GREEN}4. Evaluator Agent{RESET}      - 评估攻击效果并反馈")
    print()
    
    import subprocess
    
    cmd = [
        sys.executable,
        str(ROOT / "run_pipeline.py"),
        "--skip-phase1",
        "--mock",
        "--dry-run"
    ]
    
    print(f"{YELLOW}[执行命令]{RESET}")
    print(f"  {' '.join(cmd)}\n")
    
    try:
        result = subprocess.run(
            cmd,
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=300
        )
        
        print(result.stdout)
        return result.returncode == 0
        
    except Exception as e:
        print(f"{RED}[ERROR]{RESET} {e}")
        return False


def generate_fix_report():
    """生成修复报告"""
    print(f"\n{BOLD}{CYAN}[Generating Fix Report]{RESET}")
    print(f"{CYAN}{'='*70}{RESET}\n")
    
    fixes = {
        "CWE-89_SQL_Injection": {
            "file": "app.py",
            "lines": "73-74, 132-133",
            "severity": "CRITICAL",
            "vulnerable": 'query = f"SELECT * FROM users WHERE username = \'{username}\' AND password = \'{password}\'"',
            "fixed": 'cursor.execute("SELECT * FROM users WHERE username = ? AND password_hash = ?", (username, password_hash))',
            "description": "使用参数化查询替代字符串拼接，防止 SQL 注入"
        },
        "CWE-78_Command_Injection": {
            "file": "app.py",
            "lines": "253-268",
            "severity": "CRITICAL",
            "vulnerable": 'subprocess.run(cmd, shell=True, ...)',
            "fixed": 'subprocess.run(["tar", "czf", output_path, ...], shell=False)',
            "description": "使用列表形式传递参数，禁用 shell=True"
        },
        "CWE-502_Deserialization": {
            "file": "utils/serializer.py",
            "lines": "all pickle.loads() calls",
            "severity": "CRITICAL",
            "vulnerable": 'obj = pickle.loads(data)',
            "fixed": 'obj = json.loads(data.decode("utf-8"))',
            "description": "使用 JSON 替代 pickle 进行序列化"
        },
        "CWE-917_SSTI": {
            "file": "utils/template_engine.py",
            "lines": "render_user_template() function",
            "severity": "CRITICAL",
            "vulnerable": 'env = Environment(); template = env.from_string(user_input)',
            "fixed": 'env = SandboxedEnvironment(autoescape=True); template = env.from_string(user_input)',
            "description": "使用 Jinja2 SandboxedEnvironment 防止模板注入"
        },
        "CWE-798_Hardcoded_Credentials": {
            "file": "config.py",
            "lines": "ALL credentials",
            "severity": "CRITICAL",
            "vulnerable": 'DB_PASSWORD = "Sup3rS3cur3P@ssw0rd!2026"',
            "fixed": 'DB_PASSWORD = os.environ.get("DB_PASSWORD")',
            "description": "从环境变量读取敏感信息，不硬编码"
        }
    }
    
    fix_count = len(fixes)
    critical_count = sum(1 for f in fixes.values() if f["severity"] == "CRITICAL")
    
    print(f"{GREEN}[OK] 修复方案已生成: {fix_count} 个关键漏洞{RESET}")
    print(f"{RED}[!] CRITICAL 级别: {critical_count} 个{RESET}\n")
    
    for cwe_id, fix in fixes.items():
        print(f"{BOLD}{YELLOW}> {cwe_id}{RESET}")
        print(f"  文件: {fix['file']}:{fix['lines']}")
        print(f"  严重度: {fix['severity']}")
        print(f"  修复方案: {fix['description']}")
        print()
    
    return fixes


def show_fix_comparison():
    """展示修复前后代码对比"""
    print(f"\n{BOLD}{CYAN}[Code Comparison: Before vs After]{RESET}")
    print(f"{CYAN}{'='*70}{RESET}\n")
    
    comparisons = [
        {
            "title": "SQL Injection Fix (app.py:73)",
            "before": '''
# ❌ VULNERABLE - SQL Injection
def login():
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")
    
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    user = user_manager.execute_raw_query(query)
''',
            "after": '''
# ✅ SECURED - Parameterized Query
def login():
    data = request.get_json() or {}
    username = sanitize_input(data.get("username", ""), max_length=50)
    password = data.get("password", "")
    
    user = user_manager.authenticate_user(username, password)  # Uses parameterized query internally
'''
        },
        {
            "title": "Command Injection Fix (app.py:253)",
            "before": '''
# ❌ VULNERABLE - OS Command Injection
if backup_type == "full":
    cmd = f"tar czf {output_path} /var/lib/securepay/ /etc/securepay/"
elif backup_type == "database":
    db_name = request.json.get("database", "securepay_db")
    cmd = f"pg_dump {db_name} > {output_path}"

result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
''',
            "after": '''
# ✅ SECURED - No Shell Injection
ALLOWED_BACKUP_TYPES = {"full", "database", "logs"}
if backup_type not in ALLOWED_BACKUP_TYPES:
    return jsonify({"status": "error", "message": "Invalid backup type"}), 400

if backup_type == "full":
    cmd = ["tar", "czf", output_path, "-C", "/", "var/lib/securepay/", "etc/securepay/"]
elif backup_type == "database":
    db_name = sanitize_input(request.json.get("database", "securepay_db"), max_length=50)
    cmd = ["pg_dump", db_name, "-f", output_path]

result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, shell=False)
'''
        },
        {
            "title": "Deserialization Fix (utils/serializer.py)",
            "before": '''
# ❌ VULNERABLE - Insecure Pickle Deserialization
class DataSerializer:
    def deserialize(self, raw_data: bytes, format: str = "pickle") -> Any:
        if format == "pickle":
            obj = pickle.loads(data)  # RCE vulnerability!
            return obj
''',
            "after": '''
# ✅ SECURED - JSON Only (No Pickle)
class DataSerializer:
    supported_formats = ["json", "base64"]  # Removed "pickle"
    
    def deserialize(self, raw_data: bytes, format: str = "json") -> Any:
        if format == "json":
            return json.loads(raw_data.decode("utf-8"))
        elif format == "base64":
            decoded = base64.b64decode(raw_data)
            return json.loads(decoded.decode("utf-8"))
        else:
            raise ValueError(f"Unsupported format: {format}. Only JSON is allowed.")
'''
        },
        {
            "title": "SSTI Fix (utils/template_engine.py)",
            "before": '''
# ❌ VULNERABLE - Server-Side Template Injection
def render_user_template(template_string: str, context: Dict[str, Any]) -> None:
    env = Environment()  # No sandbox!
    template = env.from_string(template_string)
    return template.render(**context)  # User can execute arbitrary code!
''',
            "after": '''
# ✅ SECURED - Jinja2 Sandbox
def render_user_template_safe(template_string: str, context: Dict[str, Any]) -> str:
    env = SandboxedEnvironment(
        autoescape=True,
        undefined=jinja2.StrictUndefined
    )
    
    # Block dangerous patterns before rendering
    DANGEROUS_PATTERNS = [r"\{\{.*__class__.*\}\}", r"\{\{.*config.*\}\}", ...]
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, template_string):
            raise ValueError("Template contains unsafe expressions")
    
    template = env.from_string(template_string)
    return template.render(**context)
'''
        }
    ]
    
    for i, comp in enumerate(comparisons, 1):
        print(f"{BOLD}{MAGENTA}[Example {i}] {comp['title']}{RESET}\n")
        
        print(f"{RED}BEFORE (Vulnerable):{RESET}")
        print(comp["before"])
        
        print(f"{GREEN}AFTER (Secured):{RESET}")
        print(comp["after"])
        
        print(f"{CYAN}{'─'*70}{RESET}\n")


def show_agent_workflow_detail():
    """展示详细的 Agent 工作流程"""
    print(f"\n{BOLD}{CYAN}[Detailed Agent Workflow]{RESET}")
    print(f"{CYAN}{'='*70}{RESET}\n")
    
    workflow = f"""
{BOLD}{GREEN}===== PHASE 1: Vulnerability Discovery ====={RESET}

{YELLOW}+-------------------------------------------------------------+
{YELLOW}|{RESET}  {BOLD}Analysis Agent (安全分析员){RESET}                              {YELLOW}|
{YELLOW}+-------------------------------------------------------------+
{YELLOW}|{RESET}                                                       {YELLOW}|
{YELLOW}|{RESET}  [INPUT] Input:                                        {YELLOW}|
{YELLOW}|{RESET}    - System Prompt (包含 CWE 知识库 + 长期记忆)           {YELLOW}|
{YELLOW}|{RESET}    - Target Codebase (SecurePay Platform)              {YELLOW}|
{YELLOW}|{RESET}                                                       {YELLOW}|
{YELLOW}|{RESET}  [TOOLS] Tool Chain:                                   {YELLOW}|
{YELLOW}|{RESET}    - list_directory()  - 列出文件结构                    {YELLOW}|
{YELLOW}|{RESET}    - read_file()       - 读取源代码                     {YELLOW}|
{YELLOW}|{RESET}    - get_snippet()    - 提取函数上下文                  {YELLOW}|
{YELLOW}|{RESET}    - search_code()    - 正则搜索模式                    {YELLOW}|
{YELLOW}|{RESET}    - query_vuln_docs()- 查询 CWE 漏洞库                 {YELLOW}|
{YELLOW}|{RESET}                                                       {YELLOW}|
{YELLOW}|{RESET}  [OUTPUT] Output:                                      {YELLOW}|
{YELLOW}|{RESET}    - JSON 格式漏洞列表                                 {YELLOW}|
{YELLOW}|{RESET}    - 包含: cwe_id, line_number, evidence, description   {YELLOW}|
{YELLOW}|{RESET}                                                       {YELLOW}|
{YELLOW}+-------------------------------------------------------------+
                              |
{YELLOW}+-------------------------------------------------------------+
{YELLOW}|{RESET}  {BOLD}Critique Agent (挑剔评审员){RESET}                             {YELLOW}|
{YELLOW}+-------------------------------------------------------------+
{YELLOW}|{RESET}                                                       {YELLOW}|
{YELLOW}|{RESET}  [CHECK] Validation Standards:                         {YELLOW}|
{YELLOW}|{RESET}    1. 证据真实性 - 是否为真实代码？                     {YELLOW}|
{YELLOW}|{RESET}    2. 路径有效性 - 文件是否真的存在？                   {YELLOW}|
{YELLOW}|{RESET}    3. 逻辑闭环 - 漏洞描述与代码是否一致？               {YELLOW}|
{YELLOW}|{RESET}    4. 行号精度 - 是否有精确的行号定位？                 {YELLOW}|
{YELLOW}|{RESET}                                                       {YELLOW}|
{YELLOW}|{RESET}  [RESULT] Decision Results:                            {YELLOW}|
{YELLOW}|{RESET}    - APPROVED  - 证据确凿，通过                        {YELLOW}|
{YELLOW}|{RESET}    - REJECTED - AI 幻觉或虚构，拒绝                     {YELLOW}|
{YELLOW}|{RESET}    - NEEDS_REFINEMENT - 思路对但需补充证据              {YELLOW}|
{YELLOW}|{RESET}                                                       {YELLOW}|
{YELLOW}+-------------------------------------------------------------+
                              |
{YELLOW}+-------------------------------------------------------------+
{YELLOW}|{RESET}  {BOLD}Evolution Agent (经验进化器){RESET}                            {YELLOW}|
{YELLOW}+-------------------------------------------------------------+
{YELLOW}|{RESET}                                                       {YELLOW}|
{YELLOW}|{RESET}  [BRAIN] Functions:                                   {YELLOW}|
{YELLOW}|{RESET}    - 复盘本次审计过程                                  {YELLOW}|
{YELLOW}|{RESET}    - 提取通用漏洞模式经验                              {YELLOW}|
{YELLOW}|{RESET}    - 写入 ChromaDB 长期记忆库                         {YELLOW}|
{YELLOW}|{RESET}    - 下次审计时自动召回相关经验                       {YELLOW}|
{YELLOW}|{RESET}                                                       {YELLOW}|
{YELLOW}|{RESET}  [MEMORY] Memory Storage:                             {YELLOW}|
{YELLOW}|{RESET}    ./co_redteam_memory/vulnerability_patterns/        {YELLOW}|
{YELLOW}|{RESET}                                                       {YELLOW}|
{YELLOW}+-------------------------------------------------------------+


{BOLD}{GREEN}===== PHASE 2: Dynamic Exploitation ====={RESET}

{YELLOW}+-------------------------------------------------------------+
{YELLOW}|{RESET}  {BOLD}Planner Agent (攻击规划师){RESET}                             {YELLOW}|
{YELLOW}+-------------------------------------------------------------+
{YELLOW}|{RESET}  [PLAN] 制定攻击策略                                    {YELLOW}|
{YELLOW}|{RESET}  [SEARCH] 从 ChromaDB 检索历史利用经验                {YELLOW}|
{YELLOW}|{RESET}  [OUTPUT] 生成 plan.json                              {YELLOW}|
{YELLOW}+-------------------------------------------------------------+
         |
{YELLOW}+-------------------------------------------------------------+
{YELLOW}|{RESET}  {BOLD}Validator Agent (可行性验证){RESET}                           {YELLOW}|
{YELLOW}+-------------------------------------------------------------+
{YELLOW}|{RESET}  [CHECK] 检查环境依赖                                  {YELLOW}|
{YELLOW}|{RESET}  [VERIFY] 验证攻击向量有效性                           {YELLOW}|
{YELLOW}|{RESET}  [ASSESS] 评估风险等级                                 {YELLOW}|
{YELLOW}|{RESET}  [OUTPUT] 输出 validated_plan.json                    {YELLOW}|
{YELLOW}+-------------------------------------------------------------+
         |
{YELLOW}+-------------------------------------------------------------+
{YELLOW}|{RESET}  {BOLD}Executor Agent (Docker沙箱执行){RESET}                        {YELLOW}|
{YELLOW}+-------------------------------------------------------------+
{YELLOW}|{RESET}  [DOCKER] 启动临时 Docker 容器                        {YELLOW}|
{YELLOW}|{RESET}  [EXECUTE] 执行攻击脚本 (Exploit)                    {YELLOW}|
{YELLOW}|{RESET}  [CAPTURE] 收集输出和截图                             {YELLOW}|
{YELLOW}|{RESET}  [CLEANUP] 自动销毁容器                               {YELLOW}|
{YELLOW}|{RESET}  [OUTPUT] 输出 execution_result.json                 {YELLOW}|
{YELLOW}+-------------------------------------------------------------+
         |
{YELLOW}+-------------------------------------------------------------+
{YELLOW}|{RESET}  {BOLD}Evaluator Agent (效果评估){RESET}                               {YELLOW}|
{YELLOW}+-------------------------------------------------------------+
{YELLOW}|{RESET}  [METRICS] 评估指标:                                   {YELLOW}|
{YELLOW}|{RESET}    - Success Rate (成功率)                           {YELLOW}|
{YELLOW}|{RESET}    - Impact Level (影响程度)                         {YELLOW}|
{YELLOW}|{RESET}    - Detection Risk (被检测风险)                     {YELLOW}|
{YELLOW}|{RESET}  [FEEDBACK] 反馈循环:                                {YELLOW}|
{YELLOW}|{RESET}    -> 如果失败 -> 回到 Planner 调整策略              {YELLOW}|
{YELLOW}|{RESET}    -> 如果成功 -> 写入成功案例到记忆库                {YELLOW}|
{YELLOW}|{RESET}  [OUTPUT] 输出 feedback.json                          {YELLOW}|
{YELLOW}+-------------------------------------------------------------+
"""
    
    print(workflow)


def find_latest_report() -> Path | None:
    """查找最新的 Phase 1 报告"""
    if not REPORTS_DIR.exists():
        return None
    
    reports = sorted(REPORTS_DIR.glob("vulnerability_proposal_*.json"), reverse=True)
    return reports[0] if reports else None


def show_final_summary(phase1_success: bool = False, phase2_success: bool = False):
    """展示最终总结"""
    print(f"\n{BOLD}{CYAN}{'='*70}{RESET}")
    print(f"{BOLD}{CYAN}           Co-RedTeam Demo Execution Summary{RESET}")
    print(f"{BOLD}{CYAN}{'='*70}{RESET}\n")
    
    status_icon = "[OK]" if phase1_success else "[--]"
    print(f"  Phase 1 (Discovery):     {GREEN if phase1_success else RED}{status_icon}{RESET}")
    
    status_icon = "[OK]" if phase2_success else "[--]"
    print(f"  Phase 2 (Exploitation):  {GREEN if phase2_success else YELLOW}{status_icon}{RESET}")
    
    latest_report = find_latest_report()
    if latest_report:
        print(f"\n  {YELLOW}Latest Report:{RESET} {latest_report.name}")
        
        try:
            with open(latest_report, "r", encoding="utf-8") as f:
                report_data = json.load(f)
            
            vulns = report_data.get("vulnerabilities", [])
            print(f"  {YELLOW}Vulnerabilities Found:{RESET} {len(vulns)}")
            
            severity_counts = {}
            for v in vulns:
                sev = v.get("severity", "UNKNOWN")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            for sev, count in sorted(severity_counts.items()):
                color = RED if sev == "CRITICAL" else YELLOW if sev == "HIGH" else GREEN
                print(f"    {color}• {sev}: {count}{RESET}")
                
        except Exception as e:
            print(f"  {RED}Error reading report: {e}{RESET}")
    
    print(f"\n  {CYAN}Target Project:{RESET} SecurePay Platform v2.1.0")
    print(f"  {CYAN}Target Directory:{RESET} {TARGET_DIR}")
    print(f"  {CYAN}Fixed Code Available:{RESET} *_fixed.py files")
    
    print(f"\n{BOLD}{GREEN}{'='*70}{RESET}")
    print(f"{BOLD}{GREEN}  Demo Complete! Check reports/ and *_fixed.py files.{RESET}")
    print(f"{BOLD}{GREEN}{'='*70}{RESET}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Co-RedTeam Complete Demo: SecurePay Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python demo_securepy.py --info        Show target info only
  python demo_securepy.py --phase1       Run Phase 1 detection
  python demo_securepy.py --full         Run complete pipeline
  python demo_securepy.py --fix          Generate fix report
  python demo_securepy.py --compare      Show code comparison
  python demo_securepy.py --workflow     Show agent workflow detail
  python demo_securepy.py --all          Full demo with everything
        """
    )
    
    parser.add_argument("--info", action="store_true", help="Show target project information")
    parser.add_argument("--phase1", action="store_true", help="Run Phase 1 vulnerability detection")
    parser.add_argument("--phase2", action="store_true", help="Run Phase 2 exploitation")
    parser.add_argument("--full", action="store_true", help="Run full pipeline (Phase 1 + Phase 2)")
    parser.add_argument("--fix", action="store_true", help="Generate vulnerability fix report")
    parser.add_argument("--compare", action="store_true", help="Show before/after code comparison")
    parser.add_argument("--workflow", action="store_true", help="Show detailed agent workflow")
    parser.add_argument("--all", action="store_true", help="Run complete demonstration")
    
    args = parser.parse_args()
    
    if not any([args.info, args.phase1, args.phase2, args.full, 
                args.fix, args.compare, args.workflow, args.all]):
        parser.print_help()
        return 0
    
    print_banner()
    
    phase1_ok = False
    phase2_ok = False
    
    if args.info or args.all:
        show_target_structure()
    
    if args.workflow or args.all:
        show_agent_workflow_detail()
    
    if args.fix or args.all:
        generate_fix_report()
    
    if args.compare or args.all:
        show_fix_comparison()
    
    if args.phase1 or args.full or args.all:
        phase1_ok = run_phase1_detection() is not None
    
    if args.phase2 or args.full or args.all:
        phase2_ok = run_phase2_exploitation()
    
    show_final_summary(phase1_ok, phase2_ok)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
