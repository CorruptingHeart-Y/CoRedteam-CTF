"""ResponseDistiller — compress executor output into exploit-centric facts.

Purpose: strip HTML, CSS, and noise from chain_output / stdout so Planners
receive only capability-relevant signals. Never passes raw transcripts upstream.

Architecture invariant: this module produces structured dictionaries consumed
by ExploitFSM and fed as distilled_execution into the feedback loop.

v3 changes: failure_semantics replaces binary False with granular triage
(silent_strip / reflected_not_executed / exception_visible / html_rewrite).
primitive_telemetry tracks per-primitive status (untried/failed_silent/failed_error/success).
"""

from __future__ import annotations

import json
import re
from typing import Any

# ── Capability signal extraction patterns ──────────────────────────

_CAP_SIGNALS: list[tuple[str, str, str]] = [
    # (regex, capability_key, label)
    # ── template_eval ──
    (r"\b49\b(?!\d)", "template_eval", "arithmetic_eval_49"),
    # ── object_access ──
    (r"\$class\b", "object_access", "velocity_class_object"),
    (r"\bconfig\b(?!\s*:)", "object_access", "config_object_access"),
    # ── method_call ──
    (r"\.getName\(\)|\.getClass\(\)|\.getMethod\(", "method_call", "java_reflection_call"),
    (r"__class__|__mro__|__subclasses__|__globals__|__builtins__", "method_call", "python_introspection"),
    # ── classloader — 效果信号：响应体里出现了类加载成功的特征 ──
    (r"\bclass\s+java\.lang\.\w+", "classloader", "java_class_loaded_in_response"),
    (r"java\.lang\.\w+@[0-9a-f]+", "classloader", "java_object_ref_in_response"),
    # ── exec — 效果信号：响应体里出现了命令执行输出特征 ──
    (r"\buid=\d+|gid=\d+|www-data\b", "exec", "command_output_uid"),
    (r"\broot:[x*]:\d+:\d+:", "exec", "passwd_content_line"),
    (r"(?:^|\n|\s)(?:Linux|Darwin|Windows_NT)(?:\s|$|\n)", "exec", "os_fingerprint_in_output"),
    (r"/bin/sh\b|/bin/bash\b", "exec", "shell_path_in_output"),
    # ── file_read — 效果信号：响应体里出现了文件内容特征 ──
    (r"\broot:[x*]:\d+:\d+:", "file_read", "passwd_line_content"),
    (r"(?:^|\n)[\w-]+:x:\d+:\d+:", "file_read", "passwd_entry_line"),
    # ── flag_exfil ──
    (r"flag\{[^}]{3,}\}|CTF\{[^}]{3,}\}|HTB\{[^}]{3,}\}", "flag_exfil", "flag_captured"),
    # ── payload_delivery ──
    (r"STEP_OK\b", "payload_delivery", "script_completed"),
    (r"STEP_FAIL:", "payload_delivery", "script_failed"),
]

_ARTIFACT_PATTERNS: list[tuple[str, str]] = [
    (r"\b(?:49|50|64|81|100)\b", "numeric_output"),
    (r"(?:java\.(?:lang|util|io)\.\w+|com\.\w+\.\w+)", "java_classpath"),
    (r"(?:ParseException|TemplateException|NullPointerException)", "exception_ref"),
    (r"(?:\[HTTP\]\s+\d{3}\s+\w+)", "http_log"),
    (r"(?:Error:|error:|ERROR:)\s*.{10,80}", "error_line"),
]

# ── Primitive telemetry: fine-grained per-primitive tracking ──────
# Each entry maps a primitive_id to its description and the surface it belongs to.

_PRIMITIVE_DEFINITIONS: dict[str, dict[str, str]] = {
    "string_getclass_forname": {
        "description": "String.getClass().forName() chain — reflective class resolution",
        "surface": "jvm_reflection",
        "detection_keyword": "getClass()",
    },
    "class_inspect": {
        "description": "$class.inspect() — Velocity introspection interface",
        "surface": "jvm_reflection",
        "detection_keyword": "class.inspect",
    },
    "constructor_newinstance": {
        "description": "Constructor.newInstance() — reflective object creation",
        "surface": "jvm_reflection",
        "detection_keyword": "newInstance",
    },
    "static_forname": {
        "description": "Class.forName() — static class loading",
        "surface": "jvm_reflection",
        "detection_keyword": "forName(",
    },
    "runtime_exec": {
        "description": "Runtime.exec() — command execution via reflection",
        "surface": "jvm_reflection",
        "detection_keyword": "exec(",
    },
    "processbuilder": {
        "description": "ProcessBuilder — command execution with env control",
        "surface": "jvm_reflection",
        "detection_keyword": "ProcessBuilder",
    },
    "evaluate_directive": {
        "description": "#evaluate() — dynamic template evaluation",
        "surface": "template_internal",
        "detection_keyword": "#evaluate",
    },
    "macro_abuse": {
        "description": "#macro recursion/abuse — macro-based code execution",
        "surface": "template_internal",
        "detection_keyword": "#macro",
    },
    "resource_loader": {
        "description": "ResourceLoader / template.merge() — loading external templates",
        "surface": "loader_surface",
        "detection_keyword": "ResourceLoader",
    },
    "uberspect": {
        "description": "Uberspect / EventCartridge — introspector hook injection",
        "surface": "sandbox_escape",
        "detection_keyword": "Uberspect",
    },
}

# ── Stage-to-surface mapping (for FSM surface-level tracking) ─────

STAGE_SURFACE_MAP: dict[str, str] = {
    "classloader":   "jvm_reflection",
    "object_access": "jvm_reflection",
    "method_call":   "jvm_reflection",
    "exec":          "jvm_reflection",
    "breakout":      "template_internal",
    "template_eval": "template_internal",
    "reflection":    "template_internal",
}

# ── Noise stripping ────────────────────────────────────────────────

_HTML_TAG_RE = re.compile(r"<[^>]{4,}>")
_CSS_BLOCK_RE = re.compile(r"\{[^}]{20,}\}", re.DOTALL)
_BOILERPLATE_RE = re.compile(
    r"<!--.*?-->|<script[^>]*>.*?</script>|<style[^>]*>.*?</style>",
    re.IGNORECASE | re.DOTALL,
)
_WHITESPACE_RE = re.compile(r"\s{3,}")


def _strip_noise(text: str) -> str:
    """Strip HTML tags, CSS blocks, and boilerplate from raw output."""
    if not text:
        return ""
    s = _BOILERPLATE_RE.sub(" ", text)
    s = _HTML_TAG_RE.sub(" ", s)
    s = _CSS_BLOCK_RE.sub(" ", s)
    s = _WHITESPACE_RE.sub(" ", s)
    return s.strip()


def _infer_primitive_result(combined: str, success_marker: str) -> str:
    """推断某个 primitive 的执行结果。

    Returns one of: untried, failed_silent, failed_error, success
    """
    if success_marker not in combined:
        return "untried"
    # 有异常 → failed_error (engine saw the call but threw)
    if re.search(r'Exception|Error|Caused by|TemplateException|SecurityException', combined, re.IGNORECASE):
        return "failed_error"
    # 有输出但无预期结果 → failed_silent (payload went in, nothing came out)
    return "failed_silent"


def _payload_sent_but_no_output(stdout: str, response: str) -> bool:
    """检测是否发送了 payload 但响应无任何对应输出。"""
    payload_indicators = ['#set', '$class', 'forName', 'Runtime', '#evaluate',
                          'ProcessBuilder', '#macro']
    response_has_output = any(ind in response for ind in ['49', 'uid=', 'root', 'HTB{',
                                                          'flag{', 'FLAG{'])
    request_had_payload = any(ind in stdout for ind in payload_indicators)
    return request_had_payload and not response_has_output


def _extract_failure_semantics(
    raw_text: str,
    stdout: str,
    stderr: str,
    status: int | None,
    meaningful: str,
) -> list[dict[str, str]]:
    """从原始输出中提取语义化失败信号。

    返回 failure_semantics 列表，每个条目包含 mode/hypothesis/implication。
    """
    combined = f"{raw_text} {stdout} {stderr}"
    semantics: list[dict[str, str]] = []

    # 1. silent_strip: payload 已发送但响应中完全没有对应输出
    if _payload_sent_but_no_output(stdout, raw_text):
        semantics.append({
            "mode": "silent_strip",
            "hypothesis": "parser prefilter or token sanitizer — payload stripped before template engine",
            "implication": "try URL encoding, alternate delimiters, or POST body instead of GET param",
        })

    # 2. reflected_not_executed: payload 原样出现在响应（未被模板引擎解析）
    ssti_markers = ['#set', '$class', 'forName', 'getRuntime', '#evaluate']
    if not semantics:  # only if no silent_strip
        for marker in ssti_markers:
            if marker in raw_text:
                semantics.append({
                    "mode": "reflected_not_executed",
                    "marker": marker,
                    "hypothesis": "expression parsed by template engine but invocation blocked",
                    "implication": "template engine reached but method call security check triggered",
                })
                break

    # 3. exception_visible: 响应含 Java 异常
    exception_patterns = [
        r'Exception[:\s]+\S+',
        r'Caused by[:\s]+\S+',
        r'TemplateException',
        r'ParseException',
        r'SecurityException',
        r'ClassNotFoundException',
    ]
    for pat in exception_patterns:
        em = re.search(pat, combined, re.IGNORECASE)
        if em:
            semantics.append({
                "mode": "exception_visible",
                "exception": em.group(0)[:100],
                "hypothesis": "execution reached JVM, security manager or ClassLoader restriction triggered",
                "implication": "JVM security policy active — try alternate class resolution or sandbox escape",
            })
            break

    # 4. html_rewrite: 响应是默认 HTML（payload 没有传进去）
    if 'Example text' in raw_text or ('<html' in raw_text and not meaningful):
        semantics.append({
            "mode": "html_rewrite",
            "hypothesis": "payload not delivered to template — check HTTP method, param name, encoding",
            "implication": "GET vs POST, ?text= param missing, or URL encoding needed",
        })

    return semantics


def _compute_primitive_telemetry(combined: str) -> dict[str, str]:
    """根据 stdout/response 内容推断每个 primitive 的尝试状态和结果。"""
    telemetry: dict[str, str] = {}
    for pid, pdef in _PRIMITIVE_DEFINITIONS.items():
        keyword = pdef["detection_keyword"]
        if keyword in combined:
            telemetry[pid] = _infer_primitive_result(combined, keyword)
        else:
            telemetry[pid] = "untried"
    return telemetry


def _extract_meaningful_output(noisy_text: str, max_chars: int = 200) -> str:
    """Extract the most semantically dense substring — prioritize error lines
    and signal keywords, then fall back to head of cleaned text."""
    cleaned = _strip_noise(noisy_text)
    if not cleaned:
        return ""

    # Prefer lines containing exploit-relevant keywords
    signal_kw = re.compile(
        r"(?:error|exception|flag|uid=|root|success|fail|"
        r"49|config|class|runtime|exec|passwd|shadow|"
        r"STEP_OK|STEP_FAIL)",
        re.IGNORECASE,
    )
    ranked: list[tuple[int, str]] = []
    for line in cleaned.split("\n"):
        line = line.strip()
        if not line:
            continue
        score = len(signal_kw.findall(line)) * 10
        score += max(0, 5 - len(line) // 40)
        ranked.append((score, line))
    ranked.sort(key=lambda x: -x[0])
    result = " | ".join(line for _, line in ranked[:4])
    return result[:max_chars]


def _detect_failure_fingerprints(
    raw_text: str,
    step_results: list[dict[str, Any]],
) -> list[str]:
    """Produce compact failure fingerprints from execution trace."""
    fingerprints: list[str] = []

    # Structural failures
    for sr in step_results:
        rr = sr.get("result") or {}
        stderr = rr.get("stderr", "")
        stdout = rr.get("stdout", "")
        text = f"{stderr} {stdout}"
        if not rr.get("ok"):
            if "SyntaxError" in text or "NameError" in text or "IndentationError" in text:
                fingerprints.append("syntax_error")
            elif "SECURITY_BLOCKED" in text:
                fingerprints.append("security_blocked")
            elif "Connection refused" in text or "ConnectionError" in text:
                fingerprints.append("connection_refused")
            elif "All fields are required" in text:
                fingerprints.append("field_mismatch")
            elif "Invalid Email" in text:
                fingerprints.append("email_validation_block")
            elif "Invalid URL" in text:
                fingerprints.append("url_error")

    cleaned = _strip_noise(raw_text)

    # method_blocked
    if re.search(r"(?:ParseException|method.*not\s+found|NoSuchMethod|cannot\s+invoke)",
                 cleaned, re.IGNORECASE):
        if "method_blocked" not in fingerprints:
            fingerprints.append("method_blocked")

    # classloader_blocked
    if re.search(r"(?:ClassNotFoundException|NoClassDefFound|cannot\s+find\s+class)",
                 cleaned, re.IGNORECASE):
        if "classloader_blocked" not in fingerprints:
            fingerprints.append("classloader_blocked")

    # reflection_only / object_access_only
    has_template_eval = bool(re.search(r"\b49\b(?!\d)", cleaned))
    has_object_access = bool(re.search(r"\$class\b|__class__|config\b(?!\s*:)", cleaned, re.IGNORECASE))
    has_method_call = bool(re.search(r"\.getName\(\)|\.getClass\(\)|\.getMethod\(", cleaned))
    if has_template_eval and not has_object_access and not has_method_call:
        fingerprints.append("reflection_only")
    elif has_object_access and not has_method_call:
        fingerprints.append("object_access_only")

    # no_reflection
    has_payload_delivery = any(
        (rr.get("ok") for sr in step_results if (rr := sr.get("result")))
    )
    if has_payload_delivery and not has_template_eval and not has_object_access:
        fingerprints.append("no_reflection")

    # surface-level fingerprints from failure semantics
    if re.search(r'#set|#evaluate|#macro|\$class|forName', cleaned, re.IGNORECASE):
        if has_payload_delivery and not has_template_eval and not has_object_access:
            fingerprints.append("ssti_surface_blocked")
        elif has_template_eval and not has_method_call:
            fingerprints.append("template_eval_only")

    # Deduplicate
    seen: set[str] = set()
    result: list[str] = []
    for f in fingerprints:
        if f not in seen:
            seen.add(f)
            result.append(f)
    return result


def _compute_execution_topology(
    raw_text: str,
    stdout_bulk: str,
    stderr_bulk: str,
) -> dict[str, bool]:
    """Compute fine-grained execution topology: what actually happened at each semantic layer.

    Unlike the old binary capability flags, this disambiguates:
      - silently stripped payloads (never reached template)
      - reflected-but-not-executed (template saw it, didn't run it)
      - arithmetic evaluation without method invocation (Velocity parsed but SecurityManager limited)
      - reflection resolution without invocation (class loaded, call blocked)
    """
    combined = f"{raw_text} {stdout_bulk} {stderr_bulk}"
    topo: dict[str, bool] = {
        "parsed": False,
        "rendered": False,
        "variable_assignment": False,
        "arithmetic_eval": False,
        "string_output": False,
        "method_invocation": False,
        "reflection_resolution": False,
        "exception_visible": False,
        "exception_suppressed": False,
        "invocation_blocked": False,
    }

    # parsed: payload characters appear in response (may be reflected verbatim)
    payload_markers: list[str] = ['#set', '$class', 'forName', '#evaluate', '#macro']
    if any(m in raw_text for m in payload_markers):
        topo["parsed"] = True

    # arithmetic_eval: 7*7=49 — template definitely executed
    if re.search(r'\b49\b', raw_text) and '7*7' in raw_text:
        topo["arithmetic_eval"] = True
        topo["rendered"] = True
        topo["variable_assignment"] = True
        topo["string_output"] = True

    # variable_assignment: #set($x=...) and $x appears in output
    if re.search(r'#set\s*\(\s*\$\w+\s*=', combined, re.IGNORECASE):
        topo["variable_assignment"] = True

    # string_output: $variable references rendered into response body
    if re.search(r'\$\w+', raw_text):
        if len(raw_text) > 50:  # more than just the variable name itself
            topo["string_output"] = True

    # exception_visible
    if re.search(r'Exception|Caused by|TemplateException|ParseException|SecurityException',
                 combined, re.IGNORECASE):
        topo["exception_visible"] = True

    # reflection_resolution: Java class names appear in response or stdout
    if re.search(r'java\.lang\.|java\.io\.|java\.util\.', combined):
        topo["reflection_resolution"] = True

    # method_invocation: Runtime/Scanner/exec-related output
    if re.search(r'Runtime@|Scanner@|getRuntime|exec\(|ProcessBuilder|newInstance',
                 combined, re.IGNORECASE):
        topo["method_invocation"] = True

    # exception_suppressed: no visible exception but has error signals
    if not topo["exception_visible"]:
        if re.search(r'error|Error|ERROR|fail|FAIL', combined, re.IGNORECASE):
            if not topo["arithmetic_eval"]:
                topo["exception_suppressed"] = True

    # invocation_blocked: reflection reached but method not invoked, no exception visible
    if topo["reflection_resolution"] and not topo["method_invocation"] and not topo["exception_visible"]:
        topo["invocation_blocked"] = True

    return topo


def _build_failure_semantics_from_topology(
    topo: dict[str, bool],
    raw_text: str,
) -> list[dict[str, str]]:
    """Derive failure semantics from execution topology — much more precise than
    the old heuristic that confused silent_strip with reflected_not_executed."""
    semantics: list[dict[str, str]] = []

    if not topo["parsed"] and not topo["arithmetic_eval"]:
        # payload never reached the template engine at all
        semantics.append({
            "mode": "silent_strip",
            "hypothesis": "payload stripped before template engine — check encoding, param name, HTTP method",
            "implication": "try URL encoding, different param, or POST body",
        })
    elif topo["arithmetic_eval"] and not topo["method_invocation"] and not topo["reflection_resolution"]:
        # arithmetic worked but reflection doesn't — template evaluates, Java calls blocked
        semantics.append({
            "mode": "invocation_blocked",
            "hypothesis": "Velocity expression engine active but Java reflection/invocation restricted",
            "implication": "try alternate class resolution: $s.class, #evaluate directive, or loader surface",
        })
    elif topo["parsed"] and not topo["arithmetic_eval"]:
        # payload was reflected verbatim — template didn't even parse it
        semantics.append({
            "mode": "reflected_not_executed",
            "hypothesis": "template syntax reached but not parsed as Velocity — check encoding or delimiter",
            "implication": "try URL encode # as %23, or use POST with form data",
        })
    elif topo["invocation_blocked"]:
        semantics.append({
            "mode": "invocation_blocked",
            "hypothesis": "reflection resolution reached but method call blocked by SecurityManager or Uberspect",
            "implication": "switch surface: try #evaluate directive, macro abuse, or ResourceLoader",
        })
    elif topo["reflection_resolution"] and topo["method_invocation"] and not topo["exception_visible"]:
        # method was invoked but no output — could be Blind RCE or SecurityManager silent deny
        semantics.append({
            "mode": "method_invoked_no_output",
            "hypothesis": "reflection chain executed but no output visible — possible SecurityManager silent deny",
            "implication": "try file read via Java I/O instead of exec, or use in-band output capture",
        })

    return semantics

def _extract_html_form_facts(
    step_results: list[dict[str, Any]],
    chain_output: dict[str, Any] | None = None,
) -> None:
    """Deterministic HTML form extraction — write verified facts to RuntimeTruths.

    Only regex matches on actual HTTP response bodies. No LLM inference.
    Extracts: form method, action, input parameter names (with scoring),
    and confirms POST effectiveness only when arithmetic probe correlates.

    v5 changes:
      - POST confirmation requires probe correlation (arithmetic probe sent + 49 returned)
      - Parameter selection uses scoring instead of first-match (prefers known injection params)
    """
    from memory.runtime_truths import get_runtime_truths
    rtt = get_runtime_truths()

    # Collect all response body text from _http_responses
    response_bodies: list[str] = []
    all_stdout: list[str] = []

    for sr in step_results:
        rr = sr.get("result") or {}
        all_stdout.append(rr.get("stdout", ""))
        co = sr.get("chain_output") or {}
        for h in co.get("_http_responses", []):
            if isinstance(h, dict):
                body = h.get("response_body", "")
                if body:
                    response_bodies.append(body)

    if chain_output:
        for h in chain_output.get("_http_responses", []):
            if isinstance(h, dict):
                body = h.get("response_body", "")
                if body:
                    response_bodies.append(body)

    if not response_bodies:
        return

    combined_html = "\n".join(response_bodies)
    combined_stdout = "\n".join(all_stdout)

    # ── Extract form method ──
    form_method_match = re.search(
        r'<form[^>]+method\s*=\s*["\'](\w+)["\']', combined_html, re.IGNORECASE
    )
    if form_method_match:
        method = form_method_match.group(1).upper()
        rtt.set_fact(
            "form_method", method,
            evidence=f"HTML <form method='{method}'> detected in response",
        )

    # ── Extract form action ──
    form_action_match = re.search(
        r'<form[^>]+action\s*=\s*["\']([^"\']+)["\']', combined_html, re.IGNORECASE
    )
    if form_action_match:
        rtt.set_fact(
            "form_action", form_action_match.group(1),
            evidence="HTML form action detected in response",
        )

    # ── Parameter scoring: select best injection parameter ──
    BAD_FIELDS = {
        "csrf", "submit", "button", "token", "nonce",
        "_method", "action", "reset", "_token", "csrf_token",
    }
    GOOD_FIELDS = {
        "message", "text", "input", "query", "search",
        "content", "body", "data", "payload",
    }

    best_param: str | None = None
    best_score: int = -1

    for inp in re.finditer(
        r'<input[^>]+name\s*=\s*["\'](\w+)["\']', combined_html, re.IGNORECASE
    ):
        param = inp.group(1)
        param_lower = param.lower()
        if param_lower in BAD_FIELDS:
            continue
        score = 2 if param_lower in GOOD_FIELDS else 1
        if score > best_score:
            best_score = score
            best_param = param

    if best_param:
        rtt.set_fact(
            "form_param", best_param,
            evidence=f"HTML input name='{best_param}' selected by scoring (score={best_score})",
        )

    # ── Probe-correlated POST confirmation ──
    # Only confirm POST if an arithmetic probe was sent via POST and
    # the response contains the expected result (49), proving the
    # template engine renders POST body content.
    ARITHMETIC_PROBE = "#set($x=7*7)$x"
    ARITHMETIC_RESULT = "49"

    # Collect sent payloads from stdout
    sent_payload = ""
    for sr in step_results:
        rr = sr.get("result") or {}
        sent_payload += (rr.get("stdout", "") or "")
    if chain_output:
        sent_payload += (chain_output.get("_stdout", "") or "")

    probe_sent = (ARITHMETIC_PROBE in sent_payload) or ("%23set" in sent_payload)
    result_seen = bool(re.search(r'\b' + ARITHMETIC_RESULT + r'\b', combined_html))
    post_in_stdout = bool(re.search(r'\[HTTP\]\s+\d{3}\s+POST', combined_stdout))

    if probe_sent and result_seen and post_in_stdout:
        rtt.set_fact(
            "confirmed_render_method", "POST",
            evidence=(
                "POST with arithmetic probe returned 49 — "
                "confirmed POST body is rendered by template engine"
            ),
        )


def distill_response(
    step_results: list[dict[str, Any]],
    chain_output: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Main entry point: distill execution output into exploit-centric facts.

    Args:
        step_results: raw step_results from executor output
        chain_output: optional chain_context dict

    Returns structured distillation dict suitable for Planner and FSM injection.
    Backward-compatible: preserves all existing keys (capabilities, failure_fingerprints,
    meaningful_output, detected_artifacts, status_code).
    """
    if not step_results:
        return {
            "status_code": 0,
            "capabilities": {
                "payload_delivery": False, "reflection": False, "template_eval": False,
                "breakout": False, "object_access": False, "method_call": False,
                "classloader": False, "exec": False, "file_read": False, "flag_exfil": False,
            },
            "failure_fingerprints": [],
            "meaningful_output": "(no steps executed)",
            "detected_artifacts": [],
            "failure_semantics": [],
            "primitive_telemetry": {pid: "untried" for pid in _PRIMITIVE_DEFINITIONS},
            "execution_topology": {
                "parsed": False, "rendered": False, "variable_assignment": False,
                "arithmetic_eval": False, "string_output": False,
                "method_invocation": False, "reflection_resolution": False,
                "exception_visible": False, "exception_suppressed": False,
                "invocation_blocked": False,
            },
        }

    # Collect all raw text for analysis
    all_stdout_parts: list[str] = []
    all_stderr_parts: list[str] = []
    status_codes: list[int] = []

    for sr in step_results:
        rr = sr.get("result") or {}
        all_stdout_parts.append(rr.get("stdout", ""))
        all_stderr_parts.append(rr.get("stderr", ""))
        co = sr.get("chain_output") or {}
        for h in co.get("_http_responses", []):
            if isinstance(h, dict) and h.get("status_code"):
                status_codes.append(h["status_code"])

    if chain_output:
        all_stdout_parts.append(chain_output.get("_stdout", ""))
        all_stderr_parts.append(chain_output.get("_stderr", ""))

    raw_text = "\n".join(all_stdout_parts + all_stderr_parts)
    cleaned_text = _strip_noise(raw_text)

    # ── Runtime Truths: deterministic HTML form extraction ──────────
    _extract_html_form_facts(step_results, chain_output)

    # ── Flag detection (early exit) ────────────────────────────────
    flag = ""
    for pat in [r'HTB\{[^}]+\}', r'flag\{[^}]+\}', r'FLAG\{[^}]+\}', r'CTF\{[^}]+\}']:
        fm = re.search(pat, cleaned_text, re.IGNORECASE)
        if fm:
            flag = fm.group(0)
            break

    if flag:
        caps = {
            "payload_delivery": True, "reflection": True, "template_eval": True,
            "breakout": True, "object_access": True, "method_call": True,
            "classloader": True, "exec": True, "file_read": True, "flag_exfil": True,
        }
        telemetry = {pid: "success" for pid in _PRIMITIVE_DEFINITIONS}
        full_topo = {
            "parsed": True, "rendered": True, "variable_assignment": True,
            "arithmetic_eval": True, "string_output": True,
            "method_invocation": True, "reflection_resolution": True,
            "exception_visible": False, "exception_suppressed": False,
            "invocation_blocked": False,
        }
        return {
            "status_code": status_codes[-1] if status_codes else 200,
            "capabilities": caps,
            "failure_fingerprints": [],
            "meaningful_output": flag,
            "detected_artifacts": [flag],
            "failure_semantics": [],
            "primitive_telemetry": telemetry,
            "execution_topology": full_topo,
        }

    # ── Base meaningful output ─────────────────────────────────────
    meaningful = _extract_meaningful_output(raw_text)

    # ── Execution topology (fine-grained semantic layers) ──────────────
    stdout_bulk = "\n".join(all_stdout_parts)
    stderr_bulk = "\n".join(all_stderr_parts)
    exec_topo = _compute_execution_topology(cleaned_text, stdout_bulk, stderr_bulk)

    # ── Failure semantics from topology (replaces old heuristic) ───────
    failure_semantics = _build_failure_semantics_from_topology(exec_topo, cleaned_text)
    # Fall back to old heuristic if topology didn't detect anything
    if not failure_semantics:
        dominant_status = status_codes[-1] if status_codes else None
        failure_semantics = _extract_failure_semantics(
            cleaned_text, stdout_bulk, stderr_bulk, dominant_status, meaningful,
        )

    # ── Primitive telemetry (per-primitive fine-grained status) ─────
    combined = f"{cleaned_text} {' '.join(all_stdout_parts)} {' '.join(all_stderr_parts)}"
    primitive_telemetry = _compute_primitive_telemetry(combined)

    # ── Capability detection (backward-compatible signals) ──────────
    capabilities: dict[str, bool] = {
        "payload_delivery": False, "reflection": False, "template_eval": False,
        "breakout": False, "object_access": False, "method_call": False,
        "classloader": False, "exec": False, "file_read": False, "flag_exfil": False,
    }

    # payload_delivery: at least one step returned ok=True
    capabilities["payload_delivery"] = any(
        (rr.get("ok") for sr in step_results if (rr := sr.get("result")))
    )

    # Scan for legacy _CAP_SIGNALS
    for pattern, cap_key, _label in _CAP_SIGNALS:
        if re.search(pattern, cleaned_text):
            capabilities[cap_key] = True

    # reflection: non-trivial output from target
    has_http_response = bool(re.search(r"\[HTTP\]\s+\d{3}", cleaned_text))
    has_non_trivial_output = len(cleaned_text.strip()) > 20
    capabilities["reflection"] = has_http_response and has_non_trivial_output

    # Enrich capabilities from primitive_telemetry (more precise than _CAP_SIGNALS)
    tele = primitive_telemetry
    if capabilities["payload_delivery"] and not capabilities["reflection"]:
        if any(v != "untried" for v in tele.values()):
            capabilities["reflection"] = True

    if capabilities["reflection"] and re.search(r'\b49\b', cleaned_text) and '7*7' in cleaned_text:
        capabilities["template_eval"] = True

    if capabilities["template_eval"]:
        capabilities["payload_delivery"] = True
        capabilities["reflection"] = True

    # object_access: at least one jvm_reflection primitive showed any activity
    capabilities["object_access"] = any(
        tele[pid] in ("failed_silent", "failed_error", "success")
        for pid in ("string_getclass_forname", "class_inspect", "static_forname")
    ) or capabilities.get("object_access", False)

    # method_call: runtime_exec or constructor tried
    capabilities["method_call"] = any(
        tele[pid] in ("failed_silent", "failed_error", "success")
        for pid in ("runtime_exec", "constructor_newinstance", "processbuilder")
    ) or capabilities.get("method_call", False)

    # classloader: any jvm_reflection primitive succeeded
    capabilities["classloader"] = any(
        tele[pid] == "success"
        for pid in ("string_getclass_forname", "static_forname", "constructor_newinstance")
    ) or capabilities.get("classloader", False)

    if capabilities["object_access"] or capabilities["method_call"]:
        capabilities["breakout"] = True
    if capabilities["method_call"]:
        capabilities["object_access"] = True
    if capabilities["classloader"]:
        capabilities["method_call"] = True
    if capabilities["exec"]:
        capabilities["classloader"] = True
    if capabilities["file_read"]:
        capabilities["exec"] = True
    if capabilities["flag_exfil"]:
        capabilities["file_read"] = True

    capabilities["breakout"] = capabilities["template_eval"] and (
        capabilities["object_access"] or capabilities["method_call"]
    )

    # ── Artifact extraction ────────────────────────────────────────
    artifacts: list[str] = []
    for pattern, label in _ARTIFACT_PATTERNS:
        for m in re.finditer(pattern, cleaned_text):
            val = m.group(0).strip()
            if val and val not in artifacts:
                artifacts.append(val)
    artifacts = artifacts[:10]

    # ── Dominant HTTP status ───────────────────────────────────────
    dominant_status = status_codes[-1] if status_codes else 0

    # ── Failure fingerprints ───────────────────────────────────────
    fingerprints = _detect_failure_fingerprints(raw_text, step_results)

    # ── Meaningful output (fallback: strip HTML) ───────────────────
    if not meaningful:
        stripped = re.sub(r'<[^>]+>', '', cleaned_text).strip()
        stripped = re.sub(r'\s+', ' ', stripped)
        if stripped and stripped not in ('Example text', ''):
            meaningful = stripped[:200]

    return {
        "status_code": dominant_status,
        "capabilities": capabilities,
        "failure_fingerprints": fingerprints,
        "meaningful_output": meaningful,
        "detected_artifacts": artifacts,
        # ── v3: granular signals ──
        "failure_semantics": failure_semantics,
        "primitive_telemetry": primitive_telemetry,
        "execution_topology": exec_topo,
    }


def distill_batch(
    step_results: list[dict[str, Any]],
    chain_output: dict[str, Any] | None = None,
    prior_fingerprints: set[str] | None = None,
) -> dict[str, Any]:
    """Variant of distill_response that also merges prior-round fingerprints."""
    result = distill_response(step_results, chain_output)
    if prior_fingerprints:
        merged = set(prior_fingerprints) | set(result["failure_fingerprints"])
        result["failure_fingerprints"] = sorted(merged)
    return result


def format_distilled_for_prompt(distilled: dict[str, Any]) -> str:
    """Render a distilled execution as a compact text block for Planner injection.

    Budget target: ~400 chars. No HTML, no CSS, no raw transcript.
    v3: includes failure_semantics and primitive_telemetry summary.
    """
    caps = distilled.get("capabilities", {})
    fps = distilled.get("failure_fingerprints", [])
    artifacts = distilled.get("detected_artifacts", [])
    meaningful = distilled.get("meaningful_output", "")
    status = distilled.get("status_code", 0)
    fsems = distilled.get("failure_semantics", [])
    telemetry = distilled.get("primitive_telemetry", {})
    topo = distilled.get("execution_topology", {})

    achieved = [k for k, v in caps.items() if v]
    cap_line = f"caps: [{', '.join(achieved)}]" if achieved else "caps: [payload_delivery]"

    fp_line = f"fails: [{', '.join(fps[:5])}]" if fps else "fails: []"

    # Failure semantics summary
    if fsems:
        fmode = fsems[0].get("mode", "?")
        fsem_line = f"semantics: [{fmode}]"
    else:
        fsem_line = ""

    # Execution topology: show only True layers
    if topo:
        active_topo = [k for k, v in topo.items() if v]
        if active_topo:
            topo_line = f"topo: [{', '.join(active_topo[:6])}]"
        else:
            topo_line = ""
    else:
        topo_line = ""

    # Primitive telemetry: show only non-untried
    active_prims = {k: v for k, v in telemetry.items() if v != "untried"}
    if active_prims:
        prim_parts = [f"{k}={v}" for k, v in list(active_prims.items())[:4]]
        prim_line = f"prims: [{', '.join(prim_parts)}]"
    else:
        prim_line = ""

    artifact_line = f"arti: [{', '.join(artifacts[:4])}]" if artifacts else ""
    out_line = f"out: {meaningful[:120]}" if meaningful else ""

    parts = [f"HTTP {status}", cap_line, fp_line, topo_line, fsem_line, prim_line, artifact_line, out_line]
    return " | ".join(p for p in parts if p)


def derive_observed_fingerprint(
    distilled: dict[str, Any],
    fb: dict[str, Any] | None = None,
    plan: dict[str, Any] | None = None,
) -> str:
    """Derive what the Planner actually tried from execution evidence.

    Uses distiller output (capabilities, failure_fingerprints, execution_topology,
    primitive_telemetry), Evaluator detected_primitives from fb, and plan payload
    text — NOT HypothesisTracker or confirmed_vuln.

    Returns a compact normalized fingerprint like:
        ssti_jinja2, ssti_velocity, ssti_generic, crlf_injection, pickle_rce,
        object_access_only, template_eval_only, no_reflection, path_traversal,
        xss_reflected, cmd_injection, sql_injection, deserialization, ssrf,
        information_disclosure, unknown
    """
    fb = fb or {}
    plan = plan or {}
    caps = distilled.get("capabilities", {})
    topo = distilled.get("execution_topology", {})
    telemetry = distilled.get("primitive_telemetry", {})
    fingerprints = distilled.get("failure_fingerprints", [])
    detected_primitives = fb.get("detected_primitives", [])

    # ── Step 1: Infer template engine from plan payload text ─────────
    all_commands = ""
    for st in plan.get("steps", []):
        all_commands += str(st.get("command", "")) + " "
        all_commands += str(st.get("purpose", "")) + " "

    engine = ""
    if "{{" in all_commands and "}}" in all_commands:
        if any(kw in all_commands for kw in ("__class__", "__globals__", "__mro__", "__subclasses__", "lipsum", "config")):
            engine = "jinja2"
        elif "cycler" in all_commands or "joiner" in all_commands:
            engine = "jinja2"
        else:
            engine = "jinja2"  # {{...}} is Jinja2/Django/Twig signature
    elif "${" in all_commands and "}" in all_commands:
        if "#set" in all_commands or "$class" in all_commands or "#evaluate" in all_commands:
            engine = "velocity"
        else:
            engine = "mako"  # ${...} without velocity directives → Mako/Thymeleaf
    elif "#set" in all_commands or "$class" in all_commands or "#evaluate" in all_commands:
        engine = "velocity"
    elif "{%" in all_commands and "%}" in all_commands:
        engine = "jinja2"  # block tags
    elif "<%" in all_commands and "%>" in all_commands:
        engine = "jsp_el"

    # ── Step 2: Distiller failure fingerprint signals ────────────────
    ff_set = set(fingerprints)
    if "ssti_surface_blocked" in ff_set:
        return f"ssti_{engine}" if engine else "ssti_generic"
    if "template_eval_only" in ff_set:
        return f"ssti_{engine}_eval_only" if engine else "ssti_eval_only"
    if "reflection_only" in ff_set:
        return f"ssti_{engine}_reflection" if engine else "ssti_reflection"
    if "object_access_only" in ff_set:
        return "object_access_only"
    if "no_reflection" in ff_set:
        # CRLF/pickle payload detection
        if any(kw in all_commands.lower() for kw in ("crlf", "memcached", "pickle", "set%0d%0a", "%0d%0a")):
            return "crlf_injection"
        if any(kw in all_commands.lower() for kw in ("../", "..\\", "path traversal", "directory traversal")):
            return "path_traversal"
        if engine:
            return f"ssti_{engine}"
        return "no_reflection"
    if "connection_refused" in ff_set:
        return "connection_refused"
    if "syntax_error" in ff_set:
        return "syntax_error"

    # ── Step 3: Evaluator detected_primitives ────────────────────────
    if detected_primitives:
        dp_set = {p.lower() for p in detected_primitives}
        if any("ssti" in p for p in dp_set):
            return f"ssti_{engine}" if engine else "ssti_generic"
        if any("crlf" in p for p in dp_set):
            return "crlf_injection"
        if any("pickle" in p for p in dp_set) or any("deserial" in p for p in dp_set):
            return "pickle_rce"
        if any("xss" in p for p in dp_set):
            return "xss_reflected"
        if any("cmdi" in p or "command_injection" in p for p in dp_set):
            return "cmd_injection"
        if any("sqli" in p or "sql" in p for p in dp_set):
            return "sql_injection"
        if any("path_traversal" in p or "lfi" in p or "directory" in p for p in dp_set):
            return "path_traversal"

    # ── Step 4: Capabilities and topology signals ────────────────────
    if caps.get("template_eval"):
        return f"ssti_{engine}" if engine else "ssti_generic"
    if caps.get("object_access") and not caps.get("template_eval"):
        return "object_access_only"
    if topo.get("parsed") and not topo.get("rendered"):
        if "{{" in all_commands or "#set" in all_commands or "${" in all_commands:
            return f"ssti_{engine}_surface_blocked" if engine else "ssti_surface_blocked"

    # ── Step 5: Primitive telemetry — any activity? ──────────────────
    active_prims = {k: v for k, v in telemetry.items() if v != "untried"}
    if active_prims:
        # Map active primitive surfaces to observed fingerprint
        surfaces = set()
        for pid, status in active_prims.items():
            if status in ("failed_silent", "failed_error", "success"):
                if pid in ("string_getclass_forname", "class_inspect", "static_forname",
                           "constructor_newinstance", "runtime_exec", "processbuilder"):
                    surfaces.add("jvm_reflection")
                elif pid in ("evaluate_directive", "macro_abuse"):
                    surfaces.add("template_internal")
                elif pid in ("resource_loader",):
                    surfaces.add("loader_surface")
                elif pid in ("uberspect",):
                    surfaces.add("sandbox_escape")
        if surfaces:
            surf_str = "+".join(sorted(surfaces))
            return f"{surf_str}_attempt"

    # ── Step 6: Generic payload pattern detection ────────────────────
    all_lower = all_commands.lower()
    if any(kw in all_lower for kw in ("crlf", "memcached", "pickle", "%0d%0a")):
        return "crlf_injection"
    if any(kw in all_lower for kw in ("../", "..\\", "path traversal")):
        return "path_traversal"
    if any(kw in all_lower for kw in ("<script>", "alert(", "onerror=", "xss")):
        return "xss_reflected"
    if any(kw in all_lower for kw in ("exec(", "runtime.exec", "processbuilder", "os.system", "subprocess")):
        return "cmd_injection"
    if any(kw in all_lower for kw in ("select ", "union select", "sql")):
        return "sql_injection"
    if any(kw in all_lower for kw in ("ssrf", "url=", "fetch(", "http://") ):
        return "ssrf"

    # ── Step 7: Fallback — was anything even delivered? ──────────────
    if caps.get("payload_delivery"):
        return "probe_sent"
    if all_commands.strip():
        return "unknown"
    return "none"


def normalize_observed_fingerprint(observed: str) -> str | None:
    """Map observed_fingerprint to a canonical HypothesisTracker fingerprint.

    Surface labels (ssti_jinja2, crlf_injection, path_traversal, ...) map to
    vector*component*goal fingerprints for rejection tracking.

    Signal/state labels (no_reflection, connection_refused, syntax_error, ...)
    return None — they are diagnostic symptoms, not attack surfaces, and must
    not enter the hypothesis rejection system.
    """
    if not observed:
        return None

    _SIGNALS: set[str] = {
        "no_reflection", "connection_refused", "syntax_error",
        "probe_sent", "unknown", "none", "security_blocked",
        "field_mismatch", "email_validation_block", "url_error",
        "method_blocked", "classloader_blocked", "reflection_only",
    }
    if observed in _SIGNALS:
        return None

    _SURFACE_MAP: dict[str, str] = {
        # ── SSTI: Jinja2 ──
        "ssti_jinja2":                "ssti*jinja2*exec",
        "ssti_jinja2_eval_only":       "ssti*jinja2*exec",
        "ssti_jinja2_reflection":      "ssti*jinja2*exec",
        "ssti_jinja2_surface_blocked": "ssti*jinja2*exec",
        # ── SSTI: Velocity ──
        "ssti_velocity":               "ssti*velocity*exec",
        "ssti_velocity_eval_only":      "ssti*velocity*exec",
        "ssti_velocity_reflection":     "ssti*velocity*exec",
        # ── SSTI: other engines ──
        "ssti_mako":                   "ssti*mako*exec",
        "ssti_jsp_el":                 "ssti*jsp_el*exec",
        # ── SSTI: generic / unknown engine ──
        "ssti_generic":                "ssti*generic*exec",
        "ssti_eval_only":              "ssti*generic*exec",
        "ssti_reflection":             "ssti*generic*exec",
        "ssti_surface_blocked":        "ssti*generic*exec",
        "template_eval_only":          "ssti*generic*exec",
        "object_access_only":          "ssti*generic*exec",
        # ── CRLF / deserialization ──
        "crlf_injection":              "crlf*memcached*pickle_rce",
        "pickle_rce":                  "crlf*memcached*pickle_rce",
        # ── Other attack surfaces ──
        "path_traversal":              "path_traversal*fs*read",
        "cmd_injection":               "cmd_injection*shell*exec",
        "xss_reflected":               "xss*reflected*exec",
        "sql_injection":               "sql_injection*db*read",
        "ssrf":                        "ssrf*http*read",
        "deserialization":             "deserialization*generic*exec",
    }

    if observed in _SURFACE_MAP:
        return _SURFACE_MAP[observed]

    # Wildcard: ssti_*_surface_blocked variants
    if observed.startswith("ssti_") and observed.endswith("_surface_blocked"):
        return "ssti*generic*exec"

    # Compound labels (e.g. jvm_reflection+template_internal_attempt) → ambiguous
    if "+" in observed:
        return None

    return None


def map_stage_to_surface(stage: str) -> str:
    """Map an FSM stage name to its exploitation surface. Public for coordinator use."""
    return STAGE_SURFACE_MAP.get(stage, "")


# ── Self-test ──────────────────────────────────────────────────────
if __name__ == "__main__":
    sample = [
        {
            "step_id": "step-1",
            "result": {
                "ok": True,
                "stdout": "HTTP 200 <!DOCTYPE html><html>... <div>49</div> ...</html>\nSTEP_OK\n",
                "stderr": "",
            },
            "chain_output": {
                "_stdout": "resp text has 49",
                "_http_responses": [{"status_code": 200, "method": "GET", "url": "/api", "response_body": "<html>49</html>"}],
            },
        },
    ]
    d = distill_response(sample)
    print(json.dumps(d, indent=2, ensure_ascii=False))
    print()
    print(format_distilled_for_prompt(d))

    # Test with silent_strip
    print("\n--- silent_strip test ---")
    silent_sample = [
        {
            "step_id": "step-1",
            "result": {
                "ok": True,
                "stdout": (
                    "[*] Sending payload #set($x='')#set($runtime=$x.class.forName('java.lang.Runtime'))\n"
                    "HTTP 200 / => Example text\n"
                    "STEP_OK\n"
                ),
                "stderr": "",
            },
            "chain_output": {
                "_stdout": "#set runtime payload sent",
                "_http_responses": [{"status_code": 200, "method": "GET", "url": "/?text=", "response_body": "Example text"}],
            },
        },
    ]
    d2 = distill_response(silent_sample)
    print(json.dumps(d2, indent=2, ensure_ascii=False))
    print()
    print(format_distilled_for_prompt(d2))