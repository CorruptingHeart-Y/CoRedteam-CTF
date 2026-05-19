"""
ingest_patt.py — PayloadsAllTheThings + Nuclei Templates → Co-RedTeam memory ingestion

Usage:
    python b/ingest_patt.py --dry-run                   # preview PATT only, no writes
    python b/ingest_patt.py                             # ingest PATT into b/memory/*.json
    python b/ingest_patt.py --dir "SQL Injection"       # PATT single directory
    python b/ingest_patt.py --source nuclei             # ingest Nuclei templates (web only)
    python b/ingest_patt.py --source nuclei --dry-run   # preview Nuclei ingestion
    python b/ingest_patt.py --source all                # ingest both sources
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# ── Paths ────────────────────────────────────────────────────────────────────
REPO_ROOT    = Path(__file__).parent.parent          # redteam/
PATT_ROOT    = REPO_ROOT / "PayloadsAllTheThings-master"
NUCLEI_ROOT  = Path(__file__).parent / "nuclei-templates-main" / "nuclei-templates-main"
MEMORY_DIR   = Path(__file__).parent / "memory"

PATTERN_FILE  = MEMORY_DIR / "pattern.json"
STRATEGY_FILE = MEMORY_DIR / "strategy.json"
TECH_FILE     = MEMORY_DIR / "tech.json"

# ── Target directories (Web-focused) ─────────────────────────────────────────
WEB_DIRS = [
    "Command Injection",
    "Server Side Template Injection",
    "SQL Injection",
    "XSS Injection",
    "Directory Traversal",
    "File Inclusion",
    "Server Side Request Forgery",
    "Insecure Deserialization",
    "Upload Insecure Files",
    "Open Redirect",
    "Cross-Site Request Forgery",
    "NoSQL Injection",
    "GraphQL Injection",
    "LDAP Injection",
    "XPATH Injection",
    "XXE Injection",
    "XSLT Injection",
    "LaTeX Injection",
    "JSON Web Token",
    "Race Condition",
    "Request Smuggling",
    "Prototype Pollution",
    "CSS Injection",
    "CRLF Injection",
]

# Section headings that signal bypass / evasion strategies
_STRATEGY_KEYWORDS = re.compile(
    r"bypass|evasion|filter|obfuscat|trick|chaining|polyglot|waf|encode|escape"
    r"|methodology|exploit|exfiltrat|injection|payload|detection|mitigation"
    r"|blind|time.based|error.based|union|out.of.band|oob|rce|lfi|rfi|ssrf",
    re.IGNORECASE,
)

# Code fence: ```<lang>\n<body>\n```
_CODE_BLOCK_RE = re.compile(
    r"```(\w*)\n(.*?)```",
    re.DOTALL,
)

# H2 section heading
_H2_RE = re.compile(r"^## (.+)$", re.MULTILINE)
# H3 section heading
_H3_RE = re.compile(r"^### (.+)$", re.MULTILINE)


# ── Markdown helpers ──────────────────────────────────────────────────────────

def _first_paragraph(text: str) -> str:
    """Return the first non-empty, non-heading paragraph."""
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("*") and not line.startswith("-"):
            return line[:300]
    return ""


def _split_sections(text: str) -> list[tuple[str, str]]:
    """Split markdown into (heading, body) pairs at H2 level."""
    parts = _H2_RE.split(text)
    # parts[0] = preamble, then alternating heading / body
    sections: list[tuple[str, str]] = []
    if len(parts) > 1:
        for i in range(1, len(parts), 2):
            heading = parts[i].strip()
            body    = parts[i + 1] if i + 1 < len(parts) else ""
            sections.append((heading, body))
    return sections


def _extract_code_blocks(text: str, lang_filter: set[str] | None = None) -> list[dict[str, str]]:
    """Extract all fenced code blocks, optionally filtered by language."""
    blocks = []
    for m in _CODE_BLOCK_RE.finditer(text):
        lang = m.group(1).lower() or "text"
        code = m.group(2).strip()
        if not code:
            continue
        if lang_filter and lang not in lang_filter:
            continue
        blocks.append({"lang": lang, "code": code})
    return blocks


# ── Per-file parsing ──────────────────────────────────────────────────────────

def parse_readme(vuln_dir: str, readme_path: Path) -> dict[str, Any]:
    """
    Returns:
        {
          "patterns":  [ {...} ],   # → pattern.json
          "strategies": [ {...} ],  # → strategy.json
          "payloads":  [ {...} ],   # → tech.json (payload_templates)
          "scripts":   [ {...} ],   # → tech.json (scripts)
        }
    """
    text = readme_path.read_text(encoding="utf-8", errors="replace")

    # ── L1: Pattern ──────────────────────────────────────────────────────────
    first_para = _first_paragraph(text)
    # Strip leading "> " blockquote marker
    first_para = re.sub(r"^>\s*", "", first_para)

    pattern_id = vuln_dir.lower().replace(" ", "_")
    pattern_entry = {
        "id":          pattern_id,
        "vuln_type":   vuln_dir,
        "description": first_para,
        "source":      "PayloadsAllTheThings",
    }

    # ── L2: Strategies (bypass / filter-evasion sections) ────────────────────
    strategies: list[dict] = []
    for heading, body in _split_sections(text):
        if not _STRATEGY_KEYWORDS.search(heading):
            continue
        # Collect sub-headings as tactics
        tactics = _H3_RE.findall(body)
        # Collect first sentence of body as summary
        summary_line = _first_paragraph(body)
        # Collect any inline code snippets as examples (short, ≤120 chars)
        examples = [
            m.group(0)
            for m in re.finditer(r"`([^`\n]{1,120})`", body)
        ][:5]
        strategies.append({
            "context":  f"{vuln_dir} — {heading}",
            "summary":  summary_line or heading,
            "tactics":  tactics[:10],
            "examples": examples,
            "source":   "PayloadsAllTheThings",
        })

    # ── L3: Tech — payloads and scripts ──────────────────────────────────────
    payloads: list[dict] = []
    scripts:  list[dict] = []

    # Walk sections to attach context to each code block
    sections = _split_sections(text)
    # Also parse preamble (before first H2)
    preamble_end = text.find("\n## ")
    preamble = text[:preamble_end] if preamble_end != -1 else text
    sections = [("Overview", preamble)] + sections

    for heading, body in sections:
        blocks = _extract_code_blocks(body)
        for blk in blocks:
            lang = blk["lang"]
            code = blk["code"]
            # Skip table-of-contents / reference-only blocks
            if len(code) < 4 or code.startswith("http"):
                continue
            entry = {
                "name":    f"{pattern_id}_{heading.lower().replace(' ', '_')[:40]}",
                "context": f"{vuln_dir} — {heading}",
                "lang":    lang,
                "source":  "PayloadsAllTheThings",
            }
            # Multi-line → script; single-line → payload template
            if "\n" in code and len(code) > 80:
                entry["content"] = code[:2000]
                scripts.append(entry)
            else:
                entry["template"] = code[:500]
                payloads.append(entry)

    return {
        "patterns":   [pattern_entry],
        "strategies": strategies,
        "payloads":   payloads,
        "scripts":    scripts,
    }


# ── Safe merge helpers ────────────────────────────────────────────────────────

def _load_json(path: Path) -> dict:
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {}


def _merge_pattern(existing: dict, new_entries: list[dict]) -> dict:
    existing.setdefault("version", 1)
    existing.setdefault("patterns", [])
    existing_ids = {p.get("id") for p in existing["patterns"]}
    added = 0
    for entry in new_entries:
        if entry.get("id") not in existing_ids:
            existing["patterns"].append(entry)
            existing_ids.add(entry["id"])
            added += 1
    return existing, added


def _merge_strategy(existing: dict, new_entries: list[dict]) -> dict:
    existing.setdefault("version", 1)
    existing.setdefault("success_strategies", [])
    existing.setdefault("failure_lessons", [])
    existing_contexts = {s.get("context") for s in existing["success_strategies"]}
    added = 0
    for entry in new_entries:
        if entry.get("context") not in existing_contexts:
            existing["success_strategies"].append(entry)
            existing_contexts.add(entry["context"])
            added += 1
    return existing, added


def _merge_tech(existing: dict, new_payloads: list[dict], new_scripts: list[dict]) -> dict:
    existing.setdefault("version", 1)
    existing.setdefault("commands", [])
    existing.setdefault("payload_templates", [])
    existing.setdefault("scripts", [])

    # Deduplicate by (context, template/content) fingerprint
    existing_payload_fps = {
        (p.get("context", ""), p.get("template", ""))
        for p in existing["payload_templates"]
    }
    existing_script_fps = {
        (s.get("context", ""), s.get("content", "")[:80])
        for s in existing["scripts"]
    }

    p_added = s_added = 0
    for p in new_payloads:
        fp = (p.get("context", ""), p.get("template", ""))
        if fp not in existing_payload_fps:
            existing["payload_templates"].append(p)
            existing_payload_fps.add(fp)
            p_added += 1
    for s in new_scripts:
        fp = (s.get("context", ""), s.get("content", "")[:80])
        if fp not in existing_script_fps:
            existing["scripts"].append(s)
            existing_script_fps.add(fp)
            s_added += 1

    return existing, p_added, s_added


# ── Nuclei YAML parsing ───────────────────────────────────────────────────────

# Web-relevant subdirectories to ingest from nuclei-templates
_NUCLEI_WEB_DIRS = [
    "http/vulnerabilities",
    "http/fuzzing",
    "dast/vulnerabilities",
]

# Tags that map to CWE / vuln-type concepts for strategy classification
_NUCLEI_STRATEGY_TAGS = re.compile(
    r"rce|sqli|xss|ssti|ssrf|lfi|rfi|xxe|csrf|idor|redirect|upload|deserializ"
    r"|command.inject|code.inject|bypass|traversal|injection|fuzz|blind|oob|oast"
    r"|smuggling|pollution|crlf|nosql|graphql|jwt|race",
    re.IGNORECASE,
)

# CWE tag pattern in nuclei info.classification
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


def _parse_nuclei_yaml(yaml_path: Path) -> dict[str, Any] | None:
    """
    Parse a single nuclei YAML template.
    Returns dict with keys: id, name, severity, description, cwe_ids, tags,
    payloads (list[str]), matchers_hint (str), source_path (str).
    Returns None if the file is not a web HTTP/DAST template or lacks useful content.
    """
    try:
        import yaml as _yaml
        data = _yaml.safe_load(yaml_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None

    if not isinstance(data, dict):
        return None

    # Must have http or dast section
    if "http" not in data and "dast" not in data:
        return None

    info = data.get("info") or {}
    template_id   = data.get("id", yaml_path.stem)
    name          = info.get("name", template_id)
    severity      = info.get("severity", "unknown").lower()
    description   = (info.get("description") or "").strip().replace("\n", " ")[:400]
    tags_raw      = info.get("tags", "")
    tags: list[str] = [t.strip() for t in str(tags_raw).split(",") if t.strip()] if tags_raw else []

    # CWE extraction
    classification = info.get("classification") or {}
    cwe_raw = classification.get("cwe-id", "")
    cwe_ids: list[str] = []
    if cwe_raw:
        if isinstance(cwe_raw, list):
            cwe_ids = [str(c).upper() for c in cwe_raw]
        else:
            cwe_ids = [m.upper() for m in _CWE_RE.findall(str(cwe_raw))]

    # Payload extraction: collect from http[].payloads values and path/raw entries
    payloads: list[str] = []
    http_blocks = data.get("http") or data.get("dast") or []
    if isinstance(http_blocks, dict):
        http_blocks = [http_blocks]

    for block in (http_blocks if isinstance(http_blocks, list) else []):
        # payloads: dict of {key: [val, ...]}
        blk_payloads = block.get("payloads") or {}
        if isinstance(blk_payloads, dict):
            for vals in blk_payloads.values():
                if isinstance(vals, list):
                    payloads.extend(str(v)[:200] for v in vals if str(v).strip())
                elif isinstance(vals, str) and not vals.endswith(".txt"):
                    payloads.append(vals[:200])

        # fuzzing[].fuzz values
        for fuzz_block in (block.get("fuzzing") or []):
            if isinstance(fuzz_block, dict):
                for fv in (fuzz_block.get("fuzz") or []):
                    if isinstance(fv, str) and fv.strip():
                        payloads.append(fv[:200])

        # path[] entries (GET paths with injected params)
        for p in (block.get("path") or []):
            if isinstance(p, str) and len(p) > 10:
                payloads.append(p[:300])

        # raw[] entries (raw HTTP request templates)
        for r in (block.get("raw") or []):
            if isinstance(r, str) and len(r) > 20:
                payloads.append(r[:400])

    # Matcher regex/words as detection hints
    matcher_hints: list[str] = []
    for block in (http_blocks if isinstance(http_blocks, list) else []):
        for m in (block.get("matchers") or []):
            if not isinstance(m, dict):
                continue
            if m.get("type") == "regex":
                matcher_hints.extend(str(r)[:100] for r in (m.get("regex") or [])[:3])
            elif m.get("type") == "word":
                matcher_hints.extend(str(w)[:80] for w in (m.get("words") or [])[:3])

    if not payloads and not description:
        return None

    # Deduplicate payloads preserving order
    seen: set[str] = set()
    unique_payloads: list[str] = []
    for p in payloads:
        if p not in seen:
            seen.add(p)
            unique_payloads.append(p)

    return {
        "id":           template_id,
        "name":         name,
        "severity":     severity,
        "description":  description,
        "cwe_ids":      cwe_ids,
        "tags":         tags,
        "payloads":     unique_payloads[:30],
        "matcher_hint": " | ".join(matcher_hints[:5]),
        "source_path":  str(yaml_path.relative_to(NUCLEI_ROOT)),
    }


def parse_nuclei_dir(subdir: str) -> dict[str, Any]:
    """
    Walk a nuclei web subdir and return pattern/strategy/payload/script lists
    in the same shape as parse_readme().
    """
    base = NUCLEI_ROOT / subdir
    patterns:   list[dict] = []
    strategies: list[dict] = []
    payloads:   list[dict] = []
    scripts:    list[dict] = []

    yaml_files = sorted(base.rglob("*.yaml"))
    for yf in yaml_files:
        parsed = _parse_nuclei_yaml(yf)
        if parsed is None:
            continue

        vuln_type = parsed["tags"][0] if parsed["tags"] else subdir.split("/")[-1]
        pattern_id = f"nuclei_{parsed['id']}"

        # ── L1: Pattern ──
        patterns.append({
            "id":          pattern_id,
            "vuln_type":   vuln_type,
            "description": parsed["description"] or parsed["name"],
            "cwe_ids":     parsed["cwe_ids"],
            "severity":    parsed["severity"],
            "tags":        parsed["tags"],
            "source":      "nuclei-templates",
            "source_path": parsed["source_path"],
        })

        # ── L2: Strategy (only for templates with strategy-relevant tags) ──
        has_strategy_tag = any(_NUCLEI_STRATEGY_TAGS.search(t) for t in parsed["tags"])
        if has_strategy_tag and parsed["description"]:
            strategies.append({
                "context":  f"nuclei/{parsed['id']} — {parsed['name']}",
                "summary":  parsed["description"][:200],
                "tactics":  parsed["tags"][:8],
                "examples": parsed["payloads"][:3],
                "cwe_ids":  parsed["cwe_ids"],
                "severity": parsed["severity"],
                "matcher_hint": parsed["matcher_hint"],
                "source":   "nuclei-templates",
            })

        # ── L3: Tech (payloads and multi-line scripts) ──
        for pval in parsed["payloads"]:
            if "\n" in pval and len(pval) > 80:
                scripts.append({
                    "name":    f"nuclei_{parsed['id']}",
                    "context": f"nuclei/{vuln_type} — {parsed['name']}",
                    "lang":    "http",
                    "content": pval[:2000],
                    "source":  "nuclei-templates",
                })
            elif pval.strip():
                payloads.append({
                    "name":     f"nuclei_{parsed['id']}",
                    "context":  f"nuclei/{vuln_type} — {parsed['name']}",
                    "lang":     "http",
                    "template": pval[:500],
                    "source":   "nuclei-templates",
                })

    return {
        "patterns":   patterns,
        "strategies": strategies,
        "payloads":   payloads,
        "scripts":    scripts,
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def _run_patt(args: argparse.Namespace) -> tuple[list, list, list, list]:
    target_dirs = [args.dir] if args.dir else WEB_DIRS
    all_patterns:   list[dict] = []
    all_strategies: list[dict] = []
    all_payloads:   list[dict] = []
    all_scripts:    list[dict] = []

    for vuln_dir in target_dirs:
        readme = PATT_ROOT / vuln_dir / "README.md"
        if not readme.exists():
            print(f"  [skip] {vuln_dir}: README.md not found")
            continue
        parsed = parse_readme(vuln_dir, readme)
        all_patterns.extend(parsed["patterns"])
        all_strategies.extend(parsed["strategies"])
        all_payloads.extend(parsed["payloads"])
        all_scripts.extend(parsed["scripts"])
        print(
            f"  [patt] {vuln_dir}: "
            f"{len(parsed['strategies'])} strategies, "
            f"{len(parsed['payloads'])} payloads, "
            f"{len(parsed['scripts'])} scripts"
        )
    return all_patterns, all_strategies, all_payloads, all_scripts


def _run_nuclei(args: argparse.Namespace) -> tuple[list, list, list, list]:
    if not NUCLEI_ROOT.exists():
        print(f"  [error] nuclei-templates not found at: {NUCLEI_ROOT}")
        return [], [], [], []

    all_patterns:   list[dict] = []
    all_strategies: list[dict] = []
    all_payloads:   list[dict] = []
    all_scripts:    list[dict] = []

    for subdir in _NUCLEI_WEB_DIRS:
        if not (NUCLEI_ROOT / subdir).exists():
            print(f"  [skip] nuclei/{subdir}: not found")
            continue
        parsed = parse_nuclei_dir(subdir)
        all_patterns.extend(parsed["patterns"])
        all_strategies.extend(parsed["strategies"])
        all_payloads.extend(parsed["payloads"])
        all_scripts.extend(parsed["scripts"])
        print(
            f"  [nuclei] {subdir}: "
            f"{len(parsed['patterns'])} patterns, "
            f"{len(parsed['strategies'])} strategies, "
            f"{len(parsed['payloads'])} payloads, "
            f"{len(parsed['scripts'])} scripts"
        )
    return all_patterns, all_strategies, all_payloads, all_scripts


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Ingest PayloadsAllTheThings / Nuclei Templates into Co-RedTeam memory"
    )
    parser.add_argument("--dry-run", action="store_true", help="Preview only, no writes")
    parser.add_argument("--dir", metavar="NAME", help="Process a single PATT directory (patt source only)")
    parser.add_argument(
        "--source",
        choices=["patt", "nuclei", "all"],
        default="patt",
        help="Source to ingest: patt (default), nuclei, or all",
    )
    args = parser.parse_args()

    all_patterns:   list[dict] = []
    all_strategies: list[dict] = []
    all_payloads:   list[dict] = []
    all_scripts:    list[dict] = []

    if args.source in ("patt", "all"):
        print("\n── PayloadsAllTheThings ──")
        p, s, pl, sc = _run_patt(args)
        all_patterns.extend(p); all_strategies.extend(s)
        all_payloads.extend(pl); all_scripts.extend(sc)

    if args.source in ("nuclei", "all"):
        print("\n── Nuclei Templates (web only) ──")
        p, s, pl, sc = _run_nuclei(args)
        all_patterns.extend(p); all_strategies.extend(s)
        all_payloads.extend(pl); all_scripts.extend(sc)

    print(
        f"\nTotal: {len(all_patterns)} patterns, {len(all_strategies)} strategies, "
        f"{len(all_payloads)} payloads, {len(all_scripts)} scripts"
    )

    if args.dry_run:
        print("\n── DRY RUN: sample payloads (first 5) ──")
        for p in all_payloads[:5]:
            print(f"  [{p['lang']}] {p['context'][:60]}")
            print(f"    {p['template'][:120]}")
        print("\n── DRY RUN: sample strategies (first 3) ──")
        for s in all_strategies[:3]:
            print(f"  {s['context'][:70]}")
            print(f"    {s['summary'][:120]}")
        print("\nNo files written (--dry-run). Remove flag to commit.")
        return

    # ── Write ────────────────────────────────────────────────────────────────
    MEMORY_DIR.mkdir(parents=True, exist_ok=True)

    pat_data = _load_json(PATTERN_FILE)
    pat_data, pat_added = _merge_pattern(pat_data, all_patterns)
    PATTERN_FILE.write_text(json.dumps(pat_data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[pattern.json]  +{pat_added} new patterns  (total {len(pat_data['patterns'])})")

    str_data = _load_json(STRATEGY_FILE)
    str_data, str_added = _merge_strategy(str_data, all_strategies)
    STRATEGY_FILE.write_text(json.dumps(str_data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[strategy.json] +{str_added} new strategies (total {len(str_data['success_strategies'])})")

    tec_data = _load_json(TECH_FILE)
    tec_data, p_added, s_added = _merge_tech(tec_data, all_payloads, all_scripts)
    TECH_FILE.write_text(json.dumps(tec_data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[tech.json]     +{p_added} payloads, +{s_added} scripts "
          f"(total {len(tec_data['payload_templates'])} payloads, {len(tec_data['scripts'])} scripts)")

    print("\nDone. Memory updated.")


if __name__ == "__main__":
    main()
