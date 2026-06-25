"""One-shot migration: add canonical_strategy_id + stage + activation + signals to cwe-1336-cwe-1336.yaml."""
import yaml
from pathlib import Path

MIGRATIONS = {
    # Discovery (active)
    11: ("cwe-1336:discovery:macro-recursion", "discovery", "draft", [], [], ["template_directive_parsed"]),
    19: ("cwe-1336:discovery:arithmetic-detection", "discovery", "active", [], [], ["arithmetic_reflection_confirmed"]),
    24: ("cwe-1336:discovery:set-calc-probe", "discovery", "active", [], [], ["arithmetic_reflection_confirmed"]),
    27: ("cwe-1336:discovery:basic-probe", "discovery", "draft", [], [], ["template_directive_parsed"]),
    # Validation (draft)
    8: ("cwe-1336:validation:evaluate-directive", "validation", "draft",
        ["cwe-1336:discovery:arithmetic-detection"], ["arithmetic_reflection_confirmed"], ["template_directive_parsed"]),
    18: ("cwe-1336:validation:post-multigrammar", "validation", "draft",
         ["cwe-1336:discovery:basic-probe"], ["template_directive_parsed"], ["template_directive_parsed"]),
    # Escalation (draft)
    1: ("cwe-1336:escalation:arithmetic-to-rce", "escalation", "draft",
        ["cwe-1336:discovery:arithmetic-detection"], ["arithmetic_reflection_confirmed"], ["object_access_confirmed"]),
    10: ("cwe-1336:escalation:string-instance-chain", "escalation", "draft",
         ["cwe-1336:discovery:arithmetic-detection"], ["arithmetic_reflection_confirmed"], ["object_access_confirmed"]),
    12: ("cwe-1336:escalation:resource-loader", "escalation", "draft",
         ["cwe-1336:discovery:basic-probe"], ["template_directive_parsed"], ["file_read_confirmed"]),
    21: ("cwe-1336:escalation:arithmetic-to-inspection", "escalation", "draft",
         ["cwe-1336:discovery:arithmetic-detection"], ["arithmetic_reflection_confirmed"], ["object_access_confirmed"]),
}

# Late-stage warmup suffixes
WARMUP_EXECUTION_IDS = [0, 4, 5, 6, 7, 13, 16]
WARMUP_V = {0:1, 4:2, 5:3, 6:4, 7:5, 13:6, 16:7}

EXECUTION_DRAFT = [
    (2, "cwe-1336:execution:reflection-rce", ["cwe-1336:validation:evaluate-directive"], ["template_directive_parsed", "object_access_confirmed"], "command_execution_confirmed"),
    (3, "cwe-1336:execution:processbuilder-rce", ["cwe-1336:escalation:arithmetic-to-rce"], ["arithmetic_reflection_confirmed", "object_access_confirmed"], "command_execution_confirmed"),
    (9, "cwe-1336:execution:fileinputstream-read", ["cwe-1336:validation:evaluate-directive"], ["template_directive_parsed", "object_access_confirmed"], "file_read_confirmed"),
    (14, "cwe-1336:execution:double-quote-echo", ["cwe-1336:discovery:basic-probe"], ["template_directive_parsed", "object_access_confirmed"], "command_execution_confirmed"),
    (15, "cwe-1336:execution:base64-rce-backdoor", ["cwe-1336:escalation:arithmetic-to-rce"], ["arithmetic_reflection_confirmed", "object_access_confirmed"], "command_execution_confirmed"),
    (17, "cwe-1336:execution:runtime-exec-output", ["cwe-1336:escalation:arithmetic-to-rce"], ["arithmetic_reflection_confirmed", "object_access_confirmed"], "command_execution_confirmed"),
    (22, "cwe-1336:execution:reflect-chain", ["cwe-1336:escalation:string-instance-chain"], ["arithmetic_reflection_confirmed", "object_access_confirmed"], "command_execution_confirmed"),
    (23, "cwe-1336:execution:reflect-exec", ["cwe-1336:escalation:string-instance-chain"], ["arithmetic_reflection_confirmed", "object_access_confirmed"], "command_execution_confirmed"),
    (25, "cwe-1336:execution:reflect-inline", ["cwe-1336:escalation:arithmetic-to-rce"], ["arithmetic_reflection_confirmed", "object_access_confirmed"], "command_execution_confirmed"),
    (28, "cwe-1336:execution:reflect-v3", ["cwe-1336:escalation:string-instance-chain"], ["arithmetic_reflection_confirmed", "object_access_confirmed"], "command_execution_confirmed"),
    (30, "cwe-1336:execution:reflect-chain-v2", ["cwe-1336:escalation:arithmetic-to-rce"], ["arithmetic_reflection_confirmed", "object_access_confirmed"], "command_execution_confirmed"),
    (31, "cwe-1336:execution:reflect-v4", ["cwe-1336:escalation:arithmetic-to-rce"], ["arithmetic_reflection_confirmed", "object_access_confirmed"], "command_execution_confirmed"),
]

POST_EXECUTION_DRAFT = [
    (20, "cwe-1336:post-execution:reflect-oob", ["cwe-1336:execution:reflection-rce"], ["command_execution_confirmed"], "oob_callback_received"),
    (26, "cwe-1336:post-execution:reflect-oob-v2", ["cwe-1336:execution:reflection-rce"], ["command_execution_confirmed"], "oob_callback_received"),
    (29, "cwe-1336:post-execution:reflect-oob-v3", ["cwe-1336:execution:reflect-v3"], ["command_execution_confirmed"], "oob_callback_received"),
]

def build_migration():
    migration = {}
    for idx, sid, stage, act, req_ids, req_sigs, exp_sigs in [
        *[(i, s, st, a, ri, rs, es) for i,(s,st,a,ri,rs,es) in MIGRATIONS.items()],
    ]:
        migration[idx] = (sid, stage, act, req_ids, req_sigs, exp_sigs)
    for idx in WARMUP_EXECUTION_IDS:
        v = WARMUP_V[idx]
        sid = f"cwe-1336:execution:warmup-v{v}"
        migration[idx] = (sid, "execution", "draft",
                          ["cwe-1336:discovery:basic-probe"],
                          ["template_directive_parsed", "object_access_confirmed"],
                          ["command_execution_confirmed"])
    for idx, sid, req_ids, req_sigs, exp_sig in EXECUTION_DRAFT:
        migration[idx] = (sid, "execution", "draft", req_ids, req_sigs, [exp_sig])
    for idx, sid, req_ids, req_sigs, exp_sig in POST_EXECUTION_DRAFT:
        migration[idx] = (sid, "post_execution", "draft", req_ids, req_sigs, [exp_sig])
    return migration


def main():
    src = Path("b/templates/builtin/cwe-1336-cwe-1336.yaml")
    data = yaml.safe_load(src.read_text(encoding="utf-8"))
    pts = data.get("payload_templates", [])
    migration = build_migration()

    for idx, pt in enumerate(pts):
        if idx not in migration:
            print(f"[WARN] idx={idx} not in migration map, keeping as draft discovery")
            pt["canonical_strategy_id"] = f"cwe-1336:discovery:unmapped-{idx}"
            pt["stage"] = "discovery"
            pt["activation_state"] = "draft"
            pt["requires_strategy_ids"] = []
            pt["requires_signals"] = []
            pt["expected_signals"] = []
            pt["max_attempts"] = 1
            pt["timeout_seconds"] = 30
            pt["risk_level"] = "low"
            continue
        sid, stage, act, req_ids, req_sigs, exp_sigs = migration[idx]
        pt["canonical_strategy_id"] = sid
        pt["stage"] = stage
        pt["activation_state"] = act
        pt["requires_strategy_ids"] = req_ids
        pt["requires_signals"] = req_sigs
        pt["expected_signals"] = exp_sigs
        pt["max_attempts"] = 2 if stage == "discovery" else 3
        pt["timeout_seconds"] = 15 if stage == "discovery" else 30
        pt["risk_level"] = "low" if stage == "discovery" else ("medium" if stage == "validation" else ("high" if stage == "escalation" else "critical"))

    # validate uniqueness
    sids = [pt.get("canonical_strategy_id","") for pt in pts]
    empty = [i for i,s in enumerate(sids) if not s]
    dups = [s for s in sids if s and sids.count(s) > 1]
    if empty:
        print(f"[FAIL] {len(empty)} entries missing canonical_strategy_id: {empty}")
        return
    if dups:
        print(f"[FAIL] duplicate canonical_strategy_id: {set(dups)}")
        return

    data["payload_templates"] = pts
    bak = Path(f"{src}.bak")
    if not bak.exists():
        src.rename(bak)
        print(f"[OK] backup: {bak}")

    with open(src, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
    print(f"[OK] migrated {len(pts)} entries in {src}")
    active = [s for s in sids if any(pt["activation_state"] == "active" for pt in pts if pt.get("canonical_strategy_id") == s)]
    draft = [s for s in sids if any(pt["activation_state"] == "draft" for pt in pts if pt.get("canonical_strategy_id") == s)]
    print(f"[OK] {len(active)} active, {len(draft)} draft, {len(set(sids))} unique IDs")


if __name__ == "__main__":
    main()
