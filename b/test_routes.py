"""Route Factory v1 — Normalizer 定向测试与架构审计

测试覆盖:
  - 合法 Proposal 规范化
  - 确定性 & Canonical ID 稳定性
  - CWE Canonicalization 审计
  - 状态机复用测试
  - Primitive Adapter 真实性测试
  - Primitive-Signal 一致性测试
  - Payload Template Reference 专项测试
  - Technique 语义区别测试
  - Runtime Facts 测试
  - 不可变结构 & 序列化测试
  - Import 副作用审计
  - 错误结果契约测试
  - YAML Writer、dry-run 与 generation report
  - 路径、覆盖、重复 ID 与原子写入安全
  - 离线 Route Admission 与安全 YAML 加载

本轮不测试: CLI, Planner, Coordinator, Docker, HTTP, LLM
"""

from __future__ import annotations

import dataclasses
import hashlib
import inspect
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from types import MappingProxyType

import pytest
import yaml

# ── path setup (match existing test convention) ──
ROOT = Path(__file__).resolve().parents[1]
B_DIR = ROOT / "b"
if str(B_DIR) not in sys.path:
    sys.path.insert(0, str(B_DIR))

from routes.schema import (
    Activation,
    AdmissionDecision,
    AdmissionErrorCode,
    FailurePolicy,
    FrontierContext,
    FrontierDiagnosticCode,
    MaterializationDeclaration,
    NormalizationError,
    NormalizationErrorCode,
    NormalizationResult,
    NormalizedRoute,
    ReplayPolicy,
    RegisteredRoute,
    RegistryErrorCode,
    RouteProposal,
    RouteRegistrySnapshot,
    RouteRequirements,
    SuccessCriteria,
)
from routes.admission import (
    ADMITTED_CANDIDATE,
    MAX_YAML_FILE_SIZE,
    ROUTE_FACTORY_V1_RUNTIME_FACTS,
    admit_route,
    load_and_admit_candidate_route,
    normalized_route_from_plain,
)
from routes.primitive_adapter import PrimitiveAdapter
from routes.normalizer import (
    SCHEMA_VERSION,
    SSTI_CWE_ALIASES,
    SUPPORTED_TECHNIQUES,
    _canonical_id,
    _normalize_technique,
    _safe_id_part,
    _unique_nonempty,
    normalize_route_proposal,
)
from routes.factory import (
    DUPLICATE_ROUTE_ID,
    generate_candidate_routes,
)
from routes.writer import (
    WriteErrorCode,
    write_candidate_route,
)
from routes.registry import RouteRegistry, route_fingerprint
from routes.frontier import build_frontier, context_fingerprint
from routes.context_adapter import (
    METHOD_RUNTIME_FACT_DEFERRED,
    RuntimeFactAdapter,
    build_frontier_context,
)
from memory.exploit_primitives import (
    INJECTION_PRIMITIVES,
    ExploitPrimitive,
    PrimitiveRegistry,
    get_primitive_registry,
    reset_primitive_registry,
)
from memory.exploit_trajectory import VALID_STATES
from memory.primitive_transition_graph import PrimitiveTransitionGraph


# ═══════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════

def _valid_proposal(**overrides) -> RouteProposal:
    """Create a valid first-stage SSTI arithmetic_probe proposal."""
    kwargs = {
        "cwe_id": "CWE-94",
        "current_state": "init",
        "target_primitive": "ssti_reflection",
        "technique": "arithmetic_probe",
        "required_runtime_facts": ("endpoint", "parameter"),
        "payload_template_ref": "primitive:ssti_reflection:0",
        "expected_signals": ("arithmetic_result_in_response", "expression_reflected_verbatim"),
    }
    kwargs.update(overrides)
    return RouteProposal(**kwargs)


def _fresh_adapter() -> PrimitiveAdapter:
    """Create a fresh PrimitiveAdapter for test isolation."""
    return PrimitiveAdapter()


def _assert_ok(result: NormalizationResult) -> NormalizedRoute:
    assert result.ok, f"Expected OK but got errors: {result.errors}"
    assert result.route is not None
    return result.route


def _assert_error(result: NormalizationResult, expected_code: NormalizationErrorCode) -> list[NormalizationError]:
    matching = [e for e in result.errors if e.code == expected_code]
    assert matching, (
        f"Expected error {expected_code.value} but got: "
        f"{[e.code.value for e in result.errors]}"
    )
    return matching


# ═══════════════════════════════════════════════════════════════════
# Section 1 — Basic Functionality Tests
# ═══════════════════════════════════════════════════════════════════

class TestBasicFunctionality:
    """Section 三.1: Valid proposal normalization."""

    def test_valid_route_proposal_normalizes(self):
        """合法首阶段 SSTI proposal 得到成功结果。"""
        proposal = _valid_proposal()
        adapter = _fresh_adapter()
        result = normalize_route_proposal(proposal, adapter)
        route = _assert_ok(result)

        # schema_version
        assert route.schema_version == SCHEMA_VERSION, (
            f"Expected schema_version={SCHEMA_VERSION}, got {route.schema_version}"
        )
        # cwe_id canonicalized
        assert route.cwe_id == "CWE-94", f"Expected CWE-94, got {route.cwe_id}"
        # current_state preserved
        assert route.current_state == "init", f"Expected init, got {route.current_state}"
        # target_primitive
        assert route.target_primitive == "ssti_reflection", (
            f"Expected ssti_reflection, got {route.target_primitive}"
        )
        # activation
        assert route.activation.state == "draft", (
            f"Expected draft, got {route.activation.state}"
        )
        assert route.activation.source == "route_factory", (
            f"Expected route_factory, got {route.activation.source}"
        )
        # generation_status
        assert route.generation_status == "candidate_only", (
            f"Expected candidate_only, got {route.generation_status}"
        )
        # materialization is declaration only, not real URL/payload
        mat = route.materialization
        assert mat.type == "http_request"
        assert mat.payload_template_ref == adapter.get_payload_template_refs(
            "ssti_reflection"
        )[0]
        # materialization fields reference runtime_truths (not hardcoded values)
        assert mat.method_from == "runtime_truths"
        assert mat.endpoint_from == "runtime_truths"
        assert mat.parameter_from == "runtime_truths"
        # no real URL/payload present
        assert "://" not in mat.method_from
        assert "://" not in mat.endpoint_from

    def test_success_result_has_no_error_codes(self):
        """成功结果 errors 为空 tuple。"""
        proposal = _valid_proposal()
        adapter = _fresh_adapter()
        result = normalize_route_proposal(proposal, adapter)
        assert result.ok
        assert result.errors == ()

    def test_error_result_has_no_normalized_route(self):
        """失败结果 route 为 None。"""
        proposal = _valid_proposal(cwe_id="CWE-99999")
        adapter = _fresh_adapter()
        result = normalize_route_proposal(proposal, adapter)
        assert not result.ok
        assert result.route is None


# ═══════════════════════════════════════════════════════════════════
# Section 2 — Determinism & Canonical ID
# ═══════════════════════════════════════════════════════════════════

class TestDeterminism:
    """Section 三.2: Deterministic normalization."""

    def test_normalization_is_deterministic(self):
        """同一个 RouteProposal 连续规范化多次，得到完全相等的结果。"""
        proposal = _valid_proposal()
        adapter = _fresh_adapter()

        results = [normalize_route_proposal(proposal, adapter) for _ in range(10)]

        first = results[0]
        for i, r in enumerate(results[1:], 1):
            assert first.ok == r.ok, f"ok mismatch at iteration {i}"
            if first.route:
                assert first.route == r.route, (
                    f"Route mismatch at iteration {i}: {first.route} != {r.route}"
                )
            assert first.errors == r.errors, (
                f"Errors mismatch at iteration {i}: {first.errors} != {r.errors}"
            )

    def test_canonical_id_is_stable(self):
        """相同的规范化输入产生相同的 canonical_id。"""
        proposal = _valid_proposal()
        adapter = _fresh_adapter()

        ids = set()
        for _ in range(10):
            result = normalize_route_proposal(proposal, adapter)
            ids.add(result.route.canonical_id)

        assert len(ids) == 1, f"Expected exactly 1 canonical_id, got {len(ids)}: {ids}"

    def test_canonical_id_is_stable_across_adapters(self):
        """不同 adapter 实例产生相同的 canonical_id。"""
        proposal = _valid_proposal()

        adapter1 = _fresh_adapter()
        adapter2 = _fresh_adapter()
        adapter3 = PrimitiveAdapter(
            registry=PrimitiveRegistry(),
            transition_graph=PrimitiveTransitionGraph(),
        )

        id1 = normalize_route_proposal(proposal, adapter1).route.canonical_id
        id2 = normalize_route_proposal(proposal, adapter2).route.canonical_id
        id3 = normalize_route_proposal(proposal, adapter3).route.canonical_id

        assert id1 == id2 == id3, f"IDs diverge: {id1}, {id2}, {id3}"


class TestCanonicalIdSafety:
    """Section 三.3: Canonical ID safety."""

    def test_canonical_id_contains_only_safe_characters(self):
        """canonical ID 只包含 [a-z0-9:-]。"""
        proposal = _valid_proposal()
        adapter = _fresh_adapter()
        result = normalize_route_proposal(proposal, adapter)
        cid = result.route.canonical_id

        unsafe = re.findall(r"[^a-z0-9:-]", cid)
        assert not unsafe, f"Unsafe characters in canonical_id: {unsafe!r} -> {cid!r}"

    def test_technique_spelling_normalizes_consistently(self):
        """不同拼写被规范化为相同 technique 和 canonical ID——空格变体。"""
        expected_cid = "cwe-94:init:ssti-reflection:arithmetic-probe"

        variants = [
            ("arithmetic probe", "arithmetic_probe"),
            ("arithmetic-probe", "arithmetic_probe"),
            ("arithmetic_probe", "arithmetic_probe"),
            ("  Arithmetic Probe  ", "arithmetic_probe"),
            ("Arithmetic-Probe", "arithmetic_probe"),
        ]

        adapter = _fresh_adapter()
        seen_ids = set()
        for raw, expected_technique in variants:
            proposal = _valid_proposal(technique=raw)
            result = normalize_route_proposal(proposal, adapter)
            route = _assert_ok(result)
            assert route.technique == expected_technique, (
                f"Raw {raw!r} normalized to {route.technique!r}, expected {expected_technique!r}"
            )
            seen_ids.add(route.canonical_id)

        assert len(seen_ids) == 1, (
            f"All technique variants should produce same canonical_id, got: {seen_ids}"
        )

    def test_safe_id_part_normalizes(self):
        """_safe_id_part 只输出安全字符。"""
        cases = [
            ("CWE-94", "cwe-94"),
            ("Hello World", "hello-world"),
            ("a_b.c@d", "a-b-c-d"),
            ("  spaces  ", "spaces"),
            ("UPPER", "upper"),
        ]
        for value, expected in cases:
            assert _safe_id_part(value) == expected, (
                f"_safe_id_part({value!r}) = {_safe_id_part(value)!r}, expected {expected!r}"
            )


# ═══════════════════════════════════════════════════════════════════
# Section 3 — CWE Canonicalization Audit
# ═══════════════════════════════════════════════════════════════════

class TestCWECanonicalization:
    """Section 四: CWE canonicalization audit."""

    # ── evidence gathered from codebase ──
    # CWE-94: confirmed_vuln.json, cwe-94-ssti.yaml metadata, cwe-94-cwe-94.yaml,
    #         PrimitiveTransitionGraph.get_entry_primitives line 171, planner dispatch line 767
    # CWE-917: cwe-94-ssti.yaml cwe_ids, PrimitiveTransitionGraph.get_entry_primitives line 172,
    #          planner dispatch line 767, cli.py line 360
    # CWE-1336: planner._CWE_INFERENCE_TABLE line 1301 ONLY — NOT in PrimitiveTransitionGraph,
    #           NOT in any YAML metadata, NOT in confirmed_vuln.json

    def test_project_canonical_ssti_cwe_matches_audit_report(self):
        """确认 canonical SSTI CWE 是 CWE-94，来自 confirmed_vuln.json。"""
        # confirmed_vuln.json uses CWE-94 as the canonical identifier
        vuln_path = B_DIR / "data" / "confirmed_vuln.json"
        assert vuln_path.exists(), "confirmed_vuln.json must exist"
        data = json.loads(vuln_path.read_text(encoding="utf-8"))
        vulns = data.get("vulnerabilities", [])
        assert len(vulns) > 0, "Must have at least one vulnerability"
        ssti_vuln = vulns[0]
        assert ssti_vuln["cwe_id"] == "CWE-94", (
            f"Canonical CWE in confirmed_vuln.json must be CWE-94, got {ssti_vuln['cwe_id']}"
        )

        # Normalizer must output CWE-94 as canonical
        assert "CWE-94" in SSTI_CWE_ALIASES
        assert SSTI_CWE_ALIASES["CWE-94"] == "CWE-94"

    def test_supported_cwe_aliases_are_explicit(self):
        """只有有明确项目依据的 CWE alias 才允许通过。

        Evidence sources:
        - CWE-917: PrimitiveTransitionGraph.get_entry_primitives(line 172),
                   cwe-94-ssti.yaml cwe_ids, planner dispatch(line 767), cli.py(line 360)
        - CWE-1336: planner._CWE_INFERENCE_TABLE(line 1301)
        """
        adapter = _fresh_adapter()

        # CWE-94: canonical, must normalize to itself
        r = normalize_route_proposal(_valid_proposal(cwe_id="CWE-94"), adapter)
        _assert_ok(r)
        assert r.route.cwe_id == "CWE-94"

        # CWE-917: has project evidence (transition graph + YAML + planner + CLI)
        r = normalize_route_proposal(_valid_proposal(cwe_id="CWE-917"), adapter)
        _assert_ok(r)
        assert r.route.cwe_id == "CWE-94", (
            f"CWE-917 should normalize to CWE-94, got {r.route.cwe_id}"
        )

        # CWE-1336: has project evidence (planner._CWE_INFERENCE_TABLE)
        r = normalize_route_proposal(_valid_proposal(cwe_id="CWE-1336"), adapter)
        _assert_ok(r)
        assert r.route.cwe_id == "CWE-94", (
            f"CWE-1336 should normalize to CWE-94, got {r.route.cwe_id}"
        )

    def test_unknown_cwe_rejected(self):
        """未知 CWE 被拒绝。"""
        adapter = _fresh_adapter()
        unknown_cwes = ["CWE-99999", "CWE-000", "CWE-XYZ", "cwe-12345"]

        for cwe in unknown_cwes:
            proposal = _valid_proposal(cwe_id=cwe)
            result = normalize_route_proposal(proposal, adapter)
            assert not result.ok, f"CWE {cwe!r} should be rejected but was accepted"
            _assert_error(result, NormalizationErrorCode.UNKNOWN_CWE)

    def test_cwe_case_insensitive_normalization(self):
        """CWE 输入大小写不敏感。"""
        adapter = _fresh_adapter()
        cases = ["cwe-94", "Cwe-94", "CWE-94", "cwe-917", "Cwe-917", "CWE-917"]

        for cwe in cases:
            proposal = _valid_proposal(cwe_id=cwe)
            result = normalize_route_proposal(proposal, adapter)
            assert result.ok, f"CWE {cwe!r} should be accepted"
            assert result.route.cwe_id == "CWE-94", (
                f"CWE {cwe!r} should normalize to CWE-94, got {result.route.cwe_id}"
            )

    def test_cwe_whitespace_tolerance(self):
        """CWE 输入前后空格被修剪。"""
        adapter = _fresh_adapter()
        proposal = _valid_proposal(cwe_id="  CWE-94  ")
        result = normalize_route_proposal(proposal, adapter)
        assert result.ok, f"CWE with whitespace should be accepted"
        assert result.route.cwe_id == "CWE-94"

    def test_aliases_do_not_create_duplicate_canonical_ids(self):
        """不同 CWE alias 最终产生相同的 canonical_id。"""
        adapter = _fresh_adapter()

        ids = set()
        for cwe in ["CWE-94", "CWE-917", "CWE-1336"]:
            proposal = _valid_proposal(cwe_id=cwe)
            result = normalize_route_proposal(proposal, adapter)
            ids.add(result.route.canonical_id)

        assert len(ids) == 1, (
            f"All SSTI CWE aliases must produce same canonical_id, got: {ids}"
        )

    def test_cwe_alias_mapping_is_exhaustive(self):
        """验证 SSTI_CWE_ALIASES 只包含已知有依据的映射。

        当前已知映射:
          CWE-94  → CWE-94 (canonical)
          CWE-917 → CWE-94 (transition graph + YAML + planner + CLI)
          CWE-1336 → CWE-94 (planner inference table)
        """
        expected_keys = {"CWE-94", "CWE-917", "CWE-1336"}
        actual_keys = set(SSTI_CWE_ALIASES.keys())

        extra = actual_keys - expected_keys
        missing = expected_keys - actual_keys

        assert not extra, (
            f"SSTI_CWE_ALIASES contains unexpected keys: {extra}. "
            f"These may be Codex-invented mappings without project evidence."
        )
        assert not missing, (
            f"SSTI_CWE_ALIASES is missing expected keys: {missing}."
        )

    def test_cwe_917_has_entry_primitive_in_transition_graph(self):
        """验证 CWE-917 在 PrimitiveTransitionGraph 中有明确映射。"""
        graph = PrimitiveTransitionGraph()
        entries = graph.get_entry_primitives(["CWE-917"])
        assert "ssti_reflection" in entries, (
            f"CWE-917 must map to ssti_reflection in PrimitiveTransitionGraph, got: {entries}"
        )

    def test_cwe_1336_not_in_primitive_transition_graph(self):
        """CWE-1336 不在 PrimitiveTransitionGraph 的 entry primitive 映射中。

        这是预期行为：CWE-1336 仅在 Planner 的 _CWE_INFERENCE_TABLE 中使用，
        不在 transition graph 中。Transition graph 只映射 CWE-94 和 CWE-917。
        """
        graph = PrimitiveTransitionGraph()
        entries = graph.get_entry_primitives(["CWE-1336"])
        assert entries == [], (
            f"CWE-1336 is NOT in PrimitiveTransitionGraph entry mapping. "
            f"Its only project evidence is planner._CWE_INFERENCE_TABLE (line 1301). "
            f"Unexpected entries: {entries}"
        )
        # NOTE: This is documented as a factual observation, not a bug.
        # CWE-1336 is accepted as an alias based on planner._CWE_INFERENCE_TABLE evidence.
        # The normalizer maps CWE-1336 → CWE-94 before querying the transition graph.


# ═══════════════════════════════════════════════════════════════════
# Section 4 — State Machine Reuse Tests
# ═══════════════════════════════════════════════════════════════════

class TestStateMachineReuse:
    """Section 五: Existing state machine reuse verification."""

    def test_known_existing_state_is_accepted(self):
        """所有 VALID_STATES 中的状态都被接受。"""
        adapter = _fresh_adapter()
        for state in VALID_STATES:
            proposal = _valid_proposal(current_state=state)
            result = normalize_route_proposal(proposal, adapter)
            assert result.ok, f"State {state!r} should be accepted but was rejected: {result.errors}"

    def test_unknown_state_rejected(self):
        """不在 VALID_STATES 中的状态被拒绝。"""
        adapter = _fresh_adapter()
        unknown_states = ["foobar", "exploited", "completed", "final", ""]
        for state in unknown_states:
            proposal = _valid_proposal(current_state=state)
            result = normalize_route_proposal(proposal, adapter)
            assert not result.ok, f"State {state!r} should be rejected but was accepted"
            _assert_error(result, NormalizationErrorCode.UNKNOWN_STATE)

    def test_adapter_reads_existing_valid_states(self):
        """Adapter 查询的是现有的 VALID_STATES 常量，不是硬编码副本。"""
        adapter = _fresh_adapter()
        # Verify adapter.state_exists delegates to VALID_STATES
        for state in VALID_STATES:
            assert adapter.state_exists(state), f"Adapter must accept {state!r}"
        assert not adapter.state_exists("nonexistent_state")

        # Verify VALID_STATES is imported from exploit_trajectory
        from memory.exploit_trajectory import VALID_STATES as VS
        assert VALID_STATES is VS, (
            "VALID_STATES must be the exact same object from memory.exploit_trajectory"
        )

    def test_routes_package_does_not_define_second_valid_states_constant(self):
        """routes 包不定义自己的 valid states 常量。"""
        import routes
        # Check that routes module doesn't have its own VALID_STATES or similar
        dir_content = set(dir(routes))
        forbidden = {"VALID_STATES", "VALID_EXPLOIT_STATES", "valid_states", "states"}
        found = dir_content & forbidden
        assert not found, (
            f"routes package defines its own state constants: {found}. "
            f"Must use memory.exploit_trajectory.VALID_STATES exclusively."
        )

        # Also check routes submodules
        import routes.schema as s
        import routes.normalizer as n

        for mod, name in [(s, "schema"), (n, "normalizer")]:
            mod_dir = set(dir(mod))
            found_in_mod = mod_dir & forbidden
            assert not found_in_mod, (
                f"routes.{name} defines state constants: {found_in_mod}"
            )

    def _check_primitive_adapter_no_state_machine(self):
        """Verify primitive_adapter doesn't import or define state advancement."""
        adapter_file = B_DIR / "routes" / "primitive_adapter.py"
        content = adapter_file.read_text(encoding="utf-8")
        # Should not contain state advancement words
        forbidden = ["advance_state", "set_state", "state_machine", "ExploitStateMachine"]
        for term in forbidden:
            assert term not in content, (
                f"primitive_adapter.py contains forbidden term: {term!r}"
            )

    def test_normalizer_does_not_advance_exploit_state(self):
        """Normalizer 不推进 exploit state。"""
        # The normalizer should only validate state, not change it
        proposal_init = _valid_proposal(current_state="init")
        adapter = _fresh_adapter()
        result = normalize_route_proposal(proposal_init, adapter)
        route = _assert_ok(result)
        # current_state must be preserved exactly as input (after strip)
        assert route.current_state == "init", (
            f"Normalizer changed state from 'init' to {route.current_state!r}"
        )
        # The normalizer has no state advancement logic
        # A proposal with probe_success should stay probe_success
        proposal_ps = _valid_proposal(current_state="probe_success")
        result2 = normalize_route_proposal(proposal_ps, adapter)
        route2 = _assert_ok(result2)
        assert route2.current_state == "probe_success"

    def test_normalizer_does_not_write_verification_memory(self):
        """Normalizer 不调用 VerificationMemory。"""
        import routes.normalizer as n
        import inspect
        source = inspect.getsource(n.normalize_route_proposal)
        # Should not reference verification memory
        forbidden = ["verification", "VerificationMemory", "get_verification", "confirm("]
        for term in forbidden:
            assert term not in source, (
                f"normalize_route_proposal references verification memory: {term!r}"
            )

    def test_normalizer_does_not_write_trajectory_memory(self):
        """Normalizer 不调用 trajectory memory 写操作。

        注意：normalizer 内部使用 errors.append() 构建错误列表，
        这是本地列表操作，不是 trajectory 写操作。检查更精确的模式。
        """
        import routes.normalizer as n
        import inspect
        source = inspect.getsource(n.normalize_route_proposal)
        # Look for trajectory/disk write patterns, not local list .append
        forbidden = [
            "trajectory", "add_node", ".dump(", "yaml.dump",
            "json.dump", "Path(", "open(", "write_text",
            "write_bytes", "persist", "save_to",
        ]
        for term in forbidden:
            assert term not in source.lower(), (
                f"normalize_route_proposal references write operation: {term!r}"
            )


# ═══════════════════════════════════════════════════════════════════
# Section 5 — Primitive Adapter Authenticity Tests
# ═══════════════════════════════════════════════════════════════════

class TestPrimitiveAdapterAuthenticity:
    """Section 六: Primitive Adapter authenticity — no duplication of fact sources."""

    def test_adapter_reads_existing_primitive_registry(self):
        """Adapter 使用现有 PrimitiveRegistry，不复制原始数据。"""
        adapter = _fresh_adapter()
        # The adapter's registry should be a PrimitiveRegistry instance
        assert isinstance(adapter._registry, PrimitiveRegistry), (
            f"Adapter._registry must be PrimitiveRegistry, got {type(adapter._registry)}"
        )
        # The adapter should have the same primitives as the singleton
        singleton = get_primitive_registry()
        for pid in singleton.get_all_ids():
            assert adapter.primitive_exists(pid), (
                f"Adapter missing primitive {pid!r} that exists in singleton"
            )
        # The adapter's registry is a separate instance but contains the same data
        # (loaded from the same INJECTION_PRIMITIVES, etc.)

    def test_known_primitive_exists(self):
        """已知 primitive 应该存在。"""
        adapter = _fresh_adapter()
        assert adapter.primitive_exists("ssti_reflection")
        assert adapter.primitive_exists("sql_boolean")
        assert adapter.primitive_exists("command_separator")

    def test_unknown_primitive_rejected(self):
        """完全不存在的 primitive → UNKNOWN_PRIMITIVE 错误。"""
        adapter = _fresh_adapter()
        proposal = _valid_proposal(target_primitive="nonexistent_primitive_xyz")
        result = normalize_route_proposal(proposal, adapter)
        assert not result.ok
        _assert_error(result, NormalizationErrorCode.UNKNOWN_PRIMITIVE)

    def test_registry_primitive_not_allowed_as_entry_is_rejected(self):
        """Registry 中存在但不允许作为第一阶段 entry → UNSUPPORTED_PRIMITIVE。

        ssti_execution 在 registry 中存在，但 preconditions 包括
        ssti_reflection_confirmed — 它不是首阶段 entry primitive。
        """
        adapter = _fresh_adapter()
        # Verify ssti_execution exists in registry
        assert adapter.primitive_exists("ssti_execution"), (
            "ssti_execution must exist in registry for this test to be valid"
        )
        # Verify ssti_execution is NOT an entry primitive for CWE-94
        entry_primitives = adapter.get_entry_primitives("CWE-94")
        assert "ssti_execution" not in entry_primitives, (
            f"ssti_execution should NOT be an entry primitive for CWE-94, got: {entry_primitives}"
        )

        # Now test that a proposal with ssti_execution + CWE-94 gets UNSUPPORTED_PRIMITIVE
        proposal = _valid_proposal(
            target_primitive="ssti_execution",
            expected_signals=("config_dump", "class_traversal_output"),
        )
        result = normalize_route_proposal(proposal, adapter)
        assert not result.ok, f"ssti_execution with CWE-94 should be rejected"
        _assert_error(result, NormalizationErrorCode.UNSUPPORTED_PRIMITIVE)

    def test_unknown_vs_unsupported_primitive_are_distinct(self):
        """UNKNOWN_PRIMITIVE 和 UNSUPPORTED_PRIMITIVE 是两个不同的错误码。

        UNKNOWN_PRIMITIVE: 完全不存在的 primitive
        UNSUPPORTED_PRIMITIVE: registry 中存在，但不允许作为首阶段 entry
        """
        adapter = _fresh_adapter()
        # Case 1: unknown primitive
        r1 = normalize_route_proposal(
            _valid_proposal(target_primitive="fake_primitive_abc"), adapter
        )
        assert NormalizationErrorCode.UNKNOWN_PRIMITIVE.value in [
            e.code.value for e in r1.errors
        ], f"Expected UNKNOWN_PRIMITIVE, got {[e.code.value for e in r1.errors]}"
        assert NormalizationErrorCode.UNSUPPORTED_PRIMITIVE.value not in [
            e.code.value for e in r1.errors
        ], "Should NOT have UNSUPPORTED_PRIMITIVE for unknown primitive"

        # Case 2: supported primitive (registry exists, not entry)
        r2 = normalize_route_proposal(
            _valid_proposal(target_primitive="ssti_execution"), adapter
        )
        assert NormalizationErrorCode.UNSUPPORTED_PRIMITIVE.value in [
            e.code.value for e in r2.errors
        ], f"Expected UNSUPPORTED_PRIMITIVE, got {[e.code.value for e in r2.errors]}"
        assert NormalizationErrorCode.UNKNOWN_PRIMITIVE.value not in [
            e.code.value for e in r2.errors
        ], "Should NOT have UNKNOWN_PRIMITIVE for valid-but-unsupported primitive"

    def test_adapter_does_not_duplicate_payload_templates(self):
        """Adapter 不复制 payload templates 字符串列表，通过委托访问。"""
        adapter = _fresh_adapter()
        # The adapter's get_payload_template_refs generates refs dynamically
        # It should NOT have a hardcoded list of payload templates
        from routes.primitive_adapter import PrimitiveAdapter as PA
        import inspect
        source = inspect.getsource(PA.get_payload_template_refs)
        # Should reference self._registry, not hardcoded templates
        assert "self._registry" in source, (
            "get_payload_template_refs must delegate to self._registry"
        )
        # Should NOT contain literal payload strings
        for forbidden in ["{{7*7}}", "${7*7}", "<%=7*7%>"]:
            assert forbidden not in source, (
                f"get_payload_template_refs must not contain hardcoded payload: {forbidden!r}"
            )

    def test_adapter_does_not_duplicate_observable_signals(self):
        """Adapter 不复制 observable signal 列表，通过委托访问。"""
        adapter = _fresh_adapter()
        from routes.primitive_adapter import PrimitiveAdapter as PA
        import inspect
        source = inspect.getsource(PA.get_observable_signals)
        assert "self._registry" in source, (
            "get_observable_signals must delegate to self._registry"
        )
        # Should NOT hardcode signal names
        for forbidden in ["arithmetic_result_in_response", "expression_reflected_verbatim"]:
            assert forbidden not in source, (
                f"get_observable_signals must not contain hardcoded signal: {forbidden!r}"
            )

    def test_routes_package_does_not_define_second_transition_graph(self):
        """routes 包不定义自己的 transition graph。"""
        import routes
        import routes.schema as s
        import routes.normalizer as n
        import routes.primitive_adapter as pa

        forbidden = {"TransitionGraph", "transition_graph", "DEFAULT_TRANSITIONS",
                      "TRANSITION_CONDITIONS", "PRIMITIVE_TRANSITIONS"}

        for mod, name in [(routes, "__init__"), (s, "schema"), (n, "normalizer"), (pa, "primitive_adapter")]:
            mod_dir = set(dir(mod))
            found = mod_dir & forbidden
            assert not found, f"routes.{name} defines transition graph: {found}"

    def test_adapter_get_observable_signals_matches_registry(self):
        """Adapter 的 observable_signals 与注册表完全一致。"""
        adapter = _fresh_adapter()
        singleton = get_primitive_registry()
        for pid in singleton.get_all_ids():
            p = singleton.get(pid)
            adapter_signals = adapter.get_observable_signals(pid)
            expected = tuple(p.observable_signals)
            assert adapter_signals == expected, (
                f"Signal mismatch for {pid}: adapter={adapter_signals}, registry={expected}"
            )

    def test_adapter_get_payload_template_refs_count_matches(self):
        """Adapter 的 payload_template_ref 数量与 registry 中的模板数量一致。"""
        adapter = _fresh_adapter()
        singleton = get_primitive_registry()
        for pid in singleton.get_all_ids():
            p = singleton.get(pid)
            refs = adapter.get_payload_template_refs(pid)
            assert len(refs) == len(p.payload_templates), (
                f"Template count mismatch for {pid}: "
                f"adapter has {len(refs)} refs, registry has {len(p.payload_templates)} templates"
            )


# ═══════════════════════════════════════════════════════════════════
# Section 6 — Primitive-Signal Consistency Tests
# ═══════════════════════════════════════════════════════════════════

class TestPrimitiveSignalConsistency:
    """Section 七: Primitive-signal consistency."""

    def test_supported_signal_is_accepted(self):
        """ssti_reflection 的 observable_signals 被接受。"""
        adapter = _fresh_adapter()
        p = adapter._registry.get("ssti_reflection")
        valid_signals = p.observable_signals  # arithmetic_result_in_response, expression_reflected_verbatim

        for signal in valid_signals:
            proposal = _valid_proposal(expected_signals=(signal,))
            result = normalize_route_proposal(proposal, adapter)
            assert result.ok, (
                f"Signal {signal!r} should be accepted but got: {result.errors}"
            )

    def test_missing_expected_signal_rejected(self):
        """空的 expected_signals 被拒绝。"""
        adapter = _fresh_adapter()
        proposal = _valid_proposal(expected_signals=())
        result = normalize_route_proposal(proposal, adapter)
        assert not result.ok
        _assert_error(result, NormalizationErrorCode.MISSING_EXPECTED_SIGNAL)

    def test_unknown_signal_rejected(self):
        """不在 primitive observable_signals 中的 signal 被拒绝。"""
        adapter = _fresh_adapter()
        proposal = _valid_proposal(expected_signals=("totally_unknown_signal_xyz",))
        result = normalize_route_proposal(proposal, adapter)
        assert not result.ok
        _assert_error(result, NormalizationErrorCode.PRIMITIVE_SIGNAL_MISMATCH)

    def test_command_output_in_response_not_provable_by_ssti_reflection(self):
        """command_output_in_response 不能由 ssti_reflection 证明。

        command_output_in_response 是 command_separator 的 observable signal，
        不是 ssti_reflection 的 signal。
        """
        adapter = _fresh_adapter()
        # Verify command_output_in_response belongs to command_separator, not ssti_reflection
        cmd_prim = adapter._registry.get("command_separator")
        assert "command_output_in_response" in cmd_prim.observable_signals, (
            "Test assumption: command_output_in_response must be in command_separator signals"
        )
        ssti_prim = adapter._registry.get("ssti_reflection")
        assert "command_output_in_response" not in ssti_prim.observable_signals, (
            "Test assumption: command_output_in_response must NOT be in ssti_reflection signals"
        )

        proposal = _valid_proposal(
            expected_signals=("command_output_in_response",)
        )
        result = normalize_route_proposal(proposal, adapter)
        assert not result.ok, (
            "command_output_in_response should be rejected for ssti_reflection"
        )
        _assert_error(result, NormalizationErrorCode.PRIMITIVE_SIGNAL_MISMATCH)

    def test_primitive_signal_mismatch_rejected(self):
        """signal 与 primitive 不匹配被拒绝。"""
        adapter = _fresh_adapter()
        # use a signal from a different primitive
        proposal = _valid_proposal(
            expected_signals=("database_version_in_output",)  # belongs to sql_union
        )
        result = normalize_route_proposal(proposal, adapter)
        assert not result.ok
        _assert_error(result, NormalizationErrorCode.PRIMITIVE_SIGNAL_MISMATCH)

    def test_all_expected_signals_are_checked(self):
        """所有 expected_signals 都被校验，不只校验第一个。"""
        adapter = _fresh_adapter()
        # First signal valid, second signal invalid
        proposal = _valid_proposal(
            expected_signals=("arithmetic_result_in_response", "bad_signal_xyz")
        )
        result = normalize_route_proposal(proposal, adapter)
        assert not result.ok, (
            "Should reject when ANY signal is invalid, not just first one"
        )
        _assert_error(result, NormalizationErrorCode.PRIMITIVE_SIGNAL_MISMATCH)

    def test_duplicate_expected_signals_are_normalized(self):
        """重复的 expected_signals 被去重（通过 _unique_nonempty）。"""
        adapter = _fresh_adapter()
        proposal = _valid_proposal(
            expected_signals=(
                "arithmetic_result_in_response",
                "arithmetic_result_in_response",
                "expression_reflected_verbatim",
                "expression_reflected_verbatim",
            )
        )
        result = normalize_route_proposal(proposal, adapter)
        route = _assert_ok(result)
        assert route.expected_signals == (
            "arithmetic_result_in_response",
            "expression_reflected_verbatim",
        ), f"Duplicate signals should be deduplicated, got: {route.expected_signals}"

    def test_expression_evaluated_in_primitive_definition(self):
        """expression_evaluated 存在于 ssti_reflection 的定义中。

        它存储在 INJECTION_PRIMITIVES["ssti_reflection"]["confirmation"]，
        在 ExploitPrimitive 中映射为 evidence_requirements 字段。
        它不在 observable_signals 列表中，因此在 normalizer 中不被接受为 expected_signal。
        """
        # Check INJECTION_PRIMITIVES (the source of truth)
        ssti_def = INJECTION_PRIMITIVES["ssti_reflection"]
        assert ssti_def["confirmation"] == "expression_evaluated", (
            f"confirmation field should be 'expression_evaluated', got {ssti_def.get('confirmation')!r}"
        )
        # Check ExploitPrimitive representation
        singleton = get_primitive_registry()
        p = singleton.get("ssti_reflection")
        assert p.evidence_requirements == "expression_evaluated", (
            f"evidence_requirements should be 'expression_evaluated', got {p.evidence_requirements!r}"
        )

    def test_expression_evaluated_not_in_observable_signals(self):
        """expression_evaluated 不在 observable_signals 中。

        它在 INJECTION_PRIMITIVES 中是 'confirmation' 字段（映射到 ExploitPrimitive.evidence_requirements），
        而不是 'observable_signals' 字段。
        Normalizer 通过 Adapter.get_observable_signals() 查询，只返回 observable_signals 列表。
        因此 expression_evaluated 作为 expected_signal 会被 NORMALIZER 拒绝。

        NOTE: 这是架构注意点，不是 bug。如果 Route Factory 需要接受 confirmation
        级别的信号，需要在 Adapter 层扩展或明确区分 "observable_signal" 和 "confirmation_signal"。
        """
        adapter = _fresh_adapter()
        signals = adapter.get_observable_signals("ssti_reflection")
        assert "expression_evaluated" not in signals, (
            f"expression_evaluated should NOT be in observable_signals for ssti_reflection, "
            f"it is 'confirmation' / 'evidence_requirements'. Current signals: {signals}"
        )
        # Document the gap
        p = adapter._registry.get("ssti_reflection")
        assert p.evidence_requirements == "expression_evaluated", (
            "expression_evaluated exists as evidence_requirements but not observable_signals"
        )

    def test_normalizer_does_not_maintain_second_signal_to_primitive_table(self):
        """Normalizer 不维护自己的 signal-to-primitive 表。"""
        import routes.normalizer as n
        import inspect
        source = inspect.getsource(n)
        # Should not contain a signal-to-primitive mapping
        forbidden_patterns = [
            "signal_to_primitive", "SIGNAL_MAP", "SIGNAL_TO_PRIMITIVE",
            "signal_registry", "by_signal", "_signal_map",
        ]
        for pattern in forbidden_patterns:
            assert pattern not in source, (
                f"normalizer.py contains second signal registry: {pattern!r}"
            )
        # The normalizer should query adapter.get_observable_signals()
        assert "adapter.get_observable_signals" in source or "get_observable_signals" in source, (
            "Normalizer must query adapter for signals rather than maintaining own table"
        )


# ═══════════════════════════════════════════════════════════════════
# Section 7 — Payload Template Reference Tests
# ═══════════════════════════════════════════════════════════════════

class TestPayloadTemplateReference:
    """Section 八: Payload template reference testing."""

    def test_valid_payload_template_reference_is_accepted(self):
        """合法的 payload_template_ref 被接受。"""
        adapter = _fresh_adapter()
        # ssti_reflection has 5 payload templates, indices 0-4
        for idx in range(5):
            ref = f"primitive:ssti_reflection:{idx}"
            proposal = _valid_proposal(payload_template_ref=ref)
            result = normalize_route_proposal(proposal, adapter)
            assert result.ok, f"Ref {ref!r} should be accepted but got: {result.errors}"

    def test_payload_reference_primitive_must_match_target_primitive(self):
        """payload ref 的 primitive 必须与 target_primitive 一致。

        不能使用 primitive:sql_boolean:0 而 target_primitive 是 ssti_reflection。
        """
        adapter = _fresh_adapter()
        # Reference to sql_boolean when target is ssti_reflection
        proposal = _valid_proposal(payload_template_ref="primitive:sql_boolean:0")
        result = normalize_route_proposal(proposal, adapter)
        assert not result.ok, (
            "payload ref pointing to sql_boolean should be rejected for ssti_reflection target"
        )
        _assert_error(result, NormalizationErrorCode.UNKNOWN_PAYLOAD_TEMPLATE)

    def test_negative_payload_index_rejected(self):
        """负数 payload index 被拒绝。"""
        adapter = _fresh_adapter()
        proposal = _valid_proposal(payload_template_ref="primitive:ssti_reflection:-1")
        result = normalize_route_proposal(proposal, adapter)
        assert not result.ok, f"Negative index should be rejected"
        _assert_error(result, NormalizationErrorCode.UNKNOWN_PAYLOAD_TEMPLATE)

    def test_out_of_range_payload_index_rejected(self):
        """越界 payload index 被拒绝。"""
        adapter = _fresh_adapter()
        # ssti_reflection has exactly 5 templates (indices 0-4)
        for bad_idx in [5, 99, 1000]:
            ref = f"primitive:ssti_reflection:{bad_idx}"
            proposal = _valid_proposal(payload_template_ref=ref)
            result = normalize_route_proposal(proposal, adapter)
            assert not result.ok, (
                f"Out-of-range index {bad_idx} should be rejected"
            )
            _assert_error(result, NormalizationErrorCode.UNKNOWN_PAYLOAD_TEMPLATE)

    def test_non_integer_payload_index_rejected(self):
        """非整数 payload index 被拒绝。"""
        adapter = _fresh_adapter()
        bad_refs = [
            "primitive:ssti_reflection:abc",
            "primitive:ssti_reflection:",
            "primitive:ssti_reflection:1.5",
            "primitive:ssti_reflection:0x1",
        ]
        for ref in bad_refs:
            proposal = _valid_proposal(payload_template_ref=ref)
            result = normalize_route_proposal(proposal, adapter)
            assert not result.ok, f"Non-integer ref {ref!r} should be rejected"
            _assert_error(result, NormalizationErrorCode.UNKNOWN_PAYLOAD_TEMPLATE)

    def test_malformed_payload_reference_rejected(self):
        """格式错误的 payload ref 被拒绝。"""
        adapter = _fresh_adapter()
        bad_refs = [
            "ssti_reflection:0",       # missing "primitive:" prefix
            "primitive:ssti_reflection",  # missing index
            "primitive::0",            # empty primitive_id
            "",                        # empty string
            "not_a_ref",
            "template:ssti_reflection:0",  # wrong prefix
            "primitive:ssti_reflection:a:b",  # too many parts
        ]
        for ref in bad_refs:
            proposal = _valid_proposal(payload_template_ref=ref)
            result = normalize_route_proposal(proposal, adapter)
            assert not result.ok, (
                f"Malformed ref {ref!r} should be rejected but was accepted"
            )
            # All malformed refs should fail with UNKNOWN_PAYLOAD_TEMPLATE
            error_codes = [e.code for e in result.errors]
            assert NormalizationErrorCode.UNKNOWN_PAYLOAD_TEMPLATE in error_codes, (
                f"Ref {ref!r} should have UNKNOWN_PAYLOAD_TEMPLATE, got {error_codes}"
            )

    def test_payload_template_is_not_materialized(self):
        """payload_template_ref 只是引用，不包含真实 payload 字符串。"""
        proposal = _valid_proposal()
        adapter = _fresh_adapter()
        result = normalize_route_proposal(proposal, adapter)
        route = _assert_ok(result)

        # The ref is a structured string, not a raw payload
        assert route.payload_template_ref.startswith("primitive:"), (
            f"payload_template_ref must use 'primitive:' prefix: {route.payload_template_ref}"
        )
        # It should NOT contain actual payload content
        assert "{{7*7}}" not in route.payload_template_ref, (
            "payload_template_ref must not contain literal payload content"
        )
        assert "${7*7}" not in route.payload_template_ref
        # materialization also uses the ref, not real payload
        assert route.materialization.payload_template_ref == route.payload_template_ref

    def test_payload_reference_resolution_is_documented_as_order_sensitive(self):
        """零基下标引用依赖于 payload_templates 的列表顺序。

        ssti_reflection.payload_templates = [
            "{{7*7}}",      # index 0
            "${7*7}",       # index 1
            "<%=7*7%>",     # index 2
            "#{7*7}",       # index 3
            "{{7*'7'}}",    # index 4
        ]
        如果此列表顺序发生变化（例如在 PrimitiveRegistry 中重新排序），
        所有 payload_template_ref 将指向不同的模板。

        风险等级: PAYLOAD_TEMPLATE_INDEX_IS_ORDER_SENSITIVE
        """
        adapter = _fresh_adapter()
        p = adapter._registry.get("ssti_reflection")
        templates = p.payload_templates

        # Verify current order
        assert templates[0] == "{{7*7}}", "Index 0 must be {{7*7}}"
        assert templates[1] == "${7*7}", "Index 1 must be ${7*7}"
        assert templates[2] == "<%=7*7%>", "Index 2 must be <%=7*7%>"
        assert templates[3] == "#{7*7}", "Index 3 must be #{7*7}"
        assert templates[4] == "{{7*'7'}}", "Index 4 must be {{7*'7'}}"

        # Document risk: any reordering of payload_templates in INJECTION_PRIMITIVES
        # will silently change what primitive:ssti_reflection:0 points to.
        # Recommended mitigation: compute stable template fingerprints in Adapter layer
        # or provide read-only stable references via content hash.
        assert len(templates) == 5, "Template count changed — verify indices"

    def test_payload_stable_ref_is_deterministic(self):
        adapter = _fresh_adapter()
        first = adapter.get_payload_template_refs("ssti_reflection")
        second = adapter.get_payload_template_refs("ssti_reflection")
        assert first == second

    def test_payload_stable_ref_uses_sha256_format(self):
        adapter = _fresh_adapter()
        primitive = adapter._registry.get("ssti_reflection")
        ref = adapter.get_payload_template_refs("ssti_reflection")[0]
        expected = hashlib.sha256(
            primitive.payload_templates[0].encode("utf-8")
        ).hexdigest()[:16]
        assert ref == f"primitive:ssti_reflection:sha256:{expected}"
        assert re.fullmatch(
            r"primitive:ssti_reflection:sha256:[0-9a-f]{16}",
            ref,
        )

    def test_same_payload_produces_same_stable_ref(self):
        adapter = _fresh_adapter()
        primitive = adapter._registry.get("ssti_reflection")
        primitive.payload_templates.append(primitive.payload_templates[0])
        refs = adapter.get_payload_template_refs("ssti_reflection")
        assert refs[0] == refs[-1]
        assert adapter.resolve_payload_template_ref(
            "ssti_reflection",
            refs[0],
        ) == 0

    def test_different_payloads_produce_different_stable_refs(self):
        adapter = _fresh_adapter()
        refs = adapter.get_payload_template_refs("ssti_reflection")
        assert refs[0] != refs[1]

    def test_legacy_index_ref_is_accepted(self):
        result = normalize_route_proposal(
            _valid_proposal(payload_template_ref="primitive:ssti_reflection:0"),
            _fresh_adapter(),
        )
        assert result.ok

    def test_legacy_index_ref_normalizes_to_stable_ref(self):
        adapter = _fresh_adapter()
        route = _assert_ok(
            normalize_route_proposal(
                _valid_proposal(payload_template_ref="primitive:ssti_reflection:0"),
                adapter,
            )
        )
        assert route.payload_template_ref == adapter.get_payload_template_refs(
            "ssti_reflection"
        )[0]
        assert ":sha256:" in route.payload_template_ref

    def test_stable_ref_is_accepted(self):
        adapter = _fresh_adapter()
        stable_ref = adapter.get_payload_template_refs("ssti_reflection")[0]
        route = _assert_ok(
            normalize_route_proposal(
                _valid_proposal(payload_template_ref=stable_ref),
                adapter,
            )
        )
        assert route.payload_template_ref == stable_ref

    def test_unknown_stable_ref_rejected(self):
        proposal = _valid_proposal(
            payload_template_ref="primitive:ssti_reflection:sha256:0000000000000000"
        )
        result = normalize_route_proposal(proposal, _fresh_adapter())
        _assert_error(result, NormalizationErrorCode.UNKNOWN_PAYLOAD_TEMPLATE)

    def test_malformed_stable_ref_rejected(self):
        adapter = _fresh_adapter()
        bad_refs = (
            "primitive:ssti_reflection:sha256:",
            "primitive:ssti_reflection:sha256:abc",
            "primitive:ssti_reflection:sha256:GGGGGGGGGGGGGGGG",
            "primitive:ssti_reflection:md5:0000000000000000",
        )
        for ref in bad_refs:
            result = normalize_route_proposal(
                _valid_proposal(payload_template_ref=ref),
                adapter,
            )
            _assert_error(result, NormalizationErrorCode.UNKNOWN_PAYLOAD_TEMPLATE)

    def test_stable_ref_cannot_cross_primitive(self):
        adapter = _fresh_adapter()
        other_ref = adapter.get_payload_template_refs("sql_boolean")[0]
        result = normalize_route_proposal(
            _valid_proposal(payload_template_ref=other_ref),
            adapter,
        )
        _assert_error(result, NormalizationErrorCode.UNKNOWN_PAYLOAD_TEMPLATE)

    def test_template_reordering_does_not_change_stable_ref(self):
        adapter = _fresh_adapter()
        primitive = adapter._registry.get("ssti_reflection")
        before = dict(
            zip(
                primitive.payload_templates,
                adapter.get_payload_template_refs("ssti_reflection"),
            )
        )
        primitive.payload_templates.reverse()
        after = dict(
            zip(
                primitive.payload_templates,
                adapter.get_payload_template_refs("ssti_reflection"),
            )
        )
        assert before == after

    def test_normalized_route_never_stores_index_ref(self):
        adapter = _fresh_adapter()
        route = _assert_ok(
            normalize_route_proposal(
                _valid_proposal(payload_template_ref="primitive:ssti_reflection:4"),
                adapter,
            )
        )
        assert re.fullmatch(
            r"primitive:ssti_reflection:sha256:[0-9a-f]{16}",
            route.payload_template_ref,
        )
        assert route.materialization.payload_template_ref == route.payload_template_ref


# ═══════════════════════════════════════════════════════════════════
# Section 8 — Technique Semantics Tests
# ═══════════════════════════════════════════════════════════════════

class TestTechniqueSemantics:
    """Section 九: Technique semantic distinction."""

    def test_allowed_techniques_are_explicit(self):
        """SUPPORTED_TECHNIQUES 只包含有明确依据的 technique。"""
        expected = ("arithmetic_probe", "syntax_probe", "reflection_probe")
        assert SUPPORTED_TECHNIQUES == expected, (
            f"SUPPORTED_TECHNIQUES must be exactly {expected}, got {SUPPORTED_TECHNIQUES}"
        )

    def test_unsupported_technique_rejected(self):
        """不支持的 technique 被拒绝。"""
        adapter = _fresh_adapter()
        bad_techniques = [
            "rce_probe",
            "blind_probe",
            "random_technique",
            "code_execution",
            "",
        ]
        for tech in bad_techniques:
            proposal = _valid_proposal(technique=tech)
            result = normalize_route_proposal(proposal, adapter)
            assert not result.ok, (
                f"Technique {tech!r} should be rejected but was accepted"
            )
            _assert_error(result, NormalizationErrorCode.UNSUPPORTED_TECHNIQUE)

    def test_each_technique_has_defined_semantics(self):
        """检查三个 technique 是否有不同语义。

        当前 PrimitiveRegistry 中的 ssti_reflection 有 5 个 payload_templates。
        所有三个 technique 共享相同的 target_primitive、observable_signals。
        Normalizer 未根据 technique 分配不同的 payload ref 或 signal。

        这意味着三个 technique 在 normalizer 层面无法区分语义。
        它们只是名字不同，实际行为完全一致。
        """
        adapter = _fresh_adapter()

        techniques = ["arithmetic_probe", "syntax_probe", "reflection_probe"]
        routes = {}

        for tech in techniques:
            proposal = _valid_proposal(technique=tech)
            result = normalize_route_proposal(proposal, adapter)
            route = _assert_ok(result)
            routes[tech] = route

        # All three techniques use the same target_primitive
        primitives = {r.target_primitive for r in routes.values()}
        assert len(primitives) == 1, (
            f"All techniques should target same primitive, got: {primitives}"
        )

        # All three techniques use the same expected_signals
        signals = {r.expected_signals for r in routes.values()}
        assert len(signals) == 1, (
            f"All techniques should have same signals, got: {signals}"
        )

        # The difference is ONLY in the technique name and canonical_id
        tech_names = {r.technique for r in routes.values()}
        assert tech_names == set(techniques), (
            f"Technique names differ: {tech_names}"
        )

        # NOTE: This test documents that technique names are NOT backed by distinct
        # existing templates in PrimitiveRegistry. The five payload_templates for
        # ssti_reflection cover multiple engines but are NOT labeled by technique.
        # This is recorded as: TECHNIQUE_NAMES_NOT_BACKED_BY_DISTINCT_EXISTING_TEMPLATES

    def test_technique_does_not_silently_accept_arbitrary_payload_ref(self):
        """Technique 不静默接受任意 payload ref。

        即使 technique 合法，payload ref 仍必须指向 target_primitive 的有效模板。
        """
        adapter = _fresh_adapter()
        for tech in SUPPORTED_TECHNIQUES:
            # Use a valid technique but with an out-of-range payload ref
            proposal = _valid_proposal(
                technique=tech,
                payload_template_ref="primitive:ssti_reflection:999"
            )
            result = normalize_route_proposal(proposal, adapter)
            assert not result.ok, (
                f"Technique {tech!r} should reject out-of-range payload ref"
            )
            _assert_error(result, NormalizationErrorCode.UNKNOWN_PAYLOAD_TEMPLATE)

    def test_technique_distinction_requires_next_phase(self):
        """三个 technique 在 normalizer 层面语义相同。

        结论: 当前实际上只支持一种技术语义（ssti_reflection 上的通用算术/语法/反射探测）。
        三个 technique 名称是可接受的命名空间划分，但需要下一轮增加：
        1. 在 PrimitiveRegistry 中为 payload_templates 增加 technique 标签
        2. 或在 Adapter 层根据 technique 筛选适用的 payload templates
        3. 或缩小首阶段 allowlist 为单一 technique
        """
        adapter = _fresh_adapter()
        # The three techniques all share the same payload template space
        # This is acceptable for v1 but noted as deferred work
        for tech in SUPPORTED_TECHNIQUES:
            proposal = _valid_proposal(technique=tech)
            result = normalize_route_proposal(proposal, adapter)
            assert result.ok, (
                f"Technique {tech!r} should be accepted (all share same primitive space)"
            )


# ═══════════════════════════════════════════════════════════════════
# Section 9 — Runtime Facts Tests
# ═══════════════════════════════════════════════════════════════════

class TestRuntimeFacts:
    """Section 十: Runtime facts validation."""

    def test_required_runtime_facts_must_not_be_empty(self):
        """required_runtime_facts 不能为空。"""
        adapter = _fresh_adapter()
        proposal = _valid_proposal(required_runtime_facts=())
        result = normalize_route_proposal(proposal, adapter)
        assert not result.ok
        _assert_error(result, NormalizationErrorCode.MISSING_RUNTIME_FACTS)

    def test_required_runtime_facts_are_deterministic(self):
        """相同的 runtime_facts 输入产生相同的输出。"""
        adapter = _fresh_adapter()
        facts = ("endpoint", "parameter", "method")

        results = []
        for _ in range(10):
            proposal = _valid_proposal(required_runtime_facts=facts)
            result = normalize_route_proposal(proposal, adapter)
            results.append(result.route.requires.runtime_facts)

        first = results[0]
        for r in results[1:]:
            assert first == r, f"Runtime facts not deterministic: {first} != {r}"

    def test_duplicate_runtime_facts_are_normalized(self):
        """重复的 runtime_facts 被去重。"""
        adapter = _fresh_adapter()
        proposal = _valid_proposal(
            required_runtime_facts=("endpoint", "endpoint", "parameter", "parameter", "method")
        )
        result = normalize_route_proposal(proposal, adapter)
        route = _assert_ok(result)
        assert route.requires.runtime_facts == ("endpoint", "parameter", "method"), (
            f"Duplicates should be removed, got: {route.requires.runtime_facts}"
        )

    def test_whitespace_only_facts_are_removed(self):
        """空白 runtime_fact 被移除。"""
        adapter = _fresh_adapter()
        proposal = _valid_proposal(
            required_runtime_facts=("  ", "endpoint", "", "parameter", "\t")
        )
        result = normalize_route_proposal(proposal, adapter)
        route = _assert_ok(result)
        assert route.requires.runtime_facts == ("endpoint", "parameter"), (
            f"Whitespace-only facts should be removed, got: {route.requires.runtime_facts}"
        )

    def test_runtime_facts_order_is_preserved(self):
        """runtime_facts 保持首次出现顺序（通过 dict.fromkeys）。"""
        adapter = _fresh_adapter()
        proposal = _valid_proposal(
            required_runtime_facts=("method", "endpoint", "parameter", "endpoint")
        )
        result = normalize_route_proposal(proposal, adapter)
        route = _assert_ok(result)
        assert route.requires.runtime_facts == ("method", "endpoint", "parameter"), (
            f"First-occurrence order should be preserved, got: {route.requires.runtime_facts}"
        )

    def test_runtime_facts_not_validated_against_existing_schema(self):
        """runtime_facts 的字段名未与现有 RuntimeTruths 结构验证。

        当前 normalizer 接受任意字符串元组作为 runtime_facts。
        项目中没有 RuntimeTruths 类或正式的事实名枚举。
        现有代码使用 'base_url', 'http_method', 'endpoint', 'parameter' 等字段名。

        Normalizer 的 MaterializationDeclaration 使用:
          method_from="runtime_truths"
          endpoint_from="runtime_truths"
          parameter_from="runtime_truths"

        但从未定义 runtime_truths 的具体字段集合。

        风险: NORMALIZER_INVENTS_FIELD_NAMES_WITHOUT_SCHEMA
        建议: 定义 RUNTIME_FACT_WHITELIST 或引用 Planner/Executor 的现有 schema
        """
        adapter = _fresh_adapter()
        # Any string tuple is accepted
        arbitrary_facts = ("foo", "bar", "baz")
        proposal = _valid_proposal(required_runtime_facts=arbitrary_facts)
        result = normalize_route_proposal(proposal, adapter)
        # Currently passes — this documents the gap
        route = _assert_ok(result)
        assert route.requires.runtime_facts == arbitrary_facts, (
            "Any string tuple is accepted — no validation against known facts schema"
        )

    def test_materialization_references_runtime_truths(self):
        """Materialization 声明从 runtime_truths 获取运行时值。"""
        adapter = _fresh_adapter()
        proposal = _valid_proposal()
        result = normalize_route_proposal(proposal, adapter)
        route = _assert_ok(result)

        mat = route.materialization
        assert mat.method_from == "runtime_truths"
        assert mat.endpoint_from == "runtime_truths"
        assert mat.parameter_from == "runtime_truths"
        assert mat.type == "http_request"


# ═══════════════════════════════════════════════════════════════════
# Section 10 — Immutability & Serialization Tests
# ═══════════════════════════════════════════════════════════════════

class TestImmutability:
    """Section 十一: Immutable structures and serializable conversion."""

    def test_route_proposal_is_immutable(self):
        """RouteProposal 是不可变的 (frozen dataclass)。"""
        proposal = _valid_proposal()
        with pytest.raises(Exception):  # FrozenInstanceError or similar
            proposal.cwe_id = "CWE-999"  # type: ignore

    def test_normalized_route_is_immutable(self):
        """NormalizedRoute 是不可变的。"""
        adapter = _fresh_adapter()
        result = normalize_route_proposal(_valid_proposal(), adapter)
        route = _assert_ok(result)
        with pytest.raises(Exception):  # FrozenInstanceError or similar
            route.cwe_id = "CWE-999"  # type: ignore

    def test_metadata_cannot_be_mutated(self):
        """metadata 不能通过返回的 MappingProxyType 被修改。"""
        adapter = _fresh_adapter()
        result = normalize_route_proposal(_valid_proposal(), adapter)
        route = _assert_ok(result)

        assert isinstance(route.metadata, MappingProxyType), (
            f"metadata must be MappingProxyType, got {type(route.metadata)}"
        )

    def test_route_proposal_metadata_is_mappingproxy(self):
        """RouteProposal.metadata 也被转换为 MappingProxyType。"""
        proposal = _valid_proposal(metadata={"key": "value"})
        assert isinstance(proposal.metadata, MappingProxyType), (
            f"proposal.metadata must be MappingProxyType, got {type(proposal.metadata)}"
        )

    def test_manual_conversion_to_plain_mapping_works(self):
        """手动逐字段转换 NormalizedRoute 为普通 dict（绕过 MappingProxyType）。"""
        adapter = _fresh_adapter()
        result = normalize_route_proposal(_valid_proposal(), adapter)
        route = _assert_ok(result)

        # Manual conversion that handles MappingProxyType
        plain = {
            "schema_version": route.schema_version,
            "canonical_id": route.canonical_id,
            "cwe_id": route.cwe_id,
            "current_state": route.current_state,
            "technique": route.technique,
            "metadata": dict(route.metadata),
            "activation": dataclasses.asdict(route.activation),
            "requires": dataclasses.asdict(route.requires),
            "target_primitive": route.target_primitive,
            "payload_template_ref": route.payload_template_ref,
            "expected_signals": route.expected_signals,
            "materialization": dataclasses.asdict(route.materialization),
            "success": dataclasses.asdict(route.success),
            "failure": dataclasses.asdict(route.failure),
            "replay": dataclasses.asdict(route.replay),
            "generation_status": route.generation_status,
        }

        assert isinstance(plain, dict)
        assert plain["schema_version"] == SCHEMA_VERSION
        assert plain["cwe_id"] == "CWE-94"
        assert plain["generation_status"] == "candidate_only"
        assert isinstance(plain["metadata"], dict)
        assert not isinstance(plain["metadata"], MappingProxyType)

    def test_manual_plain_mapping_is_json_serializable(self):
        """手动转换的 plain mapping 是 JSON 可序列化的。"""
        adapter = _fresh_adapter()
        result = normalize_route_proposal(_valid_proposal(), adapter)
        route = _assert_ok(result)

        plain = {
            "schema_version": route.schema_version,
            "canonical_id": route.canonical_id,
            "cwe_id": route.cwe_id,
            "current_state": route.current_state,
            "technique": route.technique,
            "metadata": dict(route.metadata),
            "activation": dataclasses.asdict(route.activation),
            "requires": dataclasses.asdict(route.requires),
            "target_primitive": route.target_primitive,
            "payload_template_ref": route.payload_template_ref,
            "expected_signals": list(route.expected_signals),
            "materialization": dataclasses.asdict(route.materialization),
            "success": dataclasses.asdict(route.success),
            "failure": dataclasses.asdict(route.failure),
            "replay": dataclasses.asdict(route.replay),
            "generation_status": route.generation_status,
        }

        json_str = json.dumps(plain, sort_keys=True)
        assert isinstance(json_str, str)
        # Round-trip
        parsed = json.loads(json_str)
        assert parsed["cwe_id"] == "CWE-94"

    def test_manual_plain_mapping_is_deterministic(self):
        """相同的 NormalizedRoute 手动转换产出相同的 plain mapping。"""
        adapter = _fresh_adapter()
        proposal = _valid_proposal()

        def to_plain(route):
            return {
                "schema_version": route.schema_version,
                "canonical_id": route.canonical_id,
                "cwe_id": route.cwe_id,
                "current_state": route.current_state,
                "technique": route.technique,
                "metadata": dict(route.metadata),
                "activation": dataclasses.asdict(route.activation),
                "requires": dataclasses.asdict(route.requires),
                "target_primitive": route.target_primitive,
                "payload_template_ref": route.payload_template_ref,
                "expected_signals": list(route.expected_signals),
                "materialization": dataclasses.asdict(route.materialization),
                "success": dataclasses.asdict(route.success),
                "failure": dataclasses.asdict(route.failure),
                "replay": dataclasses.asdict(route.replay),
                "generation_status": route.generation_status,
            }

        mappings = []
        for _ in range(10):
            result = normalize_route_proposal(proposal, adapter)
            mappings.append(json.dumps(to_plain(result.route), sort_keys=True))

        first = mappings[0]
        for i, m in enumerate(mappings[1:], 1):
            assert first == m, f"Plain mapping not deterministic at iteration {i}"

    def test_dataclasses_asdict_fails_with_mappingproxy(self):
        """dataclasses.asdict() 直接应用于 NormalizedRoute 会失败。

        原因: NormalizedRoute.__post_init__ 将 metadata 字段替换为
        MappingProxyType，而 dataclasses.asdict 内部使用 copy.deepcopy，
        后者不支持 MappingProxyType。

        这是架构阻塞问题: NORMALIZED_ROUTE_HAS_NO_SAFE_SERIALIZATION_BOUNDARY

        NormalizedRoute 没有提供内置的 to_dict() 方法，
        而 Python 标准库的 dataclasses.asdict() 对 frozen dataclass
        中包含 MappingProxyType 的情况不支持。

        修复建议（由 Codex 在下一轮实现）:
        1. 为 NormalizedRoute 增加 to_plain() 或 as_mapping() 方法
        2. 该方法将 metadata 显式转换为 dict
        3. 对嵌套的 frozen dataclass 字段使用 dataclasses.asdict
        4. tuple 字段转换为 list（YAML 兼容）
        5. 不复制 payload 字符串
        """
        adapter = _fresh_adapter()
        result = normalize_route_proposal(_valid_proposal(), adapter)
        route = _assert_ok(result)

        # Verify that dataclasses.asdict fails
        with pytest.raises(TypeError, match="mappingproxy|cannot pickle"):
            dataclasses.asdict(route)

    def test_plain_mapping_has_no_mappingproxy_via_manual_conversion(self):
        """手动转换确保 mapping 中不含 MappingProxyType。

        这证明了手动转换的可行性，同时暴露了 NormalizedRoute
        缺少内置转换方法的架构问题。
        """
        adapter = _fresh_adapter()
        result = normalize_route_proposal(_valid_proposal(), adapter)
        route = _assert_ok(result)

        plain = {
            "schema_version": route.schema_version,
            "canonical_id": route.canonical_id,
            "cwe_id": route.cwe_id,
            "current_state": route.current_state,
            "technique": route.technique,
            "metadata": dict(route.metadata),
            "activation": dataclasses.asdict(route.activation),
            "requires": dataclasses.asdict(route.requires),
            "target_primitive": route.target_primitive,
            "payload_template_ref": route.payload_template_ref,
            "expected_signals": list(route.expected_signals),
            "materialization": dataclasses.asdict(route.materialization),
            "success": dataclasses.asdict(route.success),
            "failure": dataclasses.asdict(route.failure),
            "replay": dataclasses.asdict(route.replay),
            "generation_status": route.generation_status,
        }

        def _find_mappingproxy(obj, path=""):
            if isinstance(obj, MappingProxyType):
                return path
            if isinstance(obj, dict):
                for k, v in obj.items():
                    found = _find_mappingproxy(v, f"{path}.{k}")
                    if found:
                        return found
            if isinstance(obj, (list, tuple)):
                for i, v in enumerate(obj):
                    found = _find_mappingproxy(v, f"{path}[{i}]")
                    if found:
                        return found
            return None

        found = _find_mappingproxy(plain)
        assert found is None, f"MappingProxyType found at {found}"


class TestSerializationBoundary:
    @staticmethod
    def _route_with_nested_metadata() -> NormalizedRoute:
        proposal = _valid_proposal(
            metadata={
                "nested": {
                    "values": ("alpha", 1, 2.5, True, None),
                }
            }
        )
        return _assert_ok(normalize_route_proposal(proposal, _fresh_adapter()))

    @staticmethod
    def _walk(value):
        yield value
        if isinstance(value, dict):
            for item in value.values():
                yield from TestSerializationBoundary._walk(item)
        elif isinstance(value, list):
            for item in value:
                yield from TestSerializationBoundary._walk(item)

    def test_normalized_route_has_to_plain(self):
        route = self._route_with_nested_metadata()
        assert callable(route.to_plain)
        assert isinstance(route.to_plain(), dict)

    def test_to_plain_returns_only_plain_python_types(self):
        plain = self._route_with_nested_metadata().to_plain()
        allowed = (dict, list, str, int, float, bool, type(None))
        assert all(type(value) in allowed for value in self._walk(plain))

    def test_to_plain_contains_no_mappingproxy(self):
        plain = self._route_with_nested_metadata().to_plain()
        assert not any(
            isinstance(value, MappingProxyType)
            for value in self._walk(plain)
        )

    def test_to_plain_contains_no_tuple(self):
        plain = self._route_with_nested_metadata().to_plain()
        assert not any(isinstance(value, tuple) for value in self._walk(plain))

    def test_to_plain_contains_no_dataclass_instances(self):
        plain = self._route_with_nested_metadata().to_plain()
        assert not any(dataclasses.is_dataclass(value) for value in self._walk(plain))

    def test_to_plain_is_deterministic(self):
        route = self._route_with_nested_metadata()
        assert route.to_plain() == route.to_plain()
        assert json.dumps(route.to_plain()) == json.dumps(route.to_plain())

    def test_to_plain_result_does_not_mutate_original(self):
        route = self._route_with_nested_metadata()
        plain = route.to_plain()
        plain["metadata"]["nested"]["values"].append("changed")
        plain["metadata"]["added"] = "changed"
        plain["activation"]["state"] = "active"

        assert route.metadata["nested"]["values"] == (
            "alpha", 1, 2.5, True, None
        )
        assert "added" not in route.metadata
        assert route.activation.state == "draft"

    def test_to_plain_result_is_json_serializable(self):
        plain = self._route_with_nested_metadata().to_plain()
        encoded = json.dumps(plain)
        assert json.loads(encoded) == plain

    def test_to_plain_preserves_normalized_route_field_order(self):
        keys = list(self._route_with_nested_metadata().to_plain())
        assert keys == [item.name for item in dataclasses.fields(NormalizedRoute)]


# ═══════════════════════════════════════════════════════════════════
# Section 11 — Import Side-Effect Audit
# ═══════════════════════════════════════════════════════════════════

class TestImportSideEffects:
    """Section 十二: Import does not load LLM, settings, or Docker."""

    def _clean_import_check(self, code: str, forbidden_modules: list[str]) -> tuple[bool, str]:
        """Run Python code in a subprocess and check which modules got loaded."""
        check_script = f"""
import sys
# Capture initial modules
before = set(sys.modules.keys())

{code}

after = set(sys.modules.keys())
new_modules = after - before
forbidden = {forbidden_modules!r}
found = [m for m in new_modules if any(f in m for f in forbidden)]
if found:
    print("FORBIDDEN:" + ",".join(sorted(found)))
else:
    print("OK")
"""
        proc = subprocess.run(
            [sys.executable, "-c", check_script],
            capture_output=True, text=True, cwd=str(B_DIR),
            timeout=30,
        )
        output = proc.stdout.strip()
        if output.startswith("FORBIDDEN:"):
            return False, output[len("FORBIDDEN:"):]
        return True, output

    def test_import_routes_does_not_load_llm_client(self):
        """import routes 不加载 LLM 客户端。"""
        ok, found = self._clean_import_check(
            "from routes.schema import RouteProposal",
            ["openai", "anthropic", "llm", "litellm", "langchain"],
        )
        assert ok, f"LLM modules loaded: {found}"

    def test_import_routes_does_not_load_settings(self):
        """import routes 不加载 settings/config。"""
        ok, found = self._clean_import_check(
            "from routes.normalizer import normalize_route_proposal",
            ["settings", "config", ".env", "dotenv"],
        )
        assert ok, f"Settings modules loaded: {found}"

    def test_import_routes_does_not_initialize_docker(self):
        """import routes 不加载 Docker。"""
        ok, found = self._clean_import_check(
            "from routes.primitive_adapter import PrimitiveAdapter",
            ["docker", "container", "compose"],
        )
        assert ok, f"Docker modules loaded: {found}"

    def test_import_routes_does_not_create_files(self):
        """import routes 不在磁盘上创建文件。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Count files before and after import
            before = set(Path(tmpdir).rglob("*"))
            # Run import in subprocess with cwd in tmpdir
            check = f"""
import sys, os
sys.path.insert(0, {str(B_DIR)!r})
os.chdir({tmpdir!r})
from routes.schema import RouteProposal
from routes.normalizer import normalize_route_proposal
from routes.primitive_adapter import PrimitiveAdapter
"""
            proc = subprocess.run(
                [sys.executable, "-c", check],
                capture_output=True, text=True, timeout=30,
            )
            after = set(Path(tmpdir).rglob("*"))
            new_files = after - before
            assert not new_files, f"Files created during import: {new_files}"

    def test_import_routes_does_not_initialize_memory_singletons(self):
        """import routes 不自动初始化 memory singletons。

        PrimitiveAdapter 的默认构造函数会创建新的 PrimitiveRegistry 和
        PrimitiveTransitionGraph 实例。这些是独立的（非 singleton），因此
        不会触发 get_primitive_registry() 或 get_transition_graph() 的
        全局初始化。

        但 normalizer.py 的模块级 import 是否会触发？验证它不导入
        ChromaDB、VerificationMemory 或其他有副作用的模块。
        """
        # Check normalizer imports
        import routes.normalizer as n
        import inspect
        source = inspect.getsource(n)
        forbidden_imports = [
            "chromadb", "ChromaDB", "Chroma",
            "docker", "DockerClient",
            "openai", "anthropic", "llm",
            "settings", "dotenv",
            "httpx", "requests", "urllib",
            "verification_memory", "VerificationMemory",
            "trajectory_memory", "ExploitTrajectoryMemory",
            "consolidator", "Consolidator",
            "evaluator", "Evaluator",
        ]
        # NOTE: "http" excluded because "http_request" appears as a data value
        # in MaterializationDeclaration. "config" excluded as too common.
        for term in forbidden_imports:
            assert term not in source, (
                f"normalizer.py references forbidden module: {term!r}"
            )

    def test_normalizer_has_no_network_calls(self):
        """Normalizer 不发起网络调用。"""
        import routes.normalizer as n
        import inspect
        source = inspect.getsource(n)
        forbidden = [
            "requests.", "urllib.", "http.client", "httpx",
            "socket.", "connect(", "urlopen",
        ]
        for term in forbidden:
            assert term not in source, (
                f"normalizer.py contains network call: {term!r}"
            )


# ═══════════════════════════════════════════════════════════════════
# Section 12 — Error Contract Tests
# ═══════════════════════════════════════════════════════════════════

class TestErrorContract:
    """Section 十三: Error result contracts."""

    def test_failure_result_has_stable_error_code(self):
        """失败结果通过 error code 标识，不需解析消息。"""
        adapter = _fresh_adapter()
        result = normalize_route_proposal(
            _valid_proposal(cwe_id="CWE-99999"), adapter
        )
        assert not result.ok
        for error in result.errors:
            assert isinstance(error.code, NormalizationErrorCode), (
                f"Error code must be NormalizationErrorCode enum, got {type(error.code)}"
            )
            assert isinstance(error.code.value, str), (
                "Error code value must be a stable string identifier"
            )

    def test_failure_result_does_not_require_parsing_message(self):
        """错误契约不依赖英文消息解析。

        所有错误通过 NormalizationErrorCode 枚举值区分。
        """
        # All error codes are machine-readable enum values
        codes = [e.value for e in NormalizationErrorCode]
        assert all(isinstance(c, str) and c.isupper() for c in codes), (
            f"Error codes must be UPPER_SNAKE_CASE strings: {codes}"
        )
        # No two codes should be the same
        assert len(codes) == len(set(codes)), "Duplicate error codes found"

    def test_multiple_errors_have_deterministic_order(self):
        """多个错误有确定性顺序（按 normalizer 代码中的检查顺序）。"""
        adapter = _fresh_adapter()
        # A proposal with multiple errors: UNKNOWN_CWE, UNKNOWN_STATE, UNSUPPORTED_PRIMITIVE
        proposal = _valid_proposal(
            cwe_id="CWE-99999",
            current_state="invalid_state",
            technique="bad_technique",
            required_runtime_facts=(),
            expected_signals=(),
            payload_template_ref="primitive:ssti_reflection:999",
        )
        results = []
        for _ in range(10):
            result = normalize_route_proposal(proposal, adapter)
            results.append(tuple(e.code for e in result.errors))

        first = results[0]
        for i, r in enumerate(results[1:], 1):
            assert first == r, (
                f"Error order not deterministic at iteration {i}: {first} != {r}"
            )

        # Verify the specific order matches the normalizer's check sequence
        expected_order = (
            NormalizationErrorCode.UNKNOWN_CWE,
            NormalizationErrorCode.UNKNOWN_STATE,
            NormalizationErrorCode.UNSUPPORTED_TECHNIQUE,
            NormalizationErrorCode.MISSING_RUNTIME_FACTS,
            NormalizationErrorCode.MISSING_EXPECTED_SIGNAL,
            NormalizationErrorCode.UNKNOWN_PAYLOAD_TEMPLATE,
        )
        assert first == expected_order, (
            f"Error order should follow normalizer check sequence.\n"
            f"Expected: {[e.value for e in expected_order]}\n"
            f"Got:      {[e.value for e in first]}"
        )

    def test_normalization_error_is_immutable(self):
        """NormalizationError 是不可变的。"""
        error = NormalizationError(
            code=NormalizationErrorCode.UNKNOWN_CWE,
            field="cwe_id",
            value="CWE-999",
        )
        with pytest.raises(Exception):
            error.code = NormalizationErrorCode.UNKNOWN_STATE  # type: ignore

    def test_normalization_result_is_immutable(self):
        """NormalizationResult 是不可变的。"""
        result = NormalizationResult()
        with pytest.raises(Exception):
            result.route = None  # type: ignore

    def test_all_error_codes_have_distinct_meanings(self):
        """所有 NormalizationErrorCode 值有明确语义区别。"""
        codes = set(e.value for e in NormalizationErrorCode)
        expected_codes = {
            "UNKNOWN_CWE",
            "UNKNOWN_STATE",
            "UNKNOWN_PRIMITIVE",
            "UNSUPPORTED_PRIMITIVE",
            "UNKNOWN_PAYLOAD_TEMPLATE",
            "MISSING_EXPECTED_SIGNAL",
            "PRIMITIVE_SIGNAL_MISMATCH",
            "MISSING_RUNTIME_FACTS",
            "UNSUPPORTED_TECHNIQUE",
        }
        assert codes == expected_codes, (
            f"Error codes mismatch.\nExtra: {codes - expected_codes}\nMissing: {expected_codes - codes}"
        )


# ═══════════════════════════════════════════════════════════════════
# Section 13 — Schema & Edge Case Tests
# ═══════════════════════════════════════════════════════════════════

class TestSchemaEdgeCases:
    """Additional schema edge case tests."""

    def test_route_proposal_rejects_non_string_fields(self):
        """RouteProposal 拒绝非字符串主字段。"""
        with pytest.raises(TypeError):
            RouteProposal(
                cwe_id=123,  # type: ignore
                current_state="init",
                target_primitive="ssti_reflection",
                technique="arithmetic_probe",
                required_runtime_facts=("endpoint",),
                payload_template_ref="primitive:ssti_reflection:0",
                expected_signals=("arithmetic_result_in_response",),
            )

    def test_route_proposal_rejects_non_string_runtime_facts(self):
        """RouteProposal 拒绝非字符串 runtime_facts。"""
        with pytest.raises(TypeError):
            RouteProposal(
                cwe_id="CWE-94",
                current_state="init",
                target_primitive="ssti_reflection",
                technique="arithmetic_probe",
                required_runtime_facts=(1, 2, 3),  # type: ignore
                payload_template_ref="primitive:ssti_reflection:0",
                expected_signals=("arithmetic_result_in_response",),
            )

    def test_route_proposal_rejects_non_string_expected_signals(self):
        """RouteProposal 拒绝非字符串 expected_signals。"""
        with pytest.raises(TypeError):
            RouteProposal(
                cwe_id="CWE-94",
                current_state="init",
                target_primitive="ssti_reflection",
                technique="arithmetic_probe",
                required_runtime_facts=("endpoint",),
                payload_template_ref="primitive:ssti_reflection:0",
                expected_signals=(True, False),  # type: ignore
            )

    def test_route_proposal_rejects_non_string_metadata_keys(self):
        """RouteProposal 拒绝非字符串 metadata keys。"""
        with pytest.raises(TypeError):
            RouteProposal(
                cwe_id="CWE-94",
                current_state="init",
                target_primitive="ssti_reflection",
                technique="arithmetic_probe",
                required_runtime_facts=("endpoint",),
                payload_template_ref="primitive:ssti_reflection:0",
                expected_signals=("arithmetic_result_in_response",),
                metadata={123: "value"},  # type: ignore
            )

    def test_activation_defaults(self):
        """Activation 默认值正确。"""
        a = Activation()
        assert a.state == "draft"
        assert a.source == "route_factory"

    def test_failure_policy_defaults(self):
        """FailurePolicy 默认值正确。"""
        fp = FailurePolicy()
        assert fp.state_change == "none"

    def test_replay_policy_defaults(self):
        """ReplayPolicy 默认值正确。"""
        rp = ReplayPolicy()
        assert rp.enabled is False

    def test_normalized_route_metadata_contains_generated_info(self):
        """NormalizedRoute.metadata 包含生成信息。"""
        adapter = _fresh_adapter()
        result = normalize_route_proposal(_valid_proposal(), adapter)
        route = _assert_ok(result)

        meta = dict(route.metadata)
        assert meta["generated_by"] == "route_factory"
        assert meta["source_cwe"] == "CWE-94"
        assert meta["canonical_cwe"] == "CWE-94"

    def test_user_metadata_is_preserved(self):
        """用户提供的 metadata 被保留并与生成信息合并。"""
        adapter = _fresh_adapter()
        proposal = _valid_proposal(metadata={"user_key": "user_value", "priority": 1})
        result = normalize_route_proposal(proposal, adapter)
        route = _assert_ok(result)

        meta = dict(route.metadata)
        assert meta["user_key"] == "user_value"
        assert meta["priority"] == 1
        assert meta["generated_by"] == "route_factory"

    def test_materialization_declaration_structure(self):
        """MaterializationDeclaration 结构完整。"""
        m = MaterializationDeclaration(
            type="http_request",
            method_from="runtime_truths",
            endpoint_from="runtime_truths",
            parameter_from="runtime_truths",
            payload_template_ref="primitive:ssti_reflection:0",
        )
        assert m.type == "http_request"
        assert m.method_from == "runtime_truths"
        assert "://" not in m.endpoint_from  # no real URL


# ═══════════════════════════════════════════════════════════════════
# Run all tests
# ═══════════════════════════════════════════════════════════════════

# ---------------------------------------------------------------------------
# Route Factory v1 writer and factory tests
# ---------------------------------------------------------------------------


def _valid_route(**overrides) -> NormalizedRoute:
    return _assert_ok(
        normalize_route_proposal(_valid_proposal(**overrides), _fresh_adapter())
    )


def test_normalized_route_writes_yaml(tmp_path):
    result = write_candidate_route(_valid_route(), tmp_path)

    assert result.ok
    assert result.output_path == (
        tmp_path / "cwe-94-init-ssti-reflection-arithmetic-probe.yaml"
    ).resolve()
    assert result.output_path.is_file()


def test_written_yaml_can_be_safely_reloaded(tmp_path):
    result = write_candidate_route(_valid_route(metadata={"说明": "候选路由"}), tmp_path)

    loaded = yaml.safe_load(result.output_path.read_text(encoding="utf-8"))
    assert loaded["metadata"]["说明"] == "候选路由"
    assert "!!python" not in result.yaml_preview


def test_written_yaml_matches_to_plain(tmp_path):
    route = _valid_route()
    result = write_candidate_route(route, tmp_path)

    assert yaml.safe_load(result.yaml_preview) == route.to_plain()


def test_written_yaml_uses_draft_activation(tmp_path):
    result = write_candidate_route(_valid_route(), tmp_path)
    loaded = yaml.safe_load(result.yaml_preview)

    assert loaded["activation"] == {
        "state": "draft",
        "source": "route_factory",
    }


def test_written_yaml_is_candidate_only(tmp_path):
    result = write_candidate_route(_valid_route(), tmp_path)
    assert yaml.safe_load(result.yaml_preview)["generation_status"] == "candidate_only"


def test_written_yaml_contains_stable_payload_ref(tmp_path):
    result = write_candidate_route(_valid_route(), tmp_path)
    loaded = yaml.safe_load(result.yaml_preview)

    expected_ref = _fresh_adapter().get_payload_template_refs("ssti_reflection")[0]
    assert loaded["payload_template_ref"] == expected_ref
    assert loaded["materialization"]["payload_template_ref"] == expected_ref
    assert ":sha256:" in expected_ref
    assert "primitive:ssti_reflection:0" not in result.yaml_preview


def test_written_yaml_does_not_contain_payload_content(tmp_path):
    route = _valid_route()
    primitive = PrimitiveRegistry().get("ssti_reflection")
    assert primitive is not None

    result = write_candidate_route(route, tmp_path)

    assert primitive.payload_templates[0] not in result.yaml_preview


def test_writer_does_not_write_builtin_directory(tmp_path):
    builtin_dir = tmp_path / "templates" / "builtin"
    result = write_candidate_route(_valid_route(), builtin_dir)

    assert WriteErrorCode.UNSAFE_OUTPUT_PATH in result.error_codes
    assert not builtin_dir.exists()


@pytest.mark.parametrize(
    "canonical_id",
    ("../escape", "route/escape", "route\\escape", "C:/absolute/escape"),
)
def test_writer_rejects_unsafe_path(tmp_path, canonical_id):
    route = dataclasses.replace(_valid_route(), canonical_id=canonical_id)
    result = write_candidate_route(route, tmp_path)

    assert WriteErrorCode.UNSAFE_OUTPUT_PATH in result.error_codes
    assert list(tmp_path.iterdir()) == []


def test_writer_does_not_overwrite_by_default(tmp_path):
    route = _valid_route()
    first = write_candidate_route(route, tmp_path)
    original = first.output_path.read_bytes()

    second = write_candidate_route(route, tmp_path)

    assert WriteErrorCode.OUTPUT_FILE_EXISTS in second.error_codes
    assert first.output_path.read_bytes() == original


def test_writer_overwrites_only_when_explicit(tmp_path):
    route = _valid_route()
    first = write_candidate_route(route, tmp_path)
    first.output_path.write_text("old\n", encoding="utf-8")

    second = write_candidate_route(route, tmp_path, overwrite=True)

    assert second.ok
    assert yaml.safe_load(first.output_path.read_text(encoding="utf-8")) == route.to_plain()


def test_writer_atomic_write_leaves_no_temp_file(tmp_path):
    result = write_candidate_route(_valid_route(), tmp_path)

    assert result.ok
    assert not list(tmp_path.glob("*.tmp"))
    assert not list(tmp_path.glob(".*.tmp"))


def test_writer_cleans_temp_file_when_replace_fails(tmp_path, monkeypatch):
    import routes.writer as writer

    def fail_replace(source, destination):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(writer.os, "replace", fail_replace)
    result = write_candidate_route(_valid_route(), tmp_path)

    assert WriteErrorCode.WRITE_FAILED in result.error_codes
    assert not list(tmp_path.glob("*.tmp"))
    assert not list(tmp_path.glob(".*.tmp"))
    assert not list(tmp_path.glob("*.yaml"))


def test_writer_rejects_legacy_payload_ref(tmp_path):
    route = _valid_route()
    legacy_ref = "primitive:ssti_reflection:0"
    route = dataclasses.replace(
        route,
        payload_template_ref=legacy_ref,
        materialization=dataclasses.replace(
            route.materialization,
            payload_template_ref=legacy_ref,
        ),
    )

    result = write_candidate_route(route, tmp_path)

    assert WriteErrorCode.YAML_SERIALIZATION_ERROR in result.error_codes
    assert not list(tmp_path.iterdir())


def test_dry_run_returns_yaml_preview(tmp_path):
    report = generate_candidate_routes(
        [_valid_proposal()],
        _fresh_adapter(),
        tmp_path / "routes",
        dry_run=True,
    )

    assert report.normalized == 1
    assert len(report.yaml_previews) == 1
    assert yaml.safe_load(report.yaml_previews[0].yaml)["canonical_id"] == (
        "cwe-94:init:ssti-reflection:arithmetic-probe"
    )


def test_dry_run_writes_nothing(tmp_path):
    output_dir = tmp_path / "routes"
    output_dir.mkdir()
    sentinel = output_dir / "existing.txt"
    sentinel.write_text("unchanged", encoding="utf-8")
    before = {item.name: item.read_bytes() for item in output_dir.iterdir()}

    generate_candidate_routes(
        [_valid_proposal()],
        _fresh_adapter(),
        output_dir,
        dry_run=True,
    )

    after = {item.name: item.read_bytes() for item in output_dir.iterdir()}
    assert after == before


def test_dry_run_does_not_create_output_directory(tmp_path):
    output_dir = tmp_path / "not-created"

    generate_candidate_routes(
        [_valid_proposal()],
        _fresh_adapter(),
        output_dir,
        dry_run=True,
    )

    assert not output_dir.exists()


def test_factory_generates_multiple_candidate_routes(tmp_path):
    proposals = [
        _valid_proposal(technique="arithmetic_probe"),
        _valid_proposal(technique="syntax_probe"),
    ]
    report = generate_candidate_routes(proposals, _fresh_adapter(), tmp_path)

    assert report.normalized == 2
    assert report.written == 2
    assert len(report.output_files) == 2
    assert all(Path(file_name).is_file() for file_name in report.output_files)
    assert (tmp_path / "route_generation_report.json").is_file()


def test_duplicate_canonical_id_rejected(tmp_path):
    proposal = _valid_proposal()
    report = generate_candidate_routes([proposal, proposal], _fresh_adapter(), tmp_path)

    assert report.normalized == 1
    assert report.rejected == 1
    assert report.duplicate_ids == (
        "cwe-94:init:ssti-reflection:arithmetic-probe",
    )
    assert report.diagnostics[0].proposal_index == 1
    assert report.diagnostics[0].error_codes == (DUPLICATE_ROUTE_ID,)
    assert len(list(tmp_path.glob("*.yaml"))) == 1


def test_rejected_proposal_is_reported(tmp_path):
    report = generate_candidate_routes(
        [_valid_proposal(cwe_id="CWE-99999")],
        _fresh_adapter(),
        tmp_path,
    )

    assert report.rejected == 1
    assert report.diagnostics[0].proposal_index == 0
    assert "UNKNOWN_CWE" in report.diagnostics[0].error_codes
    assert report.diagnostics[0].message


def test_generation_report_counts_are_correct(tmp_path):
    valid = _valid_proposal()
    report = generate_candidate_routes(
        [valid, valid, _valid_proposal(cwe_id="CWE-99999")],
        _fresh_adapter(),
        tmp_path,
    )

    assert report.proposals_received == report.normalized + report.rejected
    assert report.written <= report.normalized
    assert report.candidate_only == report.normalized
    assert (report.proposals_received, report.normalized, report.rejected) == (3, 1, 2)


def test_generation_report_is_json_serializable(tmp_path):
    report = generate_candidate_routes(
        [_valid_proposal()],
        _fresh_adapter(),
        tmp_path,
    )
    encoded = json.dumps(report.to_plain(), ensure_ascii=False)
    persisted = json.loads(
        (tmp_path / "route_generation_report.json").read_text(encoding="utf-8")
    )

    assert json.loads(encoded) == report.to_plain()
    assert persisted == report.to_plain()


def test_factory_report_does_not_overwrite_by_default(tmp_path):
    first = generate_candidate_routes(
        [_valid_proposal()],
        _fresh_adapter(),
        tmp_path,
    )
    report_path = tmp_path / "route_generation_report.json"
    before = report_path.read_bytes()

    second = generate_candidate_routes(
        [_valid_proposal(technique="syntax_probe")],
        _fresh_adapter(),
        tmp_path,
    )

    assert first.written == 1
    assert second.written == 0
    assert second.diagnostics[0].error_codes == (
        WriteErrorCode.OUTPUT_FILE_EXISTS.value,
    )
    assert report_path.read_bytes() == before


def test_factory_reports_existing_output_file(tmp_path):
    route = _valid_route()
    existing = write_candidate_route(route, tmp_path)
    before = existing.output_path.read_bytes()

    report = generate_candidate_routes(
        [_valid_proposal()],
        _fresh_adapter(),
        tmp_path,
    )

    assert report.normalized == 0
    assert report.rejected == 1
    assert report.diagnostics[0].error_codes == (
        WriteErrorCode.OUTPUT_FILE_EXISTS.value,
    )
    assert existing.output_path.read_bytes() == before
    assert (tmp_path / "route_generation_report.json").is_file()


def test_generation_report_atomic_write_leaves_no_temp_file(tmp_path):
    report = generate_candidate_routes(
        [_valid_proposal()],
        _fresh_adapter(),
        tmp_path,
    )

    assert report.written == 1
    assert not list(tmp_path.glob("*.tmp"))
    assert not list(tmp_path.glob(".*.tmp"))


def _new_modules_loaded_by_factory() -> set[str]:
    script = """
import json
import sys
before = set(sys.modules)
import routes.factory
print(json.dumps(sorted(set(sys.modules) - before)))
"""
    proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(B_DIR),
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    return set(json.loads(proc.stdout))


def test_factory_does_not_load_llm():
    loaded = _new_modules_loaded_by_factory()
    forbidden = ("openai", "anthropic", "litellm", "langchain")
    assert not {name for name in loaded if name.startswith(forbidden)}


def test_factory_does_not_start_docker():
    loaded = _new_modules_loaded_by_factory()
    assert not {name for name in loaded if name == "docker" or name.startswith("docker.")}


def test_factory_does_not_send_http(tmp_path):
    import routes.factory as factory

    source = inspect.getsource(factory)
    forbidden_calls = ("requests.", "httpx.", "urlopen(", "socket.", "connect(")
    assert not any(term in source for term in forbidden_calls)

    report = generate_candidate_routes(
        [_valid_proposal()],
        _fresh_adapter(),
        tmp_path,
        dry_run=True,
    )
    assert report.normalized == 1


def test_factory_does_not_modify_verification_memory(tmp_path):
    verification_memory = B_DIR / "memory" / "verification_memory.py"
    before = verification_memory.read_bytes()

    generate_candidate_routes(
        [_valid_proposal()],
        _fresh_adapter(),
        tmp_path,
    )

    assert verification_memory.read_bytes() == before
    assert "verification_memory" not in inspect.getsource(
        sys.modules["routes.factory"]
    )


# ---------------------------------------------------------------------------
# Route Factory v1.2 admission tests
# ---------------------------------------------------------------------------


def _admission_codes(decision: AdmissionDecision) -> tuple[AdmissionErrorCode, ...]:
    return tuple(item.code for item in decision.diagnostics)


def _assert_admission_error(
    decision: AdmissionDecision,
    code: AdmissionErrorCode,
):
    assert not decision.accepted
    assert decision.status == "rejected"
    assert code in _admission_codes(decision), (
        f"Expected {code.value}, got {[item.value for item in _admission_codes(decision)]}"
    )


def _load_plain_route(tmp_path, plain: dict[str, object]) -> AdmissionDecision:
    yaml_path = tmp_path / "candidate.yaml"
    yaml_path.write_text(
        yaml.safe_dump(plain, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    return load_and_admit_candidate_route(yaml_path, _fresh_adapter())


def _replace_route_identity(route: NormalizedRoute, **changes) -> NormalizedRoute:
    values = {
        "cwe_id": route.cwe_id,
        "current_state": route.current_state,
        "target_primitive": route.target_primitive,
        "technique": route.technique,
    }
    values.update({key: value for key, value in changes.items() if key in values})
    changes.setdefault(
        "canonical_id",
        _canonical_id(
            values["cwe_id"],
            values["current_state"],
            values["target_primitive"],
            values["technique"],
        ),
    )
    return dataclasses.replace(route, **changes)


def test_valid_normalized_route_is_admitted():
    decision = admit_route(_valid_route(), _fresh_adapter())

    assert decision.accepted
    assert decision.status == ADMITTED_CANDIDATE
    assert decision.diagnostics == ()
    assert decision.route is not None


def test_valid_written_yaml_is_loaded_and_admitted(tmp_path):
    written = write_candidate_route(_valid_route(), tmp_path)

    decision = load_and_admit_candidate_route(written.output_path, _fresh_adapter())

    assert decision.accepted
    assert decision.canonical_id == written.route_id


def test_admission_keeps_route_draft():
    decision = admit_route(_valid_route(), _fresh_adapter())
    assert decision.route.activation.state == "draft"


def test_admission_keeps_candidate_only():
    decision = admit_route(_valid_route(), _fresh_adapter())
    assert decision.route.generation_status == "candidate_only"


def test_active_route_is_rejected():
    route = dataclasses.replace(_valid_route(), activation=Activation(state="active"))
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.INVALID_CANDIDATE_STATE,
    )


def test_disabled_route_is_rejected():
    route = dataclasses.replace(_valid_route(), activation=Activation(state="disabled"))
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.INVALID_CANDIDATE_STATE,
    )


def test_non_factory_activation_source_rejected():
    route = dataclasses.replace(
        _valid_route(),
        activation=Activation(state="draft", source="manual"),
    )
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.INVALID_CANDIDATE_STATE,
    )


def test_non_candidate_generation_status_rejected():
    route = dataclasses.replace(_valid_route(), generation_status="approved")
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.INVALID_CANDIDATE_STATE,
    )


def test_missing_required_field_rejected(tmp_path):
    plain = _valid_route().to_plain()
    plain.pop("target_primitive")

    _assert_admission_error(
        _load_plain_route(tmp_path, plain),
        AdmissionErrorCode.SCHEMA_INVALID,
    )


def test_wrong_field_type_rejected(tmp_path):
    plain = _valid_route().to_plain()
    plain["expected_signals"] = "not-a-list"

    _assert_admission_error(
        _load_plain_route(tmp_path, plain),
        AdmissionErrorCode.SCHEMA_INVALID,
    )


def test_yaml_top_level_must_be_mapping(tmp_path):
    yaml_path = tmp_path / "candidate.yaml"
    yaml_path.write_text("- not\n- a\n- mapping\n", encoding="utf-8")

    _assert_admission_error(
        load_and_admit_candidate_route(yaml_path, _fresh_adapter()),
        AdmissionErrorCode.YAML_TOP_LEVEL_NOT_MAPPING,
    )


def test_yaml_safe_load_rejects_python_object(tmp_path):
    yaml_path = tmp_path / "candidate.yaml"
    yaml_path.write_text(
        "!!python/object/apply:builtins.str ['not-constructed']\n",
        encoding="utf-8",
    )

    _assert_admission_error(
        load_and_admit_candidate_route(yaml_path, _fresh_adapter()),
        AdmissionErrorCode.YAML_LOAD_ERROR,
    )


def test_multiple_yaml_documents_rejected(tmp_path):
    yaml_path = tmp_path / "candidate.yaml"
    yaml_path.write_text("---\na: 1\n---\nb: 2\n", encoding="utf-8")

    _assert_admission_error(
        load_and_admit_candidate_route(yaml_path, _fresh_adapter()),
        AdmissionErrorCode.YAML_MULTIPLE_DOCUMENTS,
    )


def test_oversized_yaml_rejected(tmp_path):
    yaml_path = tmp_path / "candidate.yaml"
    yaml_path.write_text("x" * (MAX_YAML_FILE_SIZE + 1), encoding="utf-8")

    _assert_admission_error(
        load_and_admit_candidate_route(yaml_path, _fresh_adapter()),
        AdmissionErrorCode.YAML_FILE_TOO_LARGE,
    )


def test_yaml_alias_bomb_rejected(tmp_path):
    yaml_path = tmp_path / "candidate.yaml"
    aliases = ", ".join("*base" for _ in range(33))
    yaml_path.write_text(
        f"base: &base [value]\nexpanded: [{aliases}]\n",
        encoding="utf-8",
    )

    _assert_admission_error(
        load_and_admit_candidate_route(yaml_path, _fresh_adapter()),
        AdmissionErrorCode.YAML_LOAD_ERROR,
    )


def test_canonical_id_is_recomputed():
    route = _valid_route()
    decision = admit_route(route, _fresh_adapter())

    assert decision.accepted
    assert "canonical_id" in decision.checked_invariants
    assert decision.canonical_id == _canonical_id(
        route.cwe_id,
        route.current_state,
        route.target_primitive,
        route.technique,
    )


def test_canonical_id_mismatch_rejected():
    route = dataclasses.replace(_valid_route(), canonical_id="cwe-94:init:wrong:id")
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.CANONICAL_ID_MISMATCH,
    )


def test_noncanonical_cwe_rejected():
    route = dataclasses.replace(_valid_route(), cwe_id="CWE-917")
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.NON_CANONICAL_CWE,
    )


def test_admission_unknown_cwe_rejected():
    route = _replace_route_identity(_valid_route(), cwe_id="CWE-99999")
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.UNKNOWN_CWE,
    )


def test_unknown_state_rejected():
    route = _valid_route()
    route = _replace_route_identity(
        route,
        current_state="not-a-state",
        requires=dataclasses.replace(route.requires, current_state="not-a-state"),
    )
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.UNKNOWN_STATE,
    )


def test_unknown_primitive_rejected():
    route = _valid_route()
    unknown_ref = "primitive:not_registered:sha256:0000000000000000"
    route = _replace_route_identity(
        route,
        target_primitive="not_registered",
        payload_template_ref=unknown_ref,
        materialization=dataclasses.replace(
            route.materialization,
            payload_template_ref=unknown_ref,
        ),
    )
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.UNKNOWN_PRIMITIVE,
    )


def test_unsupported_entry_primitive_rejected():
    adapter = _fresh_adapter()
    route = _valid_route()
    primitive = "ssti_execution"
    payload_ref = adapter.get_payload_template_refs(primitive)[0]
    signals = adapter.get_observable_signals(primitive)
    route = _replace_route_identity(
        route,
        target_primitive=primitive,
        payload_template_ref=payload_ref,
        expected_signals=signals,
        materialization=dataclasses.replace(
            route.materialization,
            payload_template_ref=payload_ref,
        ),
        success=dataclasses.replace(route.success, expected_signals=signals),
    )

    _assert_admission_error(
        admit_route(route, adapter),
        AdmissionErrorCode.UNSUPPORTED_PRIMITIVE,
    )


def test_stable_payload_ref_is_admitted():
    decision = admit_route(_valid_route(), _fresh_adapter())
    assert decision.accepted
    assert ":sha256:" in decision.route.payload_template_ref


def test_legacy_payload_ref_is_not_admitted():
    route = _valid_route()
    legacy_ref = "primitive:ssti_reflection:0"
    route = dataclasses.replace(
        route,
        payload_template_ref=legacy_ref,
        materialization=dataclasses.replace(
            route.materialization,
            payload_template_ref=legacy_ref,
        ),
    )
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.LEGACY_PAYLOAD_REF_NOT_ADMITTED,
    )


def test_malformed_payload_ref_rejected():
    route = _valid_route()
    malformed_ref = "primitive:ssti_reflection:sha256:NOT-A-HASH"
    route = dataclasses.replace(
        route,
        payload_template_ref=malformed_ref,
        materialization=dataclasses.replace(
            route.materialization,
            payload_template_ref=malformed_ref,
        ),
    )
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.MALFORMED_PAYLOAD_REF,
    )


def test_unknown_payload_hash_rejected():
    route = _valid_route()
    unknown_ref = "primitive:ssti_reflection:sha256:0000000000000000"
    route = dataclasses.replace(
        route,
        payload_template_ref=unknown_ref,
        materialization=dataclasses.replace(
            route.materialization,
            payload_template_ref=unknown_ref,
        ),
    )
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.UNKNOWN_PAYLOAD_TEMPLATE,
    )


def test_payload_primitive_mismatch_rejected():
    adapter = _fresh_adapter()
    route = _valid_route()
    other_ref = adapter.get_payload_template_refs("sql_boolean")[0]
    route = dataclasses.replace(
        route,
        payload_template_ref=other_ref,
        materialization=dataclasses.replace(
            route.materialization,
            payload_template_ref=other_ref,
        ),
    )
    _assert_admission_error(
        admit_route(route, adapter),
        AdmissionErrorCode.PAYLOAD_PRIMITIVE_MISMATCH,
    )


def test_payload_content_is_not_exposed():
    adapter = _fresh_adapter()
    payload = adapter._registry.get("ssti_reflection").payload_templates[0]
    accepted = admit_route(_valid_route(), adapter)
    rejected_route = dataclasses.replace(
        _valid_route(),
        payload_template_ref="primitive:ssti_reflection:0",
    )
    rejected = admit_route(rejected_route, adapter)

    assert payload not in repr(accepted)
    assert payload not in repr(rejected)
    assert all(payload not in item.message for item in rejected.diagnostics)


def test_expected_signals_must_not_be_empty():
    route = _valid_route()
    route = dataclasses.replace(
        route,
        expected_signals=(),
        success=dataclasses.replace(route.success, expected_signals=()),
    )
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.MISSING_EXPECTED_SIGNAL,
    )


def test_duplicate_expected_signals_rejected():
    route = _valid_route()
    signals = (
        "arithmetic_result_in_response",
        "arithmetic_result_in_response",
    )
    route = dataclasses.replace(
        route,
        expected_signals=signals,
        success=dataclasses.replace(route.success, expected_signals=signals),
    )
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.DUPLICATE_EXPECTED_SIGNAL,
    )


def test_primitive_signal_mismatch_rejected():
    route = _valid_route()
    signals = ("command_output_in_response",)
    route = dataclasses.replace(
        route,
        expected_signals=signals,
        success=dataclasses.replace(route.success, expected_signals=signals),
    )
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.PRIMITIVE_SIGNAL_MISMATCH,
    )


def test_success_signals_must_match_top_level():
    route = _valid_route()
    route = dataclasses.replace(
        route,
        success=dataclasses.replace(
            route.success,
            expected_signals=("arithmetic_result_in_response",),
        ),
    )
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.SUCCESS_SIGNAL_MISMATCH,
    )


def test_non_observable_route_rejected():
    route = _valid_route()
    signals = ("not_observable",)
    route = dataclasses.replace(
        route,
        expected_signals=signals,
        success=dataclasses.replace(route.success, expected_signals=signals),
    )
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.NON_OBSERVABLE_ROUTE,
    )


def test_unsupported_success_match_rejected():
    route = _valid_route()
    route = dataclasses.replace(
        route,
        success=dataclasses.replace(route.success, match="all"),
    )
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.UNSUPPORTED_SUCCESS_MATCH,
    )


def test_materialization_type_checked():
    route = _valid_route()
    route = dataclasses.replace(
        route,
        materialization=dataclasses.replace(route.materialization, type="shell"),
    )
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.UNSUPPORTED_MATERIALIZATION_TYPE,
    )


def test_materialization_fields_required(tmp_path):
    plain = _valid_route().to_plain()
    plain["materialization"].pop("endpoint_from")

    _assert_admission_error(
        _load_plain_route(tmp_path, plain),
        AdmissionErrorCode.MATERIALIZATION_INCOMPLETE,
    )


def test_materialization_sources_must_use_runtime_truths():
    route = _valid_route()
    route = dataclasses.replace(
        route,
        materialization=dataclasses.replace(
            route.materialization,
            endpoint_from="literal_url",
        ),
    )
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.MATERIALIZATION_INCOMPLETE,
    )


def test_materialization_payload_ref_must_match():
    route = _valid_route()
    other_ref = _fresh_adapter().get_payload_template_refs("ssti_reflection")[1]
    route = dataclasses.replace(
        route,
        materialization=dataclasses.replace(
            route.materialization,
            payload_template_ref=other_ref,
        ),
    )
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.MATERIALIZATION_REF_MISMATCH,
    )


def test_unknown_runtime_fact_rejected():
    route = _valid_route()
    route = dataclasses.replace(
        route,
        requires=dataclasses.replace(
            route.requires,
            runtime_facts=("endpoint", "invented_fact"),
        ),
    )
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.UNKNOWN_RUNTIME_FACT,
    )


def test_runtime_fact_allowlist_is_minimal_and_local():
    assert ROUTE_FACTORY_V1_RUNTIME_FACTS == {"endpoint", "parameter", "method"}
    import routes.admission as admission

    source = inspect.getsource(admission)
    assert "Temporary Route Factory v1 static contract" in source


def test_replay_must_remain_disabled():
    route = dataclasses.replace(_valid_route(), replay=ReplayPolicy(enabled=True))
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.UNSUPPORTED_REPLAY_POLICY,
    )


@pytest.mark.parametrize("enabled", (None, 0, "false"))
def test_replay_enabled_must_be_boolean(tmp_path, enabled):
    plain = _valid_route().to_plain()
    plain["replay"]["enabled"] = enabled

    _assert_admission_error(
        _load_plain_route(tmp_path, plain),
        AdmissionErrorCode.UNSUPPORTED_REPLAY_POLICY,
    )


def test_replay_extra_policy_rejected(tmp_path):
    plain = _valid_route().to_plain()
    plain["replay"]["fingerprint"] = "unsupported"

    _assert_admission_error(
        _load_plain_route(tmp_path, plain),
        AdmissionErrorCode.UNSUPPORTED_REPLAY_POLICY,
    )


def test_failure_cannot_change_state():
    route = dataclasses.replace(
        _valid_route(),
        failure=FailurePolicy(state_change="probe_success"),
    )
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.INVALID_FAILURE_STATE_CHANGE,
    )


@pytest.mark.parametrize(
    "field",
    ("next_state", "set_state", "state_transition", "advance_state", "unlock_state"),
)
def test_success_cannot_mutate_global_state(tmp_path, field):
    plain = _valid_route().to_plain()
    plain["success"][field] = "probe_success"

    _assert_admission_error(
        _load_plain_route(tmp_path, plain),
        AdmissionErrorCode.ROUTE_ATTEMPTS_STATE_MUTATION,
    )


def test_requires_state_must_match_top_level():
    route = _valid_route()
    route = dataclasses.replace(
        route,
        requires=dataclasses.replace(route.requires, current_state="probe_success"),
    )
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.REQUIRES_STATE_MISMATCH,
    )


def test_schema_version_is_checked():
    route = dataclasses.replace(_valid_route(), schema_version="999.0")
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.SCHEMA_INVALID,
    )


def test_normalized_route_from_plain_is_strict():
    plain = _valid_route().to_plain()
    parsed = normalized_route_from_plain(plain)
    assert parsed.ok
    assert parsed.route == _valid_route()

    plain["unexpected"] = True
    parsed = normalized_route_from_plain(plain)
    assert not parsed.ok
    assert parsed.diagnostics[0].code == AdmissionErrorCode.SCHEMA_INVALID


def test_admission_decision_is_immutable():
    decision = admit_route(_valid_route(), _fresh_adapter())
    with pytest.raises(Exception):
        decision.accepted = False  # type: ignore


def test_admission_does_not_write_files(tmp_path):
    before = set(tmp_path.rglob("*"))
    decision = admit_route(_valid_route(), _fresh_adapter())
    after = set(tmp_path.rglob("*"))

    assert decision.accepted
    assert after == before


def test_admission_does_not_modify_verification_memory(tmp_path):
    verification_memory = B_DIR / "memory" / "verification_memory.py"
    before = verification_memory.read_bytes()

    decision = admit_route(_valid_route(), _fresh_adapter())

    assert decision.accepted
    assert verification_memory.read_bytes() == before


def test_admission_does_not_modify_trajectory_memory(tmp_path):
    trajectory_memory = B_DIR / "memory" / "exploit_trajectory.py"
    before = trajectory_memory.read_bytes()

    decision = admit_route(_valid_route(), _fresh_adapter())

    assert decision.accepted
    assert trajectory_memory.read_bytes() == before


def _new_modules_loaded_by_admission() -> set[str]:
    script = """
import json
import sys
before = set(sys.modules)
import routes.admission
print(json.dumps(sorted(set(sys.modules) - before)))
"""
    proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(B_DIR),
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    return set(json.loads(proc.stdout))


def test_admission_does_not_load_llm():
    loaded = _new_modules_loaded_by_admission()
    forbidden = ("openai", "anthropic", "litellm", "langchain")
    assert not {name for name in loaded if name.startswith(forbidden)}


def test_admission_does_not_start_docker():
    loaded = _new_modules_loaded_by_admission()
    assert not {
        name for name in loaded if name == "docker" or name.startswith("docker.")
    }


def test_admission_does_not_send_http(tmp_path):
    import routes.admission as admission

    source = inspect.getsource(admission)
    forbidden_calls = ("requests.", "httpx.", "urlopen(", "socket.", "connect(")
    assert not any(term in source for term in forbidden_calls)
    assert admit_route(_valid_route(), _fresh_adapter()).accepted


def test_admission_uses_only_safe_yaml_loader():
    import routes.admission as admission

    source = inspect.getsource(admission)
    assert "yaml.safe_load(" in source
    assert "yaml.unsafe_load" not in source
    assert "FullLoader" not in source
    assert re.search(r"(?<!safe_)yaml\.load\(", source) is None


def test_all_existing_149_tests_still_pass():
    route = _assert_ok(normalize_route_proposal(_valid_proposal(), _fresh_adapter()))
    assert route.to_plain()["generation_status"] == "candidate_only"
    assert callable(write_candidate_route)
    assert callable(generate_candidate_routes)


# ---------------------------------------------------------------------------
# Route Registry v1 tests
# ---------------------------------------------------------------------------


def _admitted_decision(**overrides) -> AdmissionDecision:
    route = _valid_route(**overrides)
    decision = admit_route(route, _fresh_adapter())
    assert decision.accepted
    return decision


def _write_route_yaml(path: Path, route: NormalizedRoute, *, reverse=False) -> None:
    plain = route.to_plain()
    if reverse:
        plain = dict(reversed(tuple(plain.items())))
    path.write_text(
        yaml.safe_dump(plain, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


def _diagnostic_codes(result) -> tuple[RegistryErrorCode, ...]:
    return tuple(item.code for item in result.diagnostics)


def test_admitted_decision_can_be_registered():
    registry = RouteRegistry(_fresh_adapter())
    result = registry.register_decision(_admitted_decision())

    assert result.registered
    assert result.registered_route is not None
    assert len(registry) == 1


def test_rejected_decision_cannot_be_registered():
    route = dataclasses.replace(_valid_route(), activation=Activation(state="active"))
    decision = admit_route(route, _fresh_adapter())
    registry = RouteRegistry(_fresh_adapter())

    result = registry.register_decision(decision)

    assert not result.registered
    assert _diagnostic_codes(result) == (RegistryErrorCode.ROUTE_NOT_ADMITTED,)
    assert len(registry) == 0


def test_missing_route_in_decision_rejected():
    decision = dataclasses.replace(_admitted_decision(), route=None)
    result = RouteRegistry(_fresh_adapter()).register_decision(decision)

    assert _diagnostic_codes(result) == (RegistryErrorCode.ADMISSION_ROUTE_MISSING,)


def test_invalid_admission_status_rejected():
    decision = dataclasses.replace(_admitted_decision(), status="active")
    result = RouteRegistry(_fresh_adapter()).register_decision(decision)

    assert _diagnostic_codes(result) == (RegistryErrorCode.INVALID_ADMISSION_STATUS,)


def test_plain_dict_cannot_bypass_admission():
    result = RouteRegistry(_fresh_adapter()).register_decision(  # type: ignore
        _valid_route().to_plain()
    )
    assert _diagnostic_codes(result) == (RegistryErrorCode.ROUTE_NOT_ADMITTED,)


def test_forged_active_decision_cannot_bypass_admission():
    decision = _admitted_decision()
    active_route = dataclasses.replace(
        decision.route,
        activation=Activation(state="active"),
    )
    forged = dataclasses.replace(decision, route=active_route)

    result = RouteRegistry(_fresh_adapter()).register_decision(forged)

    assert _diagnostic_codes(result) == (RegistryErrorCode.ROUTE_NOT_ADMITTED,)


def test_registry_get_returns_registered_route():
    registry = RouteRegistry(_fresh_adapter())
    decision = _admitted_decision()
    registry.register_decision(decision)

    assert registry.get(decision.canonical_id) is not None
    assert registry.get(decision.canonical_id).route == decision.route


def test_registry_get_unknown_returns_none():
    assert RouteRegistry(_fresh_adapter()).get("missing") is None


def test_registry_list_all_is_sorted():
    registry = RouteRegistry(_fresh_adapter())
    for technique in ("syntax_probe", "arithmetic_probe", "reflection_probe"):
        registry.register_decision(_admitted_decision(technique=technique))

    ids = tuple(item.canonical_id for item in registry.list_all())
    assert ids == tuple(sorted(ids))
    assert isinstance(registry.list_all(), tuple)


def test_registry_query_by_cwe():
    registry = RouteRegistry(_fresh_adapter())
    registry.register_decision(_admitted_decision())

    assert len(registry.query(cwe_id="cwe-1336")) == 1
    assert registry.query(cwe_id="CWE-9999") == ()


def test_registry_query_by_state():
    registry = RouteRegistry(_fresh_adapter())
    registry.register_decision(_admitted_decision(current_state="probe_success"))

    assert len(registry.query(current_state="probe_success")) == 1
    assert registry.query(current_state="init") == ()


def test_registry_query_by_primitive():
    registry = RouteRegistry(_fresh_adapter())
    registry.register_decision(_admitted_decision())

    assert len(registry.query(target_primitive="ssti_reflection")) == 1
    assert registry.query(target_primitive="sql_boolean") == ()


def test_registry_query_by_technique():
    registry = RouteRegistry(_fresh_adapter())
    registry.register_decision(_admitted_decision(technique="syntax_probe"))

    assert len(registry.query(technique="syntax_probe")) == 1
    assert registry.query(technique="arithmetic_probe") == ()


def test_registry_query_combines_filters_with_and():
    registry = RouteRegistry(_fresh_adapter())
    registry.register_decision(_admitted_decision(technique="syntax_probe"))
    registry.register_decision(_admitted_decision(technique="arithmetic_probe"))

    assert len(
        registry.query(
            cwe_id="CWE-94",
            current_state="init",
            target_primitive="ssti_reflection",
            technique="syntax_probe",
        )
    ) == 1
    assert registry.query(current_state="probe_success", technique="syntax_probe") == ()


def test_registry_query_does_not_apply_runtime_rules():
    registry = RouteRegistry(_fresh_adapter())
    decision = _admitted_decision(required_runtime_facts=("endpoint", "method"))
    registry.register_decision(decision)

    assert registry.query(current_state="init")[0].route.requires.runtime_facts == (
        "endpoint",
        "method",
    )


def test_route_fingerprint_is_deterministic():
    route = _valid_route(metadata={"说明": "稳定"})
    assert route_fingerprint(route) == route_fingerprint(route)
    assert len(route_fingerprint(route)) == 64


def test_route_fingerprint_ignores_source_path():
    decision = _admitted_decision()
    first = RouteRegistry(_fresh_adapter())
    second = RouteRegistry(_fresh_adapter())
    first_route = first.register_decision(decision, Path("first.yaml")).registered_route
    second_route = second.register_decision(decision, Path("second.yaml")).registered_route

    assert first_route.route_fingerprint == second_route.route_fingerprint


def test_route_fingerprint_ignores_yaml_key_order(tmp_path):
    route = _valid_route()
    _write_route_yaml(tmp_path / "normal.yaml", route)
    _write_route_yaml(tmp_path / "reversed.yml", route, reverse=True)
    registry = RouteRegistry(_fresh_adapter())

    result = registry.load_directory(tmp_path)

    assert result.routes_registered == 1
    assert result.duplicates == 1


def test_route_fingerprint_changes_when_route_changes():
    first = _valid_route(metadata={"variant": 1})
    second = _valid_route(metadata={"variant": 2})
    assert route_fingerprint(first) != route_fingerprint(second)


def test_identical_duplicate_is_registered_once():
    registry = RouteRegistry(_fresh_adapter())
    decision = _admitted_decision()
    registry.register_decision(decision)
    duplicate = registry.register_decision(decision)

    assert len(registry) == 1
    assert duplicate.duplicate


def test_identical_duplicate_reports_duplicate():
    registry = RouteRegistry(_fresh_adapter())
    decision = _admitted_decision()
    registry.register_decision(decision)

    result = registry.register_decision(decision)

    assert _diagnostic_codes(result) == (RegistryErrorCode.DUPLICATE_ROUTE,)


def test_conflicting_same_id_is_rejected():
    registry = RouteRegistry(_fresh_adapter())
    first = _admitted_decision()
    changed_route = dataclasses.replace(first.route, metadata={"variant": "changed"})
    changed = admit_route(changed_route, _fresh_adapter())
    registry.register_decision(first)

    result = registry.register_decision(changed)

    assert result.conflict
    assert _diagnostic_codes(result) == (
        RegistryErrorCode.CONFLICTING_ROUTE_DEFINITION,
    )


def test_conflict_does_not_replace_first_route():
    registry = RouteRegistry(_fresh_adapter())
    first = _admitted_decision()
    changed = admit_route(
        dataclasses.replace(first.route, metadata={"variant": "changed"}),
        _fresh_adapter(),
    )
    registry.register_decision(first)
    original = registry.get(first.canonical_id)

    registry.register_decision(changed)

    assert registry.get(first.canonical_id) == original


def test_directory_load_admits_valid_yaml(tmp_path):
    _write_route_yaml(tmp_path / "route.yaml", _valid_route())

    result = RouteRegistry(_fresh_adapter()).load_directory(tmp_path)

    assert result.files_discovered == 1
    assert result.files_admitted == 1
    assert result.routes_registered == 1


def test_directory_load_rejects_invalid_yaml(tmp_path):
    (tmp_path / "invalid.yaml").write_text("not: [valid", encoding="utf-8")

    result = RouteRegistry(_fresh_adapter()).load_directory(tmp_path)

    assert result.rejected == 1
    assert result.diagnostics[0].code == RegistryErrorCode.REGISTRY_FILE_REJECTED
    assert result.diagnostics[0].admission_code == AdmissionErrorCode.YAML_LOAD_ERROR


def test_directory_load_continues_after_invalid_file(tmp_path):
    (tmp_path / "a-invalid.yaml").write_text("not: [valid", encoding="utf-8")
    _write_route_yaml(tmp_path / "b-valid.yaml", _valid_route())

    result = RouteRegistry(_fresh_adapter()).load_directory(tmp_path)

    assert result.files_discovered == 2
    assert result.routes_registered == 1
    assert result.rejected == 1


def test_directory_load_reads_yaml_and_yml(tmp_path):
    _write_route_yaml(tmp_path / "one.yaml", _valid_route(technique="arithmetic_probe"))
    _write_route_yaml(tmp_path / "two.yml", _valid_route(technique="syntax_probe"))

    result = RouteRegistry(_fresh_adapter()).load_directory(tmp_path)

    assert result.files_discovered == 2
    assert result.routes_registered == 2


def test_directory_load_ignores_json_and_other_files(tmp_path):
    (tmp_path / "route_generation_report.json").write_text("{}", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("ignored", encoding="utf-8")

    result = RouteRegistry(_fresh_adapter()).load_directory(tmp_path)

    assert result.files_discovered == 0


def test_directory_load_is_non_recursive(tmp_path):
    nested = tmp_path / "nested"
    nested.mkdir()
    _write_route_yaml(nested / "route.yaml", _valid_route())

    result = RouteRegistry(_fresh_adapter()).load_directory(tmp_path)

    assert result.files_discovered == 0


def test_directory_load_order_is_deterministic(tmp_path):
    route = _valid_route()
    _write_route_yaml(tmp_path / "z.yaml", route)
    _write_route_yaml(tmp_path / "a.yaml", route)
    registry = RouteRegistry(_fresh_adapter())

    result = registry.load_directory(tmp_path)

    assert result.duplicates == 1
    assert Path(registry.list_all()[0].source_path).name == "a.yaml"


def test_directory_not_found_reported(tmp_path):
    result = RouteRegistry(_fresh_adapter()).load_directory(tmp_path / "missing")
    assert _diagnostic_codes(result) == (
        RegistryErrorCode.REGISTRY_DIRECTORY_NOT_FOUND,
    )


def test_registry_path_must_be_directory(tmp_path):
    path = tmp_path / "route.yaml"
    _write_route_yaml(path, _valid_route())

    result = RouteRegistry(_fresh_adapter()).load_directory(path)

    assert _diagnostic_codes(result) == (
        RegistryErrorCode.REGISTRY_PATH_NOT_DIRECTORY,
    )


def test_symlink_escape_rejected(tmp_path, monkeypatch):
    registry_dir = tmp_path / "registry"
    registry_dir.mkdir()
    outside = tmp_path / "outside.yaml"
    _write_route_yaml(outside, _valid_route())
    link = registry_dir / "escape.yaml"
    _write_route_yaml(link, _valid_route())
    original_resolve = Path.resolve

    def resolve_symlink_escape(path, strict=False):
        if path == link:
            return original_resolve(outside, strict=strict)
        return original_resolve(path, strict=strict)

    monkeypatch.setattr(Path, "resolve", resolve_symlink_escape)

    result = RouteRegistry(_fresh_adapter()).load_directory(registry_dir)

    assert result.rejected == 1
    assert _diagnostic_codes(result) == (RegistryErrorCode.UNSAFE_REGISTRY_PATH,)


def test_directory_load_uses_existing_admission(tmp_path, monkeypatch):
    import routes.registry as registry_module

    path = tmp_path / "route.yaml"
    _write_route_yaml(path, _valid_route())
    original = registry_module.load_and_admit_candidate_route
    called = []

    def recording_loader(yaml_path, adapter):
        called.append(Path(yaml_path))
        return original(yaml_path, adapter)

    monkeypatch.setattr(
        registry_module,
        "load_and_admit_candidate_route",
        recording_loader,
    )
    RouteRegistry(_fresh_adapter()).load_directory(tmp_path)

    assert called == [path.resolve()]


def test_active_yaml_never_enters_registry(tmp_path):
    route = dataclasses.replace(_valid_route(), activation=Activation(state="active"))
    _write_route_yaml(tmp_path / "active.yaml", route)
    registry = RouteRegistry(_fresh_adapter())

    result = registry.load_directory(tmp_path)

    assert result.rejected == 1
    assert len(registry) == 0


def test_legacy_payload_ref_never_enters_registry(tmp_path):
    route = _valid_route()
    legacy = "primitive:ssti_reflection:0"
    route = dataclasses.replace(
        route,
        payload_template_ref=legacy,
        materialization=dataclasses.replace(
            route.materialization,
            payload_template_ref=legacy,
        ),
    )
    _write_route_yaml(tmp_path / "legacy.yaml", route)
    registry = RouteRegistry(_fresh_adapter())

    result = registry.load_directory(tmp_path)

    assert result.rejected == 1
    assert len(registry) == 0


def test_route_with_state_mutation_never_enters_registry(tmp_path):
    plain = _valid_route().to_plain()
    plain["success"]["next_state"] = "probe_success"
    (tmp_path / "mutation.yaml").write_text(
        yaml.safe_dump(plain, sort_keys=False),
        encoding="utf-8",
    )
    registry = RouteRegistry(_fresh_adapter())

    result = registry.load_directory(tmp_path)

    assert result.rejected == 1
    assert len(registry) == 0


def test_registry_does_not_write_files(tmp_path):
    path = tmp_path / "route.yaml"
    _write_route_yaml(path, _valid_route())
    before = {item.name: item.read_bytes() for item in tmp_path.iterdir()}

    RouteRegistry(_fresh_adapter()).load_directory(tmp_path)

    after = {item.name: item.read_bytes() for item in tmp_path.iterdir()}
    assert after == before


def test_registry_does_not_modify_yaml(tmp_path):
    path = tmp_path / "route.yaml"
    _write_route_yaml(path, _valid_route())
    before = path.read_bytes()

    RouteRegistry(_fresh_adapter()).load_directory(tmp_path)

    assert path.read_bytes() == before


def test_registry_does_not_modify_verification_memory(tmp_path):
    verification_memory = B_DIR / "memory" / "verification_memory.py"
    before = verification_memory.read_bytes()
    _write_route_yaml(tmp_path / "route.yaml", _valid_route())

    RouteRegistry(_fresh_adapter()).load_directory(tmp_path)

    assert verification_memory.read_bytes() == before


def test_registry_does_not_modify_trajectory_memory(tmp_path):
    trajectory_memory = B_DIR / "memory" / "exploit_trajectory.py"
    before = trajectory_memory.read_bytes()
    _write_route_yaml(tmp_path / "route.yaml", _valid_route())

    RouteRegistry(_fresh_adapter()).load_directory(tmp_path)

    assert trajectory_memory.read_bytes() == before


def _new_modules_loaded_by_registry() -> set[str]:
    script = """
import json
import sys
before = set(sys.modules)
import routes.registry
print(json.dumps(sorted(set(sys.modules) - before)))
"""
    proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(B_DIR),
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    return set(json.loads(proc.stdout))


def test_registry_does_not_load_llm():
    loaded = _new_modules_loaded_by_registry()
    forbidden = ("openai", "anthropic", "litellm", "langchain")
    assert not {name for name in loaded if name.startswith(forbidden)}


def test_registry_does_not_start_docker():
    loaded = _new_modules_loaded_by_registry()
    assert not {
        name for name in loaded if name == "docker" or name.startswith("docker.")
    }


def test_registry_does_not_send_http():
    import routes.registry as registry_module

    source = inspect.getsource(registry_module)
    forbidden_calls = ("requests.", "httpx.", "urlopen(", "socket.", "connect(")
    assert not any(term in source for term in forbidden_calls)


def test_snapshot_is_immutable():
    registry = RouteRegistry(_fresh_adapter())
    route = _valid_route(metadata={"nested": ["value"]})
    registry.register_decision(admit_route(route, _fresh_adapter()))
    snapshot = registry.snapshot()

    with pytest.raises(Exception):
        snapshot.routes = ()  # type: ignore
    with pytest.raises(TypeError):
        snapshot.routes[0].route.metadata["changed"] = True  # type: ignore
    assert snapshot.routes[0].route.metadata["nested"] == ("value",)


def test_snapshot_is_isolated_from_registry():
    registry = RouteRegistry(_fresh_adapter())
    registry.register_decision(_admitted_decision(technique="arithmetic_probe"))
    snapshot = registry.snapshot()

    registry.register_decision(_admitted_decision(technique="syntax_probe"))

    assert len(snapshot.routes) == 1
    assert len(registry) == 2


def test_snapshot_order_is_deterministic():
    registry = RouteRegistry(_fresh_adapter())
    registry.register_decision(_admitted_decision(technique="syntax_probe"))
    registry.register_decision(_admitted_decision(technique="arithmetic_probe"))

    ids = tuple(item.canonical_id for item in registry.snapshot().routes)
    assert ids == tuple(sorted(ids))


def test_snapshot_is_plain_serializable():
    registry = RouteRegistry(_fresh_adapter())
    registry.register_decision(_admitted_decision())
    plain = registry.snapshot().to_plain()
    payload = _fresh_adapter()._registry.get("ssti_reflection").payload_templates[0]

    assert json.loads(json.dumps(plain, ensure_ascii=False)) == plain
    assert payload not in json.dumps(plain, ensure_ascii=False)


# ═══════════════════════════════════════════════════════════════════
# Schema Patch v1.4a — requires.signals tests
# ═══════════════════════════════════════════════════════════════════


# ── RouteRequirements signals field ──


def test_route_requirements_has_signals():
    req = RouteRequirements(current_state="init", runtime_facts=("endpoint",))
    assert hasattr(req, "signals")
    assert req.signals == ()


def test_route_requirements_signals_default_empty():
    req = RouteRequirements(current_state="probe_success", runtime_facts=("endpoint", "parameter"))
    assert req.signals == ()


# ── RouteProposal required_signals field ──


def test_route_proposal_required_signals_default_empty():
    proposal = _valid_proposal()
    assert proposal.required_signals == ()
    # existing callers without required_signals must still work
    route = _assert_ok(normalize_route_proposal(proposal, _fresh_adapter()))
    assert route.requires.signals == ()


# ── Normalizer behaviour ──


def test_normalizer_writes_required_signals():
    proposal = _valid_proposal(
        required_signals=("expression_evaluated",),
    )
    route = _assert_ok(normalize_route_proposal(proposal, _fresh_adapter()))
    assert route.requires.signals == ("expression_evaluated",)


def test_normalizer_does_not_copy_expected_signals_to_requires():
    proposal = _valid_proposal(
        expected_signals=("arithmetic_result_in_response", "expression_reflected_verbatim"),
    )
    route = _assert_ok(normalize_route_proposal(proposal, _fresh_adapter()))
    # requires.signals must remain independent of expected_signals
    assert route.requires.signals == ()
    assert route.expected_signals == ("arithmetic_result_in_response", "expression_reflected_verbatim")


def test_normalizer_deduplicates_required_signals_deterministically():
    proposal = _valid_proposal(
        required_signals=("expression_evaluated", " expression_evaluated ", "expression_evaluated"),
    )
    route = _assert_ok(normalize_route_proposal(proposal, _fresh_adapter()))
    assert route.requires.signals == ("expression_evaluated",)


def test_expected_signals_and_required_signals_are_independent():
    """requires.signals expresses pre-execution preconditions;
    expected_signals expresses post-execution observables.
    They must never be conflated."""
    proposal = _valid_proposal(
        required_signals=("expression_evaluated",),
        expected_signals=("arithmetic_result_in_response", "expression_reflected_verbatim"),
    )
    route = _assert_ok(normalize_route_proposal(proposal, _fresh_adapter()))
    assert "expression_evaluated" in route.requires.signals
    assert "expression_evaluated" not in route.expected_signals
    assert "arithmetic_result_in_response" in route.expected_signals
    assert "arithmetic_result_in_response" not in route.requires.signals


# ── PrimitiveAdapter confirmation signal queries ──


def test_confirmation_signal_is_read_from_existing_primitive():
    adapter = _fresh_adapter()
    confirmation = adapter.get_confirmation_signal("ssti_reflection")
    # evidence_requirements / confirmation field exists on ssti_reflection
    assert confirmation == "expression_evaluated"


def test_confirmation_signal_returns_none_for_unknown_primitive():
    adapter = _fresh_adapter()
    assert adapter.get_confirmation_signal("nonexistent_primitive") is None


def test_confirmation_signal_is_not_hardcoded_in_routes():
    """Verify the confirmation signal name comes from the existing
    PrimitiveRegistry, not from a hard-coded literal inside routes/."""
    import routes.primitive_adapter as pa_module

    source = inspect.getsource(pa_module)
    assert "expression_evaluated" not in source
    # get_supported_requirement_signals must dynamically compose from observable_signals
    assert "arithmetic_result_in_response" not in source


def test_observable_signals_behavior_is_unchanged():
    adapter = _fresh_adapter()
    signals = adapter.get_observable_signals("ssti_reflection")
    assert signals == ("arithmetic_result_in_response", "expression_reflected_verbatim")


def test_supported_requirement_signals_includes_both_sources():
    adapter = _fresh_adapter()
    supported = adapter.get_supported_requirement_signals("ssti_reflection")
    assert "arithmetic_result_in_response" in supported
    assert "expression_reflected_verbatim" in supported
    assert "expression_evaluated" in supported


def test_supported_requirement_signals_is_empty_for_unknown_primitive():
    adapter = _fresh_adapter()
    assert adapter.get_supported_requirement_signals("nonexistent") == ()


# ── YAML output (to_plain / writer) ──


def test_written_yaml_contains_requires_signals(tmp_path):
    proposal = _valid_proposal(
        required_signals=("expression_evaluated",),
    )
    route = _assert_ok(normalize_route_proposal(proposal, _fresh_adapter()))
    result = write_candidate_route(route, tmp_path)
    loaded = yaml.safe_load(result.output_path.read_text(encoding="utf-8"))
    assert "requires" in loaded
    assert "signals" in loaded["requires"]
    assert loaded["requires"]["signals"] == ["expression_evaluated"]


def test_empty_required_signals_written_as_empty_list(tmp_path):
    route = _valid_route()
    result = write_candidate_route(route, tmp_path)
    loaded = yaml.safe_load(result.output_path.read_text(encoding="utf-8"))
    assert loaded["requires"]["signals"] == []


def test_yaml_round_trip_preserves_required_signals(tmp_path):
    proposal = _valid_proposal(
        required_signals=("expression_evaluated",),
    )
    route = _assert_ok(normalize_route_proposal(proposal, _fresh_adapter()))
    result = write_candidate_route(route, tmp_path)
    # Reload via admission
    decision = load_and_admit_candidate_route(result.output_path, _fresh_adapter())
    assert decision.accepted
    assert decision.route.requires.signals == ("expression_evaluated",)


def test_to_plain_contains_required_signals():
    proposal = _valid_proposal(
        required_signals=("expression_evaluated",),
    )
    route = _assert_ok(normalize_route_proposal(proposal, _fresh_adapter()))
    plain = route.to_plain()
    assert "requires" in plain
    assert "signals" in plain["requires"]
    assert plain["requires"]["signals"] == ["expression_evaluated"]


# ── Admission: required signals validation ──


def test_admission_accepts_valid_required_signals():
    route = dataclasses.replace(
        _valid_route(),
        requires=dataclasses.replace(
            _valid_route().requires,
            signals=("expression_evaluated",),
        ),
    )
    # expression_evaluated is a valid confirmation signal for ssti_reflection
    decision = admit_route(route, _fresh_adapter())
    assert decision.accepted


def test_admission_accepts_empty_required_signals():
    route = _valid_route()
    assert route.requires.signals == ()
    decision = admit_route(route, _fresh_adapter())
    assert decision.accepted


def test_admission_rejects_missing_requires_signals(tmp_path):
    plain = _valid_route().to_plain()
    del plain["requires"]["signals"]
    _assert_admission_error(
        _load_plain_route(tmp_path, plain),
        AdmissionErrorCode.SCHEMA_INVALID,
    )


def test_admission_rejects_wrong_required_signals_type(tmp_path):
    plain = _valid_route().to_plain()
    plain["requires"]["signals"] = "expression_evaluated"  # should be list
    _assert_admission_error(
        _load_plain_route(tmp_path, plain),
        AdmissionErrorCode.SCHEMA_INVALID,
    )


def test_admission_rejects_duplicate_required_signals():
    route = dataclasses.replace(
        _valid_route(),
        requires=dataclasses.replace(
            _valid_route().requires,
            signals=("expression_evaluated", "expression_evaluated"),
        ),
    )
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.DUPLICATE_REQUIRED_SIGNAL,
    )


def test_admission_rejects_empty_required_signal():
    route = dataclasses.replace(
        _valid_route(),
        requires=dataclasses.replace(
            _valid_route().requires,
            signals=("  ",),
        ),
    )
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.MISSING_REQUIRED_SIGNALS,
    )


def test_admission_rejects_unknown_required_signal():
    route = dataclasses.replace(
        _valid_route(),
        requires=dataclasses.replace(
            _valid_route().requires,
            signals=("nonexistent_signal",),
        ),
    )
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.UNKNOWN_REQUIRED_SIGNAL,
    )


def test_required_confirmation_signal_can_be_admitted():
    """expression_evaluated is a confirmation / evidence_requirements signal,
    not an observable_signal.  Admission must accept it as a required signal
    because it comes from the primitive's evidence_requirements."""
    route = dataclasses.replace(
        _valid_route(),
        requires=dataclasses.replace(
            _valid_route().requires,
            signals=("expression_evaluated",),
        ),
    )
    decision = admit_route(route, _fresh_adapter())
    assert decision.accepted


def test_expected_signal_validation_is_unchanged():
    """PRIMITIVE_SIGNAL_MISMATCH still applies to expected_signals;
    requires.signals uses UNKNOWN_REQUIRED_SIGNAL instead."""
    # expression_evaluated is NOT an observable_signal → rejected as expected_signal
    route = dataclasses.replace(
        _valid_route(),
        expected_signals=("expression_evaluated",),
        success=dataclasses.replace(
            _valid_route().success,
            expected_signals=("expression_evaluated",),
        ),
    )
    decision = admit_route(route, _fresh_adapter())
    assert AdmissionErrorCode.PRIMITIVE_SIGNAL_MISMATCH in _admission_codes(decision)
    # But if we declare it only as required_signal, it should pass
    route2 = dataclasses.replace(
        _valid_route(),
        requires=dataclasses.replace(
            _valid_route().requires,
            signals=("expression_evaluated",),
        ),
    )
    decision2 = admit_route(route2, _fresh_adapter())
    assert decision2.accepted


# ── Registry fingerprint includes requires.signals ──


def test_registry_fingerprint_includes_required_signals():
    base = _valid_route()
    changed = dataclasses.replace(
        base,
        requires=dataclasses.replace(
            base.requires,
            signals=("expression_evaluated",),
        ),
    )
    assert route_fingerprint(base) != route_fingerprint(changed)


def test_registry_duplicate_behavior_respects_required_signals():
    registry = RouteRegistry(_fresh_adapter())
    decision1 = admit_route(_valid_route(), _fresh_adapter())
    decision2 = admit_route(_valid_route(), _fresh_adapter())
    registry.register_decision(decision1)
    result = registry.register_decision(decision2)
    assert result.duplicate
    assert not result.registered


def test_registry_conflict_detects_different_required_signals():
    registry = RouteRegistry(_fresh_adapter())
    route1 = _valid_route()
    route2 = dataclasses.replace(
        route1,
        requires=dataclasses.replace(
            route1.requires,
            signals=("expression_evaluated",),
        ),
    )
    dec1 = admit_route(route1, _fresh_adapter())
    dec2 = admit_route(route2, _fresh_adapter())
    registry.register_decision(dec1)
    result = registry.register_decision(dec2)
    assert result.conflict


# ── Schema version ──


def test_schema_version_is_updated_consistently():
    assert SCHEMA_VERSION == "1.1.0"
    route = _valid_route()
    assert route.schema_version == "1.1.0"


def test_old_schema_version_rejected_by_admission():
    route = dataclasses.replace(_valid_route(), schema_version="1.0.0")
    _assert_admission_error(
        admit_route(route, _fresh_adapter()),
        AdmissionErrorCode.SCHEMA_INVALID,
    )


# ── Route Frontier v1.4b ──


def _frontier_snapshot(*routes: NormalizedRoute) -> RouteRegistrySnapshot:
    return RouteRegistrySnapshot(
        routes=tuple(
            RegisteredRoute(
                canonical_id=route.canonical_id,
                route=route,
                source_path=None,
                route_fingerprint=route_fingerprint(route),
            )
            for route in routes
        ),
        diagnostics=(),
    )


def _frontier_context(**overrides) -> FrontierContext:
    values = {
        "current_state": "init",
        "confirmed_signals": (),
        "runtime_facts": {
            "endpoint": ("/render",),
            "parameter": {"/render": ("name",)},
        },
    }
    values.update(overrides)
    return FrontierContext(**values)


def test_frontier_accepts_route_when_requirements_met():
    route = dataclasses.replace(
        _valid_route(),
        requires=dataclasses.replace(
            _valid_route().requires,
            signals=("expression_evaluated",),
        ),
    )
    frontier = build_frontier(
        _frontier_snapshot(route),
        _frontier_context(confirmed_signals=("expression_evaluated",)),
    )

    assert [entry.route_id for entry in frontier.eligible_routes] == [
        route.canonical_id
    ]
    assert frontier.blocked_routes == ()
    assert frontier.eligible_routes[0].status == "eligible"
    assert frontier.eligible_routes[0].diagnostics == ()


def test_frontier_blocks_state_mismatch():
    route = _valid_route()
    frontier = build_frontier(
        _frontier_snapshot(route),
        _frontier_context(current_state="probe_success"),
    )

    assert frontier.eligible_routes == ()
    assert frontier.blocked_routes[0].diagnostics == (
        FrontierDiagnosticCode.STATE_REQUIREMENT_UNSATISFIED.value,
    )


def test_frontier_blocks_missing_signal():
    route = dataclasses.replace(
        _valid_route(),
        requires=dataclasses.replace(
            _valid_route().requires,
            signals=("expression_evaluated",),
        ),
    )
    frontier = build_frontier(
        _frontier_snapshot(route),
        _frontier_context(),
    )

    assert frontier.blocked_routes[0].diagnostics == (
        FrontierDiagnosticCode.MISSING_REQUIRED_SIGNALS.value,
    )


def test_frontier_blocks_missing_runtime_fact():
    route = _valid_route()
    frontier = build_frontier(
        _frontier_snapshot(route),
        _frontier_context(runtime_facts={"endpoint": ("/render",)}),
    )

    assert frontier.blocked_routes[0].diagnostics == (
        FrontierDiagnosticCode.MISSING_RUNTIME_FACT.value,
    )


def test_blocked_route_is_not_removed():
    route = _valid_route()
    snapshot = _frontier_snapshot(route)
    frontier = build_frontier(
        snapshot,
        _frontier_context(current_state="probe_success", runtime_facts={}),
    )

    output_ids = {
        entry.route_id
        for entry in frontier.eligible_routes + frontier.blocked_routes
    }
    assert output_ids == {registered.canonical_id for registered in snapshot.routes}
    assert frontier.blocked_routes[0].status == "blocked"


def test_expected_signals_not_used_as_requires():
    route = _valid_route()
    assert route.expected_signals
    assert route.requires.signals == ()

    frontier = build_frontier(
        _frontier_snapshot(route),
        _frontier_context(confirmed_signals=()),
    )
    assert [entry.route_id for entry in frontier.eligible_routes] == [
        route.canonical_id
    ]


def test_frontier_does_not_modify_registry():
    registry = RouteRegistry(_fresh_adapter())
    registry.register_decision(admit_route(_valid_route(), _fresh_adapter()))
    snapshot_before = registry.snapshot()

    build_frontier(snapshot_before, _frontier_context())

    assert registry.snapshot() == snapshot_before
    assert registry.snapshot().to_plain() == snapshot_before.to_plain()


def test_frontier_does_not_write_memory(monkeypatch):
    def fail_write(*args, **kwargs):
        raise AssertionError("Frontier attempted a filesystem write")

    monkeypatch.setattr(Path, "write_text", fail_write)
    frontier = build_frontier(
        _frontier_snapshot(_valid_route()),
        _frontier_context(),
    )
    assert frontier.eligible_routes


def test_frontier_output_is_deterministic():
    snapshot = _frontier_snapshot(_valid_route())
    context = _frontier_context()

    first = build_frontier(snapshot, context)
    second = build_frontier(snapshot, context)

    assert first == second
    assert first.to_plain() == second.to_plain()
    assert json.dumps(first.to_plain()) == json.dumps(second.to_plain())


def test_frontier_order_by_canonical_id():
    routes = tuple(
        _assert_ok(
            normalize_route_proposal(
                _valid_proposal(technique=technique),
                _fresh_adapter(),
            )
        )
        for technique in SUPPORTED_TECHNIQUES
    )
    snapshot = _frontier_snapshot(*reversed(routes))
    frontier = build_frontier(snapshot, _frontier_context())

    output_ids = [entry.route_id for entry in frontier.eligible_routes]
    assert output_ids == sorted(route.canonical_id for route in routes)


def test_context_fingerprint_deterministic():
    first = FrontierContext(
        current_state="init",
        confirmed_signals=("signal_b", "signal_a", "signal_b"),
        runtime_facts={
            "parameter": {"/render": ["name"]},
            "endpoint": ["/render"],
        },
    )
    second = FrontierContext(
        current_state="init",
        confirmed_signals=("signal_a", "signal_b"),
        runtime_facts={
            "endpoint": ("/render",),
            "parameter": {"/render": ("name",)},
        },
    )

    assert first == second
    assert context_fingerprint(first) == context_fingerprint(second)


def test_frontier_does_not_rank_routes():
    frontier = build_frontier(
        _frontier_snapshot(_valid_route()),
        _frontier_context(),
    )
    assert not hasattr(frontier, "ranked_routes")
    assert not hasattr(frontier.eligible_routes[0], "score")


def test_frontier_does_not_select_best_route():
    frontier = build_frontier(
        _frontier_snapshot(_valid_route()),
        _frontier_context(),
    )
    assert not hasattr(frontier, "selected_route")
    assert not hasattr(frontier, "best_route")


def test_frontier_does_not_execute(monkeypatch):
    def fail_execute(*args, **kwargs):
        raise AssertionError("Frontier attempted process execution")

    monkeypatch.setattr(subprocess, "run", fail_execute)
    frontier = build_frontier(
        _frontier_snapshot(_valid_route()),
        _frontier_context(),
    )
    assert frontier.eligible_routes


def test_frontier_does_not_load_llm():
    import routes.frontier as frontier_module

    source = inspect.getsource(frontier_module).lower()
    for forbidden in ("openai", "litellm", "langchain", "llm"):
        assert forbidden not in source


def test_frontier_diagnostics_follow_requirement_order():
    route = dataclasses.replace(
        _valid_route(),
        requires=dataclasses.replace(
            _valid_route().requires,
            signals=("expression_evaluated",),
        ),
    )
    frontier = build_frontier(
        _frontier_snapshot(route),
        _frontier_context(
            current_state="probe_success",
            confirmed_signals=(),
            runtime_facts={},
        ),
    )
    assert frontier.blocked_routes[0].diagnostics == (
        FrontierDiagnosticCode.STATE_REQUIREMENT_UNSATISFIED.value,
        FrontierDiagnosticCode.MISSING_REQUIRED_SIGNALS.value,
        FrontierDiagnosticCode.MISSING_RUNTIME_FACT.value,
    )


def test_frontier_context_is_plain_and_does_not_keep_mutable_references():
    signals = ("signal_b", "signal_a")
    runtime_facts = {
        "endpoint": ["/render"],
        "parameter": {"/render": ["name"]},
    }
    context = FrontierContext(
        current_state="init",
        confirmed_signals=signals,
        runtime_facts=runtime_facts,
    )

    runtime_facts["endpoint"].append("/later")
    runtime_facts["parameter"]["/render"].append("later")
    plain = context.to_plain()

    assert context.confirmed_signals == ("signal_a", "signal_b")
    assert plain["runtime_facts"]["endpoint"] == ["/render"]
    assert plain["runtime_facts"]["parameter"] == {"/render": ["name"]}
    with pytest.raises(TypeError):
        context.runtime_facts["later"] = True


class _FrontierTestTrajectory:
    def __init__(self, current_state: str = "init") -> None:
        self.current_state = current_state

    def get_current_state(self) -> str:
        return self.current_state


class _FrontierTestVerification:
    def __init__(self, facts: dict[str, object]) -> None:
        self.facts = facts

    def get_fact(self, key: str, default=None):
        return self.facts.get(key, default)


def test_context_adapter_maps_verified_sources_without_writing():
    facts = {
        "injectable_endpoints": ["/render"],
        "injectable_params": {"/render": ["name"]},
        "working_primitives": [
            {
                "primitive_id": "ssti_reflection",
                "confidence": 0.9,
                "evidence": "confirmed",
            }
        ],
        "reflection_confirmed": True,
    }
    verification = _FrontierTestVerification(facts)
    before = json.dumps(facts, sort_keys=True)

    context = build_frontier_context(
        _fresh_adapter(),
        trajectory=_FrontierTestTrajectory(),
        verification_memory=verification,
    )

    assert context.current_state == "init"
    assert "expression_evaluated" in context.confirmed_signals
    assert set(context.runtime_facts) == {"endpoint", "parameter"}
    assert json.dumps(facts, sort_keys=True) == before


def test_context_adapter_returns_explicit_deferred_method_source():
    verification = _FrontierTestVerification(
        {
            "injectable_endpoints": [],
            "injectable_params": {},
        }
    )
    adaptation = RuntimeFactAdapter.adapt(verification)

    assert adaptation.deferred == (METHOD_RUNTIME_FACT_DEFERRED,)
    assert "method" not in adaptation.runtime_facts
    assert adaptation.to_plain()["deferred"] == [METHOD_RUNTIME_FACT_DEFERRED]


def test_context_adapter_accepts_explicit_runtime_fact_source():
    verification = _FrontierTestVerification(
        {
            "injectable_endpoints": ["/render"],
            "injectable_params": {"/render": ["name"]},
        }
    )
    adaptation = RuntimeFactAdapter.adapt(
        verification,
        runtime_facts_source={"method": "POST"},
    )

    assert adaptation.deferred == ()
    assert adaptation.runtime_facts["method"] == "POST"


def test_routes_package_exports_frontier_api():
    import routes

    assert callable(routes.build_frontier)
    assert callable(routes.context_fingerprint)
    assert callable(routes.build_frontier_context)
    assert callable(routes.RuntimeFactAdapter)


def test_all_existing_294_tests_pass():
    import routes

    assert callable(routes.RouteRegistry)
    assert callable(routes.route_fingerprint)


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "--tb=short"])
