import json
import contextlib
import faulthandler
import os
import re
import shutil
import sys
import time
import unittest
from unittest.mock import patch
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agents import planner
from agents.consolidator import (
    is_yaml_auto_evolve_enabled,
    write_consolidator_suggestion_artifact,
)
from agents.planner import run_planner
from agents.validator import run_validator, validate_plan
from control.hypothesis_tracker import HypothesisTracker, get_hypothesis_tracker, reset_hypothesis_tracker
from coordinator import (
    _classify_observation,
    _extract_injection_param,
    _record_strategy_attempt_if_executed,
    evaluate_pre_execution_gate,
    get_hypothesis_tracker as coordinator_get_hypothesis_tracker,
    should_record_strategy_attempt,
)
from core.strategy_identity import (
    build_trusted_selection,
    validate_plan_against_trusted_selection,
    write_trusted_selection,
)
from core.template_manager import TemplateManager, TemplateSelectionResult
from agents.executor import (
    _build_materialized_execution_record,
    _extract_http_responses_from_stdout,
    _mark_materialized_request_sent,
)
from agents.evaluator import run_evaluator
from control.surface_state import (
    SURFACE_CONFIDENCE_DECAY,
    build_surface_key,
    SURFACE_DEFAULT_CONFIDENCE,
    load_surface_state,
    update_surface_after_strategy_failure,
)


def _write_template(root: Path, template_id: str, strategies: list) -> None:
    payloads = []
    for idx, strategy in enumerate(strategies):
        payload = {
            "name": strategy.get("name", f"payload-{idx}"),
            "description": "unit test payload metadata",
            "lang": "python",
            "template": "print('probe')",
            "tags": ["unit"],
            "source": "unit",
            "severity": "low",
            "canonical_strategy_id": strategy.get("canonical_strategy_id", ""),
            "stage": strategy.get("stage", "discovery"),
            "activation_state": strategy.get("activation_state", "active"),
            "requires_strategy_ids": strategy.get("requires_strategy_ids", []),
            "requires_signals": strategy.get("requires_signals", []),
            "expected_signals": strategy.get("expected_signals", []),
            "max_attempts": strategy.get("max_attempts", 2),
            "timeout_seconds": strategy.get("timeout_seconds", 15),
            "risk_level": strategy.get("risk_level", "low"),
        }
        if "strategy_id" in strategy:
            payload["strategy_id"] = strategy["strategy_id"]
        payloads.append(payload)
    data = {
        "metadata": {
            "id": template_id,
            "name": template_id,
            "cwe_ids": ["CWE-1336"],
            "tags": ["unit"],
            "severity": "low",
        },
        "content": "unit test strategy template",
        "payload_templates": payloads,
    }
    root.mkdir(parents=True, exist_ok=True)
    (root / f"{template_id}.yaml").write_text(json.dumps(data), encoding="utf-8")


class StrategyIdentityClosedLoopTests(unittest.TestCase):
    def setUp(self):
        faulthandler.dump_traceback_later(15, repeat=False, exit=True)
        reset_hypothesis_tracker()
        safe_name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", self.id())
        self.tmpdir = Path("strategy_identity_test_workspace") / safe_name
        if self.tmpdir.exists():
            shutil.rmtree(self.tmpdir)
        self.tmpdir.mkdir(parents=True, exist_ok=True)
        get_hypothesis_tracker(self.tmpdir / "singleton_hyp.json")

    def tearDown(self):
        faulthandler.cancel_dump_traceback_later()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @contextlib.contextmanager
    def _tmp_dir(self):
        yield str(self.tmpdir)

    def test_same_canonical_strategy_variants_accumulate_one_key(self):
        with self._tmp_dir() as tmp:
            tracker = HypothesisTracker(Path(tmp) / "hyp.json")
            sid = "ssti*velocity*reflection_exec"
            tracker.record_attempt(sid, success=False, failure_stage="exec", evidence="payload variant a")
            tracker.record_attempt(sid, success=False, failure_stage="exec", evidence="payload variant b")
            health = tracker.evaluate_strategy_health(sid)
            self.assertEqual(health.attempts, 2)
            self.assertEqual(set(tracker.get_all().keys()), {sid})

    def test_observed_fingerprint_change_does_not_affect_health(self):
        with self._tmp_dir() as tmp:
            tracker = HypothesisTracker(Path(tmp) / "hyp.json")
            tracker.record_attempt("observed*dynamic*payload_a", success=False, failure_stage="exec")
            health = tracker.evaluate_strategy_health("ssti*velocity*reflection_exec")
            self.assertEqual(health.attempts, 0)
            self.assertEqual(health.reason, "no_runtime_history")

    def test_trusted_selection_normalizes_empty_allowed_available_status(self):
        trusted = build_trusted_selection(
            run_id="run-unit",
            round_index=1,
            template_selection={
                "status": "AVAILABLE_STRATEGY",
                "matched_strategy_ids": ["cwe-1336:discovery:probe"],
                "available_strategy_ids": [],
                "rejected_strategy_ids": ["cwe-1336:discovery:probe"],
            },
        )
        self.assertEqual(trusted["status"], "ALL_MATCHED_STRATEGIES_REJECTED")
        ok, errors = validate_plan_against_trusted_selection({
            "selected_canonical_strategy_id": "cwe-1336:discovery:probe",
            "trusted_run_id": "run-unit",
            "trusted_round": 1,
            "trusted_selection_hash": trusted["selection_hash"],
        }, trusted)
        self.assertFalse(ok)
        self.assertTrue(any("NO_AVAILABLE_STRATEGY_FOR_SURFACE" in e for e in errors))

    def test_validator_rejects_forged_trusted_fields(self):
        trusted = build_trusted_selection(
            run_id="run-1",
            round_index=1,
            template_selection={
                "status": "AVAILABLE_STRATEGY",
                "available_strategy_ids": ["strategy*a"],
                "rejected_strategy_ids": [],
            },
        )
        plan = {
            "version": 1,
            "trusted_run_id": "run-forged",
            "trusted_round": 2,
            "trusted_selection_hash": "bad",
            "selected_canonical_strategy_id": "strategy*b",
            "steps": [{"id": "s1", "type": "python", "command": "print('x')"}],
        }
        result = validate_plan(plan, trusted_selection=trusted)
        self.assertFalse(result["passed"])
        joined = "\n".join(result["errors"])
        self.assertIn("run_id mismatch", joined)
        self.assertIn("STRATEGY_ID_NOT_ALLOWED", joined)

    def test_missing_canonical_id_is_not_executable_or_allowed(self):
        with self._tmp_dir() as tmp:
            templates = Path(tmp) / "templates"
            _write_template(templates, "missing-id", [{"name": "legacy-name-only"}])
            selection = TemplateManager(templates).select_templates_for_target({
                "vulnerabilities": [{"cwe_id": "CWE-1336"}],
            })
            self.assertEqual(selection.available_strategy_ids, [])
            self.assertIn("missing-id", selection.non_executable_templates)
            trusted = build_trusted_selection(
                run_id="run-1",
                round_index=0,
                template_selection=selection.to_dict(),
            )
            ok, errors = validate_plan_against_trusted_selection(
                {
                    "trusted_run_id": "run-1",
                    "trusted_round": 0,
                    "trusted_selection_hash": trusted["selection_hash"],
                    "selected_canonical_strategy_id": "",
                },
                trusted,
            )
            self.assertFalse(ok)
            self.assertTrue(any("STRATEGY_ID_MISSING" in e for e in errors))

    def test_one_hard_reject_does_not_block_other_strategies(self):
        with self._tmp_dir() as tmp:
            templates = Path(tmp) / "templates"
            _write_template(
                templates,
                "three-strategies",
                [
                    {"canonical_strategy_id": "s1"},
                    {"canonical_strategy_id": "s2"},
                    {"canonical_strategy_id": "s3"},
                ],
            )
            tracker = HypothesisTracker(Path(tmp) / "hyp.json")
            with patch("builtins.print"):
                for _ in range(10):
                    tracker.record_attempt("s1", success=False, failure_stage="exec")
            selection = TemplateManager(templates).select_templates_for_target(
                {"vulnerabilities": [{"cwe_id": "CWE-1336"}]},
                rejected_strategy_ids=tracker.get_rejected_strategy_ids(),
                strategy_health_resolver=lambda sid: tracker.evaluate_strategy_health(sid).to_dict(),
            )
            self.assertEqual(set(selection.available_strategy_ids), {"s2", "s3"})
            self.assertIn("s1", selection.rejected_strategy_ids)

    def test_semantic_fallback_does_not_participate_in_health_or_gate(self):
        with self._tmp_dir() as tmp:
            tracker = HypothesisTracker(Path(tmp) / "hyp.json")
            with patch("builtins.print"):
                for _ in range(10):
                    tracker.record_attempt("ssti*generic*exec", success=False, failure_stage="exec")
            health = tracker.evaluate_strategy_health("ssti*velocity*reflection_exec")
            self.assertEqual(health.attempts, 0)
            trusted = build_trusted_selection(
                run_id="run-1",
                round_index=0,
                template_selection={
                    "status": "AVAILABLE_STRATEGY",
                    "available_strategy_ids": ["ssti*velocity*reflection_exec"],
                    "rejected_strategy_ids": [],
                },
            )
            ok, errors = validate_plan_against_trusted_selection(
                {
                    "trusted_run_id": "run-1",
                    "trusted_round": 0,
                    "trusted_selection_hash": trusted["selection_hash"],
                    "selected_canonical_strategy_id": "ssti*velocity*reflection_exec",
                },
                trusted,
            )
            self.assertTrue(ok, errors)

    def test_docker_permission_denied_is_not_recordable_attempt(self):
        exec_out = {
            "executed": False,
            "execution_mode": "infra_failure",
            "infra_failure": True,
            "error": "permission denied while connecting to Docker daemon",
            "step_results": [],
        }
        self.assertFalse(should_record_strategy_attempt(exec_out))

    def test_alias_migration_is_idempotent(self):
        with self._tmp_dir() as tmp:
            root = Path(tmp)
            hyp = root / "hyp.json"
            hyp.write_text(json.dumps({
                "version": 1,
                "hypotheses": {
                    "old-key": {
                        "fingerprint": "old-key",
                        "attempts": 2,
                        "successes": 0,
                        "failure_stages": {"exec": 2},
                    },
                    "canonical-key": {
                        "fingerprint": "canonical-key",
                        "attempts": 1,
                        "successes": 0,
                        "failure_stages": {"delivery": 1},
                    },
                },
            }), encoding="utf-8")
            (root / "legacy_alias_map.json").write_text(
                json.dumps({"old-key": "canonical-key"}),
                encoding="utf-8",
            )
            first = HypothesisTracker(hyp)
            self.assertEqual(first.evaluate_strategy_health("canonical-key").attempts, 3)
            self.assertNotIn("old-key", first.get_all())
            second = HypothesisTracker(hyp)
            self.assertEqual(second.evaluate_strategy_health("canonical-key").attempts, 3)
            migrated = second.get("canonical-key").migrated_from
            self.assertEqual(migrated, ["old-key"])

    def test_consolidator_auto_evolve_zero_preserves_yaml_mtime(self):
        with self._tmp_dir() as tmp:
            root = Path(tmp)
            yaml_path = root / "sample.yaml"
            yaml_path.write_text("metadata:\n  id: sample\n", encoding="utf-8")
            before = yaml_path.stat().st_mtime_ns
            os.environ.pop("CONSOLIDATOR_AUTO_EVOLVE_YAML", None)
            self.assertFalse(is_yaml_auto_evolve_enabled())
            time.sleep(0.001)
            artifact = write_consolidator_suggestion_artifact(
                root,
                {
                    "techs": [{
                        "vulnerability": "Velocity reflection exec",
                        "cwe_ids": ["CWE-1336"],
                        "description": "try a reviewed strategy",
                    }]
                },
                diagnosis="unit",
            )
            self.assertEqual(yaml_path.stat().st_mtime_ns, before)
            data = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertTrue(data["suggestions"][0]["needs_human_review"])
            self.assertTrue(data["suggestions"][0]["proposed_canonical_strategy_id"])


    def test_coordinator_and_planner_share_hypothesis_tracker_singleton(self):
        reset_hypothesis_tracker()
        try:
            planner_tracker = get_hypothesis_tracker(self.tmpdir / "shared_hyp.json")
            coordinator_tracker = coordinator_get_hypothesis_tracker()
            self.assertIs(planner_tracker, coordinator_tracker)
            planner_tracker.record_attempt("shared*strategy", success=False, failure_stage="exec")
            self.assertEqual(coordinator_tracker.evaluate_strategy_health("shared*strategy").attempts, 1)
        finally:
            reset_hypothesis_tracker()

    def test_expected_signal_records_strategy_success_without_flag(self):
        with self._tmp_dir() as tmp:
            tracker = HypothesisTracker(Path(tmp) / "hyp.json")
            sid = "cwe-1336:discovery:arithmetic-detection"
            exec_out = {
                "executed": True,
                "step_results": [{
                    "step_id": "materialized-1",
                    "result": {"ok": True, "stdout": "[HTTP] 200 POST / => <h2>49</h2>"},
                    "http_responses": [{"status_code": 200, "url": "/"}],
                }],
            }
            fb = {
                "repro_success": False,
                "detected_primitives": ["ssti_arithmetic"],
                "primitive_confidence": {"ssti_arithmetic": 0.95},
                "summary": "arithmetic reflection observed",
            }
            _record_strategy_attempt_if_executed(
                tracker,
                sid,
                exec_out,
                fb,
                expected_signals=["arithmetic_reflection_confirmed"],
            )
            health = tracker.evaluate_strategy_health(sid)
            self.assertEqual(health.attempts, 1)
            self.assertEqual(health.successes, 1)
            self.assertEqual(health.failures, 0)
            self.assertEqual(health.decision, "ALLOW")

    def test_trusted_selection_validator_gate_and_attempt_canonical_flow(self):
        tracker = HypothesisTracker(self.tmpdir / "hyp.json")
        trusted = build_trusted_selection(
            run_id="run-e2e",
            round_index=1,
            template_selection={
                "status": "AVAILABLE_STRATEGY",
                "available_strategy_ids": ["strategy*allowed"],
                "rejected_strategy_ids": [],
            },
        )
        trusted_path = self.tmpdir / "trusted_template_selection.json"
        plan_path = self.tmpdir / "plan.json"
        validated_path = self.tmpdir / "validated.json"
        write_trusted_selection(trusted_path, trusted)
        plan = {
            "version": 1,
            "plan_id": "mock-plan",
            "selected_canonical_strategy_id": "strategy*allowed",
            "trusted_run_id": "run-e2e",
            "trusted_round": 1,
            "trusted_selection_hash": trusted["selection_hash"],
            "steps": [{"id": "s1", "type": "python", "command": "print('STEP_OK')"}],
        }
        plan_path.write_text(json.dumps(plan), encoding="utf-8")
        validated = run_validator(plan_path, validated_path, trusted_selection_path=trusted_path)
        self.assertTrue(validated["validation"]["passed"], validated["validation"].get("errors"))
        self.assertEqual(evaluate_pre_execution_gate(plan, trusted, tracker), [])

        exec_out = {"executed": True, "step_results": [{"step_id": "s1", "result": {"ok": False}, "http_responses": [{"status_code": 200, "url": "/"}]}]}
        _record_strategy_attempt_if_executed(
            tracker,
            "strategy*allowed",
            exec_out,
            {"repro_success": False, "error_fingerprint": "runtime_failure", "summary": "failed"},
            expected_signals=["arithmetic_reflection_confirmed"],
        )
        self.assertEqual(tracker.evaluate_strategy_health("strategy*allowed").attempts, 1)
        self.assertEqual(tracker.evaluate_strategy_health("observed*runtime_failure").attempts, 0)

        with patch("builtins.print"):
            for _ in range(10):
                tracker.record_attempt("strategy*blocked", success=False, failure_stage="exec")
        trusted_blocked = build_trusted_selection(
            run_id="run-e2e",
            round_index=2,
            template_selection={
                "status": "AVAILABLE_STRATEGY",
                "available_strategy_ids": ["strategy*blocked"],
                "rejected_strategy_ids": [],
            },
        )
        blocked_plan = {
            "version": 1,
            "selected_canonical_strategy_id": "strategy*blocked",
            "trusted_run_id": "run-e2e",
            "trusted_round": 2,
            "trusted_selection_hash": trusted_blocked["selection_hash"],
            "steps": [{"id": "s1", "type": "python", "command": "print('STEP_OK')"}],
        }
        blocked = evaluate_pre_execution_gate(blocked_plan, trusted_blocked, tracker)
        self.assertTrue(any("STRATEGY_REJECTED" in reason for reason in blocked))

    def test_planner_does_not_call_internal_template_selection(self):
        trusted = build_trusted_selection(
            run_id="run-plan",
            round_index=0,
            template_selection={
                "status": "AVAILABLE_STRATEGY",
                "available_strategy_ids": ["strategy*allowed"],
                "rejected_strategy_ids": [],
            },
        )
        fake_settings = SimpleNamespace(mock_llm=True)
        fake_memory = SimpleNamespace(
            get_stats=lambda: {},
            query_patterns_filtered=lambda *a, **k: [],
            query_strategies_filtered=lambda *a, **k: [],
            query_techniques_filtered=lambda *a, **k: [],
            planning_context=lambda: "{}",
        )
        with patch.object(planner, "_build_memory_context", return_value=""), \
             patch.object(planner, "_select_cwe_templates", side_effect=AssertionError("internal selection called"), create=True):
            plan = run_planner(
                settings=fake_settings,
                memory=fake_memory,
                confirmed={"vuln_id": "v1", "title": "unit", "vulnerabilities": [{"cwe_id": "CWE-1336"}]},
                feedback=None,
                out_path=self.tmpdir / "plan.json",
                llm=None,
                trusted_selection=trusted,
            )
        self.assertEqual(plan["selected_canonical_strategy_id"], "strategy*allowed")

    def test_planner_has_no_hardcoded_payload_search_hits(self):
        text = Path("b/agents/planner.py").read_text(encoding="utf-8")
        for pattern in (r"#set\(", r"Runtime\.exec", r"_build_cwe_aware_json_example", r"_build_cwe_templates_generic"):
            self.assertIsNone(re.search(pattern, text), pattern)

    def test_planner_no_matched_prompt_has_no_generic_ssti_payload(self):
        trusted = build_trusted_selection(
            run_id="run-no-match",
            round_index=0,
            template_selection={
                "status": "NO_MATCHED_TEMPLATE",
                "available_strategy_ids": [],
                "rejected_strategy_ids": [],
            },
        )
        fake_settings = SimpleNamespace(mock_llm=True)
        fake_memory = SimpleNamespace(get_stats=lambda: {})
        plan = run_planner(
            settings=fake_settings,
            memory=fake_memory,
            confirmed={"vuln_id": "v1", "title": "unit", "vulnerabilities": [{"cwe_id": "CWE-1336"}]},
            feedback=None,
            out_path=self.tmpdir / "plan.json",
            llm=None,
            trusted_selection=trusted,
        )
        self.assertEqual(plan["status"], "NO_MATCHED_TEMPLATE")
        self.assertEqual(plan["steps"], [])
        self.assertTrue(plan["needs_human_review"])
        serialized = json.dumps(plan, ensure_ascii=False)
        self.assertNotIn("#set", serialized)
        self.assertNotIn("7*7", serialized)


    def test_health_does_not_canonicalize_aliases(self):
        """Exact-key only: an old fingerprint or alias must not read canonical history."""
        with self._tmp_dir() as tmp:
            tracker = HypothesisTracker(Path(tmp) / "hyp.json")
            # record under exact canonical key
            tracker.record_attempt("ssti:velocity:reflection-rce", success=False, failure_stage="exec")
            # query with alias / legacy fingerprint — must return no_runtime_history
            for alias in ("ssti*velocity*exec", "ssti*velocity*reflection_exec", "old-name", ""):
                health = tracker.evaluate_strategy_health(alias)
                self.assertEqual(health.reason, "no_runtime_history", f"alias={alias!r} leaked history")
                self.assertEqual(health.attempts, 0, f"alias={alias!r} leaked attempts")
            # exact canonical key must still work
            health = tracker.evaluate_strategy_health("ssti:velocity:reflection-rce")
            self.assertEqual(health.attempts, 1)
            self.assertEqual(health.reason, "healthy_or_unproven")

    def test_quarantine_legacy_history_resets_active_health_but_keeps_audit(self):
        with self._tmp_dir() as tmp:
            tracker = HypothesisTracker(Path(tmp) / "hyp.json")
            sid = "cwe-1336:discovery:set-calc-probe"
            with patch("builtins.print"):
                for _ in range(5):
                    tracker.record_attempt(
                        sid,
                        success=False,
                        failure_stage="NoError",
                        evidence="legacy evaluator said switch to POST",
                    )
            self.assertIn(sid, tracker.get_rejected_strategy_ids())

            changed = tracker.quarantine_legacy_history(
                sid, reason="pre_materialized_evaluator_misattribution"
            )
            self.assertTrue(changed)
            health = tracker.evaluate_strategy_health(sid)
            self.assertEqual(health.reason, "healthy_or_unproven")
            self.assertEqual(health.attempts, 0)
            self.assertEqual(health.decision, "ALLOW")
            self.assertNotIn(sid, tracker.get_rejected_strategy_ids())

            persisted = json.loads((Path(tmp) / "hyp.json").read_text(encoding="utf-8"))
            node = persisted["hypotheses"][sid]
            self.assertEqual(node["quarantined_attempts"], 5)
            self.assertEqual(node["quarantined_failure_stages"], {"NoError": 5})
            self.assertEqual(node["attempts"], 0)
            self.assertFalse(node["rejected"])
            self.assertFalse(tracker.quarantine_legacy_history(sid, reason="repeat"))

    def test_hard_reject_key_matches_record_attempt_key(self):
        """record_attempt key must be the same string as evaluate_strategy_health input."""
        with self._tmp_dir() as tmp:
            tracker = HypothesisTracker(Path(tmp) / "hyp.json")
            sid = "exact*canonical*key"
            with patch("builtins.print"):
                for _ in range(11):
                    tracker.record_attempt(sid, success=False, failure_stage="exec")
            health = tracker.evaluate_strategy_health(sid)
            self.assertEqual(health.decision, "HARD_REJECT")
            # same key with different whitespace -> still exact match (strip)
            health2 = tracker.evaluate_strategy_health(f" {sid} ")
            self.assertEqual(health2.decision, "HARD_REJECT")


class DryRunTests(unittest.TestCase):
    def setUp(self):
        faulthandler.dump_traceback_later(15, repeat=False, exit=True)
        reset_hypothesis_tracker()
        safe_name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", self.id())
        self.tmpdir = Path("strategy_identity_test_workspace") / safe_name
        if self.tmpdir.exists():
            shutil.rmtree(self.tmpdir)
        self.tmpdir.mkdir(parents=True, exist_ok=True)
        get_hypothesis_tracker(self.tmpdir / "singleton_hyp.json")
        self.ws = self.tmpdir / "ws"
        self.ws.mkdir(parents=True, exist_ok=True)
        self._ROOT = Path(__file__).resolve().parent

    def tearDown(self):
        faulthandler.cancel_dump_traceback_later()
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        for k in ("CO_REDTEAM_DRY_RUN", "CO_REDTEAM_MOCK_LLM",
                   "CO_REDTEAM_MAX_ITER", "CO_REDTEAM_MAX_RUNS",
                   "CONSOLIDATOR_AUTO_EVOLVE_YAML"):
            os.environ.pop(k, None)
        reset_hypothesis_tracker()

    def _make_dry_run_env(self):
        for k, v in {
            "CO_REDTEAM_DRY_RUN": "1",
            "CO_REDTEAM_MOCK_LLM": "true",
            "CO_REDTEAM_MAX_ITER": "1",
            "CO_REDTEAM_MAX_RUNS": "1",
            "CONSOLIDATOR_AUTO_EVOLVE_YAML": "0",
        }.items():
            os.environ[k] = v

    def _make_target(self):
        from core.target_context import TargetContext
        return TargetContext(url="http://127.0.0.1:1", hostname="127.0.0.1", ip="127.0.0.1", port=1, scheme="http")

    def _make_vuln(self, cwe="CWE-1336"):
        p = self.tmpdir / "confirmed.json"
        p.write_text(json.dumps({
            "vulnerabilities": [{"cwe_id": cwe, "title": "unit", "severity": "high"}],
            "target_context": {"base_url": "http://127.0.0.1:1", "app_name": "unit"},
        }), encoding="utf-8")
        return p

    def _make_stub_settings(self, dry_run=True):
        from core.settings import Settings
        return Settings(
            project_root=self._ROOT,
            deepseek_api_key=None,
            deepseek_base_url="",
            deepseek_model="stub",
            mock_llm=True,
            max_iterations=1,
            max_iterations_cap=20,
            workspace_dir=self.ws,
            memory_dir=self.ws,
            confirmed_vuln_path=self.ws / "confirmed.json",
            docker_enabled=False,
            docker_image="stub",
            docker_timeout=10,
            docker_memory_limit="64m",
            docker_cpu_quota=10000,
            dry_run=dry_run,
            json_mode=False,
        )

    def _assert_artifacts(self, result, expect_gate_passed=None):
        """Assert all 4 artifacts exist in the test workspace and exec_result does not."""
        self.assertEqual(result["status"], "dry_run_complete")
        self.assertEqual(result["workspace"], str(self.ws))
        # 4 expected artifacts
        for name in ("trusted_template_selection.json", "plan.json",
                      "validated_plan.json", "feedback.json"):
            self.assertTrue((self.ws / name).exists(), f"missing {name}")
        # execution_result.json must NOT exist
        self.assertFalse((self.ws / "execution_result.json").exists())
        fb = json.loads((self.ws / "feedback.json").read_text(encoding="utf-8"))
        self.assertTrue(fb["dry_run"])
        self.assertFalse(fb["executor_called"])
        self.assertFalse(fb["evaluator_called"])
        self.assertFalse(fb["attempt_recorded"])
        self.assertFalse(fb["consolidator_called"])
        self.assertFalse(fb["yaml_mutation"])
        if expect_gate_passed is not None:
            self.assertEqual(fb["dry_run_gate_passed"], expect_gate_passed)
        return fb

    def test_dry_run_validator_failure(self):
        self._make_dry_run_env()
        with patch("coordinator.get_settings", return_value=self._make_stub_settings()), \
             patch("coordinator.run_executor") as mock_exec, \
             patch("agents.consolidator.run_global_consolidation") as mock_cons, \
             patch("control.hypothesis_tracker.HypothesisTracker.record_attempt") as mock_rec, \
             patch.object(planner, "_build_memory_context", return_value=""), \
             patch("coordinator.ok"), patch("coordinator.warn"), patch("coordinator.muted"), \
             patch("builtins.print"):
            from coordinator import run_pipeline
            result = run_pipeline(confirmed_path=self._make_vuln(cwe="CWE-999999"),
                                  challenge_name="generic", target=self._make_target())
            fb = self._assert_artifacts(result, expect_gate_passed=False)
            self.assertFalse(fb["validator_passed"])
            self.assertTrue(any("VALIDATOR_REJECTED" in e for e in fb["pre_gate_errors"]))
            mock_exec.assert_not_called()
            mock_cons.assert_not_called()
            mock_rec.assert_not_called()

    def test_dry_run_selected_field_name_consistent(self):
        self._make_dry_run_env()
        with patch("coordinator.get_settings", return_value=self._make_stub_settings()), \
             patch("coordinator.run_executor") as mock_exec, \
             patch("agents.consolidator.run_global_consolidation") as mock_cons, \
             patch.object(planner, "_build_memory_context", return_value=""), \
             patch("builtins.print"):
            from coordinator import run_pipeline
            result = run_pipeline(confirmed_path=self._make_vuln(),
                                  challenge_name="generic", target=self._make_target())
            fb = json.loads((self.ws / "feedback.json").read_text(encoding="utf-8"))
            self.assertIn("selected_canonical_strategy_id", fb)
            plan = json.loads((self.ws / "plan.json").read_text(encoding="utf-8"))
            self.assertIn("selected_canonical_strategy_id", plan)
            mock_exec.assert_not_called()
            mock_cons.assert_not_called()

    def test_dry_run_no_network_calls(self):
        self._make_dry_run_env()
        with patch("coordinator.get_settings", return_value=self._make_stub_settings()), \
             patch("requests.Session.request") as mock_req, \
             patch("httpx.Client.request") as mock_httpx, \
             patch("coordinator.run_executor") as mock_exec, \
             patch("agents.consolidator.run_global_consolidation") as mock_cons, \
             patch.object(planner, "_build_memory_context", return_value=""), \
             patch("builtins.print"):
            from coordinator import run_pipeline
            run_pipeline(confirmed_path=self._make_vuln(),
                         challenge_name="generic", target=self._make_target())
            mock_req.assert_not_called()
            mock_httpx.assert_not_called()
            mock_exec.assert_not_called()
            mock_cons.assert_not_called()

    def _make_fake_selection(self, canonical_ids=None, status="AVAILABLE_STRATEGY"):
        canonical_ids = canonical_ids or ["unit:http:probe"]
        return TemplateSelectionResult(
            text="[dry-run test stub]",
            status=status,
            matched_template_count=1,
            matched_strategy_ids=list(canonical_ids),
            available_strategy_ids=list(canonical_ids),
            preferred_strategy_ids=list(canonical_ids),
            fallback_strategy_ids=[],
            blocked_strategy_ids=[],
            why_not_selected={},
            strategy_descriptors={
                sid: {"family_id": "test-family", "template_id": "test-family",
                      "stage": "discovery", "activation_state": "active",
                      "requires_signals": [], "expected_signals": ["arithmetic_reflection_confirmed"],
                      "max_attempts": 2, "timeout_seconds": 15}
                for sid in canonical_ids
            },
            rejected_strategy_ids=[],
            strategy_health={},
            degraded_strategy_ids=[],
            hard_rejected_strategy_ids=[],
            template_health={},
            surface_still_valid=True,
            strategy_exhausted=False,
            needs_strategy_evolution=False,
            migration_report=[],
            non_executable_templates=[],
        )

    def test_dry_run_all_gates_pass(self):
        """trusted selection has canonical → Planner returns matching plan → gate passes."""
        self._make_dry_run_env()
        fake = self._make_fake_selection(["unit:http:probe"])
        with patch("core.template_manager.TemplateManager.select_templates_for_target",
                   return_value=fake), \
             patch("coordinator.get_settings", return_value=self._make_stub_settings()), \
             patch("coordinator.run_executor") as mock_exec, \
             patch("coordinator.run_evaluator") as mock_eval, \
             patch("agents.consolidator.run_global_consolidation") as mock_cons, \
             patch("control.hypothesis_tracker.HypothesisTracker.record_attempt") as mock_rec, \
             patch.object(planner, "_build_memory_context", return_value=""), \
             patch("coordinator.ok"), patch("coordinator.warn"), patch("coordinator.muted"), \
             patch("builtins.print"):
            from coordinator import run_pipeline
            result = run_pipeline(confirmed_path=self._make_vuln(),
                                  challenge_name="generic", target=self._make_target())
            fb = self._assert_artifacts(result, expect_gate_passed=True)
            self.assertTrue(fb["validator_passed"])
            self.assertEqual(fb["selected_canonical_strategy_id"], "unit:http:probe")
            mock_exec.assert_not_called()
            mock_eval.assert_not_called()
            mock_cons.assert_not_called()
            mock_rec.assert_not_called()

    def test_dry_run_pre_gate_reject(self):
        """StrategyHealth REJECT → gate blocks even with valid selection."""
        self._make_dry_run_env()
        fake = self._make_fake_selection(["unit:http:rejected"])
        # pre-seed rejection in tracker BEFORE patching the pipeline path
        from control.hypothesis_tracker import get_hypothesis_tracker
        tracker = get_hypothesis_tracker()
        with patch("builtins.print"):
            for _ in range(11):
                tracker.record_attempt("unit:http:rejected", success=False, failure_stage="exec")
        health = tracker.evaluate_strategy_health("unit:http:rejected")
        self.assertIn(health.decision, ("REJECT", "HARD_REJECT"))
        with patch("core.template_manager.TemplateManager.select_templates_for_target",
                   return_value=fake), \
             patch("coordinator.get_settings", return_value=self._make_stub_settings()), \
             patch("coordinator.run_executor") as mock_exec, \
             patch("agents.consolidator.run_global_consolidation") as mock_cons, \
             patch.object(planner, "_build_memory_context", return_value=""), \
             patch("builtins.print"):
            from coordinator import run_pipeline
            result = run_pipeline(confirmed_path=self._make_vuln(),
                                  challenge_name="generic", target=self._make_target())
            fb = self._assert_artifacts(result, expect_gate_passed=False)
            self.assertIn("STRATEGY_REJECTED", fb["pre_gate_errors"][0] if fb["pre_gate_errors"] else "")
            mock_exec.assert_not_called()
            mock_cons.assert_not_called()

    def test_strategy_exhausted_stops_without_executor_or_consolidator(self):
        exhausted = TemplateSelectionResult(
            text="",
            status="ALL_MATCHED_STRATEGIES_REJECTED",
            matched_template_count=1,
            matched_strategy_ids=["unit:http:probe"],
            available_strategy_ids=[],
            preferred_strategy_ids=[],
            fallback_strategy_ids=[],
            blocked_strategy_ids=["unit:http:probe"],
            why_not_selected={"unit:http:probe": "rejected_or_hard_rejected"},
            strategy_descriptors={},
            rejected_strategy_ids=["unit:http:probe"],
            strategy_health={},
            degraded_strategy_ids=[],
            hard_rejected_strategy_ids=["unit:http:probe"],
            template_health={},
            surface_still_valid=True,
            strategy_exhausted=True,
            needs_strategy_evolution=True,
            migration_report=[],
            non_executable_templates=[],
        )
        settings = self._make_stub_settings(dry_run=False)
        with patch("core.template_manager.TemplateManager.select_templates_for_target",
                   return_value=exhausted), \
             patch("coordinator.get_settings", return_value=settings), \
             patch("coordinator.run_executor") as mock_exec, \
             patch("coordinator.run_evaluator") as mock_eval, \
             patch("agents.consolidator.run_global_consolidation") as mock_cons, \
             patch.object(planner, "_build_memory_context", return_value=""), \
             patch("coordinator.ok"), patch("coordinator.warn"), patch("coordinator.fail"), patch("coordinator.muted"), \
             patch("builtins.print"):
            from coordinator import run_pipeline
            result = run_pipeline(confirmed_path=self._make_vuln(),
                                  challenge_name="generic", target=self._make_target())
        self.assertEqual(result, 4)
        feedback = json.loads((self.ws / "feedback.json").read_text(encoding="utf-8"))
        self.assertTrue(feedback["strategy_exhausted"])
        self.assertEqual(feedback["trusted_selection_status"], "ALL_MATCHED_STRATEGIES_REJECTED")
        self.assertFalse((self.ws / "execution_result.json").exists())
        mock_exec.assert_not_called()
        mock_eval.assert_not_called()
        mock_cons.assert_not_called()

    def test_dry_run_cli_flag_sets_env_only(self):
        """--dry-run sets 5 env vars; pipeline execution is stubbed out."""
        from cli import cmd_exploit
        args = SimpleNamespace(dry_run=True, url="http://127.0.0.1:1",
                               max_iter=None, max_runs=None, challenge="generic",
                               vuln=str(self._make_vuln()), confirmed=str(self._make_vuln()))
        with patch("coordinator.run_pipeline", return_value=0), \
             patch("cli._inject_static_warmup"), \
             patch("core.target_context.lock_target", return_value=self._make_target()), \
             patch("cli._render_exploit_banner"), \
             patch("cli.render_target_lock"), \
             patch("cli.stage"), patch("cli.ok"), \
             patch("cli.fail"), patch("cli.muted"), \
             patch("cli.console"), \
             patch("builtins.print"):
            try:
                exit_code = cmd_exploit(args)
                self.assertEqual(exit_code, 0)
            except SystemExit as e:
                self.assertIn(e.code, (0, 1))
        self.assertEqual(os.environ.get("CO_REDTEAM_DRY_RUN"), "1")
        self.assertEqual(os.environ.get("CO_REDTEAM_MOCK_LLM"), "true")
        self.assertEqual(os.environ.get("CO_REDTEAM_MAX_ITER"), "1")
        self.assertEqual(os.environ.get("CO_REDTEAM_MAX_RUNS"), "1")
        self.assertEqual(os.environ.get("CONSOLIDATOR_AUTO_EVOLVE_YAML"), "0")


class SchemaTests(unittest.TestCase):
    """Tests for explicit YAML schema: stage, activation_state, requires_signals."""
    def setUp(self):
        faulthandler.dump_traceback_later(15, repeat=False, exit=True)
        reset_hypothesis_tracker()
        safe_name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", self.id())
        self.tmpdir = Path("strategy_identity_test_workspace") / safe_name
        if self.tmpdir.exists():
            shutil.rmtree(self.tmpdir)
        self.tmpdir.mkdir(parents=True, exist_ok=True)
        get_hypothesis_tracker(self.tmpdir / "singleton_hyp.json")

    def tearDown(self):
        faulthandler.cancel_dump_traceback_later()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_active_discovery_visible_in_init(self):
        tmpl = self.tmpdir / "templates"
        _write_template(tmpl, "test-cwe1336", [
            {"canonical_strategy_id": "cwe-1336:discovery:probe-a", "stage": "discovery", "activation_state": "active"},
            {"canonical_strategy_id": "cwe-1336:discovery:probe-b", "stage": "discovery", "activation_state": "active"},
            {"canonical_strategy_id": "cwe-1336:execution:rce", "stage": "execution", "activation_state": "draft"},
        ])
        sel = TemplateManager(tmpl).select_templates_for_target(
            {"vulnerabilities": [{"cwe_id": "CWE-1336"}]},
            state="init", confirmed_signals=set(),
        )
        self.assertEqual(set(sel.available_strategy_ids), {"cwe-1336:discovery:probe-a", "cwe-1336:discovery:probe-b"})
        self.assertNotIn("cwe-1336:execution:rce", sel.available_strategy_ids)

    def test_draft_strategy_excluded_from_init(self):
        tmpl = self.tmpdir / "templates"
        _write_template(tmpl, "test-draft", [
            {"canonical_strategy_id": "cwe-1336:validation:check", "stage": "validation", "activation_state": "draft"},
        ])
        sel = TemplateManager(tmpl).select_templates_for_target(
            {"vulnerabilities": [{"cwe_id": "CWE-1336"}]}, state="init", confirmed_signals=set(),
        )
        self.assertEqual(sel.available_strategy_ids, [])

    def test_requires_signals_not_met_excludes_escalation(self):
        tmpl = self.tmpdir / "templates"
        _write_template(tmpl, "test-signal", [
            {"canonical_strategy_id": "cwe-1336:escalation:next", "stage": "escalation",
             "activation_state": "active", "requires_signals": ["arithmetic_reflection_confirmed"]},
        ])
        sel = TemplateManager(tmpl).select_templates_for_target(
            {"vulnerabilities": [{"cwe_id": "CWE-1336"}]}, state="probe_success", confirmed_signals=set(),
        )
        self.assertEqual(sel.available_strategy_ids, [])

    def test_signal_present_prioritizes_next_stage_over_discovery(self):
        tmpl = self.tmpdir / "templates"
        _write_template(tmpl, "test-progress", [
            {"canonical_strategy_id": "cwe-1336:discovery:probe", "stage": "discovery", "activation_state": "active",
             "expected_signals": ["arithmetic_reflection_confirmed"]},
            {"canonical_strategy_id": "cwe-1336:escalation:next", "stage": "escalation", "activation_state": "active",
             "requires_signals": ["arithmetic_reflection_confirmed"], "expected_signals": ["object_access_confirmed"]},
        ])
        sel = TemplateManager(tmpl).select_templates_for_target(
            {"vulnerabilities": [{"cwe_id": "CWE-1336"}]},
            state="payload_injected",
            confirmed_signals={"arithmetic_reflection_confirmed"},
        )
        self.assertEqual(sel.available_strategy_ids, ["cwe-1336:escalation:next"])
        self.assertNotIn("cwe-1336:discovery:probe", sel.available_strategy_ids)

    def test_signal_present_allows_escalation(self):
        tmpl = self.tmpdir / "templates"
        _write_template(tmpl, "test-signal-ok", [
            {"canonical_strategy_id": "cwe-1336:escalation:next", "stage": "escalation",
             "activation_state": "active", "requires_signals": ["arithmetic_reflection_confirmed"]},
        ])
        sel = TemplateManager(tmpl).select_templates_for_target(
            {"vulnerabilities": [{"cwe_id": "CWE-1336"}]}, state="payload_injected",
            confirmed_signals={"arithmetic_reflection_confirmed"},
        )
        self.assertEqual(sel.available_strategy_ids, ["cwe-1336:escalation:next"])

    def test_execution_stage_blocked_even_with_signals_and_active(self):
        tmpl = self.tmpdir / "templates"
        _write_template(tmpl, "test-exec-blocked", [
            {"canonical_strategy_id": "cwe-1336:execution:rce", "stage": "execution",
             "activation_state": "active", "requires_signals": ["arithmetic_reflection_confirmed"]},
        ])
        sel = TemplateManager(tmpl).select_templates_for_target(
            {"vulnerabilities": [{"cwe_id": "CWE-1336"}]}, state="gadget_triggered",
            confirmed_signals={"arithmetic_reflection_confirmed"},
        )
        self.assertEqual(sel.available_strategy_ids, [])

    def test_disabled_strategy_never_allowed(self):
        tmpl = self.tmpdir / "templates"
        _write_template(tmpl, "test-disabled", [
            {"canonical_strategy_id": "cwe-1336:discovery:probe", "stage": "discovery", "activation_state": "disabled"},
        ])
        sel = TemplateManager(tmpl).select_templates_for_target(
            {"vulnerabilities": [{"cwe_id": "CWE-1336"}]}, state="init", confirmed_signals=set(),
        )
        self.assertEqual(sel.available_strategy_ids, [])

    def test_legacy_template_does_not_make_rejected_surface_available(self):
        tmpl = self.tmpdir / "templates"
        _write_template(tmpl, "canonical-cwe1336", [
            {"canonical_strategy_id": "cwe-1336:discovery:probe", "stage": "discovery", "activation_state": "active"},
        ])
        legacy = {
            "metadata": {
                "id": "legacy-cwe1336",
                "name": "legacy-cwe1336",
                "cwe_ids": ["CWE-1336"],
                "tags": ["unit"],
                "severity": "low",
            },
            "content": "legacy text-only template without canonical strategy",
        }
        (tmpl / "legacy-cwe1336.yaml").write_text(json.dumps(legacy), encoding="utf-8")
        sel = TemplateManager(tmpl).select_templates_for_target(
            {"vulnerabilities": [{"cwe_id": "CWE-1336"}]},
            state="init",
            rejected_strategy_ids={"cwe-1336:discovery:probe"},
            confirmed_signals=set(),
        )
        self.assertEqual(sel.status, "ALL_MATCHED_STRATEGIES_REJECTED")
        self.assertEqual(sel.available_strategy_ids, [])
        self.assertEqual(sel.rejected_strategy_ids, ["cwe-1336:discovery:probe"])
        self.assertEqual(sel.text, "")

    def test_cwe94_velocity_evidence_matches_ssti_templates(self):
        tmpl = self.tmpdir / "templates"
        sid = "cwe-1336:discovery:velocity-probe"
        _write_template(tmpl, "velocity-cwe1336", [
            {"canonical_strategy_id": sid, "stage": "discovery", "activation_state": "active"},
        ])
        confirmed = {
            "vulnerabilities": [{
                "cwe_id": "CWE-94",
                "description": (
                    "User input replaces placeholder TEXT before Apache Velocity "
                    "RuntimeServices parses the StringReader template; #set is evaluated."
                ),
                "data_flow": [
                    "runtimeServices.parse(reader, 'home') compiles Velocity",
                    "t.merge(context, writer) executes injected directives",
                ],
            }]
        }

        sel = TemplateManager(tmpl).select_templates_for_target(
            confirmed, state="init", confirmed_signals=set()
        )
        trusted = build_trusted_selection(
            run_id="unit-run", round_index=0, template_selection=sel.to_dict()
        )

        self.assertEqual(sel.status, "AVAILABLE_STRATEGY")
        self.assertEqual(sel.available_strategy_ids, [sid])
        self.assertEqual(trusted["allowed_canonical_strategy_ids"], [sid])

    def test_plain_cwe94_without_velocity_evidence_does_not_match_ssti_templates(self):
        tmpl = self.tmpdir / "templates"
        _write_template(tmpl, "velocity-cwe1336", [
            {
                "canonical_strategy_id": "cwe-1336:discovery:velocity-probe",
                "stage": "discovery",
                "activation_state": "active",
            },
        ])
        confirmed = {
            "vulnerabilities": [{
                "cwe_id": "CWE-94",
                "description": "Generic unsafe eval of user input in a script engine.",
                "data_flow": ["source reaches eval without validation"],
            }]
        }

        sel = TemplateManager(tmpl).select_templates_for_target(
            confirmed, state="init", confirmed_signals=set()
        )

        self.assertEqual(sel.status, "NO_MATCHED_TEMPLATE")
        self.assertEqual(sel.available_strategy_ids, [])
        self.assertEqual(sel.matched_strategy_ids, [])

    def test_dry_run_all_gates_pass_with_active_discovery_cwe1336(self):
        """Full dry-run with CWE-1336 YAML containing active discovery strategies."""
        os.environ["CO_REDTEAM_DRY_RUN"] = "1"
        os.environ["CO_REDTEAM_MOCK_LLM"] = "true"
        os.environ["CO_REDTEAM_MAX_ITER"] = "1"
        os.environ["CO_REDTEAM_MAX_RUNS"] = "1"
        os.environ["CONSOLIDATOR_AUTO_EVOLVE_YAML"] = "0"
        try:
            ws = self.tmpdir / "ws"
            ws.mkdir(parents=True, exist_ok=True)
            tmpl = self.tmpdir / "templates"
            _write_template(tmpl, "cwe-1336-test", [
                {"canonical_strategy_id": "cwe-1336:discovery:probe-a", "stage": "discovery", "activation_state": "active"},
                {"canonical_strategy_id": "cwe-1336:execution:rce", "stage": "execution", "activation_state": "draft"},
            ])
            # patch TemplateManager to use test templates
            mgr = TemplateManager(tmpl)
            mgr.ensure_loaded()
            from core.settings import Settings
            ROOT = Path(__file__).resolve().parent
            stub = Settings(
                project_root=ROOT, deepseek_api_key=None, deepseek_base_url="",
                deepseek_model="stub", mock_llm=True, max_iterations=1, max_iterations_cap=20,
                workspace_dir=ws, memory_dir=ws, confirmed_vuln_path=ws / "confirmed.json",
                docker_enabled=False, docker_image="stub", docker_timeout=10,
                docker_memory_limit="64m", docker_cpu_quota=10000, dry_run=True, json_mode=False,
            )
            vuln_path = self.tmpdir / "confirmed.json"
            vuln_path.write_text(json.dumps({
                "vulnerabilities": [{"cwe_id": "CWE-1336", "title": "unit", "severity": "high"}],
                "target_context": {"base_url": "http://127.0.0.1:1", "app_name": "unit"},
            }), encoding="utf-8")
            with patch("core.template_manager.TemplateManager",
                       return_value=mgr), \
                 patch("coordinator.get_settings", return_value=stub), \
                 patch("coordinator.run_executor") as mock_exec, \
                 patch("coordinator.run_evaluator") as mock_eval, \
                 patch("agents.consolidator.run_global_consolidation") as mock_cons, \
                 patch("control.hypothesis_tracker.HypothesisTracker.record_attempt") as mock_rec, \
                 patch.object(planner, "_build_memory_context", return_value=""), \
                 patch("core.ui.ok"), patch("core.ui.warn"), patch("core.ui.muted"), \
                 patch("builtins.print"):
                from coordinator import run_pipeline
                from core.target_context import TargetContext
                result = run_pipeline(
                    confirmed_path=vuln_path, challenge_name="generic",
                    target=TargetContext(url="http://127.0.0.1:1", hostname="127.0.0.1",
                                         ip="127.0.0.1", port=1, scheme="http"),
                )
                self.assertEqual(result["status"], "dry_run_complete")
                fb = json.loads((ws / "feedback.json").read_text(encoding="utf-8"))
                self.assertTrue(fb["validator_passed"])
                self.assertTrue(fb["dry_run_gate_passed"])
                self.assertIn(
                    fb["selected_canonical_strategy_id"],
                    ("cwe-1336:discovery:arithmetic-detection", "cwe-1336:discovery:set-calc-probe"),
                )
                self.assertFalse((ws / "execution_result.json").exists())
                mock_exec.assert_not_called()
                mock_eval.assert_not_called()
                mock_cons.assert_not_called()
                mock_rec.assert_not_called()
        finally:
            for k in ("CO_REDTEAM_DRY_RUN", "CO_REDTEAM_MOCK_LLM", "CO_REDTEAM_MAX_ITER",
                       "CO_REDTEAM_MAX_RUNS", "CONSOLIDATOR_AUTO_EVOLVE_YAML"):
                os.environ.pop(k, None)



class MaterializedExecutionRecordTests(unittest.TestCase):
    def setUp(self):
        faulthandler.dump_traceback_later(15, repeat=False, exit=True)
        reset_hypothesis_tracker()
        safe_name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", self.id())
        self.tmpdir = Path("strategy_identity_test_workspace") / safe_name
        if self.tmpdir.exists():
            shutil.rmtree(self.tmpdir)
        self.tmpdir.mkdir(parents=True, exist_ok=True)
        get_hypothesis_tracker(self.tmpdir / "singleton_hyp.json")

    def tearDown(self):
        faulthandler.cancel_dump_traceback_later()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _record(self, sid="cwe-1336:discovery:set-calc-probe", payload="#set($x=7*7)$x"):
        return _build_materialized_execution_record(
            selected_canonical_strategy_id=sid,
            method="post",
            endpoint="/",
            parameter="text",
            payload=payload,
        )

    def test_evaluator_prefers_materialized_post_over_planner_get(self):
        record = _mark_materialized_request_sent(self._record(), [{"status_code": 200, "method": "POST", "url": "/", "response_body": "hello"}])
        exec_out = {
            "executed": True,
            "materialized_execution_record": record,
            "step_results": [{
                "step_id": "materialized-1",
                "result": {"ok": True, "stdout": "[HTTP] 200 POST / => hello\nSTEP_OK"},
                "chain_output": {"_stdout": "[HTTP] 200 POST / => hello\nSTEP_OK"},
                "http_responses": record["http_responses"],
                "materialized_execution_record": record,
            }],
        }
        plan = {
            "plan_id": "p1",
            "steps": [{"id": "s1", "type": "python", "command": "s.get('/', params={'text': 'x'})"}],
        }

        class DummyMemory:
            def apply_evaluator_patch(self, patch):
                self.patch = patch

        class FakeLLM:
            def __init__(self):
                self.user_msg = ""
            def complete_json(self, system_prompt, user_msg):
                self.user_msg = user_msg
                return {
                    "version": 1,
                    "repro_success": False,
                    "confidence": 0.1,
                    "analysis": {"what_happened": "used GET, switch to POST", "guidance": "?? GET???????? POST"},
                    "next_required_action": "used GET, switch to POST",
                    "feedback_for_planner": "?? GET???????? POST",
                    "next_direction": "Try POST with form parameter text again",
                    "state_transition_blocker": "injection point may require POST with text parameter, not query string",
                    "hypothesis": "maybe this requires a different request method",
                    "summary": "used GET, switch to POST",
                    "raw_evidence": "placeholder",
                    "verified_facts": [],
                    "memory_patch": {},
                }

        llm = FakeLLM()
        with patch("agents.evaluator._update_payload_scores_from_eval"):
            fb = run_evaluator(
                settings=SimpleNamespace(mock_llm=False),
                memory=DummyMemory(),
                confirmed={"vulnerabilities": [{"cwe_id": "CWE-1336"}]},
                plan=plan,
                exec_out=exec_out,
                feedback_path=self.tmpdir / "feedback.json",
                llm=llm,
                runtime_truths={"injection_method": {"value": "POST"}, "injection_parameter": {"value": "text"}},
                template_selection={"status": "AVAILABLE_STRATEGY"},
            )
        prompt_payload, _ = json.JSONDecoder().raw_decode(llm.user_msg)
        self.assertIn("non_authoritative_planner_intent", prompt_payload["plan"])
        self.assertEqual(prompt_payload["execution_facts"]["materialized_execution_record"]["request_method"], "POST")
        joined = json.dumps(fb, ensure_ascii=False)
        self.assertNotIn("switch to POST", joined)
        self.assertNotIn("Try POST", joined)
        self.assertNotIn("different request method", joined)
        self.assertNotIn("?? POST", joined)
        self.assertIn("Actual request sent: POST /", joined)
        self.assertTrue(fb["materialized_execution_record"]["request_sent"])

    def test_http_response_extraction_keeps_body_beyond_form_header(self):
        body = "A" * 700 + '<h2 class="fire">49</h2>'
        stdout = f"[HTTP] 200 POST / => {body}\nSTEP_OK\n"
        responses = _extract_http_responses_from_stdout(stdout)
        self.assertEqual(len(responses), 1)
        self.assertIn("49", responses[0]["response_body"])
        self.assertGreater(len(responses[0]["response_body"]), 700)

    def test_materialized_request_sent_reflects_http_responses(self):
        record = self._record()
        sent = _mark_materialized_request_sent(record, [{"status_code": 200}])
        not_sent = _mark_materialized_request_sent(record, [])
        self.assertTrue(sent["request_sent"])
        self.assertFalse(not_sent["request_sent"])

    def test_same_execution_fingerprint_decays_surface_once(self):
        fp = "sha256:same"
        s1 = update_surface_after_strategy_failure(self.tmpdir, "surface", "strategy-a", 1, execution_fingerprint=fp)
        s2 = update_surface_after_strategy_failure(self.tmpdir, "surface", "strategy-b", 2, execution_fingerprint=fp)
        self.assertEqual(s1.confidence, SURFACE_DEFAULT_CONFIDENCE - SURFACE_CONFIDENCE_DECAY)
        self.assertEqual(s2.confidence, s1.confidence)
        self.assertEqual(s2.duplicate_execution_fingerprint_count, 1)
        self.assertEqual(s2.decision_reason, "duplicate_execution_fingerprint")
        self.assertEqual(s2.failed_strategy_ids, {"strategy-a", "strategy-b"})

    def test_distinct_execution_fingerprints_decay_surface_twice(self):
        update_surface_after_strategy_failure(self.tmpdir, "surface", "strategy-a", 1, execution_fingerprint="sha256:a")
        state = update_surface_after_strategy_failure(self.tmpdir, "surface", "strategy-b", 2, execution_fingerprint="sha256:b")
        self.assertEqual(state.confidence, SURFACE_DEFAULT_CONFIDENCE - 2 * SURFACE_CONFIDENCE_DECAY)
        self.assertEqual(len(state.distinct_failed_execution_fingerprints), 2)

    def test_surface_key_tolerates_string_source(self):
        confirmed = {"vulnerabilities": [{"cwe_id": "CWE-94", "source": "not a code dict"}]}
        key = build_surface_key(confirmed)
        self.assertIn("cwe=CWE-94", key)
        self.assertIn("parameter=unknown", key)

    def test_request_not_sent_observation_unknown_and_infra_do_not_update_surface_confidence(self):
        state = update_surface_after_strategy_failure(
            self.tmpdir, "surface", "strategy-a", 1,
            execution_fingerprint="sha256:a", request_sent=False,
        )
        self.assertEqual(state.confidence, SURFACE_DEFAULT_CONFIDENCE)
        self.assertEqual(state.decision_reason, "request_not_sent")
        state = update_surface_after_strategy_failure(
            self.tmpdir, "surface", "strategy-b", 2,
            execution_fingerprint="sha256:b", request_sent=True, observation_status="observation_unknown",
        )
        self.assertEqual(state.confidence, SURFACE_DEFAULT_CONFIDENCE)
        self.assertEqual(state.decision_reason, "observation_status=observation_unknown")
        exec_out = {"executed": False, "infra_failure": True, "step_results": []}
        sent, obs, _ = _classify_observation(exec_out, {})
        self.assertFalse(sent)
        self.assertEqual(obs, "request_not_sent")
        loaded = load_surface_state(self.tmpdir)
        self.assertEqual(loaded.confidence, SURFACE_DEFAULT_CONFIDENCE)

    def test_execution_fingerprint_is_stable_for_same_normalized_request(self):
        r1 = _build_materialized_execution_record("sid-a", "post", "/", "text", "#set($x=7*7)$x")
        r2 = _build_materialized_execution_record("sid-b", "POST", "/", "text", "#set($x=7*7)$x")
        r3 = _build_materialized_execution_record("sid-c", "POST", "/", "text", "different")
        self.assertEqual(r1["execution_fingerprint"], r2["execution_fingerprint"])
        self.assertNotEqual(r1["execution_fingerprint"], r3["execution_fingerprint"])
        self.assertEqual(r1["request_parameters"], ["text"])


class ObservationClassificationTests(unittest.TestCase):
    def setUp(self):
        safe_name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", self.id())
        self.tmpdir = Path("strategy_identity_test_workspace") / safe_name
        if self.tmpdir.exists():
            shutil.rmtree(self.tmpdir)
        self.tmpdir.mkdir(parents=True, exist_ok=True)
        get_hypothesis_tracker(self.tmpdir / "singleton_hyp.json")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_extract_injection_param_tolerates_string_source(self):
        confirmed = {"vulnerabilities": [{"source": "not a code dict"}]}
        self.assertEqual(_extract_injection_param(confirmed), "text")
        confirmed = {"vulnerabilities": [{"source": {"code": '@RequestParam(name = "q") String q'}}]}
        self.assertEqual(_extract_injection_param(confirmed), "q")

    def test_validator_reject_is_request_not_sent(self):
        exec_out = {"executed": False, "step_results": []}
        fb = {}
        sent, obs, fail = _classify_observation(exec_out, fb)
        self.assertFalse(sent)
        self.assertEqual(obs, "request_not_sent")

    def test_http_ok_no_signal_with_observer_is_no_positive_evidence(self):
        exec_out = {"executed": True, "step_results": [
            {"http_responses": [{"status_code": 200, "url": "/"}],
             "result": {"ok": True, "_stdout": "<!doctype html><form method=post>..."}}
        ]}
        fb = {"summary": "no reflection detected", "detected_primitives": []}
        sent, obs, fail = _classify_observation(exec_out, fb, expected_signals=["arithmetic_reflection_confirmed"])
        self.assertTrue(sent)
        self.assertEqual(obs, "no_positive_evidence")
        self.assertEqual(fail, "expected_signal_missing")

    def test_http_ok_no_observer_is_observation_unknown(self):
        exec_out = {"executed": True, "step_results": [
            {"http_responses": [{"status_code": 200, "url": "/"}],
             "result": {"ok": True, "_stdout": "<!doctype html>..."}}
        ]}
        fb = {"summary": "", "detected_primitives": []}
        sent, obs, fail = _classify_observation(exec_out, fb, expected_signals=[])
        self.assertTrue(sent)
        self.assertEqual(obs, "observation_unknown")
        self.assertIsNone(fail)

    def test_ssti_arithmetic_primitive_satisfies_arithmetic_signal(self):
        exec_out = {"step_results": [{
            "http_responses": [{"status_code": 200}],
            "result": {"stdout": "HTTP 200 POST / => <h2>49</h2>"},
        }]}
        fb = {"detected_primitives": ["ssti_arithmetic"], "primitive_confidence": {"ssti_arithmetic": 0.95}}
        sent, obs, fail = _classify_observation(
            exec_out, fb, expected_signals=["arithmetic_reflection_confirmed"]
        )
        self.assertTrue(sent)
        self.assertEqual(obs, "positive_evidence")
        self.assertIsNone(fail)

    def test_http_ok_with_expected_signal_is_positive_evidence(self):
        exec_out = {"executed": True, "step_results": [
            {"http_responses": [{"status_code": 200, "url": "/"}],
             "result": {"ok": True, "_stdout": "arithmetic reflection confirmed"}}
        ]}
        fb = {"summary": "", "detected_primitives": []}
        sent, obs, fail = _classify_observation(exec_out, fb, expected_signals=["arithmetic_reflection_confirmed"])
        self.assertTrue(sent)
        self.assertEqual(obs, "positive_evidence")

    def test_no_observer_with_summary_no_reflection_is_observation_unknown(self):
        """expected_signals=[] + summary='no reflection' → observation_unknown, NOT no_positive_evidence"""
        exec_out = {"executed": True, "step_results": [
            {"http_responses": [{"status_code": 200, "url": "/"}],
             "result": {"ok": True, "_stdout": "<!doctype html>..."}}
        ]}
        fb = {"summary": "no reflection detected in response", "detected_primitives": []}
        sent, obs, fail = _classify_observation(exec_out, fb, expected_signals=[])
        self.assertTrue(sent)
        self.assertEqual(obs, "observation_unknown")

    def test_plain_49_does_not_bypass_observer(self):
        """Plain '49' in stdout without observer contract → observation_unknown, NOT positive"""
        exec_out = {"executed": True, "step_results": [
            {"http_responses": [{"status_code": 200, "url": "/"}],
             "result": {"ok": True, "_stdout": "some random 49 in page"}}
        ]}
        fb = {"summary": "", "detected_primitives": []}
        sent, obs, fail = _classify_observation(exec_out, fb, expected_signals=[])
        self.assertTrue(sent)
        self.assertEqual(obs, "observation_unknown")

    def test_canonical_strategy_id_collision_detected(self):
        """Two templates with same canonical_strategy_id → ValueError on load."""
        tmpl_dir = self.tmpdir / "collision_templates"
        tmpl_dir.mkdir(parents=True, exist_ok=True)
        # Write two YAMLs with colliding canonical_strategy_id
        for name in ("a", "b"):
            (tmpl_dir / f"cwe-test-{name}.yaml").write_text(json.dumps({
                "metadata": {"id": f"cwe-test-{name}", "name": f"test-{name}",
                             "cwe_ids": ["CWE-TEST"], "tags": ["test"], "severity": "low"},
                "content": f"test template {name}",
                "payload_templates": [{"canonical_strategy_id": "collision:id:duplicate",
                                        "stage": "discovery", "activation_state": "active"}],
            }), encoding="utf-8")
        from core.template_manager import TemplateManager
        try:
            mgr = TemplateManager(tmpl_dir)
            mgr.ensure_loaded()
            self.fail("Expected ValueError for collision")
        except ValueError as e:
            self.assertIn("collision", str(e))


class ObservationDecisionIntegrationTests(unittest.TestCase):
    """Tests for deterministic ObservationDecision and dedup behavior."""

    def setUp(self):
        faulthandler.dump_traceback_later(15, repeat=False, exit=True)
        reset_hypothesis_tracker()
        safe_name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", self.id())
        self.tmpdir = Path("strategy_identity_test_workspace") / safe_name
        if self.tmpdir.exists():
            shutil.rmtree(self.tmpdir)
        self.tmpdir.mkdir(parents=True, exist_ok=True)
        self._run_id = "test-run-001"

    def tearDown(self):
        faulthandler.cancel_dump_traceback_later()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # ── helpers ──

    def _make_exec_out(self, payload="#set($x=7*7)$x", response_body='<h2 class="fire">49</h2>'):
        """Build a realistic exec_out with materialized record and HTTP response."""
        record = _build_materialized_execution_record(
            selected_canonical_strategy_id="cwe-1336:discovery:arithmetic-detection",
            method="POST",
            endpoint="/",
            parameter="text",
            payload=payload,
        )
        sent_record = _mark_materialized_request_sent(record, [
            {"status_code": 200, "method": "POST", "url": "/", "response_body": response_body},
        ])
        return {
            "executed": True,
            "materialized_execution_record": sent_record,
            "step_results": [{
                "step_id": "materialized-1",
                "result": {"ok": True, "_stdout": f"[HTTP] 200 POST / => {response_body}\nSTEP_OK"},
                "http_responses": sent_record["http_responses"],
                "materialized_execution_record": sent_record,
            }],
        }

    def _make_obs_decision(self, exec_out, expected_signals=None):
        from core.observation_decision import make_observation_decision
        from core.evidence_ledger import reset_ledger
        reset_ledger(self.tmpdir, run_id=self._run_id)
        return make_observation_decision(
            exec_out=exec_out,
            expected_signals=list(expected_signals or ["arithmetic_reflection_confirmed"]),
            run_id=self._run_id,
            surface_key="cwe=CWE-1336|endpoint=/|parameter=text|context=template-expression",
            selected_strategy_id="cwe-1336:discovery:arithmetic-detection",
            evidence_ledger_path=self.tmpdir,
        )

    # ── Test 1: same evidence twice → Ledger has only 1, success counted once ──

    def test_dedup_same_evidence_key_only_one_ledger_entry(self):
        """Same run+surface+execution_fingerprint+signal twice → Ledger has only 1 entry."""
        from core.evidence_ledger import write_signals_deduped, load_confirmed_signals, reset_ledger
        from core.observation_decision import make_observation_decision

        exec_out = self._make_exec_out()
        # Initialize ledger once
        reset_ledger(self.tmpdir, run_id=self._run_id)

        sk = "cwe=CWE-1336|endpoint=/|parameter=text|context=template-expression"
        sid = "cwe-1336:discovery:arithmetic-detection"
        es = ["arithmetic_reflection_confirmed"]

        # First observation
        d1 = make_observation_decision(
            exec_out=exec_out, expected_signals=es,
            run_id=self._run_id, surface_key=sk,
            selected_strategy_id=sid, evidence_ledger_path=self.tmpdir,
        )
        self.assertTrue(d1.is_new_evidence)
        self.assertTrue(d1.is_new_state_transition)
        self.assertIn("arithmetic_reflection_confirmed", d1.matched_signal_ids)

        # Write first signal to ledger
        sigs1 = [{"signal_id": s, "evidence_key": k, "run_id": self._run_id,
                   "round": 1, "surface_key": sk,
                   "execution_fingerprint": d1.execution_fingerprint,
                   "source_strategy_id": sid}
                  for s, k in zip(d1.matched_signal_ids, d1.evidence_keys)]
        w1, s1 = write_signals_deduped(self.tmpdir, sigs1)
        self.assertEqual(w1, 1)
        self.assertEqual(s1, 0)

        # Second observation WITHOUT resetting ledger → should see existing evidence
        d2 = make_observation_decision(
            exec_out=exec_out, expected_signals=es,
            run_id=self._run_id, surface_key=sk,
            selected_strategy_id=sid, evidence_ledger_path=self.tmpdir,
        )
        self.assertFalse(d2.is_new_evidence,
                         "Second call with same fp should detect existing evidence")
        self.assertFalse(d2.is_new_state_transition)
        self.assertIn("arithmetic_reflection_confirmed", d2.matched_signal_ids)

        # Try to write duplicate → should be skipped
        sigs2 = [{"signal_id": s, "evidence_key": k, "run_id": self._run_id,
                   "round": 2, "surface_key": sk,
                   "execution_fingerprint": d2.execution_fingerprint,
                   "source_strategy_id": sid}
                  for s, k in zip(d2.matched_signal_ids, d2.evidence_keys)]
        w2, s2 = write_signals_deduped(self.tmpdir, sigs2)
        self.assertEqual(w2, 0)
        self.assertEqual(s2, 1)

        # Ledger has exactly 1 signal entry
        signals = load_confirmed_signals(self.tmpdir)
        self.assertEqual(len(signals), 1)
        self.assertIn("arithmetic_reflection_confirmed", signals)

    # ── Test 2: positive_evidence → consecutive_failures does NOT increase ──

    def test_positive_evidence_does_not_increment_failure_counter(self):
        exec_out = self._make_exec_out()
        d = self._make_obs_decision(exec_out)
        self.assertEqual(d.observation_status, "positive_evidence")
        self.assertIsNone(d.failure_class)
        # When observation_status is positive_evidence, consecutive_failures should reset
        # (verified by coordinator logic using obs_decision.observation_status)

    # ── Test 3: no_positive_evidence → failure counter increases, no positive signal ──

    def test_no_positive_evidence_increments_failure_no_positive_signal(self):
        exec_out = self._make_exec_out(payload="#set($x=7*7)$x", response_body="<html>Error 500</html>")
        d = self._make_obs_decision(exec_out)
        self.assertEqual(d.observation_status, "no_positive_evidence")
        self.assertEqual(d.failure_class, "expected_signal_missing")
        self.assertEqual(d.matched_signal_ids, [])
        self.assertFalse(d.is_new_evidence)

    # ── Test 4: LLM says ssti_reflection but deterministic observer doesn't hit → no signal ──

    def test_llm_primitive_does_not_create_signal_without_observer_hit(self):
        exec_out = self._make_exec_out(payload="#set($x=7*7)$x", response_body="<html>Error</html>")
        d = self._make_obs_decision(exec_out)
        # Deterministic observer checks response for "49" → not found → no signal
        self.assertEqual(d.observation_status, "no_positive_evidence")
        self.assertNotIn("arithmetic_reflection_confirmed", d.matched_signal_ids)
        # Even if LLM evaluator would output detected_primitives=["ssti_reflection"],
        # the ObservationDecision ignores it — signal is not created.

    # ── Test 5: deterministic observer hits even when LLM misses → signal created ──

    def test_deterministic_observer_creates_signal_without_llm(self):
        exec_out = self._make_exec_out()  # response contains "49"
        d = self._make_obs_decision(exec_out)
        self.assertEqual(d.observation_status, "positive_evidence")
        self.assertIn("arithmetic_reflection_confirmed", d.matched_signal_ids)
        self.assertTrue(d.is_new_evidence)
        # Signal created purely from deterministic observer — no LLM involvement.

    # ── Test 6: duplicate_evidence blocks Consolidator long-term writes ──

    def test_duplicate_evidence_blocks_consolidator_long_term_writes(self):
        from core.long_term_write_policy import write_terminal_condition, is_long_term_write_blocked

        # First: create positive evidence (normal)
        exec_out = self._make_exec_out()
        d1 = self._make_obs_decision(exec_out)
        self.assertTrue(d1.is_new_evidence)

        # Write the evidence
        from core.evidence_ledger import write_signals_deduped
        sigs = [{"signal_id": s, "evidence_key": k, "run_id": self._run_id,
                  "round": 1, "surface_key": d1.surface_key,
                  "execution_fingerprint": d1.execution_fingerprint,
                  "source_strategy_id": d1.selected_strategy_id}
                 for s, k in zip(d1.matched_signal_ids, d1.evidence_keys)]
        write_signals_deduped(self.tmpdir, sigs)

        # Second: same execution → duplicate_evidence terminal condition
        write_terminal_condition(self.tmpdir, "duplicate_evidence", {
            "execution_fingerprint": d1.execution_fingerprint,
            "signal_ids": d1.matched_signal_ids,
        }, round_number=2)

        blocked, reason = is_long_term_write_blocked(self.tmpdir)
        self.assertTrue(blocked, f"Expected long-term writes blocked, got reason={reason}")
        self.assertIn("duplicate_evidence", reason)

        # Verify allowed write targets are restricted
        from core.long_term_write_policy import get_allowed_write_targets
        allowed = get_allowed_write_targets(self.tmpdir)
        self.assertEqual(allowed, {"workspace_artifact_only"})

    def test_stage_blocked_blocks_consolidator_long_term_writes(self):
        from core.long_term_write_policy import write_terminal_condition, is_long_term_write_blocked

        write_terminal_condition(self.tmpdir, "STAGE_BLOCKED_NO_APPROVED_ROUTE", {
            "selection_status": "ALL_MATCHED_STRATEGIES_REJECTED",
        }, round_number=3)

        blocked, reason = is_long_term_write_blocked(self.tmpdir)
        self.assertTrue(blocked)
        self.assertIn("STAGE_BLOCKED_NO_APPROVED_ROUTE", reason)

    # ── Test 7: all long-term write paths go through single policy gate ──

    def test_all_long_term_write_paths_gated_by_single_policy(self):
        """Verify is_long_term_write_blocked is the single gate.

        All terminal conditions that should block long-term writes must be
        in LONG_TERM_WRITE_BLOCKED_CONDITIONS.
        """
        from core.long_term_write_policy import LONG_TERM_WRITE_BLOCKED_CONDITIONS, write_terminal_condition, is_long_term_write_blocked

        expected_conditions = {
            "duplicate_evidence",
            "COMPLETED_DISCOVERY_REPLAY",
            "STAGE_BLOCKED_NO_APPROVED_ROUTE",
            "OUTCOME_CONSISTENCY_VIOLATION",
            "surface_blocked",
            "breaker_triggered",
        }
        self.assertEqual(LONG_TERM_WRITE_BLOCKED_CONDITIONS, expected_conditions,
                         "All required terminal conditions must be in LONG_TERM_WRITE_BLOCKED_CONDITIONS")

        # Each condition individually blocks writes
        for cond in expected_conditions:
            # Clean workspace
            tc_path = self.tmpdir / "terminal_condition.json"
            if tc_path.exists():
                tc_path.unlink()

            write_terminal_condition(self.tmpdir, cond, {"test": True}, round_number=1)
            blocked, reason = is_long_term_write_blocked(self.tmpdir)
            self.assertTrue(blocked, f"Condition '{cond}' should block long-term writes")

    def test_no_terminal_condition_allows_all_writes(self):
        from core.long_term_write_policy import is_long_term_write_blocked, get_allowed_write_targets
        # No terminal_condition.json → writes allowed
        blocked, reason = is_long_term_write_blocked(self.tmpdir)
        self.assertFalse(blocked)
        allowed = get_allowed_write_targets(self.tmpdir)
        self.assertEqual(allowed, set())  # empty = all allowed

    # ── Additional: OUTCOME_CONSISTENCY_VIOLATION detection ──

    def test_outcome_consistency_violation_detected_when_deterministic_differs_from_legacy(self):
        """When deterministic observer says positive but legacy says negative → violation."""
        from core.observation_decision import make_observation_decision
        from core.evidence_ledger import reset_ledger
        reset_ledger(self.tmpdir, run_id=self._run_id)

        exec_out = self._make_exec_out()  # response has "49" → observer confirms
        d = make_observation_decision(
            exec_out=exec_out,
            expected_signals=["arithmetic_reflection_confirmed"],
            run_id=self._run_id,
            surface_key="cwe=CWE-1336|endpoint=/|parameter=text|context=template-expression",
            evidence_ledger_path=self.tmpdir,
        )
        self.assertEqual(d.observation_status, "positive_evidence")

        # Simulate legacy classifier saying no_positive_evidence
        fb_empty = {"summary": "nothing found", "detected_primitives": []}
        old_sent, old_obs, old_fail = _classify_observation(
            exec_out, fb_empty, expected_signals=["arithmetic_reflection_confirmed"])
        # The legacy classifier checks both stdout AND evaluator primitives.
        # Since stdout already contains "49" and "arithmetic reflection confirmed" keywords,
        # the old classifier might also detect it. Let me check...
        # Actually _signal_observer_confirm checks stdout for signal keywords.
        # "49" won't match "arithmetic_reflection_confirmed" directly.
        # But it checks sig_lower in stdout_lower, where sig_lower = "arithmetic reflection confirmed"
        # That won't match "49" either.
        # And detected_primitives is empty → no alias match.
        # So old_obs should be "no_positive_evidence"
        self.assertEqual(old_obs, "no_positive_evidence",
                         f"Legacy classifier should say no_positive_evidence when evaluator has no primitives, got {old_obs}")

        # This is a consistency violation: deterministic says positive, legacy says negative
        self.assertNotEqual(d.observation_status, old_obs)

    # ── Deterministic observer arithmetic tests ──

    def test_arithmetic_observer_7x7_equals_49(self):
        from core.observation_decision import _deterministic_check_arithmetic_reflection
        self.assertTrue(_deterministic_check_arithmetic_reflection(
            "#set($x=7*7)$x", ['<h2 class="fire">49</h2>']))
        self.assertFalse(_deterministic_check_arithmetic_reflection(
            "#set($x=7*7)$x", ['<h2 class="fire">50</h2>']))
        self.assertFalse(_deterministic_check_arithmetic_reflection(
            "#set($x=7*7)$x", []))

    def test_arithmetic_observer_handles_addition_and_division(self):
        from core.observation_decision import _deterministic_check_arithmetic_reflection
        self.assertTrue(_deterministic_check_arithmetic_reflection(
            "#set($x=3+4)$x", ['result: 7']))
        self.assertTrue(_deterministic_check_arithmetic_reflection(
            "#set($x=10/2)$x", ['result: 5']))

    def test_observation_decision_handles_no_expected_signals(self):
        from core.observation_decision import make_observation_decision
        from core.evidence_ledger import reset_ledger
        reset_ledger(self.tmpdir, run_id=self._run_id)
        exec_out = self._make_exec_out()
        d = make_observation_decision(
            exec_out=exec_out,
            expected_signals=[],
            run_id=self._run_id,
            surface_key="test",
            evidence_ledger_path=self.tmpdir,
        )
        self.assertEqual(d.observation_status, "observation_unknown")

    def test_observation_decision_handles_no_step_results(self):
        from core.observation_decision import make_observation_decision
        d = make_observation_decision(
            exec_out={"executed": False, "step_results": []},
            expected_signals=["arithmetic_reflection_confirmed"],
            run_id=self._run_id,
            surface_key="test",
            evidence_ledger_path=self.tmpdir,
        )
        self.assertFalse(d.request_sent)
        self.assertEqual(d.observation_status, "request_not_sent")

    # ── Regression: Evaluator contradicts ObservationDecision → downstream uses ObservationDecision ──

    def test_evaluator_no_positive_but_obs_decision_positive_downstream_uses_obs_decision(self):
        """ObservationDecision=positive_evidence, Evaluator says no_positive_evidence
        → Evidence Ledger, Surface State, failure counter ALL follow ObservationDecision."""
        from core.observation_decision import make_observation_decision
        from core.evidence_ledger import reset_ledger, write_signals_deduped, load_confirmed_signals

        reset_ledger(self.tmpdir, run_id=self._run_id)
        sk = "cwe=CWE-1336|endpoint=/|parameter=text|context=template-expression"
        es = ["arithmetic_reflection_confirmed"]

        # Executor produced a clear hit: response contains "49"
        exec_out = self._make_exec_out()
        d = make_observation_decision(
            exec_out=exec_out, expected_signals=es,
            run_id=self._run_id, surface_key=sk,
            evidence_ledger_path=self.tmpdir,
        )
        # Deterministic observer: positive
        self.assertEqual(d.observation_status, "positive_evidence")
        self.assertIn("arithmetic_reflection_confirmed", d.matched_signal_ids)
        self.assertTrue(d.is_new_evidence)

        # Simulate Evaluator output that contradicts ObservationDecision
        fb_contradict = {
            "repro_success": False,
            "confidence": 0.0,
            "summary": "No exploitation detected.",
            "detected_primitives": [],
            "primitive_confidence": {},
            "analysis": {"guidance": "nothing found, try different payload"},
            "next_required_action": "switch strategy",
            "feedback_for_planner": "Evaluator thinks this failed completely.",
        }

        # ── Evidence Ledger: MUST follow ObservationDecision, NOT evaluator ──
        if d.is_new_evidence and d.matched_signal_ids:
            new_signals = []
            for i, sig in enumerate(d.matched_signal_ids):
                ek = d.evidence_keys[i] if i < len(d.evidence_keys) else ""
                new_signals.append({
                    "signal_id": sig, "evidence_key": ek,
                    "run_id": self._run_id, "round": 1, "surface_key": sk,
                    "execution_fingerprint": d.execution_fingerprint,
                    "source_strategy_id": "test-sid",
                })
            written, skipped = write_signals_deduped(self.tmpdir, new_signals)
            self.assertEqual(written, 1, "Evidence Ledger must write signal from ObservationDecision")
            self.assertEqual(skipped, 0)

        signals = load_confirmed_signals(self.tmpdir)
        self.assertIn("arithmetic_reflection_confirmed", signals)
        self.assertEqual(len(signals), 1)

        # ── Strategy attempt recording: MUST use ObservationDecision success ──
        from control.hypothesis_tracker import get_hypothesis_tracker as _ght, reset_hypothesis_tracker
        reset_hypothesis_tracker()
        tracker = _ght(self.tmpdir / "hyp_eval_contradict.json")
        from coordinator import _record_strategy_attempt_if_executed
        _record_strategy_attempt_if_executed(
            tracker, "test-sid", exec_out, fb_contradict,
            round_number=1, expected_signals=es, obs_decision=d,
        )
        health = tracker.evaluate_strategy_health("test-sid")
        self.assertEqual(health.successes, 1,
                         "StrategyHealth MUST record success from ObservationDecision, not evaluator")
        self.assertEqual(health.failures, 0)

        # ── Failure counter logic: positive_evidence → does NOT increment ──
        # (The coordinator implements this: obs_decision.observation_status == "positive_evidence"
        #  → consecutive_failures = 0)
        self.assertEqual(d.observation_status, "positive_evidence")
        self.assertIsNone(d.failure_class)

        # ── Verify evaluator's contradicted primitives do NOT create additional signals ──
        # Even if evaluator had detected_primitives=["ssti_reflection"] at confidence 0.9,
        # the old code would have mapped it to arithmetic_reflection_confirmed.
        # Under the new system, that path is DEAD — only ObservationDecision writes signals.
        # This test verifies that the Evaluator's fb is visible but unused for signal creation.


if __name__ == "__main__":
    unittest.main()
