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


def _write_template(root: Path, template_id: str, strategies: list[dict]) -> None:
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
        }
        if "canonical_strategy_id" in strategy:
            payload["canonical_strategy_id"] = strategy["canonical_strategy_id"]
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
        safe_name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", self.id())
        self.tmpdir = Path("strategy_identity_test_workspace") / safe_name
        if self.tmpdir.exists():
            shutil.rmtree(self.tmpdir)
        self.tmpdir.mkdir(parents=True, exist_ok=True)

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

        exec_out = {"executed": True, "step_results": [{"step_id": "s1", "result": {"ok": False}}]}
        _record_strategy_attempt_if_executed(
            tracker,
            "strategy*allowed",
            exec_out,
            {"repro_success": False, "error_fingerprint": "runtime_failure", "summary": "failed"},
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
        safe_name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", self.id())
        self.tmpdir = Path("strategy_identity_test_workspace") / safe_name
        if self.tmpdir.exists():
            shutil.rmtree(self.tmpdir)
        self.tmpdir.mkdir(parents=True, exist_ok=True)
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

    def _make_stub_settings(self):
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
            dry_run=True,
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

    def test_dry_run_cli_flag_sets_env_only(self):
        """--dry-run sets 5 env vars; pipeline execution is stubbed out."""
        from cli import cmd_exploit
        args = SimpleNamespace(dry_run=True, url="http://127.0.0.1:1",
                               max_iter=None, max_runs=None, challenge="generic",
                               vuln=None, confirmed=None)
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


if __name__ == "__main__":
    unittest.main()
