import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agents import planner
from agents.consolidator import (
    is_yaml_auto_evolve_enabled,
    write_consolidator_suggestion_artifact,
)
from agents.validator import validate_plan
from control.hypothesis_tracker import HypothesisTracker
from coordinator import should_record_strategy_attempt
from core.strategy_identity import (
    build_trusted_selection,
    validate_plan_against_trusted_selection,
)
from core.template_manager import TemplateManager


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
    def test_same_canonical_strategy_variants_accumulate_one_key(self):
        with tempfile.TemporaryDirectory(dir=r"C:\tmp") as tmp:
            tracker = HypothesisTracker(Path(tmp) / "hyp.json")
            sid = "ssti*velocity*reflection_exec"
            tracker.record_attempt(sid, success=False, failure_stage="exec", evidence="payload variant a")
            tracker.record_attempt(sid, success=False, failure_stage="exec", evidence="payload variant b")
            health = tracker.evaluate_strategy_health(sid)
            self.assertEqual(health.attempts, 2)
            self.assertEqual(set(tracker.get_all().keys()), {sid})

    def test_observed_fingerprint_change_does_not_affect_health(self):
        with tempfile.TemporaryDirectory(dir=r"C:\tmp") as tmp:
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
        with tempfile.TemporaryDirectory(dir=r"C:\tmp") as tmp:
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
        with tempfile.TemporaryDirectory(dir=r"C:\tmp") as tmp:
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
        with tempfile.TemporaryDirectory(dir=r"C:\tmp") as tmp:
            tracker = HypothesisTracker(Path(tmp) / "hyp.json")
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
        with tempfile.TemporaryDirectory(dir=r"C:\tmp") as tmp:
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
        with tempfile.TemporaryDirectory(dir=r"C:\tmp") as tmp:
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

    def test_planner_no_matched_prompt_has_no_generic_ssti_payload(self):
        class EmptyManager:
            def select_templates_for_target(self, *args, **kwargs):
                from core.template_manager import TemplateSelectionResult
                return TemplateSelectionResult(
                    text="",
                    status="NO_MATCHED_TEMPLATE",
                    matched_template_count=0,
                    matched_strategy_ids=[],
                    available_strategy_ids=[],
                    rejected_strategy_ids=[],
                )

        original = planner.TemplateManager
        planner.TemplateManager = EmptyManager
        try:
            selection = planner._select_cwe_templates(
                [{"cwe_id": "CWE-1336"}],
                {"vulnerabilities": [{"cwe_id": "CWE-1336"}]},
            )
        finally:
            planner.TemplateManager = original
        self.assertIn("Generic CWE bootstrap execution is disabled", selection.text)
        self.assertNotIn("#set", selection.text)
        self.assertNotIn("7*7", selection.text)


if __name__ == "__main__":
    unittest.main()
