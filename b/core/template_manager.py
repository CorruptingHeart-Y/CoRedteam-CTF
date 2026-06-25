from __future__ import annotations

import json
import os
import re
import yaml
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal
try:
    from control.hypothesis_tracker import canonicalize_strategy_id
except Exception:  # avoid import cycles in isolated tooling
    def canonicalize_strategy_id(strategy_id: str = "", **_: Any) -> str:
        return strategy_id


TemplateSelectionStatus = Literal[
    "AVAILABLE_STRATEGY",
    "NO_MATCHED_TEMPLATE",
    "ALL_MATCHED_STRATEGIES_REJECTED",
]


@dataclass
class TemplateSelectionResult:
    text: str
    status: TemplateSelectionStatus
    matched_template_count: int
    matched_strategy_ids: list[str]
    available_strategy_ids: list[str]
    rejected_strategy_ids: list[str]
    strategy_health: dict[str, dict[str, Any]] = field(default_factory=dict)
    degraded_strategy_ids: list[str] = field(default_factory=list)
    hard_rejected_strategy_ids: list[str] = field(default_factory=list)
    template_health: dict[str, dict[str, Any]] = field(default_factory=dict)
    surface_still_valid: bool = True
    strategy_exhausted: bool = False
    needs_strategy_evolution: bool = False
    migration_report: list[dict[str, Any]] = field(default_factory=list)
    non_executable_templates: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TemplateHealth:
    template_id: str
    decision: str = "ALLOW"
    scope: str = "template_only"
    reason: str = ""
    strategy_ids: list[str] = field(default_factory=list)
    hard_rejected_strategy_ids: list[str] = field(default_factory=list)
    degraded_strategy_ids: list[str] = field(default_factory=list)
    surface_still_valid: bool = True

class AttackTemplate:
    def __init__(self, metadata: dict[str, Any], content: str):
        self.metadata = metadata
        self.content = content
        self.id = metadata.get("id", "")
        self.name = metadata.get("name", "")
        self.cwe_ids = metadata.get("cwe_ids", [])
        self.target_type = metadata.get("target_type", "generic")
        self.severity = metadata.get("severity", "medium")
        self.tags = metadata.get("tags", [])
        self.author = metadata.get("author", "unknown")
        self.version = metadata.get("version", "1.0.0")
        # Only canonical_strategy_id is executable. strategy_id is accepted as
        # legacy schema; name/metadata.id are migration hints, never identities.
        self.strategy_ids: list[str] = []
        self.migration_report: list[dict[str, Any]] = []
        self.auto_executable = True
        _pts = metadata.get("payload_templates")
        if _pts is not None:
            for idx, pt in enumerate(_pts):
                sid = pt.get("canonical_strategy_id") or pt.get("strategy_id")
                if sid:
                    self.strategy_ids.append(str(sid))
                    if not pt.get("canonical_strategy_id"):
                        self.migration_report.append({
                            "template_id": self.id,
                            "payload_index": idx,
                            "legacy_strategy_id": str(sid),
                            "needs_canonical_strategy_id": True,
                            "auto_executable": True,
                        })
                else:
                    self.migration_report.append({
                        "template_id": self.id,
                        "payload_index": idx,
                        "payload_name": pt.get("name", ""),
                        "metadata_id": self.id,
                        "needs_canonical_strategy_id": True,
                        "auto_executable": False,
                    })
            self.auto_executable = bool(self.strategy_ids)
        else:
            _legacy_sid = metadata.get("strategy_id")
            if _legacy_sid:
                self.strategy_ids.append(str(_legacy_sid))
                self.migration_report.append({
                    "template_id": self.id,
                    "legacy_strategy_id": str(_legacy_sid),
                    "needs_canonical_strategy_id": True,
                    "auto_executable": True,
                })
            else:
                self.auto_executable = False
                self.migration_report.append({
                    "template_id": self.id,
                    "metadata_id": self.id,
                    "needs_canonical_strategy_id": True,
                    "auto_executable": False,
                })

    def matches(self, cwe_id: str = "", **kwargs) -> bool:
        if cwe_id and cwe_id not in self.cwe_ids:
            return False
        tag = kwargs.get("tag", "")
        if tag and tag not in self.tags:
            return False
        severity = kwargs.get("severity", "")
        if severity and self.severity != severity:
            return False
        return True

    def to_prompt_text(self) -> str:
        parts = [f"【{self.name}】"]
        if self.cwe_ids:
            parts.append(f"CWE: {', '.join(self.cwe_ids)}")
        if self.tags:
            parts.append(f"Tags: {', '.join(self.tags)}")
        
        return "\n".join(parts) + "\n" + self.content


class TemplateManager:
    def __init__(self, templates_dir: Path | None = None):
        if templates_dir is None:
            templates_dir = Path(__file__).parent.parent / "templates"
        self.templates_dir = templates_dir
        self.templates: dict[str, AttackTemplate] = {}
        self._loaded = False

    def ensure_loaded(self) -> None:
        if not self._loaded:
            self.load_all()

    def load_all(self) -> int:
        self.templates.clear()
        if not self.templates_dir.exists():
            self.templates_dir.mkdir(parents=True, exist_ok=True)
            return 0
        
        count = 0
        for yaml_file in self.templates_dir.rglob("*.yaml"):
            try:
                template = self._load_yaml_file(yaml_file)
                if template:
                    self.templates[template.id] = template
                    count += 1
            except Exception as e:
                print(f"[template_manager] Failed to load {yaml_file}: {e}")
        
        for json_file in self.templates_dir.rglob("*.json"):
            if json_file.name.startswith("_"):
                continue
            try:
                template = self._load_json_file(json_file)
                if template:
                    self.templates[template.id] = template
                    count += 1
            except Exception as e:
                print(f"[template_manager] Failed to load {json_file}: {e}")
        
        self._loaded = True
        print(f"[template_manager] Loaded {count} templates from {self.templates_dir}")
        return count

    def _load_yaml_file(self, path: Path) -> AttackTemplate | None:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            return None
        metadata = data.get("metadata", {})
        content = data.get("content", "")
        if not metadata.get("id") or not content:
            return None
        return AttackTemplate(metadata, content)

    def _load_json_file(self, path: Path) -> AttackTemplate | None:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return None
        metadata = data.get("metadata", {})
        content = data.get("content", "")
        if not metadata.get("id") or not content:
            return None
        return AttackTemplate(metadata, content)

    def get_template(self, template_id: str) -> AttackTemplate | None:
        self.ensure_loaded()
        return self.templates.get(template_id)

    def query_templates(
        self,
        cwe_id: str = "",
        tag: str = "",
        severity: str = "",
    ) -> list[AttackTemplate]:
        self.ensure_loaded()
        results = []
        for template in self.templates.values():
            if not template.matches(cwe_id=cwe_id, tag=tag, severity=severity):
                continue
            results.append(template)
        results.sort(key=lambda t: t.severity)
        return results

    def get_templates_for_target(
        self,
        confirmed_vuln: dict[str, Any],
        state: str = "",
        rejected_strategy_ids: set[str] | None = None,
    ) -> str:
        """Backward-compatible string API. New callers should use select_templates_for_target()."""
        return self.select_templates_for_target(
            confirmed_vuln,
            state=state,
            rejected_strategy_ids=rejected_strategy_ids,
        ).text

    def select_templates_for_target(
        self,
        confirmed_vuln: dict[str, Any],
        state: str = "",
        rejected_strategy_ids: set[str] | None = None,
        strategy_health_resolver: Callable[[str], dict[str, Any]] | None = None,
    ) -> TemplateSelectionResult:
        """Return matched template text plus structured strategy availability status."""
        self.ensure_loaded()
        rejected_strategy_ids = rejected_strategy_ids or set()
        vulns = confirmed_vuln.get("vulnerabilities", [])
        cwe_set = {v.get("cwe_id", "") for v in vulns}

        matched: list[AttackTemplate] = []
        for cwe_id in cwe_set:
            matched.extend(self.query_templates(cwe_id=cwe_id))

        if not matched:
            text_parts: list[str] = []
            for v in vulns:
                for key in ("title", "description", "evidence", "source", "sink", "attack_chain"):
                    val = v.get(key)
                    if isinstance(val, str):
                        text_parts.append(val.lower())
                    elif isinstance(val, dict):
                        text_parts.append(str(val.get("code_snippet") or "").lower())
            vuln_text = " ".join(text_parts)
            for t in self.templates.values():
                for tag in t.tags:
                    normalized = tag.lower().replace("_", " ").replace("-", " ")
                    if normalized in vuln_text or tag.lower() in vuln_text:
                        matched.append(t)
                        break

        _LATE_STAGE_KEYWORDS = [
            "flag", "cat /", "head /", "tail /", "strings /", "base64 /",
            "type c:", "type d:", "type e:",
            "fileinputstream", "open('/flag", 'open("/flag', "read('/flag", 'read("/flag',
            "readfilesync", "fs.readfile", "file_get_contents", "load_file", "pg_read_file",
            "file://", "php://filter", "../flag", "..\\flag", "passwd", "shadow",
            "exfiltrat", "file_read", "file-read",
        ]
        state_order = {"init": 0, "probe_success": 1, "payload_injected": 2,
                       "gadget_triggered": 3, "oob_received": 4}
        current_idx = state_order.get(state, 0)
        in_late_stage = current_idx >= 3

        stage_filtered: list[AttackTemplate] = []
        for t in matched:
            text = (t.name + " " + " ".join(t.tags) + " " + t.content).lower()
            for pt in t.metadata.get("payload_templates", []):
                text += " " + (pt.get("name") or "").lower()
                text += " " + (pt.get("description") or "").lower()
                text += " " + (pt.get("template") or "").lower()
            is_late = any(kw in text for kw in _LATE_STAGE_KEYWORDS)
            if in_late_stage:
                if is_late:
                    stage_filtered.append(t)
            elif not is_late:
                stage_filtered.append(t)

        print(
            f"[template_manager] stage filter: {len(matched)} -> {len(stage_filtered)} "
            f"templates (state={state or 'init'}, late_stage={in_late_stage})"
        )

        seen: set[str] = set()
        unique: list[AttackTemplate] = []
        for t in stage_filtered:
            if t.id not in seen:
                seen.add(t.id)
                unique.append(t)

        migration_report = [item for t in unique for item in getattr(t, "migration_report", [])]
        non_executable_templates = [t.id for t in unique if not getattr(t, "auto_executable", True)]
        matched_strategy_ids = sorted({sid for t in unique for sid in t.strategy_ids if sid})
        strategy_health: dict[str, dict[str, Any]] = {}
        if strategy_health_resolver is not None:
            for sid in matched_strategy_ids:
                try:
                    strategy_health[sid] = dict(strategy_health_resolver(sid) or {})
                except Exception as exc:
                    strategy_health[sid] = {
                        "strategy_id": sid,
                        "canonical_strategy_id": canonicalize_strategy_id(sid),
                        "decision": "ALLOW",
                        "reason": f"health_resolver_error:{exc}",
                        "scope": "strategy_only",
                        "surface_still_valid": True,
                    }

        hard_rejected_strategy_ids = [
            sid for sid, h in strategy_health.items()
            if h.get("decision") in ("REJECT", "HARD_REJECT")
        ]
        degraded_strategy_ids = [
            sid for sid, h in strategy_health.items()
            if h.get("decision") == "DEGRADE"
        ]
        effective_rejected_strategy_ids = set(rejected_strategy_ids) | set(hard_rejected_strategy_ids)

        def _is_rejected_strategy(sid: str) -> bool:
            return sid in effective_rejected_strategy_ids

        available_strategy_ids = [sid for sid in matched_strategy_ids if not _is_rejected_strategy(sid)]
        rejected_for_surface = [sid for sid in matched_strategy_ids if _is_rejected_strategy(sid)]

        template_health: dict[str, dict[str, Any]] = {}
        for t in unique:
            hard = [sid for sid in t.strategy_ids if _is_rejected_strategy(sid)]
            degraded = [sid for sid in t.strategy_ids if sid in degraded_strategy_ids]
            if t.strategy_ids and len(hard) == len(t.strategy_ids):
                decision = "HARD_REJECT"
                reason = "all_template_strategies_rejected"
            elif degraded:
                decision = "DEGRADE"
                reason = "contains_degraded_strategy"
            else:
                decision = "ALLOW"
                reason = "available"
            template_health[t.id] = TemplateHealth(
                template_id=t.id,
                decision=decision,
                reason=reason,
                strategy_ids=list(t.strategy_ids),
                hard_rejected_strategy_ids=hard,
                degraded_strategy_ids=degraded,
            ).__dict__

        available_templates: list[AttackTemplate] = []
        filtered_out: list[tuple[str, list[str]]] = []
        for t in unique:
            if not t.strategy_ids:
                # Only old templates with no payload_templates key get legacy compatibility.
                if "payload_templates" not in t.metadata:
                    available_templates.append(t)
                continue
            rejected_sids = [sid for sid in t.strategy_ids if _is_rejected_strategy(sid)]
            surviving_sids = [sid for sid in t.strategy_ids if not _is_rejected_strategy(sid)]
            if surviving_sids:
                available_templates.append(t)
            else:
                filtered_out.append((t.id, rejected_sids))

        if unique:
            print("[template_manager] === strategy selection report ===")
            print(f"[template_manager]   matched templates: {len(unique)}")
            print(f"[template_manager]   matched strategy_ids: {matched_strategy_ids or '(none)'}")
            print(f"[template_manager]   rejected for surface: {rejected_for_surface}")
            print(f"[template_manager]   available strategy_ids: {available_strategy_ids}")
            for tid, rj in filtered_out:
                print(f"[template_manager]   filtered template [{tid}]: all strategies rejected {rj}")

        if available_templates:
            stage_label = "late (file_read / flag_exfil)" if in_late_stage else "early (probe / RCE establish)"
            sections = [
                f"[Attack Templates - {len(available_templates)} available for CWEs: "
                f"{', '.join(sorted(cwe_set))} | stage: {stage_label}]"
            ]
            for t in available_templates:
                sections.append(t.to_prompt_text())
            return TemplateSelectionResult(
                text="\n\n".join(sections),
                status="AVAILABLE_STRATEGY",
                matched_template_count=len(unique),
                matched_strategy_ids=matched_strategy_ids,
                available_strategy_ids=available_strategy_ids,
                rejected_strategy_ids=rejected_for_surface,
                strategy_health=strategy_health,
                degraded_strategy_ids=degraded_strategy_ids,
                hard_rejected_strategy_ids=hard_rejected_strategy_ids,
                template_health=template_health,
                surface_still_valid=True,
                strategy_exhausted=False,
                needs_strategy_evolution=False,
                migration_report=migration_report,
                non_executable_templates=non_executable_templates,
            )

        if unique and matched_strategy_ids and not available_strategy_ids:
            return TemplateSelectionResult(
                text="",
                status="ALL_MATCHED_STRATEGIES_REJECTED",
                matched_template_count=len(unique),
                matched_strategy_ids=matched_strategy_ids,
                available_strategy_ids=[],
                rejected_strategy_ids=rejected_for_surface,
                strategy_health=strategy_health,
                degraded_strategy_ids=degraded_strategy_ids,
                hard_rejected_strategy_ids=hard_rejected_strategy_ids,
                template_health=template_health,
                surface_still_valid=True,
                strategy_exhausted=True,
                needs_strategy_evolution=True,
                migration_report=migration_report,
                non_executable_templates=non_executable_templates,
            )

        return TemplateSelectionResult(
            text="",
            status="NO_MATCHED_TEMPLATE",
            matched_template_count=len(unique),
            matched_strategy_ids=matched_strategy_ids,
            available_strategy_ids=available_strategy_ids,
            rejected_strategy_ids=rejected_for_surface,
                strategy_health=strategy_health,
                degraded_strategy_ids=degraded_strategy_ids,
                hard_rejected_strategy_ids=hard_rejected_strategy_ids,
                template_health=template_health,
                surface_still_valid=True,
                strategy_exhausted=False,
                needs_strategy_evolution=False,
                migration_report=migration_report,
                non_executable_templates=non_executable_templates,
        )
    def add_template(
        self,
        template_id: str,
        name: str,
        content: str,
        cwe_ids: list[str],
        target_type: str = "generic",
        tags: list[str] | None = None,
        author: str = "user",
        severity: str = "medium",
    ) -> Path:
        self.ensure_loaded()
        metadata = {
            "id": template_id,
            "name": name,
            "cwe_ids": cwe_ids,
            "target_type": target_type,
            "tags": tags or [],
            "author": author,
            "severity": severity,
            "version": "1.0.0",
        }
        
        target_dir = self.templates_dir / target_type
        target_dir.mkdir(parents=True, exist_ok=True)
        
        output_path = target_dir / f"{template_id}.yaml"
        data = {"metadata": metadata, "content": content}
        
        with open(output_path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        
        template = AttackTemplate(metadata, content)
        self.templates[template_id] = template
        print(f"[template_manager] Added template: {template_id} -> {output_path}")
        return output_path

    def remove_template(self, template_id: str) -> bool:
        self.ensure_loaded()
        if template_id not in self.templates:
            return False
        template = self.templates[template_id]
        target_dir = self.templates_dir / template.target_type
        yaml_file = target_dir / f"{template_id}.yaml"
        json_file = target_dir / f"{template_id}.json"
        
        removed = False
        if yaml_file.exists():
            yaml_file.unlink()
            removed = True
        if json_file.exists():
            json_file.unlink()
            removed = True
        
        if removed:
            del self.templates[template_id]
            print(f"[template_manager] Removed template: {template_id}")
        return removed

    def list_templates(self) -> list[dict[str, Any]]:
        self.ensure_loaded()
        result = []
        for t in self.templates.values():
            result.append({
                "id": t.id,
                "name": t.name,
                "cwe_ids": t.cwe_ids,
                "target_type": t.target_type,
                "severity": t.severity,
                "tags": t.tags,
                "author": t.author,
                "version": t.version,
            })
        return result

    def export_template(self, template_id: str) -> dict[str, Any] | None:
        self.ensure_loaded()
        template = self.templates.get(template_id)
        if not template:
            return None
        return {
            "metadata": template.metadata,
            "content": template.content,
        }

    def import_template(self, data: dict[str, Any]) -> AttackTemplate | None:
        metadata = data.get("metadata", {})
        content = data.get("content", "")
        template_id = metadata.get("id", "")
        if not template_id or not content:
            return None
        return self.add_template(
            template_id=template_id,
            name=metadata.get("name", ""),
            content=content,
            cwe_ids=metadata.get("cwe_ids", []),
            target_type=metadata.get("target_type", "generic"),
            tags=metadata.get("tags", []),
            author=metadata.get("author", "imported"),
            severity=metadata.get("severity", "medium"),
        )

    def get_stats(self) -> dict[str, Any]:
        self.ensure_loaded()
        stats = {
            "total": len(self.templates),
            "by_cwe": {},
            "by_target_type": {},
            "by_severity": {},
        }
        for t in self.templates.values():
            for cwe in t.cwe_ids:
                stats["by_cwe"][cwe] = stats["by_cwe"].get(cwe, 0) + 1
            stats["by_target_type"][t.target_type] = stats["by_target_type"].get(t.target_type, 0) + 1
            stats["by_severity"][t.severity] = stats["by_severity"].get(t.severity, 0) + 1
        return stats
