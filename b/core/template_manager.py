from __future__ import annotations

import json
import os
import re
import yaml
from pathlib import Path
from typing import Any


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

    def get_template_records_for_target(
        self,
        confirmed_vuln: dict[str, Any],
        *,
        include_candidates: bool = False,
    ) -> list[AttackTemplate]:
        self.ensure_loaded()
        vulns = confirmed_vuln.get("vulnerabilities", [])
        cwe_set = {v.get("cwe_id", "") for v in vulns}

        matched = []
        for cwe_id in cwe_set:
            matched.extend(self.query_templates(cwe_id=cwe_id))

        # 关键词回退: 当 CWE 为 UNKNOWN 时, 从 vuln 文本匹配模板 tag
        if len(matched) == 0:
            text_parts = []
            for v in vulns:
                for key in ("title", "description", "evidence", "source", "sink", "attack_chain"):
                    val = v.get(key, "")
                    if isinstance(val, str):
                        text_parts.append(val.lower())
                    elif isinstance(val, dict):
                        text_parts.append(str(val.get("code_snippet", "")).lower())
            vuln_text = " ".join(text_parts)
            for t in self.templates.values():
                for tag in t.tags:
                    normalized = tag.lower().replace("_", " ").replace("-", " ")
                    if normalized in vuln_text or tag.lower() in vuln_text:
                        matched.append(t)
                        break

        seen = set()
        unique: list[AttackTemplate] = []
        _skipped_candidate = 0
        for t in matched:
            if t.id in seen:
                continue
            seen.add(t.id)
            if "consolidator_reviewed:false" in t.tags and not include_candidates:
                _skipped_candidate += 1
                continue
            unique.append(t)
        if _skipped_candidate > 0:
            print(f"[template_manager] ⏭️ 跳过 {_skipped_candidate} 个未审核 consolidator YAML（candidate）")

        return unique

    def get_templates_for_target(
        self,
        confirmed_vuln: dict[str, Any],
    ) -> str:
        records = self.get_template_records_for_target(confirmed_vuln)
        if not records:
            return ""
        cwe_set = {
            v.get("cwe_id", "")
            for v in confirmed_vuln.get("vulnerabilities", [])
        }
        sections = [
            f"【Attack Templates — {len(records)} available for CWEs: "
            f"{', '.join(sorted(cwe_set))}】"
        ]
        sections.extend(template.to_prompt_text() for template in records)
        return "\n\n".join(sections)

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
