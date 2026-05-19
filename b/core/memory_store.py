from __future__ import annotations

import hashlib
import json
import re
import uuid
from pathlib import Path
from typing import Any

import chromadb


COLLECTION_PATTERNS = "vulnerability_patterns"
COLLECTION_STRATEGY = "exploit_strategies"
COLLECTION_TECH = "exploit_techniques"

CHROMA_ALLOWED_TYPES = (str, int, float, bool, type(None))


def _extract_tokens(entry: dict) -> list[str]:
    """Extract raw keyword tokens from a JSON entry (shared by tags_str and bool_tags).

    Sources: explicit tags, CWE IDs, vulnerability name, context (with em-dash splits),
    name (nuclei-style), lang, source, and description/summary/purpose fields.
    """
    tokens: list[str] = []

    # 1. Explicit tags field
    tags = entry.get("tags")
    if isinstance(tags, list):
        tokens.extend(str(t).lower() for t in tags)
    elif isinstance(tags, str):
        tokens.extend(t.strip().lower() for t in tags.replace(",", " ").split())

    # 2. CWE IDs
    for key in ("cwe_ids", "cwe_id"):
        val = entry.get(key)
        if isinstance(val, list):
            tokens.extend(str(v).lower() for v in val)
        elif isinstance(val, str) and val.strip():
            tokens.append(val.strip().lower())

    # 3. Vulnerability field
    vuln = entry.get("vulnerability", "")
    if isinstance(vuln, str):
        for word in vuln.replace("_", " ").replace("-", " ").split():
            w = word.strip().lower()
            if w and len(w) >= 2:
                tokens.append(w)

    # 4. Context field (split on em-dash, then delimiters)
    context = entry.get("context", "")
    if isinstance(context, str) and context:
        for part in context.split(" — "):
            for segment in part.strip().replace("/", " ").replace("-", " ").split():
                seg = segment.strip().lower().rstrip(".,;:")
                if seg and len(seg) >= 2:
                    tokens.append(seg)

    # 5. Name field (nuclei-style: nuclei_yonyou-u8-crm-sqli → yonyou, u8, crm, sqli)
    name = entry.get("name", "")
    if isinstance(name, str) and name:
        cleaned = name.lower()
        if cleaned.startswith("nuclei_"):
            cleaned = cleaned[len("nuclei_"):]
        for word in cleaned.replace("_", "-").split("-"):
            w = word.strip().rstrip(".,;:")
            if w and len(w) >= 2:
                tokens.append(w)

    # 6. Lang
    lang = entry.get("lang", "")
    if isinstance(lang, str) and lang.strip():
        tokens.append(lang.strip().lower())

    # 7. Source
    source = entry.get("source", "")
    if isinstance(source, str) and source:
        tokens.append(source.lower())
        for word in source.replace("-", " ").replace("_", " ").split():
            w = word.strip().lower()
            if w and len(w) >= 2:
                tokens.append(w)

    # 8. Description / summary / purpose
    for key in ("description", "summary", "purpose"):
        text = entry.get(key, "")
        if isinstance(text, str):
            for word in text.replace("_", " ").replace("-", " ").split():
                w = word.strip().lower().rstrip(".,;:()[]{}")
                if len(w) >= 3:
                    tokens.append(w)

    return tokens


_NOISE_WORDS: set[str] = {
    "", "a", "an", "and", "are", "as", "at", "be", "by", "can", "do", "for", "from",
    "has", "he", "how", "if", "in", "is", "it", "me", "my", "no", "not", "of", "oh",
    "ok", "on", "or", "per", "so", "the", "this", "to", "up", "use", "via", "was",
    "we", "what", "when", "with", "your", "file", "line", "unknown", "none",
}


def _extract_tags_str(entry: dict) -> str:
    """Extract a space-separated tags_str for ChromaDB $contains filtering."""
    tokens = _extract_tokens(entry)
    seen: set[str] = set()
    deduped: list[str] = []
    for t in tokens:
        t = t.strip().lower()
        if t and t not in seen and t not in _NOISE_WORDS:
            seen.add(t)
            deduped.append(t)
    return " ".join(deduped)


def _extract_bool_tags(entry: dict) -> dict[str, bool]:
    """Build boolean tag fields for ChromaDB ``$or`` metadata filtering.

    ChromaDB 1.5 only supports scalar metadata values and ``$eq``/``$or``/``$and`` operators.
    Each keyword becomes a ``tag_<sanitized>`` boolean field, e.g.:
        {"tag_jwt": True, "tag_python": True, "tag_auth_bypass": True}
    """
    tokens = _extract_tokens(entry)
    seen: set[str] = set()
    bool_tags: dict[str, bool] = {}
    for t in tokens:
        t = t.strip().lower()
        safe = re.sub(r'[^a-z0-9]', '_', t)
        safe = re.sub(r'_+', '_', safe).strip('_')
        if not safe or safe in _NOISE_WORDS or len(safe) < 2:
            continue
        key = f"tag_{safe}"
        if key not in seen:
            seen.add(key)
            bool_tags[key] = True
    return bool_tags


def _extract_source(entry: dict) -> str:
    """Return the source field value or 'unknown'."""
    return entry.get("source") or "unknown"


def _build_bool_filter(target_tags: list[str]) -> dict[str, Any] | None:
    """Build a ChromaDB ``$or`` filter from target tags for boolean metadata fields.

    Each tag is converted to ``tag_<keyword>`` (e.g. ``"jwt"`` → ``{"tag_jwt": True}``).
    Returns ``None`` if target_tags is empty (meaning no filter should be applied).
    """
    if not target_tags:
        return None

    seen: set[str] = set()
    clauses: list[dict[str, Any]] = []
    for t in target_tags:
        safe = re.sub(r'[^a-z0-9]', '_', t.strip().lower())
        safe = re.sub(r'_+', '_', safe).strip('_')
        if not safe or len(safe) < 2:
            continue
        key = f"tag_{safe}"
        if key not in seen:
            seen.add(key)
            clauses.append({key: True})

    if not clauses:
        return None
    if len(clauses) == 1:
        return clauses[0]
    return {"$or": clauses}


def _sanitize_metadata(meta: dict[str, Any]) -> dict[str, Any]:
    cleaned: dict[str, Any] = {}
    for k, v in meta.items():
        if v is None or v == [] or v == {}:
            continue
        if isinstance(v, CHROMA_ALLOWED_TYPES):
            cleaned[k] = v
        elif isinstance(v, (list, tuple)):
            sanitized_list = []
            for item in v:
                if item is None or item == [] or item == {}:
                    continue
                if isinstance(item, CHROMA_ALLOWED_TYPES):
                    sanitized_list.append(item)
                else:
                    sanitized_list.append(json.dumps(item, ensure_ascii=False))
            if sanitized_list:
                cleaned[k] = sanitized_list
        elif isinstance(v, dict):
            inner = _sanitize_metadata(v)
            if inner:
                cleaned[k] = json.dumps(inner, ensure_ascii=False)
        else:
            cleaned[k] = str(v)
    return cleaned


def _make_unique_id(prefix: str, content: str, seen: set[str], hash_len: int = 10) -> str:
    base = f"{prefix}_{hashlib.md5(content.encode()).hexdigest()[:hash_len]}"
    if base not in seen:
        seen.add(base)
        return base
    for n in range(2, 1000):
        candidate = f"{base}_{n}"
        if candidate not in seen:
            seen.add(candidate)
            return candidate
    fallback = f"{base}_{uuid.uuid4().hex[:6]}"
    seen.add(fallback)
    return fallback


class LayeredMemory:
    """三层长期记忆：漏洞模式 / 策略 / 技术操作（ChromaDB 统一存储）。"""

    def __init__(self, memory_dir: Path) -> None:
        self.memory_dir = memory_dir
        root_path = memory_dir.resolve()
        if root_path.name == "b":
            root_path = root_path.parent
        db_path = root_path / "co_redteam_memory"
        self._client = chromadb.PersistentClient(path=str(db_path))
        self._collections: dict[str, Any] = {}
        self._seen_ids: dict[str, set[str]] = {}
        self._ensure_collections()

    def _get_collection(self, name: str):
        if name not in self._collections:
            self._collections[name] = self._client.get_or_create_collection(name=name)
        return self._collections[name]

    def _ensure_collections(self):
        for col_name in [COLLECTION_PATTERNS, COLLECTION_STRATEGY, COLLECTION_TECH]:
            self._get_collection(col_name)
            self._seen_ids[col_name] = set()

        # Load initial memory data
        self._load_initial_memory()

    def _load_initial_memory(self):
        """从 b/memory/ 目录加载初始记忆数据"""
        memory_dir = self.memory_dir / "memory"
        if memory_dir.exists():
            # 加载漏洞模式
            pattern_file = memory_dir / "pattern.json"
            if pattern_file.exists():
                try:
                    with open(pattern_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        if "patterns" in data:
                            self._add_patterns_to_collection(data["patterns"])
                            print(f"[memory] Loaded {len(data['patterns'])} initial patterns")
                except Exception as e:
                    print(f"[memory] Failed to load patterns: {e}")

            # 加载策略
            strategy_file = memory_dir / "strategy.json"
            if strategy_file.exists():
                try:
                    with open(strategy_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        if "success_strategies" in data:
                            self._add_strategies_to_collection(data["success_strategies"])
                            print(f"[memory] Loaded {len(data['success_strategies'])} success strategies")
                        if "failure_lessons" in data:
                            self._add_failure_lessons_to_collection(data["failure_lessons"])
                            print(f"[memory] Loaded {len(data['failure_lessons'])} failure lessons")
                except Exception as e:
                    print(f"[memory] Failed to load strategies: {e}")

            # 加载技术操作（命令 / Payload / 脚本）
            tech_file = memory_dir / "tech.json"
            if tech_file.exists():
                try:
                    with open(tech_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        if "commands" in data:
                            self._add_tech_commands_to_collection(data["commands"])
                            print(f"[memory] Loaded {len(data['commands'])} initial tech commands")
                        if "payload_templates" in data:
                            self._add_tech_payloads_to_collection(data["payload_templates"])
                            print(f"[memory] Loaded {len(data['payload_templates'])} initial payload templates")
                        if "scripts" in data:
                            self._add_tech_scripts_to_collection(data["scripts"])
                            print(f"[memory] Loaded {len(data['scripts'])} initial scripts")
                except Exception as e:
                    print(f"[memory] Failed to load tech: {e}")

    def _add_patterns_to_collection(self, patterns: list[dict]):
        """添加漏洞模式到集合"""
        docs = []
        metadatas = []
        ids = []
        
        for pattern in patterns:
            # Enrich with tags_str, bool_tags and source before building metadata
            pattern["tags_str"] = _extract_tags_str(pattern)
            pattern["source"] = _extract_source(pattern)
            pattern.update(_extract_bool_tags(pattern))

            # 构建文档内容
            content = f"{pattern.get('name', pattern.get('pattern_name', ''))}: {pattern.get('description', pattern.get('context', ''))}"
            if "features" in pattern:
                content += f" Features: {', '.join(pattern['features'])}"
            if "verification_flow" in pattern:
                content += f" Flow: {', '.join(pattern['verification_flow'])}"
            
            docs.append(content)
            metadatas.append(pattern)
            ids.append(_make_unique_id("pattern", content, self._seen_ids[COLLECTION_PATTERNS], 8))
        
        if docs:
            metadatas = [_sanitize_metadata(m) for m in metadatas]
            self.patterns_collection.add(
                documents=docs,
                metadatas=metadatas,
                ids=ids
            )

    def _add_strategies_to_collection(self, strategies: list[dict]):
        """添加成功策略到集合"""
        docs = []
        metadatas = []
        ids = []
        
        for i, strategy in enumerate(strategies):
            # Enrich with tags_str, bool_tags and source before building metadata
            strategy["tags_str"] = _extract_tags_str(strategy)
            strategy["source"] = _extract_source(strategy)
            strategy.update(_extract_bool_tags(strategy))

            content = f"{strategy.get('summary', strategy.get('strategy', ''))}: {strategy.get('context', strategy.get('description', ''))}"
            if "approach" in strategy:
                content += f" | Approach: {strategy['approach']}"
            if "effectiveness" in strategy:
                content += f" | Effectiveness: {strategy['effectiveness']}"
            
            docs.append(content)
            metadatas.append(strategy)
            ids.append(_make_unique_id(f"success_{i}", content, self._seen_ids[COLLECTION_STRATEGY], 8))
        
        if docs:
            metadatas = [_sanitize_metadata(m) for m in metadatas]
            self.strategy_collection.add(
                documents=docs,
                metadatas=metadatas,
                ids=ids
            )

    def _add_failure_lessons_to_collection(self, failures: list[dict]):
        """添加失败教训到集合"""
        docs = []
        metadatas = []
        ids = []
        
        for i, failure in enumerate(failures):
            # Enrich with tags_str, bool_tags and source before building metadata
            failure["tags_str"] = _extract_tags_str(failure)
            failure["source"] = _extract_source(failure)
            failure.update(_extract_bool_tags(failure))

            content = f"Failure: {failure.get('summary', failure.get('context', ''))}"
            if "lesson" in failure:
                content += f" | Lesson: {failure['lesson']}"
            if "reason" in failure:
                content += f" | Reason: {failure['reason']}"
            
            docs.append(content)
            metadatas.append(failure)
            ids.append(_make_unique_id(f"failure_{i}", content, self._seen_ids[COLLECTION_STRATEGY], 8))
        
        if docs:
            metadatas = [_sanitize_metadata(m) for m in metadatas]
            self.strategy_collection.add(
                documents=docs,
                metadatas=metadatas,
                ids=ids
            )

    def _add_tech_commands_to_collection(self, commands: list[dict]):
        """添加技术命令到 tech_collection"""
        docs = []
        metadatas = []
        ids = []
        for cmd in commands:
            # Enrich with tags_str, bool_tags and source before building metadata
            cmd["tags_str"] = _extract_tags_str(cmd)
            cmd["source"] = _extract_source(cmd)
            cmd.update(_extract_bool_tags(cmd))

            content = cmd.get("command") or cmd.get("content") or ""
            if not content.strip():
                continue
            purpose = cmd.get("purpose") or cmd.get("description") or ""
            ctx = cmd.get("context") or ""
            doc = f"{purpose} | context={ctx} | cmd={content}"
            docs.append(doc)
            cmd["_full_command"] = content
            metadatas.append(cmd)
            ids.append(_make_unique_id("cmd", content, self._seen_ids[COLLECTION_TECH], 10))
        if docs:
            metadatas = [_sanitize_metadata(m) for m in metadatas]
            self.tech_collection.add(documents=docs, metadatas=metadatas, ids=ids)

    def _add_tech_payloads_to_collection(self, payloads: list[dict]):
        """添加 Payload 模板到 tech_collection"""
        docs = []
        metadatas = []
        ids = []
        for p in payloads:
            # Enrich with tags_str, bool_tags and source before building metadata
            p["tags_str"] = _extract_tags_str(p)
            p["source"] = _extract_source(p)
            p.update(_extract_bool_tags(p))

            name = p.get("name", "")
            template = p.get("template") or p.get("payload") or ""
            context = p.get("context", "")
            lang = p.get("lang", "")
            source = p.get("source", "")
            doc_parts = [f"PAYLOAD: {name}"]
            if context:
                doc_parts.append(f"context={context}")
            if lang:
                doc_parts.append(f"lang={lang}")
            if source:
                doc_parts.append(f"source={source}")
            if template:
                doc_parts.append(f"payload={template}")
            doc = " | ".join(doc_parts)
            docs.append(doc)
            p["_payload_text"] = template
            metadatas.append(p)
            ids.append(_make_unique_id("payload", doc, self._seen_ids[COLLECTION_TECH], 10))
        if docs:
            metadatas = [_sanitize_metadata(m) for m in metadatas]
            self.tech_collection.add(documents=docs, metadatas=metadatas, ids=ids)

    def _add_tech_scripts_to_collection(self, scripts: list[dict]):
        """添加脚本模板到 tech_collection"""
        docs = []
        metadatas = []
        ids = []
        for sc in scripts:
            # Enrich with tags_str, bool_tags and source before building metadata
            sc["tags_str"] = _extract_tags_str(sc)
            sc["source"] = _extract_source(sc)
            sc.update(_extract_bool_tags(sc))

            name = sc.get("name", "")
            content = sc.get("content") or sc.get("command") or ""
            context = sc.get("context", "")
            desc = sc.get("description", "")
            doc = f"SCRIPT: {name} | description={desc} | context={context}"
            docs.append(doc)
            sc["_script_content"] = content
            metadatas.append(sc)
            ids.append(_make_unique_id("script", doc, self._seen_ids[COLLECTION_TECH], 10))
        if docs:
            metadatas = [_sanitize_metadata(m) for m in metadatas]
            self.tech_collection.add(documents=docs, metadatas=metadatas, ids=ids)

    @property
    def patterns_collection(self):
        return self._get_collection(COLLECTION_PATTERNS)

    @property
    def strategy_collection(self):
        return self._get_collection(COLLECTION_STRATEGY)

    @property
    def tech_collection(self):
        return self._get_collection(COLLECTION_TECH)

    def query_patterns(self, query_text: str, n_results: int = 5) -> list[dict[str, Any]]:
        results = self.patterns_collection.query(
            query_texts=[query_text],
            n_results=n_results,
        )
        items = []
        if results and results.get("documents") and results["documents"][0]:
            docs = results["documents"][0]
            metas = results.get("metadatas", [[]])[0]
            dists = results.get("distances", [[]])[0]
            for i, doc in enumerate(docs):
                items.append({
                    "content": doc,
                    "metadata": metas[i] if i < len(metas) else {},
                    "distance": dists[i] if i < len(dists) else 0.0,
                })
        return items

    def query_strategies(self, query_text: str, n_results: int = 5) -> list[dict[str, Any]]:
        results = self.strategy_collection.query(
            query_texts=[query_text],
            n_results=n_results,
        )
        items = []
        if results and results.get("documents") and results["documents"][0]:
            docs = results["documents"][0]
            metas = results.get("metadatas", [[]])[0]
            dists = results.get("distances", [[]])[0]
            for i, doc in enumerate(docs):
                items.append({
                    "content": doc,
                    "metadata": metas[i] if i < len(metas) else {},
                    "distance": dists[i] if i < len(dists) else 0.0,
                })
        return items

    def query_tech(self, query_text: str, n_results: int = 5) -> list[dict[str, Any]]:
        results = self.tech_collection.query(
            query_texts=[query_text],
            n_results=n_results,
        )
        items = []
        if results and results.get("documents") and results["documents"][0]:
            docs = results["documents"][0]
            metas = results.get("metadatas", [[]])[0]
            dists = results.get("distances", [[]])[0]
            for i, doc in enumerate(docs):
                items.append({
                    "content": doc,
                    "metadata": metas[i] if i < len(metas) else {},
                    "distance": dists[i] if i < len(dists) else 0.0,
                })
        return items

    def upsert_pattern(self, content: str, metadata: dict[str, Any] | None = None) -> str:
        doc_id = f"pattern_{hashlib.md5(content.encode()).hexdigest()[:12]}"
        meta = _sanitize_metadata(metadata or {})
        meta.setdefault("type", "pattern")
        self.patterns_collection.upsert(
            documents=[content],
            ids=[doc_id],
            metadatas=[meta],
        )
        return doc_id

    def upsert_strategy(self, content: str, strategy_type: str = "success", metadata: dict[str, Any] | None = None) -> str:
        doc_id = f"strategy_{strategy_type}_{hashlib.md5(content.encode()).hexdigest()[:12]}"
        meta = _sanitize_metadata(metadata or {})
        meta.setdefault("type", "strategy")
        meta.setdefault("strategy_type", strategy_type)
        self.strategy_collection.upsert(
            documents=[content],
            ids=[doc_id],
            metadatas=[meta],
        )
        return doc_id

    def upsert_tech(self, content: str, tech_type: str = "command", metadata: dict[str, Any] | None = None) -> str:
        doc_id = f"tech_{tech_type}_{hashlib.md5(content.encode()).hexdigest()[:12]}"
        meta = _sanitize_metadata(metadata or {})
        meta.setdefault("type", "tech")
        meta.setdefault("tech_type", tech_type)
        self.tech_collection.upsert(
            documents=[content],
            ids=[doc_id],
            metadatas=[meta],
        )
        return doc_id

    def load_all(self) -> dict[str, Any]:
        pattern_data = {"patterns": []}
        try:
            result = self.patterns_collection.get()
            if result.get("documents"):
                pattern_data["patterns"] = [
                    {"content": d, "id": result["ids"][i]}
                    for i, d in enumerate(result["documents"])
                ]
        except Exception:
            pass

        strategy_data = {"success_strategies": [], "failure_lessons": []}
        try:
            result = self.strategy_collection.get()
            if result.get("documents"):
                for i, d in enumerate(result["documents"]):
                    meta = (result.get("metadatas") or [[]])[i] if i < len(result.get("metadatas") or []) else {}
                    stype = meta.get("strategy_type", "success")
                    item = {"content": d, "id": result["ids"][i], **meta}
                    if stype == "failure":
                        strategy_data["failure_lessons"].append(item)
                    else:
                        strategy_data["success_strategies"].append(item)
        except Exception:
            pass

        tech_data = {"commands": [], "payload_templates": [], "scripts": []}
        try:
            result = self.tech_collection.get()
            if result.get("documents"):
                for i, d in enumerate(result["documents"]):
                    meta = (result.get("metadatas") or [[]])[i] if i < len(result.get("metadatas") or []) else {}
                    ttype = meta.get("tech_type", "command")
                    item = {"content": d, "id": result["ids"][i], **meta}
                    if ttype == "payload_template":
                        tech_data["payload_templates"].append(item)
                    elif ttype == "script":
                        tech_data["scripts"].append(item)
                    else:
                        tech_data["commands"].append(item)
        except Exception:
            pass

        return {
            "pattern": pattern_data,
            "strategy": strategy_data,
            "tech": tech_data,
        }

    def planning_context(self) -> str:
        bundle = self.load_all()
        slim = {
            "pattern_count": len(bundle.get("pattern", {}).get("patterns", [])),
            "pattern_samples": bundle.get("pattern", {}).get("patterns", [])[:3],
            "strategy_success_count": len(bundle.get("strategy", {}).get("success_strategies", [])),
            "strategy_failure_count": len(bundle.get("strategy", {}).get("failure_lessons", [])),
            "strategy_samples": bundle.get("strategy", {}).get("success_strategies", [])[:3],
            "failure_lesson_samples": bundle.get("strategy", {}).get("failure_lessons", [])[:5],
            "tech_commands_count": len(bundle.get("tech", {}).get("commands", [])),
            "tech_payloads_count": len(bundle.get("tech", {}).get("payload_templates", [])),
            "tech_scripts_count": len(bundle.get("tech", {}).get("scripts", [])),
            "tech_samples": bundle.get("tech", {}).get("commands", [])[:3],
        }
        return json.dumps(slim, ensure_ascii=False, indent=2)

    def apply_evaluator_patch(self, patch: dict[str, Any]) -> None:
        if "pattern" in patch:
            fragment = patch["pattern"]
            for p in fragment.get("add_patterns", []):
                if isinstance(p, dict):
                    content = p.get("content") or json.dumps(p, ensure_ascii=False)
                    meta = {k: v for k, v in p.items() if k != "content"}
                    self.upsert_pattern(content, meta)

        if "strategy" in patch:
            fragment = patch["strategy"]
            for s in fragment.get("add_success", []):
                if isinstance(s, dict):
                    content = s.get("content") or json.dumps(s, ensure_ascii=False)
                    meta = {k: v for k, v in s.items() if k != "content"}
                    self.upsert_strategy(content, "success", meta)
            for s in fragment.get("add_failures", []):
                if isinstance(s, dict):
                    content = s.get("content") or json.dumps(s, ensure_ascii=False)
                    meta = {k: v for k, v in s.items() if k != "content"}
                    self.upsert_strategy(content, "failure", meta)

        if "tech" in patch:
            fragment = patch["tech"]
            for c in fragment.get("add_commands", []):
                if isinstance(c, dict):
                    content = c.get("content") or json.dumps(c, ensure_ascii=False)
                    meta = {k: v for k, v in c.items() if k != "content"}
                    self.upsert_tech(content, "command", meta)
            for p in fragment.get("add_payload_templates", []):
                if isinstance(p, dict):
                    content = p.get("content") or json.dumps(p, ensure_ascii=False)
                    meta = {k: v for k, v in p.items() if k != "content"}
                    self.upsert_tech(content, "payload_template", meta)
            for s in fragment.get("add_scripts", []):
                if isinstance(s, dict):
                    content = s.get("content") or json.dumps(s, ensure_ascii=False)
                    meta = {k: v for k, v in s.items() if k != "content"}
                    self.upsert_tech(content, "script", meta)

    def query_tech_payloads(
        self, query_text: str, n_results: int = 10
    ) -> list[dict[str, Any]]:
        """CWE-keyed 精准检索：从 tech_collection 提取具体 Payload / 命令 / 脚本。

        与泛化的 query_tech 不同，本方法会从 metadata 中拆出
        _payload_text / _full_command / _script_content 字段，
        确保 Planner 拿到的是可直接复制的攻击载荷而非摘要描述。"""
        results = self.tech_collection.query(
            query_texts=[query_text],
            n_results=n_results,
        )
        items: list[dict[str, Any]] = []
        if results and results.get("documents") and results["documents"][0]:
            docs = results["documents"][0]
            metas = results.get("metadatas", [[]])[0]
            dists = results.get("distances", [[]])[0]
            for i, doc in enumerate(docs):
                meta = metas[i] if i < len(metas) else {}
                item: dict[str, Any] = {
                    "content": doc,
                    "metadata": meta,
                    "distance": dists[i] if i < len(dists) else 0.0,
                }
                payload_text = meta.get("_payload_text", "")
                full_cmd = meta.get("_full_command", "")
                script = meta.get("_script_content", "")
                if payload_text:
                    item["payload"] = payload_text
                if full_cmd:
                    item["command"] = full_cmd
                if script:
                    item["script"] = script
                items.append(item)
        return items

    def query_tech_payloads_filtered(
        self,
        query_text: str,
        filter_tags: list[str],
        n_results: int = 10,
    ) -> list[dict[str, Any]]:
        """Tag-filtered tech query using boolean metadata fields + ``$or``.

        ChromaDB 1.5 only supports scalar metadata and ``$eq``/``$or``/``$and``.
        We build a ``$or`` clause over ``tag_<keyword>`` boolean fields.

        Falls back to unfiltered query when the filter yields zero results.
        """
        where = _build_bool_filter(filter_tags)
        if where is not None:
            try:
                results = self.tech_collection.query(
                    query_texts=[query_text],
                    n_results=n_results,
                    where=where,
                )
                items: list[dict[str, Any]] = []
                if results and results.get("documents") and results["documents"][0]:
                    docs = results["documents"][0]
                    metas = results.get("metadatas", [[]])[0]
                    dists = results.get("distances", [[]])[0]
                    for i, doc in enumerate(docs):
                        meta = metas[i] if i < len(metas) else {}
                        item: dict[str, Any] = {
                            "content": doc,
                            "metadata": meta,
                            "distance": dists[i] if i < len(dists) else 0.0,
                        }
                        payload_text = meta.get("_payload_text", "")
                        full_cmd = meta.get("_full_command", "")
                        script = meta.get("_script_content", "")
                        if payload_text:
                            item["payload"] = payload_text
                        if full_cmd:
                            item["command"] = full_cmd
                        if script:
                            item["script"] = script
                        items.append(item)
                if items:
                    return items
            except Exception:
                pass
            print(f"[memory] tag-filter fallback for: {filter_tags}")
        return self.query_tech_payloads(query_text, n_results)

    def query_strategies_filtered(
        self,
        query_text: str,
        filter_tags: list[str],
        n_results: int = 5,
    ) -> list[dict[str, Any]]:
        """Tag-filtered strategy query using boolean metadata fields + ``$or``.

        Falls back to unfiltered query when the filter yields zero results.
        """
        where = _build_bool_filter(filter_tags)
        if where is not None:
            try:
                results = self.strategy_collection.query(
                    query_texts=[query_text],
                    n_results=n_results,
                    where=where,
                )
                items: list[dict[str, Any]] = []
                if results and results.get("documents") and results["documents"][0]:
                    docs = results["documents"][0]
                    metas = results.get("metadatas", [[]])[0]
                    dists = results.get("distances", [[]])[0]
                    for i, doc in enumerate(docs):
                        items.append({
                            "content": doc,
                            "metadata": metas[i] if i < len(metas) else {},
                            "distance": dists[i] if i < len(dists) else 0.0,
                        })
                if items:
                    return items
            except Exception:
                pass
            print(f"[memory] tag-filter fallback for: {filter_tags}")
        return self.query_strategies(query_text, n_results)

    def query_patterns_filtered(
        self,
        query_text: str,
        filter_tags: list[str],
        n_results: int = 5,
    ) -> list[dict[str, Any]]:
        """Tag-filtered pattern query using boolean metadata fields + ``$or``.

        Falls back to unfiltered query when the filter yields zero results.
        """
        where = _build_bool_filter(filter_tags)
        if where is not None:
            try:
                results = self.patterns_collection.query(
                    query_texts=[query_text],
                    n_results=n_results,
                    where=where,
                )
                items: list[dict[str, Any]] = []
                if results and results.get("documents") and results["documents"][0]:
                    docs = results["documents"][0]
                    metas = results.get("metadatas", [[]])[0]
                    dists = results.get("distances", [[]])[0]
                    for i, doc in enumerate(docs):
                        items.append({
                            "content": doc,
                            "metadata": metas[i] if i < len(metas) else {},
                            "distance": dists[i] if i < len(dists) else 0.0,
                        })
                if items:
                    return items
            except Exception:
                pass
            print(f"[memory] tag-filter fallback for: {filter_tags}")
        return self.query_patterns(query_text, n_results)

    def get_stats(self) -> dict[str, int]:
        return {
            COLLECTION_PATTERNS: self.patterns_collection.count(),
            COLLECTION_STRATEGY: self.strategy_collection.count(),
            COLLECTION_TECH: self.tech_collection.count(),
        }
