from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import chromadb


COLLECTION_PATTERNS = "vulnerability_patterns"
COLLECTION_STRATEGY = "exploit_strategies"
COLLECTION_TECH = "exploit_techniques"

CHROMA_ALLOWED_TYPES = (str, int, float, bool, type(None))


def _sanitize_metadata(meta: dict[str, Any]) -> dict[str, Any]:
    cleaned: dict[str, Any] = {}
    for k, v in meta.items():
        if isinstance(v, CHROMA_ALLOWED_TYPES):
            cleaned[k] = v
        elif isinstance(v, (list, tuple)):
            cleaned[k] = [
                json.dumps(item, ensure_ascii=False) if not isinstance(item, CHROMA_ALLOWED_TYPES) else item
                for item in v
            ]
        elif isinstance(v, dict):
            cleaned[k] = json.dumps(v, ensure_ascii=False)
        else:
            cleaned[k] = str(v)
    return cleaned


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
        self._ensure_collections()

    def _get_collection(self, name: str):
        if name not in self._collections:
            self._collections[name] = self._client.get_or_create_collection(name=name)
        return self._collections[name]

    def _ensure_collections(self):
        for col_name in [COLLECTION_PATTERNS, COLLECTION_STRATEGY, COLLECTION_TECH]:
            self._get_collection(col_name)
        
        # 加载初始记忆数据
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

    def _add_patterns_to_collection(self, patterns: list[dict]):
        """添加漏洞模式到集合"""
        docs = []
        metadatas = []
        ids = []
        
        for pattern in patterns:
            # 构建文档内容
            content = f"{pattern.get('name', pattern.get('pattern_name', ''))}: {pattern.get('description', pattern.get('context', ''))}"
            if "features" in pattern:
                content += f" Features: {', '.join(pattern['features'])}"
            if "verification_flow" in pattern:
                content += f" Flow: {', '.join(pattern['verification_flow'])}"
            
            docs.append(content)
            metadatas.append(pattern)
            ids.append(f"pattern_{hashlib.md5(content.encode()).hexdigest()[:8]}")
        
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
            content = f"{strategy.get('summary', strategy.get('strategy', ''))}: {strategy.get('context', strategy.get('description', ''))}"
            if "approach" in strategy:
                content += f" | Approach: {strategy['approach']}"
            if "effectiveness" in strategy:
                content += f" | Effectiveness: {strategy['effectiveness']}"
            
            docs.append(content)
            metadatas.append(strategy)
            ids.append(f"success_{i}_{hashlib.md5(f'{content}_{i}'.encode()).hexdigest()[:8]}")
        
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
            content = f"Failure: {failure.get('summary', failure.get('context', ''))}"
            if "lesson" in failure:
                content += f" | Lesson: {failure['lesson']}"
            if "reason" in failure:
                content += f" | Reason: {failure['reason']}"
            
            docs.append(content)
            metadatas.append(failure)
            ids.append(f"failure_{i}_{hashlib.md5(f'{content}_{i}'.encode()).hexdigest()[:8]}")
        
        if docs:
            metadatas = [_sanitize_metadata(m) for m in metadatas]
            self.strategy_collection.add(
                documents=docs,
                metadatas=metadatas,
                ids=ids
            )

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

    def get_stats(self) -> dict[str, int]:
        return {
            COLLECTION_PATTERNS: self.patterns_collection.count(),
            COLLECTION_STRATEGY: self.strategy_collection.count(),
            COLLECTION_TECH: self.tech_collection.count(),
        }
