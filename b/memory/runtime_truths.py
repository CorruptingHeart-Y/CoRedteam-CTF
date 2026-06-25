"""Runtime Truth Layer — verified physical facts about the current target.

Only deterministic code-observed facts are stored here. LLM inference is
never accepted as a source. Reset on each new target (new base_url).

Consumed by Coordinator each round and injected into Planner L4 as
high-attention target_facts block.
"""

from __future__ import annotations

import json
from pathlib import Path

RUNTIME_TRUTHS_PATH = Path(__file__).resolve().parent / "runtime_truths.json"


class RuntimeTruths:
    """Store verified physical facts about the current target.

    Write path: only deterministic code (distiller regex, executor SDK
    probes) — never LLM inference.
    """

    def __init__(self) -> None:
        self.data: dict[str, dict[str, object]] = {}
        if RUNTIME_TRUTHS_PATH.exists():
            try:
                self.data = json.loads(RUNTIME_TRUTHS_PATH.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self.data = {}

    # ── CRUD ──────────────────────────────────────────────────────────

    def set_fact(self, key: str, value: object, evidence: str) -> None:
        self.data[key] = {"value": value, "evidence": evidence}
        self._persist()
        print(f"[runtime_truths] {key}={value} | evidence={evidence[:60]}")

    def get(self, key: str, default: object = None) -> object:
        entry = self.data.get(key)
        return entry["value"] if entry else default

    def has(self, key: str) -> bool:
        return key in self.data

    # ── Planner injection ─────────────────────────────────────────────

    def to_planner_block(self) -> str:
        """Generate a <=200 char text block for L4 injection."""
        if not self.data:
            return ""
        lines = ["[TARGET_FACTS]"]
        for k, v in self.data.items():
            lines.append(f"  {k}={v['value']}")
        return "\n".join(lines)

    def to_method_override_message(self) -> str:
        """If POST is confirmed, produce a mandatory method directive."""
        confirmed = self.get("confirmed_render_method")
        form_method = self.get("form_method")
        if confirmed == "POST" or form_method == "POST":
            param = self.get("form_param", "text")
            return (
                "[TARGET_FACT] HTML form uses POST method. "
                "You MUST submit payloads via POST body, NEVER via GET query string. "
                f"Injection parameter: {param}"
            )
        return ""

    # ── Step override (last-resort before Executor) ──────────────────

    def apply_method_override_to_steps(
        self, steps: list[dict[str, object]]
    ) -> list[dict[str, object]]:
        """Auto-inject _runtime_override into steps when POST is confirmed.

        This is the last-resort defense: even if Validator doesn't catch a
        GET call, the Executor will see _runtime_override and do string
        replacement before executing the code.
        """
        confirmed_method = self.get("confirmed_render_method") or self.get("form_method")
        confirmed_param = self.get("form_param")

        if confirmed_method != "POST":
            return steps

        for step in steps:
            override: dict[str, object] = {"http_method": "POST"}
            if confirmed_param:
                override["inject_param"] = confirmed_param
            step.setdefault("_runtime_override", {})  # type: ignore[union-attr]
            step["_runtime_override"] = override  # type: ignore[index]

        print(
            f"[runtime_truths] 🔧 applied method override to {len(steps)} steps: "
            f"method=POST, param={confirmed_param}"
        )
        return steps

    # ── Persistence ───────────────────────────────────────────────────

    def reset(self) -> None:
        self.data = {}
        self._persist()

    def _persist(self) -> None:
        RUNTIME_TRUTHS_PATH.write_text(
            json.dumps(self.data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )


# Module-level singleton (one per process — coordinator is single-process)
_runtime_truths: RuntimeTruths | None = None


def get_runtime_truths() -> RuntimeTruths:
    global _runtime_truths
    if _runtime_truths is None:
        _runtime_truths = RuntimeTruths()
    return _runtime_truths


def reset_runtime_truths() -> None:
    global _runtime_truths
    if _runtime_truths is not None:
        _runtime_truths.reset()
    else:
        RuntimeTruths().reset()
