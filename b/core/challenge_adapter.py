from __future__ import annotations

from typing import Any


class ChallengeAdapter:

    challenge_name: str = "generic"

    def extra_rules(self) -> str:
        return ""

    def http_semantic_errors(self) -> dict[str, str]:
        return {}

    def eval_extra_rules(self) -> str:
        return ""

    def preprocess_confirmed(self, confirmed: dict[str, Any]) -> dict[str, Any]:
        return confirmed

    def postprocess_step(self, command: str, step_type: str) -> str:
        return command


_registry: dict[str, type[ChallengeAdapter]] = {}


def register_adapter(name: str):
    def decorator(cls: type[ChallengeAdapter]) -> type[ChallengeAdapter]:
        _registry[name] = cls
        return cls
    return decorator


def get_adapter(name: str) -> ChallengeAdapter:
    if name in _registry:
        return _registry[name]()
    return ChallengeAdapter()


def list_adapters() -> list[str]:
    return sorted(_registry.keys())