from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Settings:
    project_root: Path
    deepseek_api_key: str | None
    deepseek_base_url: str
    deepseek_model: str
    mock_llm: bool
    max_iterations: int
    workspace_dir: Path
    memory_dir: Path
    confirmed_vuln_path: Path
    docker_enabled: bool
    docker_image: str
    docker_timeout: int
    docker_memory_limit: str
    docker_cpu_quota: int


def get_settings() -> Settings:
    mock = os.getenv("CO_REDTEAM_MOCK_LLM", "false").lower() in ("1", "true", "yes")
    docker_enabled = os.getenv("CO_REDTEAM_DOCKER_ENABLED", "true").lower() in ("1", "true", "yes")
    return Settings(
        project_root=ROOT,
        deepseek_api_key=os.getenv("DEEPSEEK_API_KEY") or None,
        deepseek_base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
        deepseek_model=os.getenv("DEEPSEEK_MODEL", "deepseek-chat"),
        mock_llm=mock,
        max_iterations=int(os.getenv("CO_REDTEAM_MAX_ITER", "8")),
        workspace_dir=ROOT / "workspace",
        memory_dir=ROOT,
        confirmed_vuln_path=ROOT.parent / "reports" / "vulnerability_proposal_latest.json",
        docker_enabled=docker_enabled,
        docker_image=os.getenv("CO_REDTEAM_DOCKER_IMAGE", "co-redteam-sandbox:latest"),
        docker_timeout=int(os.getenv("CO_REDTEAM_DOCKER_TIMEOUT", "60")),
        docker_memory_limit=os.getenv("CO_REDTEAM_DOCKER_MEMORY", "512m"),
        docker_cpu_quota=int(os.getenv("CO_REDTEAM_DOCKER_CPU_QUOTA", "100000")),
    )
