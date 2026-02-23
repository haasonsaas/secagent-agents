from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any

import yaml


@dataclass
class VulnerabilityClass:
    name: str
    description: str
    detector_instructions: str
    manager_checks: list[str]


@dataclass
class AppConfig:
    profile_name: str
    profile_version: str
    model: str
    max_file_bytes: int
    max_files: int
    include_globs: list[str]
    exclude_globs: list[str]
    stage_timeout_seconds: int
    max_validation_items: int
    max_fix_items: int
    use_context_cache: bool
    vulnerability_classes: list[VulnerabilityClass]


DEFAULT_CONFIG_PATH = Path("skills/default_security_skills.yaml")


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def load_config(path: str | Path | None = None) -> AppConfig:
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH
    raw = yaml.safe_load(config_path.read_text())

    vulns: list[VulnerabilityClass] = []
    for item in raw.get("vulnerability_classes", []):
        vulns.append(
            VulnerabilityClass(
                name=str(item["name"]),
                description=str(item["description"]),
                detector_instructions=str(item["detector_instructions"]),
                manager_checks=_as_list(item.get("manager_checks")),
            )
        )

    if not vulns:
        raise ValueError("No vulnerability classes found in config")

    model = os.getenv("OPENAI_MODEL", str(raw.get("model", "gpt-4.1")))
    max_file_bytes = int(raw.get("max_file_bytes", 12000))
    max_files = int(raw.get("max_files", 80))
    stage_timeout_seconds = int(raw.get("stage_timeout_seconds", 180))
    max_validation_items = int(raw.get("max_validation_items", 100))
    max_fix_items = int(raw.get("max_fix_items", 100))
    use_context_cache = bool(raw.get("use_context_cache", True))
    if max_file_bytes <= 0:
        raise ValueError("max_file_bytes must be > 0")
    if max_files <= 0:
        raise ValueError("max_files must be > 0")
    if stage_timeout_seconds <= 0:
        raise ValueError("stage_timeout_seconds must be > 0")
    if max_validation_items <= 0:
        raise ValueError("max_validation_items must be > 0")
    if max_fix_items <= 0:
        raise ValueError("max_fix_items must be > 0")

    return AppConfig(
        profile_name=str(raw.get("profile_name", "custom")),
        profile_version=str(raw.get("profile_version", "1")),
        model=model,
        max_file_bytes=max_file_bytes,
        max_files=max_files,
        include_globs=_as_list(raw.get("include_globs", ["**/*.py", "**/*.ts", "**/*.tsx", "**/*.js", "**/*.go"])),
        exclude_globs=_as_list(raw.get("exclude_globs", ["**/node_modules/**", "**/.git/**", "**/.venv/**", "**/dist/**", "**/build/**"])),
        stage_timeout_seconds=stage_timeout_seconds,
        max_validation_items=max_validation_items,
        max_fix_items=max_fix_items,
        use_context_cache=use_context_cache,
        vulnerability_classes=vulns,
    )
