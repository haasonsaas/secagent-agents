from __future__ import annotations

from pathlib import Path

PROFILE_CONFIGS = {
    "general": Path("skills/default_security_skills.yaml"),
    "llm": Path("skills/llm_security_skills.yaml"),
}


def resolve_config_path(profile: str, config_override: str | None) -> Path:
    if config_override:
        return Path(config_override)
    if profile not in PROFILE_CONFIGS:
        raise ValueError(f"Unknown profile: {profile}")
    return PROFILE_CONFIGS[profile]
