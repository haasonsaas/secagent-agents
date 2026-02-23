from pathlib import Path

from security_agents.profiles import resolve_config_path


def test_resolve_config_default_profile():
    path = resolve_config_path("general", None)
    assert path == Path("skills/default_security_skills.yaml")


def test_resolve_config_override_wins():
    path = resolve_config_path("general", "custom.yaml")
    assert path == Path("custom.yaml")


def test_resolve_new_profiles():
    assert resolve_config_path("llm", None) == Path("skills/llm_security_skills.yaml")
    assert resolve_config_path("fintech", None) == Path("skills/fintech_security_skills.yaml")
    assert resolve_config_path("health", None) == Path("skills/health_security_skills.yaml")
