from pathlib import Path

from security_agents.profiles import resolve_config_path


def test_resolve_config_default_profile():
    path = resolve_config_path("general", None)
    assert path == Path("skills/default_security_skills.yaml")


def test_resolve_config_override_wins():
    path = resolve_config_path("general", "custom.yaml")
    assert path == Path("custom.yaml")
