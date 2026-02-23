from security_agents.config import load_config


def test_load_general_profile_metadata():
    cfg = load_config("skills/default_security_skills.yaml")
    assert cfg.profile_name == "general"
    assert cfg.profile_version == "2"
    assert cfg.stage_timeout_seconds > 0


def test_load_llm_profile_metadata():
    cfg = load_config("skills/llm_security_skills.yaml")
    assert cfg.profile_name == "llm"
    assert cfg.profile_version == "1"


def test_load_fintech_and_health_profiles():
    fintech = load_config("skills/fintech_security_skills.yaml")
    health = load_config("skills/health_security_skills.yaml")
    assert fintech.profile_name == "fintech"
    assert health.profile_name == "health"
    assert len(fintech.vulnerability_classes) >= 5
    assert len(health.vulnerability_classes) >= 5
