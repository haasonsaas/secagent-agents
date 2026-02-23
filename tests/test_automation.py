from security_agents.automation import validate_patch_guardrails


def test_validate_patch_guardrails_limits():
    stats = {"files": 3, "added": 50, "deleted": 20, "paths": ["src/a.py", "src/b.py"]}
    ok, reason = validate_patch_guardrails(stats, max_files=5, max_changed_lines=100, deny_path_prefixes=[], allow_protected_paths=False)
    assert ok
    assert reason == ""


def test_validate_patch_guardrails_protected_path():
    stats = {"files": 1, "added": 5, "deleted": 1, "paths": ["auth/policy.py"]}
    ok, reason = validate_patch_guardrails(
        stats,
        max_files=5,
        max_changed_lines=100,
        deny_path_prefixes=["auth/"],
        allow_protected_paths=False,
    )
    assert not ok
    assert "protected path" in reason
