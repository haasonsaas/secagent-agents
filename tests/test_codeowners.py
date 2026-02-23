from pathlib import Path

from security_agents.codeowners import (
    expand_owner_aliases,
    owners_for_paths,
    parse_codeowners,
    resolve_codeowners_path,
)


def test_parse_and_match_codeowners(tmp_path: Path):
    codeowners = tmp_path / "CODEOWNERS"
    codeowners.write_text(
        """
# comment
/auth/* @sec-team
/src/payments/ @payments-team @lead
*.py @python-team
""".strip()
    )

    rules = parse_codeowners(codeowners)
    owners = owners_for_paths(["auth/policy.txt", "src/payments/settle.ts", "app/main.py"], rules)
    assert "sec-team" in owners
    assert "payments-team" in owners
    assert "python-team" in owners


def test_resolve_codeowners_fallback(tmp_path: Path):
    (tmp_path / ".github").mkdir()
    p = tmp_path / ".github" / "CODEOWNERS"
    p.write_text("/src/* @team")
    resolved = resolve_codeowners_path(tmp_path, None)
    assert resolved == p


def test_expand_owner_aliases():
    owners = ["team-a", "alice"]
    aliases = {"team-a": ["bob", "carol"]}
    expanded = expand_owner_aliases(owners, aliases)
    assert expanded == ["bob", "carol", "alice"]
