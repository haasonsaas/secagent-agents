from pathlib import Path

from security_agents.codeowners import owners_for_paths, parse_codeowners


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
