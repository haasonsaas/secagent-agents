from pathlib import Path

from security_agents.codeowners import load_reviewer_aliases


def test_load_reviewer_aliases(tmp_path: Path):
    f = tmp_path / "aliases.yaml"
    f.write_text(
        """
aliases:
  sec-team:
    - alice
    - "@bob"
  lead: carol
""".strip()
    )
    aliases = load_reviewer_aliases(f)
    assert aliases["sec-team"] == ["alice", "bob"]
    assert aliases["lead"] == ["carol"]
