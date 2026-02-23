from pathlib import Path

from security_agents.benchmark import run_fixture


def test_run_fixture_missing_expected(tmp_path: Path):
    fixture = tmp_path / "fx"
    fixture.mkdir()
    result = run_fixture(fixture, profile="general")
    assert result["skipped"] is True
