from pathlib import Path

from security_agents.execution import detect_test_environment, run_validation_execution


def test_detect_test_environment(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies=['pytest']\n")
    (tmp_path / "package.json").write_text('{"devDependencies":{"jest":"^29.0.0"}}')
    env = detect_test_environment(tmp_path)
    assert env.has_pytest
    assert env.has_node
    assert env.has_jest


def test_fallback_validation_commands_with_template(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies=['pytest']\n")
    items = [
        {
            "id": "f-1",
            "test_file_suggestion": "tests/test_api.py",
            "test_name": "test_idor",
            "execution_commands": [],
        }
    ]

    results = run_validation_execution(
        repo=tmp_path,
        validation_items=items,
        command_template="echo RUN {test_file}::{test_name}",
        timeout_seconds=30,
        max_items=5,
    )
    assert results[0]["status"] == "passed"
    assert "RUN tests/test_api.py::test_idor" in results[0]["results"][0]["stdout"]
