from __future__ import annotations

from dataclasses import dataclass
import shlex
import subprocess
from pathlib import Path
import shutil
import tempfile
from typing import Any


@dataclass
class ValidationExecutionResult:
    id: str
    command: str
    status: str
    exit_code: int | None
    stdout: str
    stderr: str
    error: str | None
    cwd: str


@dataclass
class TestEnvironment:
    has_pytest: bool
    has_go: bool
    has_jest: bool
    has_node: bool
    has_rust: bool


MANIFEST_FILES = ["pyproject.toml", "go.mod", "package.json", "Cargo.toml", "requirements.txt"]


def detect_test_environment(repo: Path) -> TestEnvironment:
    pyproject = repo / "pyproject.toml"
    requirements = repo / "requirements.txt"
    go_mod = repo / "go.mod"
    package_json = repo / "package.json"
    cargo = repo / "Cargo.toml"

    pyproject_text = pyproject.read_text(errors="ignore") if pyproject.exists() else ""
    requirements_text = requirements.read_text(errors="ignore") if requirements.exists() else ""
    package_json_text = package_json.read_text(errors="ignore") if package_json.exists() else ""

    has_pytest = "pytest" in pyproject_text or "pytest" in requirements_text
    has_go = go_mod.exists()
    has_node = package_json.exists()
    has_jest = "jest" in package_json_text
    has_rust = cargo.exists()

    return TestEnvironment(
        has_pytest=has_pytest,
        has_go=has_go,
        has_jest=has_jest,
        has_node=has_node,
        has_rust=has_rust,
    )


def _find_project_root(repo: Path, test_file: str) -> Path:
    candidate = (repo / test_file).resolve()
    if not candidate.exists():
        return repo
    current = candidate.parent
    repo_resolved = repo.resolve()
    while str(current).startswith(str(repo_resolved)):
        if any((current / name).exists() for name in MANIFEST_FILES):
            return current
        if current == repo_resolved:
            break
        current = current.parent
    return repo


def _run_command(command: str, cwd: Path, timeout_seconds: int) -> ValidationExecutionResult:
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd),
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return ValidationExecutionResult(
            id="",
            command=command,
            status="error",
            exit_code=None,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
            error=f"timeout after {timeout_seconds}s",
            cwd=str(cwd),
        )
    except Exception as exc:  # pragma: no cover - defensive
        return ValidationExecutionResult(
            id="",
            command=command,
            status="error",
            exit_code=None,
            stdout="",
            stderr="",
            error=str(exc),
            cwd=str(cwd),
        )

    status = "failed" if completed.returncode != 0 else "passed"
    return ValidationExecutionResult(
        id="",
        command=command,
        status=status,
        exit_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        error=None,
        cwd=str(cwd),
    )


def _render_command(template: str, item: dict[str, Any], project_root: Path) -> str:
    return template.format(
        id=item.get("id", ""),
        test_file=item.get("test_file_suggestion", ""),
        test_name=item.get("test_name", ""),
        project_root=str(project_root),
    )


def _infer_fallback_commands(item: dict[str, Any], env: TestEnvironment) -> list[str]:
    test_file = str(item.get("test_file_suggestion", "")).strip()
    test_name = str(item.get("test_name", "")).strip()

    if test_file.endswith(".py") and env.has_pytest:
        file_part = shlex.quote(test_file) if test_file else ""
        name_part = f" -k {shlex.quote(test_name)}" if test_name else ""
        return [f"pytest {file_part}{name_part}".strip()]

    if test_file.endswith(".go") and env.has_go:
        name_part = f" -run {shlex.quote(test_name)}" if test_name else ""
        return [f"go test ./...{name_part}".strip()]

    if any(test_file.endswith(ext) for ext in [".ts", ".tsx", ".js", ".jsx"]) and env.has_node:
        if env.has_jest:
            file_part = f" {shlex.quote(test_file)}" if test_file else ""
            name_part = f" -t {shlex.quote(test_name)}" if test_name else ""
            return [f"npx jest{file_part}{name_part}".strip()]
        return ["npm test -- --runInBand"]

    if test_file.endswith(".rs") and env.has_rust:
        name_part = f" {shlex.quote(test_name)}" if test_name else ""
        return [f"cargo test{name_part}".strip()]

    if env.has_pytest:
        return ["pytest"]
    if env.has_go:
        return ["go test ./..."]
    if env.has_jest:
        return ["npx jest"]
    if env.has_node:
        return ["npm test"]
    if env.has_rust:
        return ["cargo test"]
    return []


def run_validation_execution(
    repo: Path,
    validation_items: list[dict[str, Any]],
    command_template: str | None,
    timeout_seconds: int,
    max_items: int,
) -> list[dict[str, Any]]:
    execution: list[dict[str, Any]] = []
    env = detect_test_environment(repo)

    for item in validation_items[:max_items]:
        item_id = str(item.get("id", ""))
        test_file = str(item.get("test_file_suggestion", "")).strip()
        project_root = _find_project_root(repo, test_file)
        commands = [str(c) for c in item.get("execution_commands", []) if str(c).strip()]
        if not commands and command_template:
            commands = [_render_command(command_template, item, project_root)]
        if not commands:
            commands = _infer_fallback_commands(item, env)

        if not commands:
            execution.append(
                {
                    "id": item_id,
                    "status": "skipped",
                    "reason": "no execution command available",
                    "results": [],
                }
            )
            continue

        results: list[dict[str, Any]] = []
        final_status = "passed"
        for command in commands:
            result = _run_command(command=command, cwd=project_root, timeout_seconds=timeout_seconds)
            result.id = item_id
            result_payload = {
                "id": result.id,
                "command": result.command,
                "status": result.status,
                "exit_code": result.exit_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "error": result.error,
                "cwd": result.cwd,
            }
            results.append(result_payload)
            if result.status == "failed":
                final_status = "failed"
                break
            if result.status == "error" and final_status != "failed":
                final_status = "error"

        execution.append(
            {
                "id": item_id,
                "status": final_status,
                "results": results,
            }
        )

    return execution


def run_validation_execution_in_worktree(
    repo: Path,
    validation_items: list[dict[str, Any]],
    command_template: str | None,
    timeout_seconds: int,
    max_items: int,
    base_ref: str = "HEAD",
) -> list[dict[str, Any]]:
    temp_dir = Path(tempfile.mkdtemp(prefix="secagent-validate-"))
    try:
        add = subprocess.run(
            ["git", "worktree", "add", "--detach", str(temp_dir), base_ref],
            cwd=str(repo),
            capture_output=True,
            text=True,
            check=False,
        )
        if add.returncode != 0:
            return [
                {
                    "id": "",
                    "status": "error",
                    "reason": add.stderr.strip() or "failed to create validation worktree",
                    "results": [],
                }
            ]
        return run_validation_execution(
            repo=temp_dir,
            validation_items=validation_items,
            command_template=command_template,
            timeout_seconds=timeout_seconds,
            max_items=max_items,
        )
    finally:
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(temp_dir)],
            cwd=str(repo),
            capture_output=True,
            text=True,
            check=False,
        )
        shutil.rmtree(temp_dir, ignore_errors=True)
