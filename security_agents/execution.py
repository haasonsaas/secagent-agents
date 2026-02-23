from __future__ import annotations

from dataclasses import dataclass
import subprocess
from pathlib import Path
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
    )


def _render_command(template: str, item: dict[str, Any]) -> str:
    return template.format(
        id=item.get("id", ""),
        test_file=item.get("test_file_suggestion", ""),
        test_name=item.get("test_name", ""),
    )


def run_validation_execution(
    repo: Path,
    validation_items: list[dict[str, Any]],
    command_template: str | None,
    timeout_seconds: int,
    max_items: int,
) -> list[dict[str, Any]]:
    execution: list[dict[str, Any]] = []

    for item in validation_items[:max_items]:
        item_id = str(item.get("id", ""))
        commands = [str(c) for c in item.get("execution_commands", []) if str(c).strip()]
        if not commands and command_template:
            commands = [_render_command(command_template, item)]

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
            result = _run_command(command=command, cwd=repo, timeout_seconds=timeout_seconds)
            result.id = item_id
            result_payload = {
                "id": result.id,
                "command": result.command,
                "status": result.status,
                "exit_code": result.exit_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "error": result.error,
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
