from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import subprocess
import tempfile
from typing import Any


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=str(cwd), capture_output=True, text=True, check=False)


def ensure_clean_git_repo(repo: Path) -> tuple[bool, str]:
    status = _run(["git", "status", "--porcelain"], cwd=repo)
    if status.returncode != 0:
        return False, status.stderr.strip() or "failed to run git status"
    if status.stdout.strip():
        return False, "repository has uncommitted changes"
    return True, ""


def apply_fix_diffs(repo: Path, fixes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for fix in fixes:
        fix_id = str(fix.get("id", ""))
        diff_text = str(fix.get("patch_diff", ""))
        if not diff_text.strip():
            results.append({"id": fix_id, "applied": False, "error": "missing patch_diff"})
            continue

        with tempfile.NamedTemporaryFile("w", suffix=".diff", delete=False) as tmp:
            tmp.write(diff_text)
            tmp_path = tmp.name

        applied = _run(["git", "apply", "--index", tmp_path], cwd=repo)
        if applied.returncode != 0:
            fallback = _run(["git", "apply", tmp_path], cwd=repo)
            if fallback.returncode != 0:
                results.append(
                    {
                        "id": fix_id,
                        "applied": False,
                        "error": (applied.stderr.strip() or fallback.stderr.strip() or "git apply failed"),
                    }
                )
                continue

        results.append({"id": fix_id, "applied": True, "error": None})

    return results


def create_pr_for_changes(
    repo: Path,
    base: str,
    branch: str | None,
    title: str,
    body: str,
    draft: bool,
    commit_message: str,
) -> dict[str, Any]:
    final_branch = branch or f"secagent/auto-fixes-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    checkout = _run(["git", "checkout", "-b", final_branch], cwd=repo)
    if checkout.returncode != 0:
        return {"ok": False, "error": checkout.stderr.strip() or "failed to create branch"}

    add = _run(["git", "add", "-A"], cwd=repo)
    if add.returncode != 0:
        return {"ok": False, "error": add.stderr.strip() or "git add failed"}

    commit = _run(["git", "commit", "-m", commit_message], cwd=repo)
    if commit.returncode != 0:
        return {"ok": False, "error": commit.stderr.strip() or commit.stdout.strip() or "git commit failed"}

    push = _run(["git", "push", "-u", "origin", final_branch], cwd=repo)
    if push.returncode != 0:
        return {"ok": False, "error": push.stderr.strip() or "git push failed"}

    pr_cmd = ["gh", "pr", "create", "--base", base, "--head", final_branch, "--title", title, "--body", body]
    if draft:
        pr_cmd.append("--draft")
    pr = _run(pr_cmd, cwd=repo)
    if pr.returncode != 0:
        return {"ok": False, "error": pr.stderr.strip() or pr.stdout.strip() or "gh pr create failed"}

    return {
        "ok": True,
        "branch": final_branch,
        "pr_url": pr.stdout.strip(),
    }
