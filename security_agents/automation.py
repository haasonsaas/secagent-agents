from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
import shutil
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


def _sanitize_slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip().lower()).strip("-")
    return slug[:48] or "group"


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
            tmp_path = Path(tmp.name)

        try:
            applied = _run(["git", "apply", "--index", str(tmp_path)], cwd=repo)
            if applied.returncode != 0:
                fallback = _run(["git", "apply", str(tmp_path)], cwd=repo)
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
        finally:
            tmp_path.unlink(missing_ok=True)

    return results


def get_staged_diff_stats(repo: Path) -> dict[str, Any]:
    diff = _run(["git", "diff", "--cached", "--numstat"], cwd=repo)
    if diff.returncode != 0:
        return {"files": 0, "added": 0, "deleted": 0, "paths": [], "error": diff.stderr.strip()}

    files = 0
    added = 0
    deleted = 0
    paths: list[str] = []
    for line in diff.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        add_s, del_s, path = parts[0], parts[1], parts[2]
        files += 1
        paths.append(path)
        try:
            added += int(add_s)
        except ValueError:
            pass
        try:
            deleted += int(del_s)
        except ValueError:
            pass
    return {"files": files, "added": added, "deleted": deleted, "paths": paths}


def validate_patch_guardrails(
    stats: dict[str, Any],
    max_files: int | None,
    max_changed_lines: int | None,
    deny_path_prefixes: list[str],
    allow_protected_paths: bool,
) -> tuple[bool, str]:
    files = int(stats.get("files", 0))
    changed_lines = int(stats.get("added", 0)) + int(stats.get("deleted", 0))
    paths = [str(p) for p in stats.get("paths", [])]

    if max_files is not None and files > max_files:
        return False, f"changed file count {files} exceeds max_files {max_files}"
    if max_changed_lines is not None and changed_lines > max_changed_lines:
        return False, f"changed lines {changed_lines} exceed max_changed_lines {max_changed_lines}"

    if deny_path_prefixes and not allow_protected_paths:
        for path in paths:
            for prefix in deny_path_prefixes:
                normalized = prefix.strip()
                if normalized and path.startswith(normalized):
                    return False, f"patch touches protected path '{normalized}' (file: {path})"

    return True, ""


def _create_pr_with_worktree(
    repo: Path,
    base: str,
    branch: str,
    title: str,
    body: str,
    draft: bool,
    commit_message: str,
    fixes: list[dict[str, Any]],
    max_files: int | None,
    max_changed_lines: int | None,
    deny_path_prefixes: list[str],
    allow_protected_paths: bool,
    labels: list[str],
    reviewers: list[str],
) -> dict[str, Any]:
    temp_dir = Path(tempfile.mkdtemp(prefix="secagent-pr-"))
    try:
        add = _run(["git", "worktree", "add", "--detach", str(temp_dir), base], cwd=repo)
        if add.returncode != 0:
            return {"ok": False, "error": add.stderr.strip() or "failed to create worktree"}

        checkout = _run(["git", "checkout", "-b", branch], cwd=temp_dir)
        if checkout.returncode != 0:
            return {"ok": False, "error": checkout.stderr.strip() or "failed to create branch in worktree"}

        apply_results = apply_fix_diffs(temp_dir, fixes)
        applied_count = sum(1 for item in apply_results if item.get("applied"))
        if applied_count == 0:
            return {
                "ok": False,
                "error": "no fixes were applied in worktree",
                "apply_results": apply_results,
            }

        add_changes = _run(["git", "add", "-A"], cwd=temp_dir)
        if add_changes.returncode != 0:
            return {"ok": False, "error": add_changes.stderr.strip() or "git add failed", "apply_results": apply_results}

        stats = get_staged_diff_stats(temp_dir)
        passed, reason = validate_patch_guardrails(
            stats=stats,
            max_files=max_files,
            max_changed_lines=max_changed_lines,
            deny_path_prefixes=deny_path_prefixes,
            allow_protected_paths=allow_protected_paths,
        )
        if not passed:
            return {"ok": False, "error": f"guardrail failed: {reason}", "apply_results": apply_results, "diff_stats": stats}

        commit = _run(["git", "commit", "-m", commit_message], cwd=temp_dir)
        if commit.returncode != 0:
            return {
                "ok": False,
                "error": commit.stderr.strip() or commit.stdout.strip() or "git commit failed",
                "apply_results": apply_results,
            }

        push = _run(["git", "push", "-u", "origin", branch], cwd=temp_dir)
        if push.returncode != 0:
            return {"ok": False, "error": push.stderr.strip() or "git push failed", "apply_results": apply_results}

        pr_cmd = ["gh", "pr", "create", "--base", base, "--head", branch, "--title", title, "--body", body]
        for label in labels:
            pr_cmd.extend(["--label", label])
        for reviewer in reviewers:
            pr_cmd.extend(["--reviewer", reviewer])
        if draft:
            pr_cmd.append("--draft")
        pr = _run(pr_cmd, cwd=temp_dir)
        if pr.returncode != 0:
            return {
                "ok": False,
                "error": pr.stderr.strip() or pr.stdout.strip() or "gh pr create failed",
                "apply_results": apply_results,
            }

        return {
            "ok": True,
            "branch": branch,
            "pr_url": pr.stdout.strip(),
            "apply_results": apply_results,
            "diff_stats": stats,
        }
    finally:
        _run(["git", "worktree", "remove", "--force", str(temp_dir)], cwd=repo)
        shutil.rmtree(temp_dir, ignore_errors=True)


def create_pr_for_changes(
    repo: Path,
    base: str,
    branch: str | None,
    title: str,
    body: str,
    draft: bool,
    commit_message: str,
    fixes: list[dict[str, Any]],
    max_files: int | None,
    max_changed_lines: int | None,
    deny_path_prefixes: list[str],
    allow_protected_paths: bool,
    labels: list[str],
    reviewers: list[str],
) -> dict[str, Any]:
    final_branch = branch or f"secagent/auto-fixes-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    return _create_pr_with_worktree(
        repo=repo,
        base=base,
        branch=final_branch,
        title=title,
        body=body,
        draft=draft,
        commit_message=commit_message,
        fixes=fixes,
        max_files=max_files,
        max_changed_lines=max_changed_lines,
        deny_path_prefixes=deny_path_prefixes,
        allow_protected_paths=allow_protected_paths,
        labels=labels,
        reviewers=reviewers,
    )


def create_multi_prs_for_groups(
    repo: Path,
    base: str,
    groups: list[dict[str, Any]],
    title_prefix: str,
    body_prefix: str,
    draft: bool,
    commit_message_prefix: str,
    max_files: int | None,
    max_changed_lines: int | None,
    deny_path_prefixes: list[str],
    allow_protected_paths: bool,
    labels: list[str],
    reviewers: list[str],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

    for index, group in enumerate(groups, start=1):
        label = str(group.get("label", f"group-{index}"))
        fixes = list(group.get("fixes", []))
        if not fixes:
            results.append({"ok": False, "label": label, "error": "empty fix group"})
            continue

        slug = _sanitize_slug(label)
        branch = f"secagent/{slug}-{now}-{index}"
        title = f"{title_prefix} [{label}]"
        body = f"{body_prefix}\n\nGroup: {label}\nFixes: {len(fixes)}"
        commit_message = f"{commit_message_prefix} ({label})"

        created = _create_pr_with_worktree(
            repo=repo,
            base=base,
            branch=branch,
            title=title,
            body=body,
            draft=draft,
            commit_message=commit_message,
            fixes=fixes,
            max_files=max_files,
            max_changed_lines=max_changed_lines,
            deny_path_prefixes=deny_path_prefixes,
            allow_protected_paths=allow_protected_paths,
            labels=labels,
            reviewers=reviewers,
        )
        created["label"] = label
        created["fix_count"] = len(fixes)
        results.append(created)

    return results
