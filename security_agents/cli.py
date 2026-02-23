from __future__ import annotations

import argparse
from collections import defaultdict
import json
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import uuid

from security_agents.automation import (
    apply_fix_diffs,
    create_multi_prs_for_groups,
    create_pr_for_changes,
    ensure_clean_git_repo,
    get_staged_diff_stats,
    validate_patch_guardrails,
)
from security_agents.codeowners import owners_for_paths, parse_codeowners
from security_agents.config import load_config
from security_agents.execution import run_validation_execution, run_validation_execution_in_worktree
from security_agents.history import annotate_new_findings
from security_agents.pipeline import run_pipeline
from security_agents.policy import load_policy
from security_agents.profiles import resolve_config_path
from security_agents.reporting import findings_to_sarif
from security_agents.selection import (
    SEVERITY_ORDER,
    filter_and_rank_fixes,
    finding_risk_score,
    finding_severity,
    summarize_findings_by_class,
)
from security_agents.suppression import apply_suppressions, load_suppressions
from security_agents.telemetry import append_metrics_jsonl


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a detector-manager-validator-fixer security pipeline")
    parser.add_argument("--repo", default=".", help="Path to target repository")
    parser.add_argument(
        "--profile",
        choices=["general", "llm", "fintech", "health"],
        default="general",
        help="Built-in skill profile to use when --config is not set.",
    )
    parser.add_argument("--config", default=None, help="Path to YAML config")
    parser.add_argument("--policy", default="secagent.policy.yaml", help="Policy file path (policy-as-code).")
    parser.add_argument("--suppressions", default="secagent.ignore.yaml", help="Suppression file path.")
    parser.add_argument("--out", default="security_report.json", help="Output JSON file")
    parser.add_argument(
        "--sarif-out",
        default=None,
        help="Optional SARIF output path (e.g. secagent.sarif).",
    )
    parser.add_argument(
        "--sarif-scope",
        choices=["accepted", "validated"],
        default=None,
        help="Scope of findings exported to SARIF. Defaults to validated when --run-validation is enabled, otherwise accepted.",
    )
    parser.add_argument(
        "--artifacts-dir",
        default=".secagent_runs",
        help="Directory for per-run stage artifacts and metadata.",
    )
    parser.add_argument(
        "--metrics-jsonl",
        default=".secagent_runs/metrics.jsonl",
        help="JSONL path for run telemetry metrics.",
    )
    parser.add_argument("--changed-only", action="store_true", help="Scan only changed files (plus focus radius).")
    parser.add_argument("--changed-base", default="origin/main", help="Git base ref used with --changed-only.")
    parser.add_argument(
        "--changed-radius",
        type=int,
        default=1,
        help="Directory radius for additional context around changed files.",
    )
    parser.add_argument(
        "--new-only",
        action="store_true",
        help="Only select fixes for findings not seen in prior runs (fingerprint-based).",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Write only high-level counts and accepted findings (skip rejected/validation/fixes payloads).",
    )
    parser.add_argument(
        "--fail-on-severity",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="Exit non-zero if any accepted finding is at or above this severity.",
    )
    parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Only include fixes for findings at or above this severity.",
    )
    parser.add_argument(
        "--only-severity",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="Only include fixes for findings at exactly this severity.",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        help="Only include fixes for findings with confidence >= this value (0..1).",
    )
    parser.add_argument(
        "--min-risk-score",
        type=float,
        default=0.0,
        help="Only include fixes for findings with composite risk score >= this value (0..1).",
    )
    parser.add_argument(
        "--max-fixes",
        type=int,
        default=None,
        help="Maximum number of fixes to apply/create PRs for after filtering and ranking.",
    )
    parser.add_argument(
        "--run-validation",
        action="store_true",
        help="Execute validator-provided test commands against --repo.",
    )
    parser.add_argument(
        "--validation-in-worktree",
        action="store_true",
        help="Run validation in an isolated temporary git worktree.",
    )
    parser.add_argument(
        "--validation-gate",
        choices=["none", "pre", "pre-post"],
        default="none",
        help="Validation gate mode: pre (must reproduce before fix) or pre-post (must reproduce before and pass after apply).",
    )
    parser.add_argument(
        "--validation-command-template",
        default=None,
        help="Fallback command template if validator does not provide execution_commands. Supports {id}, {test_file}, {test_name}, {project_root}.",
    )
    parser.add_argument(
        "--validation-timeout-seconds",
        type=int,
        default=120,
        help="Timeout for each validation command.",
    )
    parser.add_argument(
        "--validation-max-items",
        type=int,
        default=20,
        help="Maximum number of validation items to execute.",
    )
    parser.add_argument(
        "--apply-fixes",
        action="store_true",
        help="Attempt to apply generated patch diffs with git apply.",
    )
    parser.add_argument(
        "--allow-dirty-repo",
        action="store_true",
        help="Allow applying fixes in a repo with existing uncommitted changes.",
    )
    parser.add_argument(
        "--guardrail-max-files",
        type=int,
        default=60,
        help="Maximum number of changed files allowed in an automated patch.",
    )
    parser.add_argument(
        "--guardrail-max-lines",
        type=int,
        default=1200,
        help="Maximum added+deleted lines allowed in an automated patch.",
    )
    parser.add_argument(
        "--guardrail-protected-path",
        action="append",
        default=[],
        help="Path prefix that requires manual override if touched. Can be set multiple times.",
    )
    parser.add_argument(
        "--allow-protected-paths",
        action="store_true",
        help="Allow automated patches to touch protected path prefixes.",
    )
    parser.add_argument(
        "--create-pr",
        action="store_true",
        help="Create branch, commit, push, and open a PR with applied fixes (requires --apply-fixes).",
    )
    parser.add_argument("--pr-base", default="main", help="Base branch for PR creation.")
    parser.add_argument("--pr-branch", default=None, help="Override PR branch name.")
    parser.add_argument("--pr-title", default="secagent: automated security fixes", help="PR title.")
    parser.add_argument(
        "--pr-body",
        default=(
            "Automated security fixes generated by secagent.\n\n"
            "- Detector/manager triage completed\n"
            "- Validation stage executed where configured\n"
            "- Minimal patch diffs applied automatically\n"
        ),
        help="PR body.",
    )
    parser.add_argument("--pr-draft", action="store_true", help="Open the PR as draft.")
    parser.add_argument("--pr-label", action="append", default=[], help="Label to apply to created PR(s).")
    parser.add_argument("--pr-reviewer", action="append", default=[], help="Reviewer to request on created PR(s).")
    parser.add_argument(
        "--auto-reviewers-from-codeowners",
        action="store_true",
        help="Automatically request reviewers from CODEOWNERS based on files_to_change.",
    )
    parser.add_argument(
        "--codeowners-path",
        default="CODEOWNERS",
        help="Path to CODEOWNERS file used with --auto-reviewers-from-codeowners.",
    )
    parser.add_argument(
        "--multi-pr-mode",
        choices=["none", "class", "severity", "class-severity"],
        default="none",
        help="Split fixes into multiple PRs by vulnerability class/severity.",
    )
    parser.add_argument(
        "--multi-pr-limit",
        type=int,
        default=10,
        help="Maximum number of multi-PR groups to create.",
    )
    parser.add_argument(
        "--commit-message",
        default="secagent: apply automated security fixes",
        help="Commit message used for PR flow.",
    )
    return parser.parse_args()


def _build_fix_lookup(accepted_findings: list[dict]) -> dict[str, dict]:
    return {str(item.get("id", "")): item for item in accepted_findings}


def _group_key_for_fix(fix: dict, lookup: dict[str, dict], mode: str) -> str:
    fix_id = str(fix.get("id", ""))
    finding = lookup.get(fix_id, {})
    vuln_class = str(finding.get("vulnerability_class", "unknown-class"))
    severity = finding_severity(finding)
    if mode == "class":
        return vuln_class
    if mode == "severity":
        return severity
    if mode == "class-severity":
        return f"{vuln_class} :: {severity}"
    return "all"


def _write_artifacts(artifacts_root: Path, run_id: str, payload: dict) -> Path:
    run_dir = artifacts_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "report.json").write_text(json.dumps(payload, indent=2))
    return run_dir


def _changed_files(repo: Path, base_ref: str) -> set[str]:
    diff = subprocess.run(
        ["git", "diff", "--name-only", f"{base_ref}...HEAD"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=False,
    )
    if diff.returncode != 0:
        return set()
    return {line.strip() for line in diff.stdout.splitlines() if line.strip()}


def main() -> int:
    args = parse_args()
    repo = Path(args.repo).resolve()
    config_path = resolve_config_path(args.profile, args.config)
    config = load_config(config_path)
    policy = load_policy(args.policy)

    suppressions = load_suppressions(args.suppressions)

    if args.min_confidence < 0 or args.min_confidence > 1:
        raise ValueError("--min-confidence must be between 0 and 1")
    if args.min_risk_score < 0 or args.min_risk_score > 1:
        raise ValueError("--min-risk-score must be between 0 and 1")
    if args.max_fixes is not None and args.max_fixes < 0:
        raise ValueError("--max-fixes must be >= 0")
    if args.validation_gate != "none" and not args.run_validation:
        raise ValueError("--validation-gate requires --run-validation")
    if args.create_pr and not args.apply_fixes:
        raise ValueError("--create-pr requires --apply-fixes")
    if args.multi_pr_limit <= 0:
        raise ValueError("--multi-pr-limit must be > 0")

    changed_files = _changed_files(repo, args.changed_base) if args.changed_only else set()

    output = run_pipeline(
        repo,
        config,
        focus_files=changed_files if args.changed_only else None,
        focus_radius=args.changed_radius,
    )

    output.accepted_findings, new_count = annotate_new_findings(repo, output.accepted_findings)
    unsuppressed, suppressed_entries = apply_suppressions(output.accepted_findings, suppressions)
    output.accepted_findings = unsuppressed

    run_id = uuid.uuid4().hex[:12]
    generated_at = datetime.now(timezone.utc).isoformat()

    severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for finding in output.accepted_findings:
        severity_counts[finding_severity(finding)] += 1
    class_summary = summarize_findings_by_class(output.accepted_findings)

    validation_execution_pre: list[dict] = []
    validation_execution_post: list[dict] = []
    failed_validation_ids: set[str] = set()

    effective_min_confidence = max(args.min_confidence, policy.min_confidence)
    effective_min_risk = max(args.min_risk_score, policy.min_risk_score)
    protected_paths = args.guardrail_protected_path or policy.deny_path_prefixes

    selected_fixes = filter_and_rank_fixes(
        accepted_findings=output.accepted_findings,
        fixes=output.fixes,
        min_confidence=effective_min_confidence,
        min_risk_score=effective_min_risk,
        min_severity=args.min_severity,
        only_severity=args.only_severity,
        max_fixes=args.max_fixes,
        new_only=args.new_only,
    )
    filtered_fixes = selected_fixes

    if policy.require_validation_for_critical and not args.run_validation:
        has_critical = any(finding_severity(f) == "critical" for f in output.accepted_findings)
        if has_critical:
            raise RuntimeError("Policy requires validation when critical findings exist.")

    if args.run_validation:
        runner = run_validation_execution_in_worktree if args.validation_in_worktree else run_validation_execution
        validation_execution_pre = runner(
            repo=repo,
            validation_items=output.validation,
            command_template=args.validation_command_template,
            timeout_seconds=args.validation_timeout_seconds,
            max_items=args.validation_max_items,
        )
        failed_validation_ids = {
            str(item.get("id", "")) for item in validation_execution_pre if item.get("status") == "failed"
        }
        filtered_fixes = [fix for fix in selected_fixes if str(fix.get("id", "")) in failed_validation_ids]
        if args.validation_gate in {"pre", "pre-post"} and not filtered_fixes:
            raise RuntimeError("Validation gate failed: no findings reproduced pre-fix.")

    apply_results: list[dict] = []
    pr_result: dict | None = None
    pr_results: list[dict] = []
    guardrail_stats: dict | None = None
    auto_reviewers: list[str] = []
    reviewers: list[str] = list(args.pr_reviewer)

    if args.apply_fixes and not args.create_pr:
        if not args.allow_dirty_repo:
            clean, reason = ensure_clean_git_repo(repo)
            if not clean:
                raise RuntimeError(f"Refusing to apply fixes: {reason}. Use --allow-dirty-repo to override.")
        apply_results = apply_fix_diffs(repo, filtered_fixes)
        add_all = subprocess.run(["git", "add", "-A"], cwd=str(repo), capture_output=True, text=True)
        if add_all.returncode != 0:
            raise RuntimeError(add_all.stderr.strip() or "git add failed after patch apply")
        guardrail_stats = get_staged_diff_stats(repo)
        passed, reason = validate_patch_guardrails(
            stats=guardrail_stats,
            max_files=args.guardrail_max_files,
            max_changed_lines=args.guardrail_max_lines,
            deny_path_prefixes=protected_paths,
            allow_protected_paths=args.allow_protected_paths,
        )
        if not passed:
            raise RuntimeError(f"Patch guardrail failed: {reason}")

        if args.validation_gate == "pre-post":
            fixed_ids = {str(item.get("id", "")) for item in apply_results if item.get("applied")}
            target_validation = [item for item in output.validation if str(item.get("id", "")) in fixed_ids]
            runner = run_validation_execution_in_worktree if args.validation_in_worktree else run_validation_execution
            validation_execution_post = runner(
                repo=repo,
                validation_items=target_validation,
                command_template=args.validation_command_template,
                timeout_seconds=args.validation_timeout_seconds,
                max_items=args.validation_max_items,
            )
            not_passing = [item for item in validation_execution_post if item.get("status") != "passed"]
            if not_passing:
                raise RuntimeError("Validation gate failed: some fixed findings did not pass post-fix validation.")

    if args.create_pr:
        if args.validation_gate == "pre-post":
            raise RuntimeError("--validation-gate pre-post is only supported for local --apply-fixes runs (without --create-pr).")
        if not filtered_fixes:
            raise RuntimeError("No fixes selected; refusing to create PR.")
        if args.auto_reviewers_from_codeowners:
            rules = parse_codeowners(args.codeowners_path)
            candidate_paths: list[str] = []
            for fix in filtered_fixes:
                for path in fix.get("files_to_change", []) or []:
                    path_s = str(path)
                    if path_s and path_s not in candidate_paths:
                        candidate_paths.append(path_s)
            auto_reviewers = owners_for_paths(candidate_paths, rules)
        reviewers = list(dict.fromkeys(args.pr_reviewer + auto_reviewers))

        if args.multi_pr_mode == "none":
            pr_result = create_pr_for_changes(
                repo=repo,
                base=args.pr_base,
                branch=args.pr_branch,
                title=args.pr_title,
                body=args.pr_body,
                draft=args.pr_draft,
                commit_message=args.commit_message,
                fixes=filtered_fixes,
                max_files=args.guardrail_max_files,
                max_changed_lines=args.guardrail_max_lines,
                deny_path_prefixes=protected_paths,
                allow_protected_paths=args.allow_protected_paths,
                labels=args.pr_label,
                reviewers=reviewers,
            )
            if not pr_result.get("ok"):
                raise RuntimeError(f"PR creation failed: {pr_result.get('error', 'unknown error')}")
            apply_results = list(pr_result.get("apply_results", []))
            guardrail_stats = pr_result.get("diff_stats")
        else:
            lookup = _build_fix_lookup(output.accepted_findings)
            grouped: dict[str, list[dict]] = defaultdict(list)
            for fix in filtered_fixes:
                grouped[_group_key_for_fix(fix, lookup, args.multi_pr_mode)].append(fix)
            group_items = [
                {"label": label, "fixes": fixes}
                for label, fixes in sorted(grouped.items(), key=lambda pair: pair[0])[: args.multi_pr_limit]
            ]
            if not group_items:
                raise RuntimeError("No fix groups to create PRs for.")
            pr_results = create_multi_prs_for_groups(
                repo=repo,
                base=args.pr_base,
                groups=group_items,
                title_prefix=args.pr_title,
                body_prefix=args.pr_body,
                draft=args.pr_draft,
                commit_message_prefix=args.commit_message,
                max_files=args.guardrail_max_files,
                max_changed_lines=args.guardrail_max_lines,
                deny_path_prefixes=protected_paths,
                allow_protected_paths=args.allow_protected_paths,
                labels=args.pr_label,
                reviewers=reviewers,
            )
            if not any(item.get("ok") for item in pr_results):
                raise RuntimeError("Multi-PR creation failed for all groups.")

    risk_summary = {
        "avg_risk": round(
            sum(finding_risk_score(finding) for finding in output.accepted_findings) / max(len(output.accepted_findings), 1),
            4,
        ),
        "max_risk": max([finding_risk_score(finding) for finding in output.accepted_findings], default=0.0),
    }

    payload = {
        "run_id": run_id,
        "generated_at": generated_at,
        "repo": str(repo),
        "profile": args.profile,
        "profile_name": config.profile_name,
        "profile_version": config.profile_version,
        "config_path": str(config_path),
        "model": config.model,
        "context_cache": {
            "enabled": config.use_context_cache,
            "hit": output.context_cache_hit,
            "key": output.context_cache_key,
        },
        "diff_scope": {
            "changed_only": args.changed_only,
            "changed_base": args.changed_base,
            "changed_radius": args.changed_radius,
            "changed_file_count": len(changed_files),
            "changed_files": sorted(changed_files),
        },
        "budgets": {
            "stage_timeout_seconds": config.stage_timeout_seconds,
            "max_validation_items": config.max_validation_items,
            "max_fix_items": config.max_fix_items,
        },
        "scanned_file_count": len(output.scanned_files),
        "scanned_files": output.scanned_files,
        "severity_counts": severity_counts,
        "class_summary": class_summary,
        "risk_summary": risk_summary,
        "selection": {
            "min_severity": args.min_severity,
            "only_severity": args.only_severity,
            "min_confidence": effective_min_confidence,
            "min_risk_score": effective_min_risk,
            "max_fixes": args.max_fixes,
            "new_only": args.new_only,
            "selected_fix_count_pre_validation": len(selected_fixes),
            "new_findings_count": new_count,
        },
        "policy": {
            "path": args.policy,
            "effective": {
                "min_confidence": policy.min_confidence,
                "min_risk_score": policy.min_risk_score,
                "require_validation_for_critical": policy.require_validation_for_critical,
                "deny_path_prefixes": policy.deny_path_prefixes,
            },
        },
        "suppressions": {
            "path": args.suppressions,
            "count": len(suppressed_entries),
            "entries": suppressed_entries,
        },
        "guardrails": {
            "max_files": args.guardrail_max_files,
            "max_lines": args.guardrail_max_lines,
            "protected_paths": protected_paths,
            "allow_protected_paths": args.allow_protected_paths,
            "diff_stats": guardrail_stats,
        },
        "pr_controls": {
            "labels": args.pr_label,
            "requested_reviewers": reviewers,
            "auto_reviewers": auto_reviewers,
            "codeowners_path": args.codeowners_path if args.auto_reviewers_from_codeowners else None,
        },
        "accepted_findings": output.accepted_findings,
        "rejected_findings": [] if args.summary_only else output.rejected_findings,
        "validation": [] if args.summary_only else output.validation,
        "fixes": [] if args.summary_only else output.fixes,
        "validation_execution_pre": validation_execution_pre,
        "validation_execution_post": validation_execution_post,
        "fixes_selected_after_validation": filtered_fixes,
        "fix_application": apply_results,
        "stage_artifacts": output.stage_artifacts,
        "pr": pr_result,
        "prs": pr_results,
    }

    out_path = Path(args.out)
    out_path.write_text(json.dumps(payload, indent=2))

    sarif_scope = args.sarif_scope or ("validated" if args.run_validation else "accepted")
    if args.sarif_out:
        if sarif_scope == "validated":
            sarif_findings = [
                finding
                for finding in output.accepted_findings
                if str(finding.get("id", "")) in failed_validation_ids
            ]
        else:
            sarif_findings = output.accepted_findings
        sarif_payload = findings_to_sarif(sarif_findings)
        Path(args.sarif_out).write_text(json.dumps(sarif_payload, indent=2))

    artifacts_root = Path(args.artifacts_dir)
    artifact_dir = _write_artifacts(artifacts_root, run_id, payload)

    telemetry_payload = {
        "run_id": run_id,
        "generated_at": generated_at,
        "profile": args.profile,
        "accepted": len(output.accepted_findings),
        "rejected": len(output.rejected_findings),
        "selected_fixes": len(filtered_fixes),
        "new_findings": new_count,
        "context_cache_hit": output.context_cache_hit,
        "stage_timing": output.stage_artifacts.get("timing", {}),
    }
    append_metrics_jsonl(args.metrics_jsonl, telemetry_payload)

    print(f"Run ID: {run_id}")
    print(f"Wrote report: {out_path}")
    print(f"Wrote artifacts: {artifact_dir}")
    if args.sarif_out:
        print(f"Wrote SARIF: {args.sarif_out}")
    print(f"Accepted findings: {len(output.accepted_findings)}")
    print(f"Rejected findings: {len(output.rejected_findings)}")
    print(f"Validation items: {len(output.validation)}")
    print(f"Fix plans: {len(output.fixes)}")
    print(f"Fixes selected (pre-validation): {len(selected_fixes)}")
    if args.run_validation:
        print(f"Validation execution (pre): {len(validation_execution_pre)}")
        print(f"Fixes selected after validation execution: {len(filtered_fixes)}")
        if validation_execution_post:
            print(f"Validation execution (post): {len(validation_execution_post)}")
    if args.apply_fixes:
        applied_count = sum(1 for item in apply_results if item.get("applied"))
        print(f"Fixes applied: {applied_count}/{len(apply_results)}")
    if pr_result and pr_result.get("ok"):
        print(f"PR created: {pr_result.get('pr_url')}")
    if pr_results:
        created = [item for item in pr_results if item.get("ok")]
        print(f"PRs created: {len(created)}/{len(pr_results)}")
        for item in created:
            print(f"- [{item.get('label')}] {item.get('pr_url')}")
    print(f"Severity counts: {severity_counts}")

    if args.fail_on_severity:
        threshold = SEVERITY_ORDER[args.fail_on_severity]
        has_blocker = any(
            SEVERITY_ORDER[finding_severity(finding)] >= threshold for finding in output.accepted_findings
        )
        if has_blocker:
            print(f"Failing because finding severity meets threshold: {args.fail_on_severity}")
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
