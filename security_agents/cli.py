from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from security_agents.config import load_config
from security_agents.pipeline import run_pipeline


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a detector-manager-validator-fixer security pipeline")
    parser.add_argument("--repo", default=".", help="Path to target repository")
    parser.add_argument("--config", default=None, help="Path to YAML config")
    parser.add_argument("--out", default="security_report.json", help="Output JSON file")
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
    return parser.parse_args()


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _finding_severity(finding: dict) -> str:
    explicit = str(finding.get("updated_severity", "")).lower()
    if explicit in SEVERITY_ORDER:
        return explicit
    nested = finding.get("finding", {})
    nested_sev = str(nested.get("severity", "")).lower()
    if nested_sev in SEVERITY_ORDER:
        return nested_sev
    return "low"


def main() -> int:
    args = parse_args()
    repo = Path(args.repo).resolve()
    config = load_config(args.config)

    output = run_pipeline(repo, config)
    generated_at = datetime.now(timezone.utc).isoformat()
    severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for finding in output.accepted_findings:
        severity_counts[_finding_severity(finding)] += 1

    payload = {
        "generated_at": generated_at,
        "repo": str(repo),
        "model": config.model,
        "scanned_file_count": len(output.scanned_files),
        "scanned_files": output.scanned_files,
        "severity_counts": severity_counts,
        "accepted_findings": output.accepted_findings,
        "rejected_findings": [] if args.summary_only else output.rejected_findings,
        "validation": [] if args.summary_only else output.validation,
        "fixes": [] if args.summary_only else output.fixes,
    }

    out_path = Path(args.out)
    out_path.write_text(json.dumps(payload, indent=2))

    print(f"Wrote report: {out_path}")
    print(f"Accepted findings: {len(output.accepted_findings)}")
    print(f"Rejected findings: {len(output.rejected_findings)}")
    print(f"Validation items: {len(output.validation)}")
    print(f"Fix plans: {len(output.fixes)}")
    print(f"Severity counts: {severity_counts}")

    if args.fail_on_severity:
        threshold = SEVERITY_ORDER[args.fail_on_severity]
        has_blocker = any(
            SEVERITY_ORDER[_finding_severity(finding)] >= threshold for finding in output.accepted_findings
        )
        if has_blocker:
            print(f"Failing because finding severity meets threshold: {args.fail_on_severity}")
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
