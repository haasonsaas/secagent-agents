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
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo = Path(args.repo).resolve()
    config = load_config(args.config)

    output = run_pipeline(repo, config)
    generated_at = datetime.now(timezone.utc).isoformat()
    payload = {
        "generated_at": generated_at,
        "repo": str(repo),
        "model": config.model,
        "scanned_file_count": len(output.scanned_files),
        "scanned_files": output.scanned_files,
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
