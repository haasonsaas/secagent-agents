from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run secagent benchmarks against fixtures")
    parser.add_argument("--fixtures-root", default="benchmarks/fixtures", help="Benchmarks fixtures root")
    parser.add_argument("--profile", default="general", help="secagent profile")
    parser.add_argument("--strict", action="store_true", help="Fail if expected classes are missing")
    return parser.parse_args()


def run_fixture(fixture_dir: Path, profile: str) -> dict:
    expected_path = fixture_dir / "expected.json"
    if not expected_path.exists():
        return {"fixture": fixture_dir.name, "skipped": True, "reason": "missing expected.json"}

    expected = json.loads(expected_path.read_text())
    expected_classes = set(expected.get("expected_classes", []))

    out_path = fixture_dir / "_benchmark_report.json"
    cmd = [
        "uv",
        "run",
        "secagent",
        "--repo",
        str(fixture_dir),
        "--profile",
        profile,
        "--summary-only",
        "--out",
        str(out_path),
    ]
    completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        return {
            "fixture": fixture_dir.name,
            "ok": False,
            "error": completed.stderr.strip() or completed.stdout.strip() or "secagent run failed",
        }

    report = json.loads(out_path.read_text())
    found_classes = {str(item.get("vulnerability_class", "")) for item in report.get("accepted_findings", [])}
    missing = sorted(expected_classes - found_classes)

    return {
        "fixture": fixture_dir.name,
        "ok": len(missing) == 0,
        "expected_classes": sorted(expected_classes),
        "found_classes": sorted(found_classes),
        "missing_classes": missing,
    }


def main() -> int:
    args = parse_args()
    fixtures_root = Path(args.fixtures_root)
    fixtures = sorted([p for p in fixtures_root.iterdir() if p.is_dir()]) if fixtures_root.exists() else []

    if not fixtures:
        print("No fixtures found")
        return 1

    results = [run_fixture(fixture, args.profile) for fixture in fixtures]
    failing = [r for r in results if not r.get("ok", False) and not r.get("skipped", False)]

    print(json.dumps({"results": results, "failing": len(failing)}, indent=2))

    if args.strict and failing:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
