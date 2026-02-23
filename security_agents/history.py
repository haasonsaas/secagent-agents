from __future__ import annotations

from pathlib import Path
from typing import Any
import json

from security_agents.reporting import finding_fingerprint


def _history_path(repo: Path) -> Path:
    p = repo / ".secagent_cache" / "finding_history.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def load_history(repo: Path) -> dict[str, Any]:
    p = _history_path(repo)
    if not p.exists():
        return {"seen": {}}
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        return {"seen": {}}


def save_history(repo: Path, data: dict[str, Any]) -> None:
    p = _history_path(repo)
    p.write_text(json.dumps(data, indent=2))


def annotate_new_findings(repo: Path, findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    history = load_history(repo)
    seen = history.get("seen", {})
    new_count = 0

    for finding in findings:
        nested = finding.get("finding", {})
        vuln_class = str(finding.get("vulnerability_class", ""))
        fp = finding_fingerprint(vuln_class, nested)
        is_new = fp not in seen
        finding["fingerprint"] = fp
        finding["is_new"] = is_new
        if is_new:
            new_count += 1
        seen[fp] = {
            "id": finding.get("id"),
            "vulnerability_class": vuln_class,
            "file": nested.get("file"),
            "line": nested.get("line"),
        }

    history["seen"] = seen
    save_history(repo, history)
    return findings, new_count
