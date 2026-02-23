from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from security_agents.reporting import finding_fingerprint


@dataclass
class SuppressionRule:
    id: str | None
    fingerprint: str | None
    vulnerability_class: str | None
    path_prefix: str | None
    expires_on: date | None
    reason: str


def _parse_date(value: Any) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        return None


def load_suppressions(path: str | Path | None) -> list[SuppressionRule]:
    if not path:
        return []
    p = Path(path)
    if not p.exists():
        return []
    raw = yaml.safe_load(p.read_text()) or {}
    suppressions = raw.get("suppressions", [])
    rules: list[SuppressionRule] = []
    for item in suppressions:
        rules.append(
            SuppressionRule(
                id=str(item.get("id")) if item.get("id") is not None else None,
                fingerprint=str(item.get("fingerprint")) if item.get("fingerprint") is not None else None,
                vulnerability_class=str(item.get("vulnerability_class")) if item.get("vulnerability_class") is not None else None,
                path_prefix=str(item.get("path_prefix")) if item.get("path_prefix") is not None else None,
                expires_on=_parse_date(item.get("expires_on")),
                reason=str(item.get("reason", "no reason provided")),
            )
        )
    return rules


def _rule_matches(rule: SuppressionRule, finding: dict[str, Any], today: date) -> bool:
    if rule.expires_on and today > rule.expires_on:
        return False

    nested = finding.get("finding", {})
    finding_id = str(finding.get("id", nested.get("id", "")))
    vuln_class = str(finding.get("vulnerability_class", ""))
    file_path = str(nested.get("file", ""))
    fingerprint = finding_fingerprint(vuln_class, nested)

    if rule.id and rule.id != finding_id:
        return False
    if rule.fingerprint and rule.fingerprint != fingerprint:
        return False
    if rule.vulnerability_class and rule.vulnerability_class != vuln_class:
        return False
    if rule.path_prefix and not file_path.startswith(rule.path_prefix):
        return False
    return True


def apply_suppressions(
    findings: list[dict[str, Any]],
    rules: list[SuppressionRule],
    today: date | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not rules:
        return findings, []

    current_day = today or date.today()
    kept: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []

    for finding in findings:
        matched_rule = next((rule for rule in rules if _rule_matches(rule, finding, current_day)), None)
        if matched_rule is None:
            kept.append(finding)
            continue
        entry = {
            "id": finding.get("id"),
            "vulnerability_class": finding.get("vulnerability_class"),
            "reason": matched_rule.reason,
        }
        suppressed.append(entry)

    return kept, suppressed
