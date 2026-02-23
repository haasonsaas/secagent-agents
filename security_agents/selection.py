from __future__ import annotations

from typing import Any

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def finding_severity(finding: dict[str, Any]) -> str:
    explicit = str(finding.get("updated_severity", "")).lower()
    if explicit in SEVERITY_ORDER:
        return explicit
    nested = finding.get("finding", {})
    nested_sev = str(nested.get("severity", "")).lower()
    if nested_sev in SEVERITY_ORDER:
        return nested_sev
    return "low"


def finding_confidence(finding: dict[str, Any]) -> float:
    nested = finding.get("finding", {})
    raw = nested.get("confidence", 0.0)
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return 0.0
    if value < 0:
        return 0.0
    if value > 1:
        return 1.0
    return value


def finding_exploitability(finding: dict[str, Any]) -> float:
    data = finding.get("exploitability", {})
    raw = data.get("exploitability_score", 0.0)
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return 0.0
    if value < 0:
        return 0.0
    if value > 1:
        return 1.0
    return value


def finding_risk_score(finding: dict[str, Any]) -> float:
    severity_weight = SEVERITY_ORDER[finding_severity(finding)] / 4.0
    confidence_weight = finding_confidence(finding)
    exploitability_weight = finding_exploitability(finding)
    return round((0.45 * severity_weight) + (0.35 * exploitability_weight) + (0.20 * confidence_weight), 4)


def filter_and_rank_fixes(
    accepted_findings: list[dict[str, Any]],
    fixes: list[dict[str, Any]],
    min_confidence: float,
    min_risk_score: float,
    min_severity: str,
    only_severity: str | None,
    max_fixes: int | None,
    new_only: bool,
) -> list[dict[str, Any]]:
    min_threshold = SEVERITY_ORDER[min_severity]
    lookup = {str(item.get("id", "")): item for item in accepted_findings}

    selected: list[dict[str, Any]] = []
    for fix in fixes:
        fix_id = str(fix.get("id", ""))
        finding = lookup.get(fix_id)
        if not finding:
            continue

        severity = finding_severity(finding)
        if only_severity and severity != only_severity:
            continue
        if SEVERITY_ORDER[severity] < min_threshold:
            continue
        if finding_confidence(finding) < min_confidence:
            continue
        if finding_risk_score(finding) < min_risk_score:
            continue
        if new_only and not bool(finding.get("is_new", False)):
            continue
        selected.append(fix)

    selected.sort(
        key=lambda fix: (
            finding_risk_score(lookup.get(str(fix.get("id", "")), {})),
            SEVERITY_ORDER[finding_severity(lookup.get(str(fix.get("id", "")), {}))],
        ),
        reverse=True,
    )

    if max_fixes is not None and max_fixes >= 0:
        return selected[:max_fixes]
    return selected


def summarize_findings_by_class(accepted_findings: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    summary: dict[str, dict[str, int]] = {}
    for finding in accepted_findings:
        cls = str(finding.get("vulnerability_class", "unknown"))
        sev = finding_severity(finding)
        if cls not in summary:
            summary[cls] = {"low": 0, "medium": 0, "high": 0, "critical": 0, "total": 0}
        summary[cls][sev] += 1
        summary[cls]["total"] += 1
    return summary
