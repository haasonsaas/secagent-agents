from __future__ import annotations

from typing import Any


def _normalize_severity(sev: str) -> str:
    value = (sev or "").lower()
    if value in {"critical", "high"}:
        return "error"
    if value == "medium":
        return "warning"
    return "note"


def findings_to_sarif(findings: list[dict[str, Any]], tool_name: str = "secagent") -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        vuln_class = str(finding.get("vulnerability_class", "Unknown"))
        nested = finding.get("finding", {})
        finding_id = str(finding.get("id", nested.get("id", "unknown")))
        rule_id = f"{vuln_class}:{finding_id}"

        title = str(nested.get("title", vuln_class))
        summary = str(nested.get("summary", finding.get("rationale", "Security finding")))
        severity = str(finding.get("updated_severity", nested.get("severity", "low"))).lower()

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": title,
                "shortDescription": {"text": title},
                "fullDescription": {"text": summary},
                "properties": {
                    "tags": ["security", vuln_class],
                    "precision": "medium",
                    "problem.severity": severity,
                },
            }

        file_path = str(nested.get("file", ""))
        line = int(nested.get("line", 1) or 1)
        if line <= 0:
            line = 1

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _normalize_severity(severity),
            "message": {"text": summary},
        }
        if file_path:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_path},
                        "region": {"startLine": line},
                    }
                }
            ]
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "informationUri": "https://github.com/haasonsaas/secagent-agents",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
