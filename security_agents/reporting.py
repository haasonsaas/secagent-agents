from __future__ import annotations

import hashlib
import re
from typing import Any


def _normalize_severity(sev: str) -> str:
    value = (sev or "").lower()
    if value in {"critical", "high"}:
        return "error"
    if value == "medium":
        return "warning"
    return "note"


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "unknown"


def _help_uri_for_class(vuln_class: str) -> str:
    name = vuln_class.lower()
    if "idor" in name or "bola" in name:
        return "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
    if "ssrf" in name:
        return "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"
    if "xss" in name:
        return "https://owasp.org/www-community/attacks/xss/"
    if "csrf" in name:
        return "https://owasp.org/www-community/attacks/csrf"
    if "sql" in name or "injection" in name:
        return "https://owasp.org/www-community/attacks/SQL_Injection"
    if "prompt" in name or "llm" in name or "agent" in name:
        return "https://genai.owasp.org/llm-top-10/"
    return "https://owasp.org/www-project-top-ten/"


def _cwe_tags_for_class(vuln_class: str) -> list[str]:
    name = vuln_class.lower()
    tags = ["security"]
    if "idor" in name or "bola" in name:
        tags.extend(["CWE-639", "CWE-285"])
    if "ssrf" in name:
        tags.append("CWE-918")
    if "xss" in name:
        tags.append("CWE-79")
    if "csrf" in name:
        tags.append("CWE-352")
    if "sql" in name or "injection" in name:
        tags.append("CWE-89")
    if "deserialization" in name:
        tags.append("CWE-502")
    if "path traversal" in name:
        tags.append("CWE-22")
    if "command injection" in name:
        tags.append("CWE-78")
    if "prompt" in name or "llm" in name or "agent" in name:
        tags.append("OWASP-LLM")
    return list(dict.fromkeys(tags))


def finding_fingerprint(vuln_class: str, nested: dict[str, Any]) -> str:
    raw = "|".join(
        [
            vuln_class,
            str(nested.get("file", "")),
            str(nested.get("line", "")),
            str(nested.get("title", "")),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def findings_to_sarif(findings: list[dict[str, Any]], tool_name: str = "secagent") -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        vuln_class = str(finding.get("vulnerability_class", "Unknown"))
        nested = finding.get("finding", {})
        finding_id = str(finding.get("id", nested.get("id", "unknown")))
        rule_id = f"secagent/{_slug(vuln_class)}"

        title = str(nested.get("title", vuln_class))
        summary = str(nested.get("summary", finding.get("rationale", "Security finding")))
        severity = str(finding.get("updated_severity", nested.get("severity", "low"))).lower()
        confidence = nested.get("confidence", 0.0)
        try:
            confidence_value = max(0.0, min(1.0, float(confidence)))
        except (TypeError, ValueError):
            confidence_value = 0.0
        help_text = str(nested.get("recommended_fix", "")).strip() or "Review authorization, validation, and safe handling controls."

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": vuln_class,
                "shortDescription": {"text": vuln_class},
                "fullDescription": {"text": f"{vuln_class} detected by secagent."},
                "helpUri": _help_uri_for_class(vuln_class),
                "help": {
                    "text": f"Finding class: {vuln_class}. Default remediation: {help_text}",
                },
                "properties": {
                    "tags": _cwe_tags_for_class(vuln_class) + [vuln_class],
                    "precision": "medium",
                    "problem.severity": "warning",
                },
            }

        file_path = str(nested.get("file", ""))
        line = int(nested.get("line", 1) or 1)
        if line <= 0:
            line = 1

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _normalize_severity(severity),
            "message": {"text": f"[{finding_id}] {title}: {summary}"},
            "partialFingerprints": {
                "primaryLocationLineHash": finding_fingerprint(vuln_class, nested),
            },
            "properties": {
                "security-severity": severity,
                "confidence": confidence_value,
                "finding-id": finding_id,
                "vulnerability-class": vuln_class,
            },
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
