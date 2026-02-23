from security_agents.selection import filter_and_rank_fixes, finding_confidence, finding_severity, summarize_findings_by_class


def test_finding_helpers():
    finding = {
        "updated_severity": "high",
        "finding": {"confidence": 1.2, "severity": "low"},
    }
    assert finding_severity(finding) == "high"
    assert finding_confidence(finding) == 1.0


def test_filter_and_rank_fixes():
    accepted = [
        {
            "id": "a",
            "updated_severity": "high",
            "vulnerability_class": "Auth",
            "finding": {"confidence": 0.9, "severity": "medium"},
        },
        {
            "id": "b",
            "updated_severity": "medium",
            "vulnerability_class": "IDOR",
            "finding": {"confidence": 0.8, "severity": "low"},
        },
        {
            "id": "c",
            "updated_severity": "critical",
            "vulnerability_class": "SQLi",
            "finding": {"confidence": 0.2, "severity": "critical"},
        },
    ]
    fixes = [
        {"id": "a", "patch_diff": "diff a"},
        {"id": "b", "patch_diff": "diff b"},
        {"id": "c", "patch_diff": "diff c"},
    ]

    selected = filter_and_rank_fixes(
        accepted_findings=accepted,
        fixes=fixes,
        min_confidence=0.7,
        min_severity="medium",
        only_severity=None,
        max_fixes=None,
    )

    assert [x["id"] for x in selected] == ["a", "b"]


def test_summarize_findings_by_class():
    accepted = [
        {"id": "a", "updated_severity": "high", "vulnerability_class": "Auth", "finding": {}},
        {"id": "b", "updated_severity": "medium", "vulnerability_class": "Auth", "finding": {}},
        {"id": "c", "updated_severity": "critical", "vulnerability_class": "SQLi", "finding": {}},
    ]
    summary = summarize_findings_by_class(accepted)
    assert summary["Auth"]["total"] == 2
    assert summary["Auth"]["high"] == 1
    assert summary["SQLi"]["critical"] == 1
