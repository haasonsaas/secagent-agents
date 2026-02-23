from security_agents.reporting import findings_to_sarif


def test_findings_to_sarif_basic():
    findings = [
        {
            "id": "f-1",
            "vulnerability_class": "SQL/ORM Injection",
            "updated_severity": "high",
            "finding": {
                "title": "SQL injection in search endpoint",
                "summary": "Unsanitized query parameter reaches SQL builder.",
                "file": "app/routes/search.py",
                "line": 42,
            },
        }
    ]
    sarif = findings_to_sarif(findings)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "secagent"
    assert len(run["results"]) == 1
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["ruleId"] == "secagent/sql-orm-injection"
    assert "primaryLocationLineHash" in run["results"][0]["partialFingerprints"]
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app/routes/search.py"
