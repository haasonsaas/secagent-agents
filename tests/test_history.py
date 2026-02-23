from security_agents.history import annotate_new_findings


def test_annotate_new_findings(tmp_path):
    findings = [
        {"id": "a", "vulnerability_class": "XSS", "finding": {"file": "a.py", "line": 1, "title": "x"}},
    ]
    annotated, new_count = annotate_new_findings(tmp_path, findings)
    assert new_count == 1
    assert annotated[0]["is_new"] is True

    findings2 = [
        {"id": "a", "vulnerability_class": "XSS", "finding": {"file": "a.py", "line": 1, "title": "x"}},
    ]
    annotated2, new_count2 = annotate_new_findings(tmp_path, findings2)
    assert new_count2 == 0
    assert annotated2[0]["is_new"] is False
