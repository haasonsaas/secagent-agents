from datetime import date

from security_agents.suppression import SuppressionRule, apply_suppressions


def test_apply_suppressions_by_class():
    findings = [
        {"id": "a", "vulnerability_class": "SQL/ORM Injection", "finding": {"file": "app/a.py", "line": 3, "title": "x"}},
        {"id": "b", "vulnerability_class": "XSS", "finding": {"file": "app/b.py", "line": 7, "title": "y"}},
    ]
    rules = [
        SuppressionRule(
            id=None,
            fingerprint=None,
            vulnerability_class="XSS",
            path_prefix=None,
            expires_on=date(2099, 1, 1),
            reason="accepted risk",
        )
    ]
    kept, suppressed = apply_suppressions(findings, rules, today=date(2026, 2, 23))
    assert len(kept) == 1
    assert kept[0]["id"] == "a"
    assert len(suppressed) == 1
    assert suppressed[0]["id"] == "b"
