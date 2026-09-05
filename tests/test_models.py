
from sentinel.models import (
    Finding,
    Severity,
    compute_verdict_score,
    severity_from_str,
)


def test_severity_from_str():
    assert severity_from_str("CRITICAL") == Severity.CRITICAL
    assert severity_from_str("High") == Severity.HIGH
    assert severity_from_str("bogus") == Severity.LOW


def test_finding_roundtrip():
    f = Finding(rule_id="S001", severity=Severity.HIGH, file="a.py", line=3,
                code_snippet="secret = 'x'", description="d", suggested_fix="use env")
    d = f.to_dict()
    f2 = Finding.from_dict(d)
    assert f2.rule_id == f.rule_id
    assert f2.severity == f.severity
    assert f2.file == "a.py"
    assert f2.line == 3


def test_verdict_score_clean():
    assert compute_verdict_score([]) == 100


def test_verdict_score_critical_sinks():
    findings = [Finding(rule_id="S", severity=Severity.CRITICAL, file="a.py", line=1)]
    assert compute_verdict_score(findings) == 70


def test_verdict_floor():
    fs = [Finding(rule_id="S", severity=Severity.CRITICAL, file="a.py", line=i) for i in range(10)]
    assert compute_verdict_score(fs) == 0