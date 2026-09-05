from sentinel.analyzers import analyze_changesets
from sentinel.analyzers.custom_rules import RULES
from sentinel.diffparse import parse_diff
from sentinel.models import Severity


def build_diff(code_lines: list[str], header: str = "x.py"):
    body = "\n".join("+" + ln for ln in code_lines)
    return (
        f"diff --git a/{header} b/{header}\n"
        f"--- a/{header}\n+++ b/{header}\n"
        f"@@ -0,0 +1,{len(code_lines)} @@\n{body}\n"
    )


def analyze(code: str, header: str = "x.py"):
    return analyze_changesets(parse_diff(build_diff(code.splitlines(), header)))


def test_sql_injection_fstring():
    findings = analyze('query = f"SELECT * FROM users WHERE id = {uid}"')
    assert any(f.rule_id == "S004" and f.severity == Severity.CRITICAL for f in findings)


def test_eval_flagged():
    findings = analyze('eval(payload)  # noqa')
    assert any(f.rule_id == "S005" for f in findings)


def test_secret_flagged():
    findings = analyze('password = "hunter2hunter2hunter2"')
    assert any(f.rule_id == "S001" for f in findings)


def test_cloud_key_flagged():
    findings = analyze('key = "AKIAIOSFODNN7EXAMPLE"')
    assert any(f.rule_id == "S002" for f in findings)


def test_shell_true_flagged():
    findings = analyze("subprocess.run(cmd, shell=True)")
    assert any(f.rule_id == "S006" for f in findings)


def test_pickle_flagged():
    findings = analyze("data = pickle.loads(raw)")
    assert any(f.rule_id == "S008" for f in findings)


def test_yaml_load_flagged():
    findings = analyze("cfg = yaml.load(data)")
    assert any(f.rule_id == "S009" for f in findings)


def test_md5_flagged():
    findings = analyze("h = hashlib.md5(salt).hexdigest()")
    assert any(f.rule_id == "S010" for f in findings)


def test_mutable_default_flagged():
    findings = analyze("def f(items=[]):")
    assert any(f.rule_id == "B004" for f in findings)


def test_clean_code_no_findings():
    findings = analyze("value = compute(x) + 1")
    assert findings == []


def test_rule_registry_has_security_rules():
    ids = {r.rule_id for r in RULES}
    assert {"S001", "S004", "S005", "S008"}.issubset(ids)