"""Regression tests for the dogfood auto-fix PR (analyzer tuning)."""

from __future__ import annotations

from sentinel.analyzers.custom_rules import SentinelRulesAnalyzer
from sentinel.diffparse import Changeset, DiffLine
from sentinel.models import Finding


def _cs(file: str, *lines: str) -> Changeset:
    return Changeset(
        file=file,
        additions=[
            DiffLine(kind="add", old_line=None, new_line=i + 1, text=t)
            for i, t in enumerate(lines)
        ],
    )


def test_custom_rules_ignore_non_code_fixture_files():
    findings = SentinelRulesAnalyzer().analyze(
        _cs("sentinel/rules/books/python.yml", "eval(user_input)")
    )
    assert findings == []
    findings = SentinelRulesAnalyzer().analyze(
        _cs("README.md", "Api_Id = 'AIzaSyBwoEioGpdkssG3m6y8KM0AcTpDB9Yorjc'")
    )
    assert findings == []


def test_custom_rules_s005_no_longer_flags_re_compile():
    findings = SentinelRulesAnalyzer().analyze(
        _cs("verify.py", "rx = re.compile(rule.regex)")
    )
    assert not any(f.rule_id == "S005" for f in findings)


def test_custom_rules_still_flag_real_runtime_exec():
    findings = SentinelRulesAnalyzer().analyze(
        _cs("app.py", "result = eval(request.body)")
    )
    assert any(f.rule_id == "S005" for f in findings)


def test_custom_rules_flag_sql_and_secrets_in_code():
    findings = SentinelRulesAnalyzer().analyze(
        _cs("query.py", "Api_Id = 'AKIAIOSFODNN7EXAMPLE'")
    )
    assert any(f.rule_id == "S002" for f in findings)


def test_bandit_config_filters_excluded_dirs():
    from sentinel.analyzers.bandit_analyzer import _under_excluded

    assert _under_excluded("tests/test_api.py", ["tests", ".venv"])
    assert _under_excluded("sentinel/tests/fixtures/x.py", ["tests"])
    assert not _under_excluded("sentinel/cli.py", ["tests", ".venv"])
    assert not _under_excluded("src/app/main.py", ["tests"])


def test_sentinel_rules_analyzer_returns_findings_type():
    findings = SentinelRulesAnalyzer().analyze(
        _cs("server.py", "exec('os.system(cmd)')")
    )
    assert findings
    assert all(isinstance(f, Finding) for f in findings)