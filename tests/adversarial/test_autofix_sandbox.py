"""Adversarial tests for the autofix sandbox + fail-closed regression gates.

Rule: Sentinel must never execute a repository's own tests (or accept its
results) unless the workspace is explicitly allowlisted as a test sandbox, and a
file-analyzer security regression can never be "proven fixed" without
deterministic re-scan evidence.
"""

from __future__ import annotations

from sentinel.autofix import _run_fast_tests, apply_fix
from sentinel.models import Finding, Severity


def _finding(snippet: str, fix: str, analyzer: str = "sentinel-rules", rule_id: str = "S001") -> Finding:
    f = Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        file="app.py",
        line=1,
        code_snippet=snippet,
        description="hardcoded secret",
        evidence=rule_id,
        suggested_fix=fix,
    )
    f.analyzer = analyzer
    return f


def test_fast_tests_require_allowlist(tmp_path):
    assert _run_fast_tests(str(tmp_path), ()) is None
    assert _run_fast_tests(str(tmp_path), (str(tmp_path / "elsewhere"),)) is None


def test_fast_tests_run_only_inside_allowlisted_sandbox(tmp_path):
    (tmp_path / "test_t.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    allowed = (str(tmp_path),)
    assert _run_fast_tests(str(tmp_path), allowed) is True
    assert _run_fast_tests(str(tmp_path), (str(tmp_path / "sub"),)) is None


def test_apply_fix_records_tests_not_run(tmp_path):
    src = tmp_path / "app.py"
    src.write_text("password = 'hunter2secretvalue'\nprint('ok')\n", encoding="utf-8")
    fix = _finding(
        snippet="password = 'hunter2secretvalue'",
        fix="password = os.environ['DB_PASSWORD']",
    )
    patch = apply_fix(None, fix, str(src), workspace_root=str(tmp_path))
    assert patch is not None and patch.validated is True
    assert patch.tests_passed is None
    assert "tests not run" in patch.validation_notes


def test_file_analyzer_finding_fails_closed_without_workspace():
    # A bandit/semgrep finding without a workspace cannot be proven fixed:
    # the patch must come back as NOT validated, never silently "accepted".
    fix = _finding(
        snippet="insecure",
        fix="safe",
        analyzer="bandit",
    )
    patch = apply_fix(None, fix, path="app.py", workspace_root=None)
    assert patch is not None
    assert patch.validated is False
    assert "manual review" in patch.validation_notes


def test_file_analyzer_regression_reproduced_fails_closed(tmp_path, monkeypatch):
    # If re-scan of the patched file still shows the finding (or the scan
    # cannot run), the patch is rejected — fail-closed, no silent acceptance.
    from sentinel.models import Finding

    src = tmp_path / "app.py"
    src.write_text("x = request.args  # bandit-ish sink\n", encoding="utf-8")

    def mimicking_scan(path, files, timeout=120, env=None):
        finding = Finding(
            rule_id="BANDIT-101",
            severity=Severity.MEDIUM,
            file="app.py",
            line=1,
            code_snippet="x = request.args",
            description="still present",
        )
        return [finding], {"bandit": {"status": "FINDINGS", "detail": "1 finding(s)"}}

    monkeypatch.setattr("sentinel.analyzers.base.analyze_files_full", mimicking_scan)
    fix = _finding(
        snippet="x = request.args",
        fix="x = sanitize(request.args, allowed)",
        analyzer="bandit",
        rule_id="BANDIT-101",
    )
    patch = apply_fix(None, fix, str(src), workspace_root=str(tmp_path))
    assert patch is not None and patch.validated is False
    assert "security regression" in patch.validation_notes