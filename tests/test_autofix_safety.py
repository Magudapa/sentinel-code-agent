"""Auto-fix safety gates: containment, sensitive paths, non-code, security regression."""

from __future__ import annotations

from sentinel.autofix import autofix_candidates, build_patch_file, is_sensitive_relpath
from sentinel.models import Finding, Severity


def _finding(rule_id="S001", file="app.py", line=1, snippet="password = 'hunter2secretvalue'",
             fix="password = os.environ['DB_PASSWORD']", analyzer="sentinel-rules"):
    return Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        file=file,
        line=line,
        code_snippet=snippet,
        suggested_fix=fix,
        analyzer=analyzer,
    )


def test_sensitive_relpath_blocked():
    assert is_sensitive_relpath(".env") is True
    assert is_sensitive_relpath("sub/.env.example") is True


def test_escape_via_dotdot_rejected(tmp_path):
    # a finding claiming to be in ../outside must be rejected and yield no patch
    f = _finding(file="../outside.py")
    patches = autofix_candidates(None, [f], workspace_root=str(tmp_path))
    assert patches == []


def test_absolute_path_rejected(tmp_path):
    f = _finding(file=str(tmp_path / "evil"))
    patches = autofix_candidates(None, [f], workspace_root=str(tmp_path))
    assert patches == []


def test_non_code_file_rejected(tmp_path):
    f = _finding(file="README.md")
    patches = autofix_candidates(None, [f], workspace_root=str(tmp_path))
    assert patches == []


def test_apply_fix_without_workspace_is_unvalidated(tmp_path):
    from sentinel.autofix import apply_fix

    f = _finding()
    patch = apply_fix(None, f)
    assert patch is not None
    assert patch.validated is False
    assert "manual" in patch.validation_notes


def test_security_regression_requires_removal(tmp_path):
    """A patch that leaves the vulnerable line in place cannot validate."""
    from sentinel.autofix import apply_fix

    src = tmp_path / "app.py"
    src.write_text("password = 'hunter2secretvalue'\nprint('ok')\n", encoding="utf-8")

    # vulnerable line kept in the "fix" -> gate 5 must reject
    bad_fix = _finding(snippet="password = 'hunter2secretvalue'",
                       fix="password = 'hunter2secretvalue'  # untouched")
    patch = apply_fix(None, bad_fix, str(src), workspace_root=str(tmp_path))
    assert patch is None or patch.validated is False

    # a real fix removing the hardcoded secret passes the gate
    good_fix = _finding(snippet="password = 'hunter2secretvalue'",
                        fix="password = os.environ['DB_PASSWORD']")
    patch = apply_fix(None, good_fix, str(src), workspace_root=str(tmp_path))
    assert patch is not None
    assert patch.validated is True
    assert "security regression cleared" in patch.validation_notes


def test_unrelated_code_preserved(tmp_path):
    """Auto-fix must only replace the finding snippet — never nearby code."""
    original = "DB = 'prod'\npassword = 'hunter2secretvalue'\nprint('done')\n"
    updated = "DB = 'prod'\npassword = os.environ['DB_PASSWORD']\nprint('done')\n"
    diff = build_patch_file(original, updated, "app.py")
    assert "print('done')" not in diff.splitlines()[1]  # no touching the print line
    assert "+password = os.environ['DB_PASSWORD']" in diff