from sentinel.autofix import _python_syntax_ok, build_patch_file
from sentinel.model import ModelClient
from sentinel.models import Finding, Severity


def test_syntax_ok():
    ok, note = _python_syntax_ok("def f():\n    return 1\n")
    assert ok
    bad, note = _python_syntax_ok("def f(:\n")
    assert not bad
    assert "line" in note.lower() or bad is False


def test_patch_file_build(tmp_path):
    a = "a = 1\nb = 2\n"
    b = "a = 1\nb = 3\n"
    diff = build_patch_file(a, b, "src/x.py")
    assert "+b = 3" in diff
    assert "-b = 2" in diff


def test_apply_fix_none_with_no_suggestion():
    model = ModelClient()  # never actually hit when no suggestion
    f = Finding(rule_id="S001", severity=Severity.HIGH, file="x.py", line=1,
                code_snippet="bad", suggested_fix="")
    patch = __import__("sentinel.autofix", fromlist=["apply_fix"]).apply_fix(model, f)
    assert patch is None


def test_extract_llm_fix_codeblock():
    from sentinel.model import extract_llm_fix

    raw = '```python\nresult = safe()\n```'
    assert extract_llm_fix(raw) == "result = safe()"