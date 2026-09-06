"""AST-based analyzer tests — catches what regex misses, avoids regex FPs."""

from __future__ import annotations

from sentinel.analyzers.ast_analyzer import PythonASTAnalyzer
from sentinel.diffparse import Changeset, DiffLine


def _run(src: str, file: str = "app.py"):
    changeset = Changeset(
        file=file,
        additions=[DiffLine(kind="add", text=ln, new_line=i + 1, old_line=None)
                   for i, ln in enumerate(src.splitlines())],
    )
    return PythonASTAnalyzer().analyze(changeset)


def _ids(src: str) -> set[str]:
    return {f.rule_id for f in _run(src)}


def test_eval_flagged():
    assert "AST-001" in _ids("x = eval(user_input)\n")


def test_exec_flagged():
    assert "AST-001" in _ids("exec(payload)\n")


def test_os_system_flagged():
    assert "AST-002" in _ids("import os; os.system('rm -rf /')\n")


def test_subprocess_shell_true_flagged():
    assert "AST-003" in _ids("subprocess.run(cmd, shell=True)\n")


def test_subprocess_list_not_flagged():
    assert "AST-003" not in _ids("subprocess.run(cmd.split())\n")


def test_pickle_loads_flagged():
    assert "AST-004" in _ids("data = pickle.loads(buf)\n")


def test_yaml_load_without_loader_flagged():
    assert "AST-005" in _ids("cfg = yaml.load(raw)\n")


def test_yaml_safe_load_not_flagged():
    assert "AST-005" not in _ids("cfg = yaml.safe_load(raw)\n")


def test_requests_verify_false_flagged():
    assert "AST-006" in _ids("import requests; requests.get(url, verify=False)\n")


def test_bare_except_flagged():
    assert "AST-007" in _ids("try:\n    risky()\nexcept:\n    pass\n")


def test_named_except_not_flagged():
    assert "AST-007" not in _ids("try:\n    risky()\nexcept Exception:\n    pass\n")


def test_recompile_is_not_eval():
    # The classic false positive: re.compile must never be confused with exec/eval
    assert "AST-001" not in _ids("import re; pattern = re.compile(r'\\d+')\n")


def test_clean_code_has_no_ast_findings():
    clean = (
        "def add(a, b):\n"
        "    return a + b\n"
        "\n"
        "result = add(1, 2)\n"
    )
    assert _run(clean) == []


def test_incomplete_snippet_is_skipped_not_crash():
    # A single added line that is not syntactically valid on its own must not crash
    assert _run("def foo(:\n") == []