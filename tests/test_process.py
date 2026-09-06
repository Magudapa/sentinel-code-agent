"""Safe-subprocess tests: argv-only, timeouts, env isolation, bounded output."""

from __future__ import annotations

import os
import sys

import pytest

from sentinel.process import CommandSafetyError, run_safe


def _py(code: str) -> list[str]:
    return [sys.executable, "-c", code]


def test_string_command_rejected():
    with pytest.raises(CommandSafetyError):
        run_safe("echo hi")


def test_empty_argv_rejected():
    with pytest.raises(CommandSafetyError):
        run_safe([])


def test_non_string_argv_rejected():
    with pytest.raises(CommandSafetyError):
        run_safe(["python", 123])


def test_missing_cwd_rejected(tmp_path):
    with pytest.raises(CommandSafetyError):
        run_safe(["python", "-c", "pass"], cwd=str(tmp_path / "nope"))


def test_successful_command():
    res = run_safe(_py("print('hello')"))
    assert res.ok
    assert res.stdout.strip() == "hello"


def test_program_not_found():
    res = run_safe(["_definitely_not_a_real_program_123"])
    assert res.error
    assert not res.ok
    assert res.returncode == -1


def test_timeout_classified(tmp_path):
    slow = _py("import time; time.sleep(30)")
    res = run_safe(slow, timeout=1)
    assert res.timed_out is True
    assert "timed out" in res.error


def test_output_capped():
    big = _py("print('x' * 10_000_000)")
    res = run_safe(big, max_output=1000)
    assert res.stdout.startswith("xxx")
    assert "truncated" in res.stdout


def test_env_is_isolated():
    test_var_name = "SENTINEL_TEST_ENV_SECRET"
    os.environ[test_var_name] = "super-secret"
    probe = _py(
        f"import os; print(os.environ.get({test_var_name!r}, 'stripped'))"
    )
    res = run_safe(probe)
    assert res.stdout.strip() == "stripped"
    del os.environ[test_var_name]


def test_extra_env_passthrough():
    probe = _py("import os; print(os.environ.get('SENT_FOO','missing'))")
    res = run_safe(probe, extra_env={"SENT_FOO": "bar"})
    assert res.stdout.strip() == "bar"


def test_stdin_input_text():
    code = "import sys; data=sys.stdin.read(); print('got:%s' % data.strip())"
    res = run_safe(_py(code), input_text="hello")
    assert res.stdout.strip() == "got:hello"