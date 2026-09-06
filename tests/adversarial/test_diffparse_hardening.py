"""Adversarial tests for diff parsing limits and path-traversal guards.

A hostile/untrusted diff must fail loudly instead of exhausting memory, and its
file headers must never be able to address the working tree outside the repo.
"""

from __future__ import annotations

import pytest

from sentinel.diffparse import (
    MAX_DIFF_BYTES,
    MAX_DIFF_LINES,
    MAX_LINE_LEN,
    Changeset,
    DiffTooLargeError,
    parse_diff,
)


def test_huge_diff_rejected():
    with pytest.raises(DiffTooLargeError, match="bytes"):
        parse_diff("+" * (MAX_DIFF_BYTES + 1))


def test_too_many_lines_rejected():
    chunk = "diff --git a/a.py b/a.py\n@@ -1,1 +1,1 @@\n+x\n"
    with pytest.raises(DiffTooLargeError, match="lines"):
        parse_diff(chunk * (MAX_DIFF_LINES // 3 + 1))


def test_pathological_line_rejected():
    header = "diff --git a/a.py b/a.py\n@@ -1,1 +1,1 @@\n+"
    with pytest.raises(DiffTooLargeError, match="line longer"):
        parse_diff(header + "x" * (MAX_LINE_LEN + 1))


def test_absolute_path_in_diff_header_dropped():
    raw = "diff --git a/C:/Windows/system32/x.dll b/C:/Windows/system32/x.dll\n@@ -1,1 +1,1 @@\n+x\n"
    assert parse_diff(raw) == {}


def test_dotdot_path_in_diff_header_dropped():
    raw = "diff --git a/../../../etc/passwd b/../../../etc/passwd\n@@ -1,1 +1,1 @@\n+x\n"
    assert parse_diff(raw) == {}


def test_normal_diff_still_parses():
    raw = (
        "diff --git a/app.py b/app.py\n"
        "index 000..111 100644\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,2 +1,3 @@\n"
        " def a():\n"
        "+    password = 'hunter2'\n"
        "     return 1\n"
    )
    out = parse_diff(raw)
    assert "app.py" in out
    assert [l.text for l in out["app.py"].additions if l.kind == "add"] == ["    password = 'hunter2'"]


def test_binary_files_diff_skipped():
    raw = "diff --git a/a.bin b/a.bin\nBinary files a/a.bin and b/a.bin differ\n"
    out = parse_diff(raw)
    # the binary marker is recognized and the hunk contributes no lines
    assert list(out) == ["a.bin"]
    assert out["a.bin"].additions == []


def test_nested_subdir_path_kept_relative():
    raw = "diff --git a/src/deep/name with space.py b/src/deep/name with space.py\n@@ -1,1 +1,1 @@\n+x\n"
    out = parse_diff(raw)
    assert list(out) == ["src/deep/name with space.py"]
    assert isinstance(out["src/deep/name with space.py"], Changeset)