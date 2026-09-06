"""Path-containment and sensitive-path tests (workspace-escape defence)."""

from __future__ import annotations

import pytest

from sentinel.pathsec import (
    PathEscapeError,
    ensure_within,
    is_sensitive_relpath,
    is_within,
    resolve_within,
)


def test_relative_path_resolves_inside(tmp_path):
    resolved = resolve_within(tmp_path, "sub/app.py")
    assert str(resolved).startswith(str(tmp_path.resolve()))


def test_dotdot_escape_raises(tmp_path):
    with pytest.raises(PathEscapeError):
        ensure_within(tmp_path, "../outside.txt")


def test_absolute_path_rejected_in_resolve(tmp_path):
    with pytest.raises(PathEscapeError):
        resolve_within(tmp_path, str(tmp_path))


def test_symlink_escape_detected(tmp_path):
    outside = tmp_path.parent / "outside_dir"
    outside.mkdir(exist_ok=True)
    target = outside / "secret.txt"
    target.write_text("secret", encoding="utf-8")
    link = tmp_path / "evil"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks not permitted on this platform")
    with pytest.raises(PathEscapeError):
        ensure_within(tmp_path, "evil/secret.txt")
    assert not is_within(tmp_path, "evil/secret.txt")


def test_is_within_happy_path(tmp_path):
    assert is_within(tmp_path, "app.py") is True


def test_sensitive_paths_blocked():
    for path in (".env", ".git/config", "credentials.json", "keys/id_rsa",
                 "ssh/cert.pem", ".ssh/authorized_keys", "src/secrets.txt"):
        assert is_sensitive_relpath(path), path


def test_normal_code_path_allowed():
    for path in ("src/app.py", "lib/utils.js", "docs/README.md"):
        assert not is_sensitive_relpath(path), path


def test_nonexistent_candidate_resolves(tmp_path):
    # resolving inside root that doesn't exist yet is still fine (no escape)
    assert is_within(tmp_path, "newdir/newfile.py") is True