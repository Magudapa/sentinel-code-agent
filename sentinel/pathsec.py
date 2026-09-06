"""Path containment — prevents workspace escapes via absolute paths or symlinks.

Security model:
* ``resolve_relative`` resolves a user-supplied relative path against ``root``;
  the result must still be physically inside ``root`` (realpath check so that
  symlink tricks cannot escape).
* ``ensure_within`` rejects any path that is not strictly contained in ``root``.
"""

from __future__ import annotations

import os
from pathlib import Path


class PathEscapeError(ValueError):
    """Raised when a path resolves outside the permitted root."""


def _norm(p: str) -> str:
    return os.path.normpath(os.path.abspath(p))


def ensure_within(root: str | os.PathLike, candidate: str | os.PathLike) -> Path:
    """Return candidate normalized+realpath'd, guaranteed inside root.

    Raises PathEscapeError otherwise. ``candidate`` may be absolute or relative
    (relative is resolved against ``root``).
    """
    root_path = Path(_norm(os.fspath(root)))
    root_real = root_path.resolve()

    cand = os.fspath(candidate)
    full = Path(_norm(cand)) if os.path.isabs(cand) else Path(_norm(str(root_path / cand)))
    cand_real = full.resolve()

    if cand_real == root_real or root_real in cand_real.parents:
        return cand_real
    raise PathEscapeError(f"path escapes workspace: {cand!r} -> {cand_real}")


def resolve_within(root: str | os.PathLike, relative: str) -> Path:
    """Resolve ``relative`` inside ``root`` (it must stay inside)."""
    if os.path.isabs(relative):
        raise PathEscapeError(f"absolute path not allowed here: {relative!r}")
    return ensure_within(root, relative)


def is_within(root: str | os.PathLike, candidate: str | os.PathLike) -> bool:
    try:
        ensure_within(root, candidate)
        return True
    except PathEscapeError:
        return False


_SECRET_SEGMENT_TOKENS = {
    ".git", ".ssh", ".env", "credentials", "secret", "secrets",
    "id_rsa", "id_ed25519", "passwd", "shadow", ".htpasswd",
    "authorized_keys", "known_hosts", "keystore", "keyring",
}
_SECRET_SUFFIXES = (".pem", ".p12", ".pfx", ".key")


def is_sensitive_relpath(relative: str) -> bool:
    """True if a relative path looks like a secret/infra file that must never be modified."""
    norm = relative.replace("\\", "/")
    lowered = norm.lower()
    for segment in [s for s in lowered.split("/") if s]:
        if segment in _SECRET_SEGMENT_TOKENS:
            return True
        if segment.startswith(".env") or segment.endswith(_SECRET_SUFFIXES):
            return True
        if "secret" in segment or "credential" in segment:
            return True
    return False