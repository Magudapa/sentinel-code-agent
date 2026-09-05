"""Local git repository provider (no network needed)."""

from __future__ import annotations

import subprocess
from pathlib import Path

from .base import BaseProvider, ProviderContext, register


def _run(cmd: list[str], cwd: Path) -> str:
    res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    if res.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{res.stderr}")
    return res.stdout


@register
class LocalProvider(BaseProvider):
    name = "local"

    def _repo_root(self, path: str) -> Path:
        root = Path(path).resolve()
        marker = (root / ".git")
        candidate = root
        while not marker.exists() and candidate.parent != candidate:
            candidate = candidate.parent
            marker = candidate / ".git"
        if not marker.exists():
            raise RuntimeError(f"{path} is not inside a git repository")
        return candidate

    def fetch_context(self, path: str, commit_range: str = "", diff: str = "") -> ProviderContext:
        root = self._repo_root(path)
        repo_name = root.name

        if diff:
            return ProviderContext(
                provider=self.name,
                repo=repo_name,
                target="<stdin diff>",
                diff=diff,
            )

        if commit_range:
            raw = _run(["git", "diff", commit_range, "--unified=200"], root)
            base_sha, head_sha = "", ""
            parts = commit_range.split("..")
            if len(parts) == 2:
                base_sha, head_sha = parts
        else:
            # default: review working tree vs HEAD
            raw = _run(["git", "diff", "HEAD", "--unified=200"], root)
            base_sha = "HEAD"
            head_sha = "working-tree"
            parts = []

        return ProviderContext(
            provider=self.name,
            repo=repo_name,
            target=commit_range or "HEAD..working-tree",
            diff=raw,
            base_sha=base_sha,
            head_sha=head_sha,
            files={},
        )