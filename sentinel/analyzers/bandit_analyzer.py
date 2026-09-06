"""Bandit-based file analyzer (real security scan of a working tree)."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from ..models import Finding, severity_from_str
from .base import FileAnalyzer, register_file


def _find_bandit_config(cwd: Path) -> tuple[Path | None, list[str]]:
    """Locate the repo's bandit configuration and its exclude_dirs (if pyproject)."""
    for name in ("pyproject.toml", "bandit.yaml", "bandit.yml", ".bandit"):
        p = cwd / name
        if not p.exists():
            continue
        if name != "pyproject.toml":
            return p, []
        try:
            import tomllib

            data = tomllib.loads(p.read_text(encoding="utf-8"))
            excluded = list(
                data.get("tool", {}).get("bandit", {}).get("exclude_dirs", [])
            )
            return p, excluded
        except Exception:
            return p, []
    return None, []


def _under_excluded(rel_file: str, excluded: list[str]) -> bool:
    normal = rel_file.replace("\\", "/")
    for ex in excluded:
        exn = ex.replace("\\", "/").rstrip("/")
        if not exn:
            continue
        if normal == exn or normal.startswith(exn + "/"):
            return True
        if f"/{exn}/" in normal:
            return True
    return False


@register_file
class BanditAnalyzer(FileAnalyzer):
    name = "bandit"

    def analyze_files(self, path: str, files: list[str]) -> list[Finding]:
        if not files:
            return []
        cwd = Path(path)
        config_path, excluded = _find_bandit_config(cwd)
        files = [f for f in files if not _under_excluded(f, excluded)]
        if not files:
            return []
        try:
            out_dir = tempfile.mkdtemp(prefix="sentinel_bandit_")
            report_path = Path(out_dir) / "bandit.json"
            cmd = ["bandit", "-q", "-f", "json", "-o", str(report_path)]
            if config_path is not None:
                cmd += ["-c", str(config_path)]
            res = subprocess.run(
                cmd + files,
                cwd=path, capture_output=True, text=True, check=False,
            )
            if res.returncode not in (0, 1) or not report_path.exists():
                return []
        except FileNotFoundError:
            return []

        try:
            data = json.loads(report_path.read_text(encoding="utf-8"))
        except Exception:
            return []

        findings: list[Finding] = []
        for issue in data.get("results", []):
            fname = issue.get("filename", "")
            findings.append(
                Finding(
                    rule_id=f"BANDIT-{issue.get('test_id', '')}",
                    severity=severity_from_str(issue.get("issue_severity", "low")),
                    file=fname,
                    line=int(issue.get("line_number", 0) or 0),
                    code_snippet=issue.get("code", "").strip(),
                    description=issue.get("issue_text", ""),
                    evidence=issue.get("test_name", ""),
                    suggested_fix="Review the Bandit test for this line and apply a safe alternative.",
                )
            )
        return findings