"""Bandit-based file analyzer (real security scan of a working tree)."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from ..models import Finding, severity_from_str
from .base import FileAnalyzer, register_file


@register_file
class BanditAnalyzer(FileAnalyzer):
    name = "bandit"

    def analyze_files(self, path: str, files: list[str]) -> list[Finding]:
        if not files:
            return []
        try:
            out_dir = tempfile.mkdtemp(prefix="sentinel_bandit_")
            report_path = Path(out_dir) / "bandit.json"
            res = subprocess.run(
                ["bandit", "-q", "-f", "json", "-o", str(report_path)] + files,
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