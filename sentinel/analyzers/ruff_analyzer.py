"""Ruff-based file analyzer (bug + lint scan of a working tree)."""

from __future__ import annotations

import json
import shutil
import subprocess

from ..models import Finding, severity_from_str
from .base import FileAnalyzer, register_file


@register_file
class RuffAnalyzer(FileAnalyzer):
    name = "ruff"
    version = "1.1"
    supported_languages: tuple[str, ...] = ("python",)

    def available(self) -> tuple[bool, str]:
        if shutil.which("ruff"):
            return True, ""
        return False, "ruff binary not found on PATH"

    def analyze_files(
        self, path: str, files: list[str], timeout: int = 120, env: dict | None = None
    ) -> list[Finding]:
        if not files:
            return []
        try:
            res = subprocess.run(
                ["ruff", "check", "--output-format", "json", "--quiet", "--no-cache"] + files,
                cwd=path, capture_output=True, text=True, check=False,
                timeout=timeout, env=env,
            )
            if not res.stdout.strip():
                return []
        except FileNotFoundError:
            return []
        except subprocess.TimeoutExpired:
            raise TimeoutError(f"ruff exceeded {timeout}s") from None

        def _sev(code: str):
            if code.startswith(("E9", "F")):  # logic errors / pyflakes
                return "medium"
            return "low"

        findings: list[Finding] = []
        try:
            issues = json.loads(res.stdout)
        except Exception:
            return findings

        for issue in issues:
            code = issue.get("code", "RUFF")
            findings.append(
                Finding(
                    rule_id=f"RUFF-{code}",
                    severity=severity_from_str(_sev(code)),
                    file=issue.get("filename", ""),
                    line=int(issue.get("location", {}).get("row", 0) or 0),
                    code_snippet=issue.get("fix", {}).get("applier_available", False) and "" or "",
                    description=issue.get("message", ""),
                    evidence=code,
                    suggested_fix="Auto-fixable with `ruff check --fix`. Review then commit.",
                )
            )
        return findings