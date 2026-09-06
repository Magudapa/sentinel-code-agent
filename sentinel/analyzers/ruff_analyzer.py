"""Ruff-based file analyzer (bug + lint scan of a working tree)."""

from __future__ import annotations

import json
import shutil

from ..models import Finding, severity_from_str
from ..process import run_safe
from .base import FileAnalyzer, MalformedAnalyzerOutput, register_file


@register_file
class RuffAnalyzer(FileAnalyzer):
    name = "ruff"
    version = "1.2"
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
            res = run_safe(
                ["ruff", "check", "--output-format", "json", "--quiet", "--no-cache"] + files,
                cwd=path, timeout=timeout, extra_env=env or None,
            )
            if res.timed_out:
                raise TimeoutError(f"ruff exceeded {timeout}s") from None
            if res.error:
                if "program not found" in res.error:
                    raise FileNotFoundError("ruff binary not found on PATH")
                raise RuntimeError(res.error)
            if not res.stdout.strip():
                if res.returncode != 0:
                    raise MalformedAnalyzerOutput(
                        f"ruff exited {res.returncode} with no JSON output: {res.stderr[:200]}"
                    )
                return []
        except (FileNotFoundError, RuntimeError, TimeoutError, MalformedAnalyzerOutput):
            raise
        except Exception as exc:
            raise RuntimeError(f"ruff failed to run: {type(exc).__name__}: {exc}") from exc

        def _sev(code: str):
            if code.startswith(("E9", "F")):  # logic errors / pyflakes
                return "medium"
            return "low"

        findings: list[Finding] = []
        try:
            issues = json.loads(res.stdout)
        except Exception as exc:
            raise MalformedAnalyzerOutput(
                f"unparseable ruff JSON output: {type(exc).__name__}"
            ) from exc
        if not isinstance(issues, list):
            raise MalformedAnalyzerOutput("ruff JSON output is not a list")

        for issue in issues:
            try:
                if not isinstance(issue, dict):
                    continue
                code = issue.get("code") or "RUFF"
                findings.append(
                    Finding(
                        rule_id=f"RUFF-{code}",
                        severity=severity_from_str(_sev(code)),
                        file=issue.get("filename", ""),
                        line=int(issue.get("location", {}).get("row", 0) or 0),
                        code_snippet="",
                        description=issue.get("message", ""),
                        evidence=code,
                        suggested_fix="Auto-fixable with `ruff check --fix`. Review then commit.",
                    )
                )
            except Exception:
                continue
        return findings