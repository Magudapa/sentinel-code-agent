"""Optional Semgrep file analyzer.

Semgrep is an optional analyzer: when the binary is absent the analyzer is
still registered, but ``available()`` reports it missing.  The runner layer
turns that into an explicit ``NOT_INSTALLED`` status (never a silent skip), so
the trust layer can downgrade the report to INCOMPLETE unless the operator
explicitly configured semgrep as optional.
"""

from __future__ import annotations

import json
import shutil

from ..models import Finding, severity_from_str
from ..process import run_safe
from .base import FileAnalyzer, MalformedAnalyzerOutput, register_file


@register_file
class SemgrepAnalyzer(FileAnalyzer):
    name = "semgrep"
    version = "1.1"
    supported_languages: tuple[str, ...] = ("python", "javascript", "typescript", "yaml")

    def available(self) -> tuple[bool, str]:
        if shutil.which("semgrep"):
            return True, ""
        return False, "semgrep binary not found on PATH (optional analyzer)"

    def analyze_files(
        self, path: str, files: list[str], timeout: int = 300, env: dict | None = None
    ) -> list[Finding]:
        if not files:
            return []
        try:
            res = run_safe(
                ["semgrep", "scan", "--json", "--quiet", "--no-rewrite-rule-ids", *files],
                cwd=path, timeout=timeout, extra_env=env or None, max_output=20_000_000,
            )
            if res.timed_out:
                raise TimeoutError(f"semgrep exceeded {timeout}s") from None
            if res.error:
                if "program not found" in res.error:
                    raise FileNotFoundError("semgrep binary not found on PATH")
                raise RuntimeError(res.error)
        except (FileNotFoundError, RuntimeError, TimeoutError):
            raise
        except Exception as exc:
            raise RuntimeError(f"semgrep failed to run: {type(exc).__name__}: {exc}") from exc

        try:
            data = json.loads(res.stdout or "{}")
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise MalformedAnalyzerOutput(
                f"unparseable semgrep JSON output: {type(exc).__name__}"
            ) from exc
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            raise MalformedAnalyzerOutput("semgrep report missing 'results' array")

        findings: list[Finding] = []
        for result in data.get("results", []):
            loc = result.get("location", {})
            rule = result.get("check_id", "") or "unknown"
            fname = loc.get("path", "")
            findings.append(
                Finding(
                    rule_id=f"SEMGREP-{rule.replace('/', '-')}",
                    severity=severity_from_str(_sev(result.get("extra", {}))),
                    file=fname,
                    line=int(loc.get("start", {}).get("line", 0) or 0),
                    end_line=int(loc.get("end", {}).get("line", 0) or 0),
                    code_snippet=(result.get("extra", {}).get("lines", "") or "").strip(),
                    description=(result.get("extra", {}).get("message", "") or "").strip(),
                    evidence="semgrep rule match",
                    suggested_fix="Review the semgrep rule guidance and apply a safe pattern.",
                )
            )
        return findings


def _sev(extra: dict) -> str:
    sev = (extra.get("severity") or "").lower()
    return {"error": "high", "warning": "medium", "info": "low"}.get(sev, "low")