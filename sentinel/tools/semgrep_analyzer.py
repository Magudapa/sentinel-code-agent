"""Optional Semgrep adapter — used only when the `semgrep` binary is on PATH.

Sentinel is resilient: if semgrep is absent the analyzer is skipped quietly and
the rest of the pipeline still runs (bandit/ruff/book rules are always active).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..analyzers.base import FileAnalyzer, register_file
from ..models import Finding, severity_from_str

_BINARY = shutil.which("semgrep")

_META = {"ContributingTeam": "Semgrep Community", "Security": "audit"}
_SEVERITY_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


@register_file
class SemgrepAnalyzer(FileAnalyzer):
    """Runs `semgrep --config p/security-audit` over the given files."""

    name = "semgrep"

    def available(self) -> bool:
        return _BINARY is not None

    def analyze_files(self, path: str, files: list[str]) -> list[Finding]:
        if not self.available():
            return []
        targets = [f for f in files if Path(f).exists()]
        if not targets:
            return []
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as out:
            out_path = out.name
        cmd = [
            _BINARY, "--config", "p/security-audit",
            "--json", "--quiet", "--no-git-ignore",
            "--output", out_path, *targets[:50],
        ]
        try:
            subprocess.run(cmd, cwd=path, capture_output=True, timeout=300, check=False)
            data = json.loads(Path(out_path).read_text(encoding="utf-8"))
        except Exception:
            data = {}
        finally:
            try:
                Path(out_path).unlink(missing_ok=True)
            except Exception:
                pass

        findings: list[Finding] = []
        for res in data.get("results", []):
            rule = res.get("rule") or {}
            rid = rule.get("id") or res.get("check_id") or "SEMGREP"
            sev = rule.get("severity", "WARNING")
            findings.append(
                Finding(
                    rule_id=rid,
                    severity=severity_from_str(_SEVERITY_MAP.get(sev, "low")),
                    file=res.get("path", ""),
                    line=int(res.get("start", {}).get("line") or 0),
                    code_snippet=(res.get("extra", {}).get("lines") or "")[:400],
                    description=(rule.get("message") or rid)[:300],
                    evidence=f"semgrep {rid}",
                    suggested_fix="",
                )
            )
        return findings