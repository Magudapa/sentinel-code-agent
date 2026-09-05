"""The Reviewer pipeline: evidence -> explain -> classify -> report.

Pipeline stages (documented in BRD section 7):
1. extract diff + changesets        (providers)
2. run content analyzers on diffs   (custom rules — works even without a checkout)
3. run file analyzers on disk       (bandit, ruff — when a working tree is available)
4. optional LLM explanations        (model layer; skipped when no model is reachable)
5. memory recall                    (chroma/json store of "fixed before")
6. rank + score findings            (verdict score, severity sort)
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import os

from .analyzers import analyze_changesets, analyze_files
from .config import SentinelConfig, load_config
from .diffparse import Changeset, parse_diff
from .memory import MemoryStore
from .model import ModelClient
from .models import Finding, ReviewReport, Severity, compute_verdict_score
from .providers import BaseProvider, ProviderContext


class Reviewer:
    def __init__(self, config: SentinelConfig | None = None):
        self.config = config or load_config()
        self.model = ModelClient(self.config.model)
        self.memory: MemoryStore | None = None
        if self.config.memory_enabled:
            try:
                self.memory = MemoryStore(self.config.memory_dir)
            except Exception:
                self.memory = None

    # ---- public entry ------------------------------------------------
    def review(self, provider: BaseProvider, context: ProviderContext,
               explain: bool = True, working_dir: str = "") -> ReviewReport:
        changesets = parse_diff(context.diff) or context.files
        findings = self._run_analyzers(context, changesets, working_dir)
        findings = [f for f in findings if self._should_include(f.file)]

        if self.memory and findings:
            self._apply_memory_recall(findings)

        if explain:
            findings = self._explain(findings)

        findings.sort(key=lambda f: (f.severity, f.file, f.line), reverse=True)

        report = ReviewReport(
            provider=provider.name,
            repo=context.repo,
            target=context.target,
            verdict_score=compute_verdict_score(findings),
            findings=findings,
            created_at=dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        )
        report.summary_md = self._summarize(report)
        return report

    # ---- stages ------------------------------------------------------
    def _run_analyzers(self, context: ProviderContext, changesets: dict[str, Changeset], working_dir: str) -> list[Finding]:
        findings = analyze_changesets(changesets)

        if working_dir and os.path.isdir(working_dir):
            changed_files = [cs.file for cs in changesets.values() if not cs.file.endswith(("LOCK", "lock"))]
            existing = [f for f in changed_files if os.path.exists(os.path.join(working_dir, f))]
            findings += analyze_files(working_dir, existing[:50])

        return findings

    def _should_include(self, file: str) -> bool:
        for pat in self.config.ignore_paths:
            if fnmatch.fnmatch(file, pat) or fnmatch.fnmatch(file, pat.rstrip("/") + "/*"):
                return False
        return True

    def _apply_memory_recall(self, findings: list[Finding]) -> None:
        for f in findings:
            entry = self.memory.recall(f)  # type: ignore[union-attr]
            if entry:
                f.memory_hint = f"Your team fixed this exact pattern before in `{entry.file}` (rule {entry.rule_id}). Consider the same fix: {entry.fix_summary[:120]}"

    def _explain(self, findings: list[Finding]) -> list[Finding]:
        if not self.model.is_available():
            return findings  # model offline -> analyzers only (still useful)
        lang = "python"
        for f in findings:
            try:
                res = self.model.explain_finding(f, lang)
                f.model_explanation = res["explanation"]
                if res.get("suggested_fix") and res["suggested_fix"] != f.code_snippet:
                    f.suggested_fix = res["suggested_fix"]
            except Exception:
                continue
        return findings

    def _summarize(self, report: ReviewReport) -> str:
        counts = report.counts
        parts = [
            f"**{len(report.findings)} finding(s)**: "
            + ", ".join(f"{counts.get(s, 0)} {s}" for s in ("critical", "high", "medium", "low", "info") if s in counts),
            f"**Verdict:** {report.verdict_score}/100",
        ]
        top = [f for f in report.findings if f.severity >= Severity.HIGH][:5]
        if top:
            parts.append("**Top issues:**")
            for f in top:
                parts.append(f"- `{f.rule_id}` {f.description} @ `{f.file}:{f.line}`")
        return "\n".join(parts)


# ―― convenience facade -------------------------------------------------
def run_review(provider: BaseProvider, context: ProviderContext, config: SentinelConfig | None = None,
               explain: bool = True, working_dir: str = "") -> ReviewReport:
    reviewer = Reviewer(config)
    return reviewer.review(provider, context, explain=explain, working_dir=working_dir)