"""The Reviewer pipeline: evidence -> explain -> classify -> report.

Pipeline stages (documented in BRD section 7):
1. extract diff + changesets        (providers)
2. run content analyzers on diffs   (custom rules — works even without a checkout)
3. run file analyzers on disk       (bandit, ruff, semgrep — working tree only)
4. optional LLM explanations        (advisory only; capped; never sets verdicts)
5. memory recall                    (chroma/json store of "fixed before")
6. rank + score findings            (verdict score, severity sort)
7. trust layer                      (evidence items, analyzer status map,
                                     deterministic report-level verdict)

Trust semantics
---------------
* Analyzer status is recorded per analyzer on every run.
* A per-finding verdict depends only on its own evidence chain
  (rule_match + analyzer), never on AI output.
* The report-level verdict is computed by ``trust.report_verdict`` from the
  status map: any applicable analyzer ERROR/TIMEOUT downgrades the report to
  INCOMPLETE; any operator-required analyzer that could not run (e.g. Semgrep
  not installed) also produces INCOMPLETE — the report never claims safety it
  could not verify.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import os
import uuid

from .analyzers import analyze_changesets_full, analyze_files_full
from .config import SentinelConfig, load_config
from .diffparse import Changeset, parse_diff
from .memory import MemoryStore
from .model import ModelClient
from .models import Finding, ReviewReport, Severity, compute_verdict_score
from .providers import BaseProvider, ProviderContext
from .trust import (
    EvidenceStatus,
    Verdict,
    ev,
    report_verdict,
)

DEFAULT_REQUIRED_ANALYZERS = ("bandit", "ruff", "semgrep")
_MAX_EXPLANATIONS = 12
_AI_TIME_SECONDS = 120


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
        findings, status_map = self._run_analyzers(context, changesets, working_dir)
        findings = [f for f in findings if self._should_include(f.file)]

        if self.memory and findings:
            self._apply_memory_recall(findings)

        if explain:
            self._explain(findings)

        findings.sort(key=lambda f: (f.severity, f.file, f.line), reverse=True)

        report = ReviewReport(
            provider=provider.name,
            repo=context.repo,
            target=context.target,
            verdict_score=compute_verdict_score(findings),
            findings=findings,
            created_at=dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
            sentinel_version=_sentinel_version(),
            review_id=uuid.uuid4().hex[:12],
        )
        report.analyzer_status = status_map
        self._finalize_verdict(report, status_map, bool(working_dir and os.path.isdir(working_dir)))
        report.summary_md = self._summarize(report)
        return report

    # ---- trust layer -------------------------------------------------
    def _finalize_verdict(self, report: ReviewReport, status_map: dict, has_worktree: bool) -> None:
        required = self._required_analyzers(has_worktree)
        verdict, reason = report_verdict(status_map, required, has_worktree)
        report.verdict = verdict
        report.verdict_reason = reason

        verified = sum(1 for f in report.findings if f.verdict == Verdict.VERIFIED.value)
        incomplete = sum(1 for f in report.findings if f.verdict == Verdict.INCOMPLETE.value)
        failed = sum(1 for f in report.findings if f.verdict == Verdict.FAILED.value)

        ai = {
            "provider": self.config.model.provider,
            "model": self.config.model.model,
            "available": self.model.is_available(),
            "advisory_only": "explanations never set verdicts",
        }
        report.verification = {
            "verdict": verdict,
            "reason": reason,
            "required_analyzers": sorted(required),
            "policy": "report VERIFIED only if every required analyzer executed cleanly",
            "per_finding": {"verified": verified, "incomplete": incomplete, "failed": failed},
            "ai": ai,
        }

    def _required_analyzers(self, has_worktree: bool) -> set[str]:
        configured = self.config.resources.get("required_analyzers")
        if configured:
            return set(configured)
        if has_worktree:
            return set(DEFAULT_REQUIRED_ANALYZERS)
        return set()

    # ---- stages ------------------------------------------------------
    def _run_analyzers(self, context: ProviderContext, changesets: dict[str, Changeset], working_dir: str) -> tuple[list[Finding], dict]:
        findings, content_status = analyze_changesets_full(changesets)
        file_status: dict = {}
        if working_dir and os.path.isdir(working_dir):
            changed_files = [cs.file for cs in changesets.values() if not cs.file.endswith(("LOCK", "lock"))]
            existing = [f for f in changed_files if os.path.exists(os.path.join(working_dir, f))]
            f_findings, file_status = analyze_files_full(
                working_dir, existing[:50],
                timeout=self.config.resources.get("analyzer_timeout", 120),
            )
            findings += f_findings
        else:
            for name in ("bandit", "ruff", "semgrep"):
                file_status[name] = {"status": EvidenceStatus.NOT_SUPPORTED.value,
                                     "detail": "no working tree provided"}
        for name, info in content_status.items():
            if name not in file_status:
                file_status[name] = info
        return findings, file_status

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

    def _explain(self, findings: list[Finding]) -> None:
        """Advisory per-finding AI explanations.

        Bounded: capped count; skips files/patterns already explained (by
        rule_id+file); every explanation failure is recorded as an advisory
        evidence item (type `ai`, optional — never blocks a verdict).
        """
        if not self.model.is_available():
            for f in findings:
                f.evidence_items.append(
                    ev("ai", "model", EvidenceStatus.SKIPPED, detail="model offline — explanations skipped")
                )
            return
        lang = "python"
        explained: set[tuple[str, str]] = set()
        ordered = sorted(findings, key=lambda f: (f.severity, f.file, f.line), reverse=True)
        done = 0
        for f in ordered:
            key = (f.rule_id, f.file)
            if key in explained:
                f.evidence_items.append(
                    ev("ai", "model", EvidenceStatus.SKIPPED, detail="duplicate pattern already explained")
                )
                continue
            if done >= _MAX_EXPLANATIONS:
                f.evidence_items.append(
                    ev("ai", "model", EvidenceStatus.SKIPPED, detail=f"explanation cap reached ({_MAX_EXPLANATIONS})")
                )
                continue
            try:
                res = self.model.explain_finding(f, lang, timeout=self.config.model.timeout or _AI_TIME_SECONDS)
                f.model_explanation = res["explanation"]
                if res.get("suggested_fix") and res["suggested_fix"] != f.code_snippet:
                    f.suggested_fix = res["suggested_fix"]
                f.evidence_items.append(
                    ev("ai", "model", EvidenceStatus.PASS, detail="explanation produced (advisory)")
                )
                explained.add(key)
                done += 1
            except Exception as exc:
                f.evidence_items.append(
                    ev("ai", "model", EvidenceStatus.ERROR,
                       detail="AI explanation failed (advisory, does not affect verdict)",
                       error=f"{type(exc).__name__}")
                )
                done += 1  # bound work even on failures

    def _summarize(self, report: ReviewReport) -> str:
        counts = report.counts
        parts = [
            f"**{len(report.findings)} finding(s)**: "
            + ", ".join(f"{counts.get(s, 0)} {s}" for s in ("critical", "high", "medium", "low", "info") if s in counts),
            f"**Verdict:** {report.verdict} — {report.verdict_reason}",
        ]
        top = [f for f in report.findings if f.severity >= Severity.HIGH][:5]
        if top:
            parts.append("**Top issues:**")
            for f in top:
                parts.append(f"- `{f.rule_id}` {f.description} @ `{f.file}:{f.line}`")
        return "\n".join(parts)


def _sentinel_version() -> str:
    try:
        from . import __version__
        return __version__
    except Exception:
        return "unknown"


# ―― convenience facade -------------------------------------------------
def run_review(provider: BaseProvider, context: ProviderContext, config: SentinelConfig | None = None,
               explain: bool = True, working_dir: str = "") -> ReviewReport:
    reviewer = Reviewer(config)
    return reviewer.review(provider, context, explain=explain, working_dir=working_dir)