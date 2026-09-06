"""Trust-model invariants — the core of the verification state machine.

These lock the rules that MUST never regress:
  * missing evidence can never produce VERIFIED
  * an ERROR/TIMEOUT/NOT_INSTALLED analyzer can never produce VERIFIED
  * a FAIL evidence item always produces FAILED
  * the AI sumbmitted content is data — the pipeline never lets a model set a verdict
"""

from __future__ import annotations

from sentinel.trust import (
    EvidenceStatus,
    Verdict,
    ev,
    finding_evidence,
    finding_verdict,
    report_verdict,
    verdict_of,
)


def st(status: EvidenceStatus | str) -> dict:
    return {"status": status.value if isinstance(status, EvidenceStatus) else status, "detail": ""}


class TestVerdictPolicy:
    def test_missing_evidence_cannot_be_verified(self):
        verdict, _ = verdict_of([], ("rule_match", "analyzer"))
        assert verdict == Verdict.INCOMPLETE

    def test_partial_evidence_cannot_be_verified(self):
        items = [ev("rule_match", "sentinel-rules", EvidenceStatus.PASS)]
        verdict, _ = verdict_of(items, ("rule_match", "analyzer"))
        assert verdict == Verdict.INCOMPLETE

    def test_error_evidence_blocks_verified(self):
        items = [
            ev("rule_match", "sentinel-rules", EvidenceStatus.PASS),
            ev("analyzer", "sentinel-rules", EvidenceStatus.ERROR, error="boom"),
        ]
        verdict, reason = verdict_of(items, ("rule_match", "analyzer"))
        assert verdict == Verdict.INCOMPLETE
        assert "ERROR" in reason

    def test_timeout_evidence_blocks_verified(self):
        items = [
            ev("rule_match", "x", EvidenceStatus.PASS),
            ev("analyzer", "x", EvidenceStatus.TIMEOUT),
        ]
        assert verdict_of(items, ("rule_match", "analyzer"))[0] == Verdict.INCOMPLETE

    def test_not_installed_blocks_verified(self):
        items = [
            ev("rule_match", "x", EvidenceStatus.PASS),
            ev("analyzer", "semgrep", EvidenceStatus.NOT_INSTALLED),
        ]
        assert verdict_of(items, ("rule_match", "analyzer"))[0] == Verdict.INCOMPLETE

    def test_fail_is_always_failed(self):
        items = [
            ev("rule_match", "x", EvidenceStatus.PASS),
            ev("analyzer", "x", EvidenceStatus.PASS),
            ev("gate", "patch", EvidenceStatus.FAIL, detail="patch does not apply"),
        ]
        verdict, _reason = verdict_of(items, ("rule_match", "analyzer"))
        assert verdict == Verdict.FAILED

    def test_all_positive_verifies(self):
        items = [
            ev("rule_match", "sentinel-rules", EvidenceStatus.PASS),
            ev("analyzer", "sentinel-rules", EvidenceStatus.PASS),
        ]
        verdict, _reason = verdict_of(items, ("rule_match", "analyzer"))
        assert verdict == Verdict.VERIFIED

    def test_findings_status_is_positive_evidence(self):
        items = [
            ev("rule_match", "bandit", EvidenceStatus.FINDINGS),
            ev("analyzer", "bandit", EvidenceStatus.FINDINGS),
        ]
        assert verdict_of(items, ("rule_match", "analyzer"))[0] == Verdict.VERIFIED


class TestFindingEvidence:
    def test_finding_evidence_verifies(self):
        items = finding_evidence("sentinel-rules", EvidenceStatus.PASS, loc="app.py:3")
        verdict, _ = finding_verdict(items)
        assert verdict == Verdict.VERIFIED

    def test_finding_evidence_with_failed_analyzer_is_incomplete(self):
        items = finding_evidence("semgrep", EvidenceStatus.NOT_INSTALLED)
        verdict, _ = finding_verdict(items)
        assert verdict == Verdict.INCOMPLETE

    def test_evidence_item_serializes(self):
        item = ev("rule_match", "sentinel-rules", EvidenceStatus.PASS, detail="matched at app.py:3")
        d = item.to_dict()
        from sentinel.trust import EvidenceItem

        back = EvidenceItem.from_dict(d)
        assert back.type == "rule_match"
        assert back.status == EvidenceStatus.PASS
        assert back.detail == d["detail"]


class TestReportVerdict:
    def test_no_analyzers_runs_is_incomplete(self):
        verdict, _ = report_verdict({}, {"semgrep"}, has_worktree=True)
        assert verdict == Verdict.INCOMPLETE.value

    def test_semgrep_missing_in_worktree_is_incomplete(self):
        vm = {
            "sentinel-rules": st(EvidenceStatus.PASS),
            "sentinel-rules-book": st(EvidenceStatus.PASS),
            "bandit": st(EvidenceStatus.PASS),
            "ruff": st(EvidenceStatus.PASS),
            "semgrep": st(EvidenceStatus.NOT_INSTALLED),
        }
        verdict, reason = report_verdict(vm, {"semgrep"}, has_worktree=True)
        assert verdict == Verdict.INCOMPLETE.value
        assert "semgrep" in reason

    def test_semgrep_only_required_when_worktree(self):
        vm = {
            "sentinel-rules": st(EvidenceStatus.PASS),
            "sentinel-rules-book": st(EvidenceStatus.PASS),
        }
        verdict, _ = report_verdict(vm, {"semgrep"}, has_worktree=False)
        assert verdict == Verdict.VERIFIED.value

    def test_errored_analyzer_is_incomplete_even_if_not_required(self):
        vm = {
            "sentinel-rules": st(EvidenceStatus.PASS),
            "bandit": st(EvidenceStatus.ERROR),
        }
        verdict, _ = report_verdict(vm, set(), has_worktree=True)
        assert verdict == Verdict.INCOMPLETE.value

    def test_clean_required_set_verifies(self):
        vm = {
            "sentinel-rules": st("PASS"),
            "sentinel-rules-book": st("PASS"),
            "bandit": st("PASS"),
            "ruff": st("PASS"),
            "semgrep": st("PASS"),
        }
        verdict, _ = report_verdict(vm, {"bandit", "ruff", "semgrep"}, has_worktree=True)
        assert verdict == Verdict.VERIFIED.value

    def test_required_analyzer_that_did_not_run_is_incomplete(self):
        vm = {"sentinel-rules": st("PASS")}
        verdict, _ = report_verdict(vm, {"bandit"}, has_worktree=True)
        assert verdict == Verdict.INCOMPLETE.value

    def test_pure_diff_mode_runs_only_content_analyzers(self):
        vm = {"sentinel-rules": st("PASS"), "sentinel-rules-book": st("PASS")}
        verdict, _ = report_verdict(vm, {"bandit", "ruff", "semgrep"}, has_worktree=False)
        assert verdict == Verdict.VERIFIED.value