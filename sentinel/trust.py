"""Central evidence & verification model — the Sentinel trust core.

Principle (do not compromise):

    AI can suggest.  Evidence decides.

Every security decision carries structured evidence.  Verdicts are produced by a
deterministic policy engine from that evidence — never by an AI, and never by
free-form strings such as "PASS" set from arbitrary places in the application.

Verdict semantics
-----------------
VERIFIED      every mandatory evidence gate executed and passed.
INCOMPLETE    a mandatory gate could not execute or its outcome is unknown
              (missing analyzer, error, timeout, unavailable tool, …).
FAILED        a mandatory gate executed and explicitly failed.
NOT_APPLICABLE / SKIPPED
              informational only — these can never be reinterpreted as VERIFIED.

Invariants enforced here (and locked by tests):
    * missing evidence can never produce VERIFIED
    * analyzer ERROR / TIMEOUT / NOT_INSTALLED can never produce PASS or VERIFIED
    * a FAIL evidence item always makes the verdict FAILED
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from enum import Enum


class EvidenceStatus(str, Enum):
    PASS = "PASS"  # nosec B105 - enum literal used for report serialization, not a credential
    FINDINGS = "FINDINGS"            # executed cleanly and found issues (evidence, not a pass)
    FAIL = "FAIL"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    MALFORMED_OUTPUT = "MALFORMED_OUTPUT"  # analyzer ran but produced unparseable output (never a pass)
    NOT_INSTALLED = "NOT_INSTALLED"
    NOT_SUPPORTED = "NOT_SUPPORTED"  # not applicable in this environment (e.g. no working tree)
    SKIPPED = "SKIPPED"
    MISSING = "MISSING"

    @property
    def positive(self) -> bool:
        """True when the item can count *towards* verification."""
        return self in (EvidenceStatus.PASS, EvidenceStatus.FINDINGS)

    @property
    def blocks(self) -> bool:
        """True when the item makes VERIFIED impossible (but not FAILED)."""
        return self in (
            EvidenceStatus.ERROR,
            EvidenceStatus.TIMEOUT,
            EvidenceStatus.MALFORMED_OUTPUT,
            EvidenceStatus.NOT_INSTALLED,
            EvidenceStatus.MISSING,
            EvidenceStatus.SKIPPED,
        )


class Verdict(str, Enum):
    VERIFIED = "VERIFIED"
    INCOMPLETE = "INCOMPLETE"
    FAILED = "FAILED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    SKIPPED = "SKIPPED"


# Evidence `type` constants (stable identifiers used by the policy engine).
EV_RULE_MATCH = "rule_match"
EV_ANALYZER = "analyzer"
EV_PATCH = "patch"
EV_SYNTAX = "syntax"
EV_TEST = "test"
EV_AI = "ai"
EV_CONFIG = "config"
EV_GATE = "gate"


@dataclass
class EvidenceItem:
    """One atomic piece of verification evidence."""

    type: str                 # EV_* constant, e.g. "rule_match", "analyzer", "test"
    source: str               # analyzer name, rule id, gate name, …
    status: EvidenceStatus
    detail: str = ""
    error: str = ""
    recorded_at: str = ""

    def __post_init__(self) -> None:
        if not self.recorded_at:
            self.recorded_at = dt.datetime.now(dt.UTC).isoformat(timespec="seconds")

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "source": self.source,
            "status": self.status.value,
            "detail": self.detail,
            "error": self.error,
            "recorded_at": self.recorded_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> EvidenceItem:
        return cls(
            type=str(d.get("type", "")),
            source=str(d.get("source", "")),
            status=EvidenceStatus(str(d.get("status", "MISSING"))),
            detail=str(d.get("detail", "")),
            error=str(d.get("error", "")),
            recorded_at=str(d.get("recorded_at", "")),
        )


def ev(
    type_: str,
    source: str,
    status: EvidenceStatus | str,
    detail: str = "",
    error: str = "",
) -> EvidenceItem:
    if isinstance(status, str):
        status = EvidenceStatus(status)
    return EvidenceItem(type=type_, source=source, status=status, detail=detail, error=error)


def finding_evidence(
    source: str,
    analyzer_status: EvidenceStatus | str = EvidenceStatus.PASS,
    loc: str = "",
) -> list[EvidenceItem]:
    """Standard evidence chain for a finding reported by analyzer ``source``.

    Contains the mandatory gate types EV_RULE_MATCH + EV_ANALYZER, so a finding
    can reach VERIFIED only when both are positive.
    """
    if isinstance(analyzer_status, str):
        analyzer_status = EvidenceStatus(analyzer_status)
    if loc:
        match_detail = f"rule matched at {loc}"
    else:
        match_detail = "rule matched"
    return [
        ev(EV_RULE_MATCH, source, EvidenceStatus.PASS, detail=match_detail),
        ev(EV_ANALYZER, source, analyzer_status, detail="analyzer executed cleanly"),
    ]


def finding_verdict(
    items: list[EvidenceItem],
) -> tuple[Verdict, str]:
    """Verdict for a single finding: both rule_match and analyzer must be positive."""
    return verdict_of(items, (EV_RULE_MATCH, EV_ANALYZER))


# Analyzers that need a working tree on disk. Without a working tree their
# status is NOT_SUPPORTED (environmental) and they cannot block a verdict.
WORKTREE_ANALYZERS = frozenset({"bandit", "ruff", "semgrep"})


def report_verdict(
    status_map: dict[str, dict[str, str]],
    required: set[str],
    has_worktree: bool,
) -> tuple[str, str]:
    """Deterministic report-level verdict from the analyzer status map.

    * any applicable analyzer that crashed (ERROR/TIMEOUT)          -> INCOMPLETE
    * any *required* analyzer that is unavailable (NOT_INSTALLED /
      MISSING / SKIPPED)                                           -> INCOMPLETE
    * everything required present and healthy                       -> VERIFIED
    * ``required`` is operator policy (default: bandit, ruff, semgrep).
    ``has_worktree`` controls whether worktree analyzers are applicable.
    """
    if not status_map:
        return Verdict.INCOMPLETE.value, "no analyzers executed"

    def applicable(name: str, s: str) -> bool:
        return not (name in WORKTREE_ANALYZERS and not has_worktree)

    reasons: list[str] = []

    for name, info in status_map.items():
        s = info.get("status", "")
        if applicable(name, s) and s in ("FAIL",):
            return Verdict.FAILED.value, f"{name} reported FAIL: {info.get('detail', '')}"

    crashed = [
        f"{name} {info.get('status')}: {info.get('detail', '')}"
        for name, info in status_map.items()
        if applicable(name, info.get("status", ""))
        and info.get("status") in ("ERROR", "TIMEOUT", "MALFORMED_OUTPUT")
    ]
    if crashed:
        return Verdict.INCOMPLETE.value, " | ".join(crashed)

    for name in sorted(required):
        info = status_map.get(name)
        if info is None:
            if name in WORKTREE_ANALYZERS and not has_worktree:
                continue  # worktree analyzers are not applicable in pure-diff mode
            reasons.append(f"{name} did not run (missing from analyzer output)")
            continue
        s = info.get("status", "")
        if not applicable(name, s):
            continue
        if s in ("NOT_INSTALLED", "MISSING", "SKIPPED"):
            reasons.append(f"{name} unavailable: {info.get('detail', '')}")
        elif info.get("status") not in ("PASS", "FINDINGS"):
            reasons.append(f"{name} status {s}: {info.get('detail', '')}")

    if reasons:
        return Verdict.INCOMPLETE.value, " | ".join(reasons)

    return Verdict.VERIFIED.value, "all required analyzers executed cleanly"


def verdict_of(items: list[EvidenceItem], required: tuple[str, ...]) -> tuple[Verdict, str]:
    """Deterministic verdict policy.

    ``required`` is a tuple of evidence *types* that must all be present with a
    positive status for VERIFIED.

    Order of evaluation matters:
      1. any FAIL                     -> FAILED        (explicit validation failure)
      2. any required type missing    -> INCOMPLETE
      3. any required item that blocks -> INCOMPLETE
      4. everything present & positive -> VERIFIED
    """
    by_type: dict[str, list[EvidenceItem]] = {}
    for it in items:
        by_type.setdefault(it.type, []).append(it)

    for it in items:
        if it.status == EvidenceStatus.FAIL:
            return Verdict.FAILED, f"evidence {it.type}:{it.source} explicitly FAILED"

    missing = [t for t in required if not by_type.get(t)]
    if missing:
        return Verdict.INCOMPLETE, f"missing required evidence: {', '.join(sorted(missing))}"

    blockers = [
        it
        for t in required
        for it in by_type[t]
        if it.status.blocks or not it.status.positive
    ]
    if blockers:
        b = blockers[0]
        return (
            Verdict.INCOMPLETE,
            f"required evidence {b.type}:{b.source} was {b.status.value}"
            + (f" — {b.error}" if b.error else ""),
        )

    return Verdict.VERIFIED, "all required evidence passed"


def reason_of(items: list[EvidenceItem], required: tuple[str, ...]) -> tuple[Verdict, str]:
    """Per-gate 'why' text: e.g. '✓ rule matched / ✗ semgrep unavailable'."""
    verdict, _ = verdict_of(items, required)
    lines = []
    for it in items:
        mark = "✓" if it.status.positive else "✗"
        lines.append(f"{mark} {it.type}:{it.source} — {it.status.value}")
    lines.append(f"Therefore: {verdict.value}")
    return verdict, "\n".join(lines)


@dataclass
class VerificationReport:
    """Structured verification result attached to a ReviewReport."""

    verdict: str = Verdict.INCOMPLETE.value
    reason: str = ""
    evidence: list[EvidenceItem] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "evidence": [e.to_dict() for e in self.evidence],
        }

    @classmethod
    def from_dict(cls, d: dict) -> VerificationReport:
        return cls(
            verdict=str(d.get("verdict", Verdict.INCOMPLETE.value)),
            reason=str(d.get("reason", "")),
            evidence=[EvidenceItem.from_dict(e) for e in d.get("evidence", [])],
        )