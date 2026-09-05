"""AI cross-verification gate for rule submissions.

Submission policy (see BRD): a rule may enter a book (or be marked verified)
ONLY after two independent gates pass:

1. Empirical gate — the regex must fire on ``vulnerable_example`` and stay
   silent on ``safe_example`` (deterministic, no model involved).
2. AI gate — an independent model reviews the rule against a strict rubric
   (real vulnerability? correct severity? obvious false positives? safe fix?)
   and returns PASS/REVISE/REJECT with a reason.

``ai_verified: true`` is therefore never hand-written; it is stamped here.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from dataclasses import dataclass

from ..model import ModelClient
from .defs import RuleDefinition


class RuleVerificationError(RuntimeError):
    """Raised when a rule cannot be verified (e.g. missing regex/examples)."""

RUBRIC = (
    "You are the independent security reviewer on Gate 2 of a rule submission.\n"
    "Judge the rule against CODE QUALITY standards of a senior security engineer:\n"
    "1. Is this a REAL vulnerability category (not a style nit)?\n"
    "2. Is the severity right (info/low/medium/high/critical)?\n"
    "3. Does the regex risk obvious FALSE POSITIVES on legitimate code?\n"
    "4. Is the suggested fix safe and correct?\n"
    "Reply with strict JSON only: {\"verdict\": \"PASS\"|\"REVISE\"|\"REJECT\", "
    "\"reason\": \"one short paragraph\"}"
)


@dataclass
class VerificationResult:
    rule_id: str
    empirical_passed: bool = False
    empirical_notes: str = ""
    ai_verdict: str = "SKIPPED"   # PASS | REVISE | REJECT | SKIPPED
    ai_reason: str = ""
    verified: bool = False
    model: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "empirical_passed": self.empirical_passed,
            "empirical_notes": self.empirical_notes,
            "ai_verdict": self.ai_verdict,
            "reason": self.ai_reason,
            "verified": self.verified,
            "verified_by": self.model,
        }


def empirical_check(rule: RuleDefinition) -> tuple[bool, str]:
    """Gate 1 — deterministic match/no-match on provided examples."""
    try:
        rx = re.compile(rule.regex)
    except re.error as e:
        return False, f"invalid regex: {e}"
    notes = []
    if rule.vulnerable_example:
        if not rx.search(rule.vulnerable_example):
            notes.append("FAIL: vulnerable_example did not match")
            return False, "; ".join(notes)
        notes.append("OK: vulnerable_example matched")
    if rule.safe_example:
        if rx.search(rule.safe_example):
            notes.append("FAIL: safe_example matched (false positive)")
            return False, "; ".join(notes)
        notes.append("OK: safe_example clean")
    if not notes:
        return False, "no vulnerable_example/safe_example supplied for Gate 1"
    return True, "; ".join(notes)


def _extract_verdict(raw: str) -> dict:
    try:
        m = re.search(r"\{[\s\S]*\}", raw)
        obj = json.loads(m.group(0)) if m else {}
    except Exception:
        obj = {}
    verdict = str(obj.get("verdict", "")).strip().upper()
    if verdict not in ("PASS", "REVISE", "REJECT"):
        verdict = "REVISE"
    return {"verdict": verdict, "reason": str(obj.get("reason", raw[:200]))}


def ai_check(model: ModelClient, rule: RuleDefinition) -> dict:
    """Gate 2 — independent model cross-review (never the rule author)."""
    body = (
        "RULE SUBMISSION\n"
        f"id={rule.id}\nlanguage={rule.language}\nseverity={rule.severity}\n"
        f"category={rule.category}\ndescription={rule.description}\n"
        f"regex={rule.regex!r}\nmessage={rule.message}\nfix={rule.fix}\n"
        f"vulnerable_example={rule.vulnerable_example!r}\n"
        f"safe_example={rule.safe_example!r}\n"
    )
    try:
        raw = model.chat(RUBRIC, body)
    except Exception as e:
        return {"verdict": "SKIPPED", "reason": f"model unavailable: {e}"}
    return _extract_verdict(raw)


def verify_rule(rule: RuleDefinition, model: ModelClient | None = None) -> VerificationResult:
    """Run both gates. ``verified`` requires empirical + AI PASS."""
    emp_pass, emp_notes = empirical_check(rule)
    res = VerificationResult(
        rule_id=rule.id,
        empirical_passed=emp_pass,
        empirical_notes=emp_notes,
        model=(model.config.model if model else ""),
    )
    if not emp_pass:
        res.verified = False
        return res
    ai = ai_check(model, rule) if model else {"verdict": "SKIPPED", "reason": "no model configured"}
    res.ai_verdict = ai["verdict"]
    res.ai_reason = ai["reason"]
    res.verified = bool(model) and ai["verdict"] == "PASS"
    return res


def stamp(rule: RuleDefinition, res: VerificationResult) -> RuleDefinition:
    """Apply the verifier's result onto a rule (never sets verified itself)."""
    now = dt.datetime.now(dt.UTC).isoformat(timespec="seconds")
    rule.ai_verified = res.verified
    rule.verified_by = res.model if res.verified else ""
    rule.verified_at = now if res.verified else ""
    rule.verification_notes = (
        f"gate1={res.empirical_notes}; gate2={res.ai_verdict}: {res.ai_reason[:300]}"
    )
    return rule