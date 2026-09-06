"""Core data models for Sentinel."""

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

SEVERITY_COLORS = {
    "info": "#64748b",
    "low": "#3b82f6",
    "medium": "#f59e0b",
    "high": "#f97316",
    "critical": "#ef4444",
}


def severity_from_str(value: str) -> Severity:
    try:
        return Severity[value.strip().upper()]
    except KeyError:
        return Severity.LOW


@dataclass
class Finding:
    """A single review finding."""

    rule_id: str
    severity: Severity
    file: str
    line: int
    end_line: int = 0
    code_snippet: str = ""
    description: str = ""
    evidence: str = ""
    model_explanation: str = ""
    suggested_fix: str = ""
    fix_difficulty: str = "easy"
    memory_hint: str = ""
    # trust layer
    analyzer: str = ""
    verdict: str = "INCOMPLETE"          # one of trust.Verdict
    verdict_reason: str = ""
    evidence_items: list = field(default_factory=list)  # list[EvidenceItem]

    @property
    def severity_name(self) -> str:
        return self.severity.name.lower()

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity_name,
            "file": self.file,
            "line": self.line,
            "end_line": self.end_line,
            "description": self.description,
            "evidence": self.evidence,
            "explanation": self.model_explanation,
            "suggested_fix": self.suggested_fix,
            "fix_difficulty": self.fix_difficulty,
            "memory_hint": self.memory_hint,
            "code_snippet": self.code_snippet,
            "analyzer": self.analyzer,
            "verdict": self.verdict,
            "verdict_reason": self.verdict_reason,
            "evidence_items": [e.to_dict() for e in self.evidence_items],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        from .trust import EvidenceItem

        return cls(
            rule_id=data.get("rule_id", "unknown"),
            severity=severity_from_str(data.get("severity", "low")),
            file=data.get("file", ""),
            line=int(data.get("line", 0) or 0),
            end_line=int(data.get("end_line", 0) or 0),
            code_snippet=data.get("code_snippet", ""),
            description=data.get("description", ""),
            evidence=data.get("evidence", ""),
            model_explanation=data.get("explanation", ""),
            suggested_fix=data.get("suggested_fix", ""),
            fix_difficulty=data.get("fix_difficulty", "easy"),
            memory_hint=data.get("memory_hint", ""),
            analyzer=data.get("analyzer", ""),
            verdict=data.get("verdict", "INCOMPLETE"),
            verdict_reason=data.get("verdict_reason", ""),
            evidence_items=[EvidenceItem.from_dict(e) for e in data.get("evidence_items", [])],
        )


@dataclass
class Patch:
    """A validated auto-fix patch."""

    finding: Finding
    diff: str
    validated: bool = False
    tests_passed: bool | None = None
    validation_notes: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding.rule_id,
            "file": self.finding.file,
            "diff": self.diff,
            "validated": self.validated,
            "tests_passed": self.tests_passed,
            "notes": self.validation_notes,
        }


@dataclass
class ReviewReport:
    """Result of a full review."""

    provider: str
    repo: str
    target: str  # PR number, diff key, commit range, local path
    verdict_score: int = 0
    summary_md: str = ""
    findings: list[Finding] = field(default_factory=list)
    patches: list[Patch] = field(default_factory=list)
    created_at: str = ""
    # trust layer
    schema_version: str = "1.1"
    sentinel_version: str = ""
    verdict: str = "INCOMPLETE"
    verdict_reason: str = ""
    analyzer_status: dict = field(default_factory=dict)
    verification: dict = field(default_factory=dict)
    review_id: str = ""

    @property
    def counts(self) -> dict:
        out = {}
        for f in self.findings:
            out[f.severity_name] = out.get(f.severity_name, 0) + 1
        return out

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "repo": self.repo,
            "target": self.target,
            "verdict_score": self.verdict_score,
            "summary_md": self.summary_md,
            "counts": self.counts,
            "findings": [f.to_dict() for f in self.findings],
            "patches": [p.to_dict() for p in self.patches],
            "created_at": self.created_at,
            "schema_version": self.schema_version,
            "sentinel_version": self.sentinel_version,
            "status": self.verdict,
            "verdict_reason": self.verdict_reason,
            "analyzers": self.analyzer_status,
            "verification": self.verification,
            "review_id": self.review_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ReviewReport":
        return cls(
            provider=data.get("provider", ""),
            repo=data.get("repo", ""),
            target=data.get("target", ""),
            verdict_score=data.get("verdict_score", 0),
            summary_md=data.get("summary_md", ""),
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
            patches=[
                Patch(finding=Finding.from_dict(p.get("finding", {})), diff=p.get("diff", ""))
                for p in data.get("patches", [])
            ],
            created_at=data.get("created_at", ""),
            schema_version=data.get("schema_version", "1.1"),
            sentinel_version=data.get("sentinel_version", ""),
            verdict=data.get("status") or data.get("verdict", "INCOMPLETE"),
            verdict_reason=data.get("verdict_reason", ""),
            analyzer_status=data.get("analyzers", {}),
            verification=data.get("verification", {}),
            review_id=data.get("review_id", ""),
        )


def compute_verdict_score(findings: list[Finding]) -> int:
    """Score 0-100, higher is healthier. Start at 100, subtract per finding by severity."""
    weights = {Severity.INFO: 1, Severity.LOW: 3, Severity.MEDIUM: 8, Severity.HIGH: 15, Severity.CRITICAL: 30}
    score = 100
    for f in findings:
        score -= weights[f.severity]
    return max(0, score)