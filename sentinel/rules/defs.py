"""Rule book definitions for Sentinel's multi-language rules system.

A :class:`RuleDefinition` is a single entry in a language rule book. Every rule
carries an ``author`` and a verification status. Rules are only considered
``ai_verified`` after passing the two-gate verification in
:mod:`sentinel.rules.verify` (empirical match test + AI cross-review).
"""

from __future__ import annotations

from dataclasses import dataclass

VALID_SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class RuleDefinition:
    """One verifiable rule in a language book."""

    id: str
    language: str
    description: str          # human name, e.g. "Cleartext HTTP request"
    severity: str             # info|low|medium|high|critical
    regex: str                # python re pattern tested against added lines
    message: str = ""         # shown in reports
    fix: str = ""             # the safe alternative
    category: str = "best-practice"
    author: str = ""          # credited rule author
    source: str = "manual"    # manual | learned | ai-generated | community
    ai_verified: bool = False # only set by the verify gate (never hand-written)
    verified_by: str = ""     # model id of the AI that cross-reviewed it
    verified_at: str = ""     # ISO timestamp of verification
    verification_notes: str = ""  # what the AI reviewer decided/flagged
    vulnerable_example: str = ""  # snippet that MUST match (empirical gate)
    safe_example: str = ""        # snippet that MUST NOT match (empirical gate)
    version: int = 1              # rule semantic version (bumps with each edit)
    lifecycle: str = "active"     # active | deprecated | retired
    deprecation_note: str = ""    # why retired/deprecated (if any)
    last_modified: str = ""       # ISO timestamp of last edit

    def __post_init__(self) -> None:
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity {self.severity!r} for rule {self.id}")
        if not self.regex:
            raise ValueError(f"Rule {self.id} has no regex pattern")
        if self.version < 1:
            raise ValueError(f"Rule {self.id} has invalid version {self.version}")
        if self.lifecycle not in ("active", "deprecated", "retired"):
            raise ValueError(f"Rule {self.id} has invalid lifecycle {self.lifecycle!r}")

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "language": self.language,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "regex": self.regex,
            "message": self.message,
            "fix": self.fix,
            "author": self.author,
            "source": self.source,
            "ai_verified": self.ai_verified,
            "verified_by": self.verified_by,
            "verified_at": self.verified_at,
            "verification_notes": self.verification_notes,
            "vulnerable_example": self.vulnerable_example,
            "safe_example": self.safe_example,
            "version": self.version,
            "lifecycle": self.lifecycle,
            "deprecation_note": self.deprecation_note,
            "last_modified": self.last_modified,
        }

    @classmethod
    def from_dict(cls, d: dict) -> RuleDefinition:
        return cls(
            id=str(d.get("id", "")).strip(),
            language=str(d.get("language", "")).strip(),
            description=str(d.get("description", "")).strip(),
            severity=str(d.get("severity", "low")).lower(),
            regex=str(d.get("regex", "")),
            message=str(d.get("message", "")),
            fix=str(d.get("fix", "")),
            category=str(d.get("category", "best-practice")),
            author=str(d.get("author", "")),
            source=str(d.get("source", "manual")),
            ai_verified=bool(d.get("ai_verified", False)),
            verified_by=str(d.get("verified_by", "")),
            verified_at=str(d.get("verified_at", "")),
            verification_notes=str(d.get("verification_notes", "")),
            vulnerable_example=str(d.get("vulnerable_example", "")),
            safe_example=str(d.get("safe_example", "")),
            version=int(d.get("version", 1) or 1),
            lifecycle=str(d.get("lifecycle", "active")),
            deprecation_note=str(d.get("deprecation_note", "")),
            last_modified=str(d.get("last_modified", "")),
        )

    @property
    def verified(self) -> bool:
        """A rule counts as verified only through the AI gate."""
        return self.ai_verified and self.lifecycle == "active"


def dedupe_rules(rules: list[RuleDefinition]) -> list[RuleDefinition]:
    seen: set[str] = set()
    out: list[RuleDefinition] = []
    for r in rules:
        if r.id in seen:
            continue
        seen.add(r.id)
        out.append(r)
    return out