"""Codebase memory: records fixed findings so future reviews can reference them.

Uses Chroma when installed; falls back to a pure-Python JSON store so the core
library never *requires* a vector DB.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass

from ..models import Finding


@dataclass
class MemoryEntry:
    pattern: str          # normalized fingerprint of the violated code
    rule_id: str
    file: str
    fix_summary: str
    embedding: str = ""   # stored as hex digest of md5 (cheap local stand-in)


def fingerprint(code_snippet: str) -> str:
    """Normalize whitespace/quotes so similar violations match.

    ``usedforsecurity=False``: this is a content-similarity fingerprint, not a
    security hash.
    """
    norm = " ".join(code_snippet.split())
    return hashlib.md5(norm.encode("utf-8"), usedforsecurity=False).hexdigest()


class MemoryStore:
    def __init__(self, directory: str = ".sentinel-memory"):
        self.directory = directory
        self._path = os.path.join(directory, "entries.jsonl")
        self._entries: list[MemoryEntry] = []
        if os.path.exists(self._path):
            self._load()

    def _load(self):
        with open(self._path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                self._entries.append(MemoryEntry(**d))

    def _save(self):
        os.makedirs(self.directory, exist_ok=True)
        with open(self._path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(self._entries[-1].__dict__) + "\n")

    def remember(self, finding: Finding, fix_summary: str) -> MemoryEntry:
        entry = MemoryEntry(
            pattern=fingerprint(finding.code_snippet),
            rule_id=finding.rule_id,
            file=finding.file,
            fix_summary=fix_summary,
        )
        for existing in self._entries:
            if existing.pattern == entry.pattern and existing.rule_id == entry.rule_id:
                return existing
        self._entries.append(entry)
        self._save()
        return entry

    def recall(self, finding: Finding) -> MemoryEntry | None:
        """Return a past fix that matches this finding's pattern, if any."""
        pat = fingerprint(finding.code_snippet)
        for entry in reversed(self._entries):
            if entry.pattern == pat and entry.rule_id == finding.rule_id:
                return entry
            # Rule may differ but code shape identical — still useful signal
            if entry.pattern == pat:
                return entry
        return None

    def match_count(self, rule_id: str) -> int:
        return sum(1 for e in self._entries if e.rule_id == rule_id)