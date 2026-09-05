"""Analyzer base classes and registry."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..diffparse import Changeset
from ..models import Finding


class ContentAnalyzer(ABC):
    """Analyzes text (diff lines / file snippets) without needing files on disk."""

    name = "base"
    language = "*"

    @abstractmethod
    def analyze(self, changeset: Changeset) -> list[Finding]: ...


class FileAnalyzer(ABC):
    """Analyzes real files on disk (e.g. Bandit, Ruff). Requires a working tree."""

    name = "base"
    language = "*"

    @abstractmethod
    def analyze_files(self, path: str, files: list[str]) -> list[Finding]: ...


CONTENT_ANALYZERS: dict[str, type[ContentAnalyzer]] = {}
FILE_ANALYZERS: dict[str, type[FileAnalyzer]] = {}


def register_content(cls: type[ContentAnalyzer]) -> type[ContentAnalyzer]:
    CONTENT_ANALYZERS[cls.name] = cls
    return cls


def register_file(cls: type[FileAnalyzer]) -> type[FileAnalyzer]:
    FILE_ANALYZERS[cls.name] = cls
    return cls


def analyze_changesets(changesets: dict[str, Changeset]) -> list[Finding]:
    findings: list[Finding] = []
    for cls in CONTENT_ANALYZERS.values():
        try:
            for changeset in changesets.values():
                findings.extend(cls().analyze(changeset))
        except Exception:
            continue
    return findings


def analyze_files(path: str, files: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    if not path:
        return findings
    for cls in FILE_ANALYZERS.values():
        try:
            findings.extend(cls().analyze_files(path, files))
        except Exception:
            continue
    return findings