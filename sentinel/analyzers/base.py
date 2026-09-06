"""Analyzer base classes and registry.

Analyzers are grouped in two families:

* ``ContentAnalyzer`` — analyse text (diff lines / file snippets) with no disk
  access.  These are deterministic, dependency-free and always available.
* ``FileAnalyzer``    — analyse real files on disk (Bandit, Ruff, Semgrep, …).
  They need a working tree and may rely on external binaries.

Every analyzer exposes ``version`` and can report ``available()``.  The runner
functions execute every applicable analyzer and return a **status map** next to
the findings, so the trust layer can prove what ran, what failed, and what was
missing.  Exceptions are never swallowed silently — an errored analyzer becomes
an ``ERROR`` status entry, which prevents a VERIFIED verdict upstream.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

from ..diffparse import Changeset
from ..models import Finding
from ..trust import EvidenceStatus, finding_evidence, finding_verdict

AnalyzerStatus = "dict[str, dict[str, str]]"


def _status(name: str, status: str, detail: str = "") -> dict[str, str]:
    return {"status": status, "detail": detail}


class ContentAnalyzer(ABC):
    """Analyzes text (diff lines / file snippets) without needing files on disk."""

    name = "base"
    language = "*"
    version = "1.0"
    supported_languages: tuple[str, ...] = ("*",)

    @abstractmethod
    def analyze(self, changeset: Changeset) -> list[Finding]: ...

    def available(self) -> tuple[bool, str]:
        return True, ""

    def health_check(self) -> tuple[EvidenceStatus, str]:
        ok, why = self.available()
        return (EvidenceStatus.PASS if ok else EvidenceStatus.NOT_INSTALLED), why


class FileAnalyzer(ABC):
    """Analyzes real files on disk (e.g. Bandit, Ruff). Requires a working tree."""

    name = "base"
    language = "*"
    version = "1.0"
    supported_languages: tuple[str, ...] = ("*",)

    @abstractmethod
    def analyze_files(self, path: str, files: list[str]) -> list[Finding]: ...

    def available(self) -> tuple[bool, str]:
        return True, ""

    def health_check(self) -> tuple[EvidenceStatus, str]:
        ok, why = self.available()
        return (EvidenceStatus.PASS if ok else EvidenceStatus.NOT_INSTALLED), why


CONTENT_ANALYZERS: dict[str, type[ContentAnalyzer]] = {}
FILE_ANALYZERS: dict[str, type[FileAnalyzer]] = {}


def register_content(cls: type[ContentAnalyzer]) -> type[ContentAnalyzer]:
    CONTENT_ANALYZERS[cls.name] = cls
    return cls


def register_file(cls: type[FileAnalyzer]) -> type[FileAnalyzer]:
    FILE_ANALYZERS[cls.name] = cls
    return cls


def _ext_language(path: str) -> str:
    lower = path.lower()
    if lower.endswith(".py"):
        return "python"
    if lower.endswith((".js", ".mjs", ".cjs")):
        return "javascript"
    if lower.endswith((".ts", ".tsx")):
        return "typescript"
    if lower.endswith((".yml", ".yaml")):
        return "yaml"
    if lower.endswith(".sql"):
        return "sql"
    return "other"


def _content_languages(changesets: dict[str, Changeset]) -> set[str]:
    return {_ext_language(cs.file) for cs in changesets.values()}


def _file_languages(files: list[str]) -> set[str]:
    langs = {_ext_language(f) for f in files}
    return langs or {"*"}


def _matches(analyser: ContentAnalyzer | FileAnalyzer, langs: set[str]) -> bool:
    supported = set(analyser.supported_languages)
    if "*" in supported:
        return True
    return bool(langs & supported)


def analyze_changesets(changesets: dict[str, Changeset]) -> list[Finding]:
    findings, _ = analyze_changesets_full(changesets)
    return findings


def analyze_changesets_full(
    changesets: dict[str, Changeset],
) -> tuple[list[Finding], dict[str, dict[str, str]]]:
    """Run every content analyzer; return (findings, {name: status}).

    Status values comply with ``trust.EvidenceStatus``: PASS, ERROR, or SKIPPED
    (when the analyzer does not support the changeset languages).
    """
    findings: list[Finding] = []
    status_map: dict[str, dict[str, str]] = {}
    langs = _content_languages(changesets)

    for name, cls in CONTENT_ANALYZERS.items():
        try:
            if not _matches(cls(), langs):
                status_map[name] = _status(name, EvidenceStatus.SKIPPED.value,
                                           f"no files of supported languages {cls().supported_languages}")
                continue
        except Exception as exc:
            status_map[name] = _status(name, EvidenceStatus.ERROR.value, f"class init failed: {exc!r}")
            continue
        instances: list[ContentAnalyzer] = []
        try:
            instances = [cls()]
        except Exception as exc:
            status_map[name] = _status(name, EvidenceStatus.ERROR.value, f"init failed: {exc!r}")
            continue
        analyzer = instances[0]
        try:
            hit = 0
            for changeset in changesets.values():
                fs = analyzer.analyze(changeset)
                for f in fs:
                    f.analyzer = name
                    loc = f"{f.file}:{f.line}" if f.file else ""
                    f.evidence_items = finding_evidence(name, EvidenceStatus.PASS, loc=loc)
                    f.verdict, f.verdict_reason = finding_verdict(f.evidence_items)
                hit += len(fs)
                findings.extend(fs)
            status_map[name] = _status(name, EvidenceStatus.PASS.value, f"{hit} finding(s)")
        except Exception as exc:
            status_map[name] = _status(name, EvidenceStatus.ERROR.value, f"{type(exc).__name__}: {str(exc)[:200]}")
    return findings, status_map


def analyze_files(path: str, files: list[str]) -> list[Finding]:
    findings, _ = analyze_files_full(path, files)
    return findings


def analyze_files_full(
    path: str, files: list[str], timeout: int = 120, env: dict | None = None
) -> tuple[list[Finding], dict[str, dict[str, str]]]:
    """Run every file analyzer; return (findings, {name: status}).

    Status values: PASS, ERROR, TIMEOUT (subprocess exceeded ``timeout``),
    NOT_INSTALLED (required binary missing), or SKIPPED.
    """
    findings: list[Finding] = []
    status_map: dict[str, dict[str, str]] = {}
    if not path:
        return findings, status_map
    langs = _file_languages(files)

    for name, cls in FILE_ANALYZERS.items():
        try:
            analyzer = cls()
        except Exception as exc:
            status_map[name] = _status(name, EvidenceStatus.ERROR.value, f"init failed: {exc!r}")
            continue
        if not _matches(analyzer, langs):
            status_map[name] = _status(name, EvidenceStatus.SKIPPED.value,
                                       f"no files of supported languages {analyzer.supported_languages}")
            continue
        ok, why = analyzer.available()
        if not ok:
            status_map[name] = _status(name, EvidenceStatus.NOT_INSTALLED.value, why)
            continue
        try:
            res = analyzer.analyze_files(path, files, timeout=timeout, env=env) \
                if _accepts_extra_kwargs(analyzer.analyze_files) else analyzer.analyze_files(path, files)
            for f in res:
                f.analyzer = name
                loc = f"{f.file}:{f.line}" if f.file else ""
                f.evidence_items = finding_evidence(name, EvidenceStatus.PASS, loc=loc)
                f.verdict, f.verdict_reason = finding_verdict(f.evidence_items)
            status_map[name] = _status(name, EvidenceStatus.PASS.value, f"{len(res)} finding(s)")
            findings.extend(res)
        except TimeoutError:
            status_map[name] = _status(name, EvidenceStatus.TIMEOUT.value, f"exceeded {timeout}s")
        except FileNotFoundError:
            status_map[name] = _status(name, EvidenceStatus.NOT_INSTALLED.value, "binary not found")
        except Exception as exc:
            status_map[name] = _status(name, EvidenceStatus.ERROR.value, f"{type(exc).__name__}: {str(exc)[:200]}")
    return findings, status_map


def _accepts_extra_kwargs(fn: Callable[..., Any]) -> bool:
    import inspect

    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return False
    params = sig.parameters
    if "timeout" in params or "env" in params:
        return True
    return any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())