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

#: Per-analyzer execution budget for content analyzers (regex scanning is CPU
#: bound; a pathological rule on a hostile input must time out, not hang).
CONTENT_TIMEOUT = 60

#: Content-analyzer blocks that ran past their budget are tracked so a later
#: run cannot be distorted by an earlier one.
_analyzer_violations: dict[str, int] = {}


class MalformedAnalyzerOutput(RuntimeError):
    """Raised when an analyzer executed but produced unparseable/malformed output.

    The runner maps this to ``EvidenceStatus.MALFORMED_OUTPUT``, which (like
    ERROR/TIMEOUT) can never yield a VERIFIED verdict upstream.
    """


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

    Content analyzers execute in a disposable subprocess (``analyzers._worker``)
    with a single shared wall-clock budget (``CONTENT_TIMEOUT``). A hostile or
    pathological analyzer cannot hang the review and is reported as TIMEOUT;
    everything that ran reports per-analyzer status PASS or ERROR.  Any of
    ERROR/TIMEOUT/MALFORMED_OUTPUT makes a VERIFIED verdict impossible upstream.
    """
    findings: list[Finding] = []
    status_map: dict[str, dict[str, str]] = {}
    if not changesets:
        return findings, status_map

    # Reset per-call: each review starts with a clean slate. Violations from a
    # prior call must not silently block this one (that was a bug in the old
    # design too, but batch isolation makes it worse).
    _analyzer_violations.clear()

    joined: list[str] = []
    for name, cls in CONTENT_ANALYZERS.items():
        try:
            if name in _analyzer_violations:
                continue  # already proven hostile this process — stay fail-closed
            if not _matches(cls(), _content_languages(changesets)):
                status_map[name] = _status(
                    name, EvidenceStatus.SKIPPED.value,
                    f"no files of supported languages {cls().supported_languages}",
                )
                continue
        except Exception as exc:
            status_map[name] = _status(name, EvidenceStatus.ERROR.value, f"class init failed: {exc!r}")
            continue
        joined.append(name)

    if joined:
        _run_batch_worker(changesets, joined, findings, status_map)

    return findings, status_map


def _batch_changeset_json(cs: Changeset) -> dict:
    return {
        "file": cs.file,
        "additions": [
            {"kind": d.kind, "text": d.text, "new_line": d.new_line, "old_line": d.old_line}
            for d in cs.additions
        ],
    }


def _run_batch_worker(
    changesets: dict[str, Changeset],
    names: list[str],
    findings: list[Finding],
    status_map: dict[str, dict[str, str]],
) -> None:
    """Single bounded subprocess runs the whole content phase (see module doc)."""
    import json as _json
    import os
    import sys
    import tempfile

    from ..process import ProcessResult, run_safe

    try:
        with tempfile.TemporaryDirectory(prefix="sentinel_content_") as tmp:
            in_path = os.path.join(tmp, "changesets.json")
            out_path = os.path.join(tmp, "results.json")
            progress_path = os.path.join(tmp, "phase.json")
            with open(in_path, "w", encoding="utf-8") as fh:
                _json.dump(
                    {
                        "changesets": {name: _batch_changeset_json(cs) for name, cs in changesets.items()},
                        "analyzers": names,
                    },
                    fh,
                )

            res: ProcessResult = run_safe(
                [
                    sys.executable, "-m", "sentinel.analyzers._worker",
                    "--in", in_path,
                    "--out", out_path,
                    "--phase", progress_path,
                ],
                cwd=tmp,
                timeout=CONTENT_TIMEOUT,
                max_output=200_000,
            )

            phase: dict = {}
            if os.path.exists(progress_path):
                try:
                    with open(progress_path, encoding="utf-8") as fh:
                        phase = _json.load(fh)
                except (_json.JSONDecodeError, OSError):
                    phase = {}
            done = phase.get("done", {}) if isinstance(phase, dict) else {}
            current = phase.get("current") if isinstance(phase, dict) else None

            if res.timed_out:
                _mark_timeout(names, done, current, findings, status_map)
                return

            if res.error or res.returncode != 0:
                detail = res.error or f"worker exit {res.returncode}"
                for name in names:
                    status_map[name] = _status(name, EvidenceStatus.ERROR.value, f"worker failed: {detail}")
                return

            try:
                with open(out_path, encoding="utf-8") as fh:
                    payload = _json.load(fh)
            except (_json.JSONDecodeError, OSError) as exc:
                for name in names:
                    status_map[name] = _status(
                        name, EvidenceStatus.MALFORMED_OUTPUT.value,
                        f"worker output unparseable: {type(exc).__name__}",
                    )
                return
    except (FileNotFoundError, OSError) as exc:
        for name in names:
            status_map[name] = _status(name, EvidenceStatus.ERROR.value,
                                       f"content worker could not start: {type(exc).__name__}: {exc}")
        return

    results = payload.get("results") if isinstance(payload, dict) else None
    if results is None:
        for name in names:
            status_map[name] = _status(name, EvidenceStatus.MALFORMED_OUTPUT.value,
                                       "worker returned no analyzer results")
        return

    for name in names:
        if name in _analyzer_violations:
            status_map[name] = _status(
                name, EvidenceStatus.TIMEOUT.value,
                f"flagged earlier — exceeded {CONTENT_TIMEOUT}s budget once this process",
            )
            continue
        item = results.get(name)
        if item is None:
            status_map[name] = _status(name, EvidenceStatus.MISSING.value, "no result from worker")
            continue
        if item.get("error"):
            status_map[name] = _status(name, EvidenceStatus.ERROR.value, str(item["error"])[:200])
            continue
        raw = item.get("findings")
        if not isinstance(raw, list):
            status_map[name] = _status(name, EvidenceStatus.MALFORMED_OUTPUT.value,
                                       "worker returned malformed findings")
            continue
        for d in raw:
            f = Finding(
                rule_id=d.get("rule_id", ""),
                severity=_severity_value(d.get("severity", "")),
                file=d.get("file", ""),
                line=int(d.get("line", 0) or 0),
                code_snippet=d.get("code_snippet", ""),
                description=d.get("description", ""),
                evidence=d.get("evidence", ""),
                suggested_fix=d.get("suggested_fix", ""),
            )
            f.analyzer = name
            loc = f"{f.file}:{f.line}" if f.file else ""
            f.evidence_items = finding_evidence(name, EvidenceStatus.PASS, loc=loc)
            f.verdict, f.verdict_reason = finding_verdict(f.evidence_items)
            findings.append(f)
        status_map[name] = _status(name, EvidenceStatus.PASS.value, f"{len(raw)} finding(s)")


def _mark_timeout(
    names: list[str],
    done: dict,
    current: str | None,
    findings: list[Finding],
    status_map: dict[str, dict[str, str]],
) -> None:
    """After a killed worker: keep done analyzers, mark the rest TIMEOUT."""
    for name in names:
        _analyzer_violations[name] = _analyzer_violations.get(name, 0) + 1
    for name in names:
        done_item = done.get(name)
        if isinstance(done_item, dict) and isinstance(done_item.get("findings"), list):
            for d in done_item["findings"]:
                f = Finding(
                    rule_id=d.get("rule_id", ""),
                    severity=_severity_value(d.get("severity", "")),
                    file=d.get("file", ""),
                    line=int(d.get("line", 0) or 0),
                    code_snippet=d.get("code_snippet", ""),
                    description=d.get("description", ""),
                    evidence=d.get("evidence", ""),
                    suggested_fix=d.get("suggested_fix", ""),
                )
                f.analyzer = name
                loc = f"{f.file}:{f.line}" if f.file else ""
                f.evidence_items = finding_evidence(name, EvidenceStatus.PASS, loc=loc)
                f.verdict, f.verdict_reason = finding_verdict(f.evidence_items)
                findings.append(f)
            status_map[name] = _status(name, EvidenceStatus.PASS.value, f"{len(done_item['findings'])} finding(s)")
            continue
        if name == current:
            status_map[name] = _status(
                name, EvidenceStatus.TIMEOUT.value,
                f"exceeded {CONTENT_TIMEOUT}s budget (killed mid-run)",
            )
        else:
            status_map[name] = _status(
                name, EvidenceStatus.TIMEOUT.value,
                f"worker killed before {name} ran (some analyzer exceeded {CONTENT_TIMEOUT}s)",
            )


def _severity_value(value: str):
    from ..models import severity_from_str

    return severity_from_str(value)


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
        except MalformedAnalyzerOutput as exc:
            status_map[name] = _status(name, EvidenceStatus.MALFORMED_OUTPUT.value, str(exc)[:200])
        except Exception as exc:
            status_map[name] = _status(name, EvidenceStatus.ERROR.value, f"{type(exc).__name__}: {str(exc)[:200]}")
    return findings, status_map


def _severity_value(value: str):
    from ..models import severity_from_str

    return severity_from_str(value)


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