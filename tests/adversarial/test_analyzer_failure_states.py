"""Adversarial tests for analyzer failure states.

The core invariant: an analyzer that runs but produces garbage output (or runs
forever) must NEVER be silently treated as a clean PASS — it becomes
MALFORMED_OUTPUT / TIMEOUT and blocks any VERIFIED verdict upstream.
"""

from __future__ import annotations

import pytest

from sentinel.analyzers import analyze_changesets_full, analyze_files_full
from sentinel.analyzers.base import (
    CONTENT_ANALYZERS,
    MalformedAnalyzerOutput,
)
from sentinel.diffparse import Changeset
from sentinel.trust import EvidenceStatus


def _changeset(content: str = "x = 1\n") -> dict[str, Changeset]:
    from sentinel.diffparse import DiffLine

    cs = Changeset(file="app.py", additions=[
        DiffLine(kind="add", text=ln, new_line=i + 1, old_line=None)
        for i, ln in enumerate(content.splitlines())
    ])
    return {"app.py": cs}


@pytest.fixture
def _py_target(tmp_path):
    target = tmp_path / "app.py"
    target.write_text("x = 1\n", encoding="utf-8")
    return tmp_path


def test_bandit_malformed_output_status_blocks_verified(_py_target, monkeypatch):
    # The status map produced by analyze_files_full must surface MALFORMED_OUTPUT
    # so report_verdict downgrades to INCOMPLETE/FAILED, never VERIFIED.
    from sentinel.analyzers.bandit_analyzer import BanditAnalyzer

    def fake_available(self):
        return True, ""

    def fake_analyze(self, path, files, timeout=120, env=None):
        raise MalformedAnalyzerOutput("bandit produced unparseable JSON")

    monkeypatch.setattr(BanditAnalyzer, "available", fake_available)
    monkeypatch.setattr(BanditAnalyzer, "analyze_files", fake_analyze)

    tmp_path = _py_target
    _findings, status = analyze_files_full(str(tmp_path), ["app.py"], timeout=5)
    assert status["bandit"]["status"] == EvidenceStatus.MALFORMED_OUTPUT.value

    from sentinel.trust import Verdict, report_verdict

    verdict, _reason = report_verdict(status, set(), True)
    assert verdict != Verdict.VERIFIED.value


def test_content_analyzer_timeout_blocks_verified(monkeypatch):
    # When the worker blows its budget, the analyzer must be recorded as
    # TIMEOUT (never a silent pass) and subsequent blocks bailed on.
    from sentinel.process import ProcessResult

    def fake_run_safe(argv, *, cwd=None, timeout=120, extra_env=None, max_output=1_000_000, input_text=None):
        assert "sentinel.analyzers._worker" in argv
        return ProcessResult(returncode=-1, timed_out=True, error="timed out after 1s")

    monkeypatch.setattr("sentinel.process.run_safe", fake_run_safe)

    from sentinel.analyzers.base import _analyzer_violations

    monkeypatch.setattr("sentinel.analyzers.base.CONTENT_TIMEOUT", 1)
    _analyzer_violations.pop("sentinel-rules", None)

    findings, status = analyze_changesets_full(_changeset())
    assert status["sentinel-rules"]["status"] == EvidenceStatus.TIMEOUT.value
    assert findings == []
    # a later review must stay fail-closed for this analyzer
    findings2, _ = analyze_changesets_full(_changeset())
    assert findings2 == []
    _analyzer_violations.pop("sentinel-rules", None)


def test_ruff_malformed_output_status(tmp_path, monkeypatch):
    from sentinel.analyzers.ruff_analyzer import RuffAnalyzer

    target = tmp_path / "app.py"
    target.write_text("x = 1\n", encoding="utf-8")

    monkeypatch.setattr(RuffAnalyzer, "available", lambda self: (True, ""))
    monkeypatch.setattr(
        RuffAnalyzer, "analyze_files",
        lambda self, p, f, timeout=120, env=None: _raise_bad(),
    )

    _, status = analyze_files_full(str(tmp_path), ["app.py"], timeout=5)
    assert status["ruff"]["status"] == EvidenceStatus.MALFORMED_OUTPUT.value


def _raise_bad():
    raise MalformedAnalyzerOutput("unparseable ruff output")


def test_analyzer_errored_status_also_blocks(tmp_path, monkeypatch):
    # Even a generic exception inside a content analyzer becomes ERROR, never PASS.
    from sentinel.analyzers.base import ContentAnalyzer

    class Boom(ContentAnalyzer):
        name = "_boom_test"
        version = "1.0"

        def analyze(self, changeset):
            raise ValueError("class init failed")

    try:
        CONTENT_ANALYZERS["_boom_test"] = Boom
        findings, status = analyze_changesets_full(_changeset())
        assert status["_boom_test"]["status"] == EvidenceStatus.ERROR.value
        assert findings == []
    finally:
        CONTENT_ANALYZERS.pop("_boom_test", None)