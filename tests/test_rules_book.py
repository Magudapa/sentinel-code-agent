"""Tests for the multi-language rule book system (loader, detector, gates)."""

from __future__ import annotations

import re

import pytest

from sentinel.rules import RuleDefinition, detect_language, empirical_check, load_all_rules, load_book
from sentinel.rules.detector import known_languages, normalize_language


def test_known_languages_include_starters():
    langs = known_languages()
    assert "python" in langs
    assert "javascript" in langs
    assert "sql" in langs


def test_all_books_load_valid():
    rules = load_all_rules()
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids)), "duplicate rule ids across books"
    assert any(r.id == "PY-001" for r in rules)
    assert any(r.id == "JS-001" for r in rules)
    assert any(r.id == "SQL-001" for r in rules)
    for r in rules:
        assert r.author, f"rule {r.id} must credit an author"
        assert r.ai_verified is False, "starter rules must not hand-claim verification"
        assert r.language in known_languages() or r.language == "*"


def test_books_have_every_required_field():
    for lang in ("python", "javascript", "sql"):
        for r in load_book(lang):
            assert r.regex
            re.compile(r.regex)
            assert r.vulnerable_example, r.id
            assert r.safe_example, r.id


def test_detect_language():
    assert detect_language("app/views.py") == "python"
    assert detect_language("web/src/index.tsx") == "javascript"
    assert detect_language("migrations/001.sql") == "sql"
    assert detect_language("README.md") is None


def test_normalize_language_aliases():
    assert normalize_language("node") == "javascript"
    assert normalize_language("TS") == "javascript"
    assert normalize_language("py") == "python"


@pytest.mark.parametrize("rule", load_all_rules())
def test_empirical_gate_passes_for_ship_rules(rule):
    """Every shipped rule must fire on its own vulnerable example and skip the safe one."""
    ok, notes = empirical_check(rule)
    assert ok, f"{rule.id}: {notes}"


def test_empirical_gate_rejects_bad_regex():
    r = RuleDefinition(
        id="X-1", language="python", description="bad", severity="low",
        regex="[unclosed", vulnerable_example="x", safe_example="y",
    )
    ok, notes = empirical_check(r)
    assert not ok
    assert "invalid regex" in notes


def test_book_analyzer_reports_findings():
    from sentinel.analyzers.book_analyzer import BookRulesAnalyzer
    from sentinel.diffparse import Changeset, DiffLine

    cs = Changeset(
        file="api.py",
        additions=[
            DiffLine(kind="add", old_line=None, new_line=1, text="import requests"),
            DiffLine(kind="add", old_line=None, new_line=2,
                     text="requests.post('http://api.example.com/x', data=creds)"),
            DiffLine(kind="add", old_line=None, new_line=3,
                     text="token = secrets.token_urlsafe(32)"),
        ],
    )
    findings = BookRulesAnalyzer().analyze(cs)
    assert any(f.rule_id == "PY-001" for f in findings)
    assert not any(f.rule_id == "PY-003" for f in findings), "safe line flagged"


def test_book_analyzer_ignores_other_languages():
    from sentinel.analyzers.book_analyzer import BookRulesAnalyzer
    from sentinel.diffparse import Changeset, DiffLine

    cs = Changeset(
        file="queries.sql",
        additions=[DiffLine(kind="add", old_line=None, new_line=1,
                            text="requests.post('http://x', d)")],
    )
    assert BookRulesAnalyzer().analyze(cs) == []


def test_ruleset_registry_registered():
    from sentinel.analyzers.base import CONTENT_ANALYZERS
    assert "sentinel-rules-book" in CONTENT_ANALYZERS


def test_write_book_roundtrips_without_name_error(tmp_path, monkeypatch):
    """Regression: write_book used an undefined ``yaml`` name and crashed.

    The serializer must produce a file that loads back to the same rule,
    never raise NameError (previously a live crash via `ruleset generate/merge`).
    """
    from sentinel.rules import RuleDefinition
    from sentinel.rules.loader import load_book, write_book

    tmp_book = tmp_path / "python.yml"
    monkeypatch.setattr("sentinel.rules.loader.book_path", lambda lang: tmp_book)

    rule = RuleDefinition(
        id="TMP-001",
        language="python",
        description="temp roundtrip rule",
        severity="low",
        regex="acme_token",
        author="audit",
    )
    out = write_book("python", [rule])
    assert out == tmp_book
    assert tmp_book.exists()
    loaded = load_book("python")
    assert len(loaded) == 1
    assert loaded[0].id == "TMP-001"
    assert loaded[0].regex == "acme_token"
