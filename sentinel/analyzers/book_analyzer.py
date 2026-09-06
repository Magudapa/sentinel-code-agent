"""Content analyzer that applies language-tagged book rules to added lines."""

from __future__ import annotations

import re

from ..diffparse import Changeset
from ..models import Finding, severity_from_str
from ..rules.detector import detect_language
from ..rules.loader import load_all_rules
from .base import ContentAnalyzer, register_content

#: Truncate absurd lines before pattern matching (DOS guard; the per-analyzer
#: CPU budget in ``analyzers.base`` is the outer defense).
MAX_SCAN_LINE = 8000


@register_content
class BookRulesAnalyzer(ContentAnalyzer):
    """Runs the curated rule books against each changed line.

    Only lines whose file matches the rule's language are tested (plus any
    ``language: "*"`` rules that apply everywhere). All book regexes are
    Python ``re`` patterns.
    """

    name = "sentinel-rules-book"

    _per_lang: dict[str, list[tuple[str, re.Pattern, object]]] | None = None
    _global: list[tuple[str, re.Pattern, object]] | None = None

    @classmethod
    def _compile(cls) -> None:
        if cls._per_lang is not None:
            return
        per_lang: dict[str, list[tuple[str, re.Pattern, object]]] = {}
        global_rules: list[tuple[str, re.Pattern, object]] = []
        for r in load_all_rules():
            try:
                rx = re.compile(r.regex)
            except re.error:
                continue
            entry = (r.regex, rx, r)
            if r.language == "*":
                global_rules.append(entry)
            else:
                per_lang.setdefault(r.language, []).append(entry)
        cls._per_lang = per_lang
        cls._global = global_rules

    @staticmethod
    def _safe_regex_search(rx: re.Pattern, text: str) -> bool:
        try:
            return bool(rx.search(text))
        except re.error:
            return False

    def analyze(self, changeset: Changeset) -> list[Finding]:
        self._compile()
        lang = detect_language(changeset.file)
        rules: list[tuple[str, re.Pattern, object]] = list(self._global)
        if lang and lang in self._per_lang:
            rules += self._per_lang[lang]

        findings: list[Finding] = []
        for line in changeset.additions:
            if line.kind != "add":
                continue
            text = line.text.rstrip()[:MAX_SCAN_LINE]
            if not text.strip() or text.strip().startswith("#"):
                continue
            for regex, rx, rule in rules:
                if self._safe_regex_search(rx, text):
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            severity=severity_from_str(rule.severity),
                            file=changeset.file,
                            line=line.new_line or 0,
                            code_snippet=text.strip(),
                            description=rule.description or rule.message or rule.id,
                            evidence=regex[:200],
                            suggested_fix=rule.fix,
                        )
                    )
        # de-duplicate per (rule, file, line)
        seen: set[tuple] = set()
        out: list[Finding] = []
        for f in findings:
            key = (f.rule_id, f.file, f.line)
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out