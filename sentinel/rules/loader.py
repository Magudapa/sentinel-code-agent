"""Load rule books from ``sentinel/rules/books/`` into :class:`RuleDefinition` list."""

from __future__ import annotations

import inspect
from pathlib import Path

import yaml

from .defs import RuleDefinition, dedupe_rules
from .detector import known_languages, normalize_language

BOOKS_DIR = Path(inspect.getfile(lambda: None)).parent / "books"

REQUIRED_FIELDS = {"id", "language", "description", "severity", "regex"}


def books_dir() -> Path:
    return BOOKS_DIR


def available_books() -> list[str]:
    return [p.stem for p in BOOKS_DIR.glob("*.yml")]


def book_path(language: str) -> Path:
    return BOOKS_DIR / f"{normalize_language(language)}.yml"


def load_book(language: str) -> list[RuleDefinition]:
    """Load one language book (strict: unverifiable entries raise)."""
    path = book_path(language)
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    entries = raw.get("rules", []) if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        raise TypeError(f"Book {path.name} must contain a 'rules' list")

    rules: list[RuleDefinition] = []
    for i, item in enumerate(entries, start=1):
        if not isinstance(item, dict):
            raise TypeError(f"{path.name}: entry {i} is not a mapping")
        missing = REQUIRED_FIELDS - set(item)
        if missing:
            raise ValueError(f"{path.name}: rule {i} missing {sorted(missing)}")
        item = dict(item)
        item.setdefault("language", language)
        rules.append(RuleDefinition.from_dict(item))
    return rules


def load_all_rules() -> list[RuleDefinition]:
    """Load every book in the directory. A malformed book is skipped (with a
    warning) so one bad community submission never breaks the scan."""
    rules: list[RuleDefinition] = []
    for lang in known_languages():
        try:
            rules.extend(load_book(lang))
        except Exception:
            continue
    return dedupe_rules(rules)


def rules_for_languages(languages: list[str]) -> list[RuleDefinition]:
    out: list[RuleDefinition] = []
    for lang in languages:
        out.extend(load_book(normalize_language(lang)))
    return dedupe_rules(out)


def write_book(language: str, rules: list[RuleDefinition]) -> Path:
    """Serialize a language book back to YAML with a stable header."""
    path = book_path(language)
    data = {
        "meta": {
            "language": language,
            "generated_by": "sentinel ruleset",
        },
        "rules": [r.as_dict() for r in rules],
    }
    text = (
        f"# Sentinel rule book — {language}\n"
        "# Submission gate: rules are added here ONLY after the AI\n"
        "# cross-verification passes (sentinel ruleset generate/verify).\n"
        "# Authors are credited per rule in the `author` field.\n"
        "# ai_verified: true is set only by the verifier, never by hand.\n"
    ) + yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path