"""Rule book package: definitions, loading, language detection, verification."""

from .defs import RuleDefinition, dedupe_rules
from .detector import detect_language, known_languages, normalize_language
from .generate import generate_verified, prefix_for
from .loader import (
                     available_books,
                     book_path,
                     books_dir,
                     load_all_rules,
                     load_book,
                     rules_for_languages,
                     write_book,
)
from .verify import RuleVerificationError, VerificationResult, empirical_check, stamp, verify_rule

__all__ = [
    "RuleDefinition",
    "RuleVerificationError",
    "VerificationResult",
    "available_books",
    "book_path",
    "books_dir",
    "dedupe_rules",
    "detect_language",
    "empirical_check",
    "generate_verified",
    "known_languages",
    "load_all_rules",
    "load_book",
    "normalize_language",
    "prefix_for",
    "rules_for_languages",
    "stamp",
    "verify_rule",
    "write_book",
]