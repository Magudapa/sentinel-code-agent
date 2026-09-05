"""Language detection from file paths — drives which rule book applies."""

from __future__ import annotations

import os

EXTENSION_MAP: dict[str, str] = {
    # Python
    ".py": "python", ".pyi": "python", ".pyw": "python",
    # JavaScript / TypeScript / Node / React
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".ts": "javascript", ".tsx": "javascript",
    ".vue": "javascript",
    # SQL
    ".sql": "sql",
    # Swift / iOS (book ships with JS/py/sql now; detector already knows them)
    ".swift": "swift",
    # Go
    ".go": "go",
    # Java / Kotlin
    ".java": "java", ".kt": "kotlin",
    # Ruby
    ".rb": "ruby", ".rake": "ruby", ".gemspec": "ruby",
    # Config / IaC
    ".tf": "terraform", ".tfvars": "terraform",
    "Dockerfile": "dockerfile",
}

# Language -> tool adapters + file extensions (single source of truth for UI/tooling)
LANGUAGES: dict[str, dict] = {
    "python": {"extensions": [".py", ".pyi", ".pyw"], "tools": ["bandit", "ruff"]},
    "javascript": {"extensions": [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue"],
                    "tools": ["eslint", "semgrep"]},
    "sql": {"extensions": [".sql"], "tools": ["sqlfluff"]},
    "swift": {"extensions": [".swift"], "tools": ["semgrep", "swiftlint"]},
    "go": {"extensions": [".go"], "tools": ["gosec", "semgrep"]},
    "java": {"extensions": [".java"], "tools": ["semgrep"]},
    "kotlin": {"extensions": [".kt"], "tools": ["semgrep"]},
    "ruby": {"extensions": [".rb", ".rake"], "tools": ["brakeman", "semgrep"]},
    "terraform": {"extensions": [".tf", ".tfvars"], "tools": ["tfsec", "semgrep"]},
    "dockerfile": {"extensions": ["Dockerfile"], "tools": ["hadolint", "semgrep"]},
}

BOOK_FILE_NAMES: set[str] = {"Dockerfile", "dockerfile"}


def detect_language(path: str) -> str | None:
    """Map a file path to a language key, or ``None`` when unknown."""
    basename = os.path.basename(path)
    if basename in BOOK_FILE_NAMES:
        return "dockerfile"
    ext = os.path.splitext(basename)[1].lower()
    return EXTENSION_MAP.get(ext)


def known_languages() -> list[str]:
    return sorted(LANGUAGES)


def normalize_language(name: str) -> str:
    """Accept fuzzy names like ``node``/``react``/``ts`` and map to a book language."""
    alias = {
        "node": "javascript", "nodejs": "javascript", "js": "javascript",
        "typescript": "javascript", "ts": "javascript", "react": "javascript",
        "jsx": "javascript", "tsx": "javascript", "pg": "sql", "postgres": "sql",
        "mysql": "sql", "sqlite": "sql", "py": "python",
        "ios": "swift", "xcode": "swift",
    }
    key = name.strip().lower()
    return alias.get(key, key)