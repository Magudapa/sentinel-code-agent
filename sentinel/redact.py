"""Secret redaction — a SAFE default.

Policies:
* redact()        masks known secret-shaped strings (AWS/Google/PATs/private
                  keys, mongodb/connection URIs with creds, KEY=VALUE pairs).
* Never mutates the original strings; always returns new text.
* Applied at trust boundaries: AI prompts, logs, posted comments, JSON/SARIF
  and Markdown output.  Finding code snippets shown to users stay redacted too.
"""

from __future__ import annotations

import re

_SECRET_PATTERNS: list[tuple[str, str]] = [
    (r"AKIA[0-9A-Z]{16}", "<AWS_ACCESS_KEY>"),
    (r"AIza[0-9A-Za-z_-]{20,}", "<GOOGLE_API_KEY>"),
    (r"https://xox[baprs]-[0-9A-Za-z-]{20,}", "<SLACK_TOKEN>"),
    (r"gh[pousr]_[0-9A-Za-z]{20,}", "<GITHUB_TOKEN>"),
    (r"sk-[0-9A-Za-z_-]{20,}", "<OPENAI_TOKEN>"),
    (r"Bearer\s+[0-9A-Za-z._-]{16,}", "<BEARER_TOKEN>"),
    (r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
     "<PRIVATE_KEY>"),
]

# e.g. password=..., Password: 1234, PASSWORD=supersecret, api_key = abc…
_KEY_VALUE = re.compile(
    r"(?im)(?P<key>password|passwd|pwd|secret|api[_-]?key|token|access[_-]?key"
    r"|client[_-]?secret|auth|private[_-]?key|mongodb_uri|mongo[_-]?uri)"
    r"(?P<sep>\s*[:=]\s*)(?P<val>['\"]?[^\s'\" ,;]+)",
)
_URI_CRED = re.compile(r"(?i)([a-z][\w+.-]*://)[^/@\s]+@", )


def redact(text: str) -> str:
    """Return ``text`` with obvious secrets masked. Pure — never mutates input."""
    if not text:
        return text
    out = text
    for pattern, repl in _SECRET_PATTERNS:
        out = re.sub(pattern, repl, out)
    out = _KEY_VALUE.sub(
        lambda m: f"{m.group('key')}{m.group('sep')}<REDACTED>", out
    )
    out = _URI_CRED.sub(r"\1<REDACTED>@", out)
    return out


def redact_secrets_in(text: str) -> str:
    """Alias used at provider/MCP boundaries (kept explicit about intent)."""
    return redact(text)


def mask_uri(uri: str) -> str:
    """Redact user:pass@ inside URIs (e.g. mongodb://...)."""
    return _URI_CRED.sub(r"\1<REDACTED>@", uri)