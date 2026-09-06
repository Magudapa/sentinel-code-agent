"""Regex-based security & bug rules that work on diff lines (no checkout needed).

These rules catch the classic dangerous patterns that always matter:

* hardcoded secrets / API keys
* SQL injection (string interpolation into execute/SELECT)
* command injection (os.system, subprocess with shell=True, eval/exec)
* unsafe deserialization (pickle, yaml.load)
* weak crypto (MD5/SHA1 for passwords, hardcoded crypto keys)
* network exposure (bind 0.0.0.0, debug=True on prod)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

from ..diffparse import Changeset
from ..models import Finding, Severity
from .base import ContentAnalyzer, register_content


class Rule:
    def __init__(self, rule_id: str, name: str, severity: Severity, pattern: re.Pattern, advice: str, language: str = "*"):
        self.rule_id = rule_id
        self.name = name
        self.severity = severity
        self.pattern = pattern
        self.advice = advice
        self.language = language

    def match_line(self, text: str) -> bool:
        return bool(self.pattern.search(text))


def _key_like(value: str) -> bool:
    """Heuristic: long high-entropy string likely to be a secret."""
    return len(value) >= 20 and re.search(r"[A-Za-z0-9_\-/+=.]{20,}", value)


def _build_secret_rule(rule_id: str, name: str, regex: str, hint: str) -> Rule:
    return Rule(rule_id, name, Severity.HIGH, re.compile(regex, re.IGNORECASE), hint)


RULES: list[Rule] = [
    _build_secret_rule(
        "S001", "Hardcoded API key / password",
        r"(?i)(api[_-]?key|secret|password|passwd|token)\s*[:=]\s*['\"][^'\"]{12,}['\"]",
        "A long literal assigned to a secret-looking variable was detected. Move it to an environment "
        "variable or a secrets manager (`.env`, keyring, Vault) and load it at runtime.",
    ),
    _build_secret_rule(
        "S002", "AWS / cloud access key",
        r"(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_\-]{35})",
        "This looks like a real credential for AWS/GitHub/OpenAI/Slack/GCP. Revoke it immediately if it was "
        "ever committed and remove it from history ({`git filter-repo`}).",
    ),
    _build_secret_rule(
        "S003", "Private key / JWT literal",
        r"(-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.)",
        "A private key or JWT appears inline. Keys must live in a secrets manager; JWTs must be signed "
        "server-side with the secret never in source.",
    ),
    Rule(
        "S004", "SQL injection (string interpolation)", Severity.CRITICAL,
        re.compile(
            r"(?i)f['\"][^'\"]*(SELECT|INSERT|UPDATE|DELETE|DROP)[^'\"]*\{"
            r"|(SELECT|INSERT|UPDATE|DELETE|DROP).{0,120}(%|format\(|\{[a-z0-9_]+\})"
            r"|\.execute\(\s*f['\"]"
        ),
        "User-controlled input is interpolated into a SQL string, enabling injection. Use parameterised "
        "queries: `cursor.execute('SELECT * FROM t WHERE id = %s', (user_id,))`.",
    ),
    Rule(
        "S005", "Unsafe eval/exec of runtime input", Severity.CRITICAL,
        re.compile(r"(?i)\b(?:eval|exec)\s*\("),
        "Executing dynamic strings can run arbitrary code. Prefer safe parsers (`ast.literal_eval`, JSON, "
        "or a parser library). Never pass untrusted input to eval/exec.",
    ),
    Rule(
        "S006", "subprocess with shell=True", Severity.HIGH,
        re.compile(r"(?i)subprocess\.(run|call|Popen)\([^)]*shell\s*=\s*True"),
        "shell=True lets shell metacharacters in arguments become code. Drop the shell and pass args as a "
        "list: `subprocess.run(['git', 'status'])`.",
    ),
    Rule(
        "S007", "os.system / os.popen", Severity.HIGH,
        re.compile(r"(?i)\bos\.(system|popen)\s*\("),
        "os.system runs commands through the shell — command injection and cross-platform bugs. Use "
        "subprocess with an argument list instead.",
    ),
    Rule(
        "S008", "Unsafe pickle.loads on untrusted data", Severity.CRITICAL,
        re.compile(r"(?i)\b(pickle|_pickle)\.(load|loads)\s*\("),
        "pickle executes arbitrary code during loading. Use JSON or another data-safe format for "
        "anything not fully trusted.",
    ),
    Rule(
        "S009", "yaml.load without SafeLoader", Severity.HIGH,
        re.compile(r"(?i)\byaml\.load\s*\([^)]*(?!SafeLoader)"),
        "yaml.load uses an unsafe constructor — arbitrary Python can execute. Use yaml.safe_load.",
    ),
    Rule(
        "S010", "Weak hashing for passwords (md5/sha1)", Severity.MEDIUM,
        re.compile(r"(?i)(md5|sha1)\s*\("),
        "md5/sha1 are broken for password/secret hashing. Use bcrypt/argon2/pbkdf2.",
    ),
    Rule(
        "S011", "Hardcoded symmetric key / nonce", Severity.HIGH,
        re.compile(r"(?i)(crypto|encrypt).{0,80}(key|iv|nonce)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
        "Embedding crypto keys/nonces in code makes encryption theatre. Derive keys from a KDF or env.",
    ),
    Rule(
        "S012", "Debug mode enabled in production paths", Severity.MEDIUM,
        re.compile(r"(?i)debug\s*=\s*True"),
        "debug=True exposes stack traces and debug consoles. Gate it behind an environment flag.",
    ),
    Rule(
        "S013", "Bind to all interfaces (0.0.0.0)", Severity.MEDIUM,
        re.compile(r"(?i)(host|address)\s*=\s*['\"]0\.0\.0\.0['\"]"),
        "Binding 0.0.0.0 exposes the service on every network interface. Bind 127.0.0.1 unless public "
        "exposure is intended.",
    ),
    Rule(
        "S014", "CORS wildcard with credentials", Severity.HIGH,
        re.compile(r"(?i)(allow.*origin|Access-Control-Allow-Origin).{0,30}['\"*]['\"]"),
        "CORS `*` combined with credentials lets any site read authenticated responses. Restrict origins.",
    ),
    Rule(
        "S015", "Insecure `requests.verify=False` / TLS off", Severity.HIGH,
        re.compile(r"(?i)(verify\s*=\s*False|ssl_context.*(check_hostname=False|verify_mode.*CERT_NONE))"),
        "Disabling TLS verification allows man-in-the-middle interception. Keep verification on.",
    ),
    Rule(
        "B001", "TODO/FIXME left in code", Severity.LOW,
        re.compile(r"(?i)#\s*(TODO|FIXME|HACK|XXX)\b"),
        "A TODO/FIXME was committed. Consider resolving it or tracking it in your issue tracker.",
    ),
    Rule(
        "B002", "Broad bare except", Severity.LOW,
        re.compile(r"(?m)^\s*except\s*:\s*$"),
        "A bare except swallows all errors, including KeyboardInterrupt. Catch specific exceptions.",
    ),
    Rule(
        "B003", "Print statement in library code", Severity.LOW,
        re.compile(r"(?m)^\s*print\s*\("),
        "print in library code pollutes stdout. Use the logging module.",
    ),
    Rule(
        "B004", "Mutable default argument", Severity.MEDIUM,
        re.compile(r"def\s+\w+\([^)]*=\s*(\[|\{|set\()"),
        "Mutable default arguments persist across calls and cause state leaks. Use None and initialise inside "
        "the function.",
    ),
    Rule(
        "B005", "Comparing `==` to None", Severity.LOW,
        re.compile(r"(?i)[!=]=+\s*None\b|\bNone\s*[!=]=+"),
        "Use `is None` / `is not None` for identity comparisons.",
    ),
    Rule(
        "B006", "Hardcoded email/phone patterns to redact", Severity.INFO,
        re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
        "An email-looking literal was committed. If it is real personally-identifiable data, externalise it.",
    ),
]


@register_content
class SentinelRulesAnalyzer(ContentAnalyzer):
    """Applies the built-in rule set to every added line in a changeset."""

    name = "sentinel-rules"

    _CODE_EXTENSIONS: ClassVar[set[str]] = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".go", ".rs",
        ".java", ".php", ".sh", ".sql", ".scala", ".kt", ".swift",
    }

    def analyze(self, changeset: Changeset) -> list[Finding]:
        findings: list[Finding] = []
        if Path(changeset.file).suffix.lower() not in self._CODE_EXTENSIONS:
            return findings
        for line in changeset.additions:
            if line.kind != "add":
                continue
            text = line.text.rstrip()
            if not text.strip() or text.strip().startswith("#") and not any(
                r.pattern.search(text) for r in RULES
            ):
                continue
            for rule in RULES:
                if not rule.match_line(text):
                    continue
                # Skip pure comments for most rules; keep TODO rule which needs comments
                if text.strip().startswith("#") and rule.rule_id not in ("B001",):
                    continue
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        file=changeset.file,
                        line=line.new_line or 0,
                        code_snippet=text.strip(),
                        description=rule.name,
                        evidence=rule.pattern.pattern[:200],
                        suggested_fix=rule.advice,
                    )
                )
        return _dedupe(findings)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    out = []
    for f in findings:
        key = (f.rule_id, f.file, f.line)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out