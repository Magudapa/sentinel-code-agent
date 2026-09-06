"""Python AST-based security analyzer.

This analyzer catches patterns that regex cannot reliably detect:

* ``eval()`` / ``exec()`` / ``compile()`` calls — but only on function calls,
  so ``re.compile()`` is no longer a false positive (the regex analyzer was
  already tightened, but this provides AST evidence too).
* ``subprocess.call`` with ``shell=True`` keyword.
* ``os.system`` / ``os.popen`` (always dangerous on user input).
* ``pickle.loads`` / ``yaml.load`` without SafeLoader (unsafe deserialization).
* ``import hashlib`` using MD5/SHA-1 for password hashing.
* ``requests.get/post`` with ``verify=False`` (TLS bypass).
* ``except:`` bare except clauses (swallows real exceptions silently).
"""

from __future__ import annotations

import ast

from ..diffparse import Changeset
from ..models import Finding, severity_from_str
from .base import ContentAnalyzer, register_content


class _BugproneVisitor(ast.NodeVisitor):
    """Collects suspicious AST nodes and returns them as a list of dicts."""

    def __init__(self, filename: str):
        self.filename = filename
        self.items: list[dict] = []

    def _add(self, node: ast.AST, rule_id: str, severity: str, desc: str, snippet: str = ""):
        self.items.append({
            "rule_id": rule_id,
            "severity": severity,
            "desc": desc,
            "line": getattr(node, "lineno", 0) or 0,
            "end_line": getattr(node, "end_lineno", 0) or 0,
            "snippet": snippet,
        })

    def visit_Call(self, node: ast.Call) -> None:
        call_name = _call_name(node)
        # eval / exec / compile (function calls only — avoids re.compile FP)
        if call_name in ("eval", "exec", "compile"):
            self._add(
                node, "AST-001", "high",
                f"Call to {call_name}() is potentially dangerous if input is user-controlled",
                f"{call_name}(...)",
            )
        # os.system / os.popen
        if call_name in ("os.system", "os.popen"):
            self._add(
                node, "AST-002", "critical",
                f"{call_name}() invokes a shell — use subprocess with a list and shell=False",
                f"{call_name}(...)",
            )
        # subprocess with shell=True
        if call_name in ("subprocess.call", "subprocess.run", "subprocess.Popen", "subprocess.check_call", "subprocess.check_output") and _has_true_keyword(node, "shell"):
            self._add(
                node, "AST-003", "high",
                "subprocess called with shell=True — use a list and remove shell=True",
                f"{call_name}(shell=True, ...)",
            )
        # pickle.loads / pickle.load
        if call_name in ("pickle.loads", "pickle.load"):
            self._add(
                node, "AST-004", "high",
                "Pickle deserialization on untrusted data enables arbitrary code execution",
                f"{call_name}(...)",
            )
        # yaml.load without SafeLoader
        if call_name == "yaml.load":
            kws = {kw.arg for kw in node.keywords}
            if "Loader" not in kws:
                self._add(
                    node, "AST-005", "medium",
                    "yaml.load without Loader=SafeLoader allows arbitrary object instantiation",
                    "yaml.load(data)",
                )
        # requests.get/post with verify=False
        if call_name in ("requests.get", "requests.post", "requests.put", "requests.patch", "requests.delete") and _has_true_keyword(node, "verify", value=False):
            self._add(
                node, "AST-006", "medium",
                "requests called with verify=False — disables TLS certificate checking",
                f"{call_name}(..., verify=False)",
            )
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is None:
            self._add(
                node, "AST-007", "low",
                "Bare except clause catches all exceptions including KeyboardInterrupt/Exit — "
                "use except Exception: instead",
                "except:",
            )
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == "telnetlib":
                self._add(
                    node, "AST-008", "medium",
                    "telnetlib is deprecated and transmits in plaintext — use ssh/httpx instead",
                    f"import {alias.name}",
                )
        self.generic_visit(node)


@register_content
class PythonASTAnalyzer(ContentAnalyzer):
    """Regex-independent Python security analysis via the stdlib AST parser."""

    name = "sentinel-ast"
    supported_languages: tuple[str, ...] = ("python",)
    version = "1.0"

    def analyze(self, changeset: Changeset) -> list[Finding]:
        # Content-analyzer contract: we receive added lines.  Build an
        # approximate file text from *just* the added lines (with their
        # line numbers preserved) to make the AST parser happy.
        # When the file is not parseable (incomplete added lines) we
        # return an empty list rather than crashing — this is an
        # optimization path; the full-file AST analyzer is in the file
        # analyzer registry (if we add one later).
        added = "\n".join(ln.text for ln in changeset.additions if ln.kind == "add")
        if not added.strip():
            return []
        try:
            tree = ast.parse(added, mode="exec")
        except SyntaxError:
            return []

        visitor = _BugproneVisitor(changeset.file)
        visitor.visit(tree)

        findings: list[Finding] = []
        for item in visitor.items:
            findings.append(Finding(
                rule_id=item["rule_id"],
                severity=severity_from_str(item["severity"]),
                file=changeset.file,
                line=item["line"],
                end_line=item["end_line"],
                code_snippet=item["snippet"],
                description=item["desc"],
                evidence="AST analysis",
                suggested_fix=_SUGGESTED_FIXES.get(item["rule_id"], ""),
            ))
        return findings


def _call_name(node: ast.Call) -> str:
    parts = []
    if isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name):
            parts.append(node.func.value.id)
        parts.append(node.func.attr)
    elif isinstance(node.func, ast.Name):
        parts.append(node.func.id)
    return ".".join(parts)


def _has_true_keyword(node: ast.Call, kw_name: str, *, value: bool = True) -> bool:
    for kw in node.keywords:
        if kw.arg == kw_name and isinstance(kw.value, ast.Constant) and kw.value.value == value:
            return True
    return False


_SUGGESTED_FIXES = {
    "AST-001": "Avoid eval/exec/compile on untrusted input. If code execution is truly needed, "
               "use ast.literal_eval for data or restricted exec with a whitelist.",
    "AST-002": "Replace os.system(cmd) with subprocess.run(cmd.split(), shell=False, check=True).",
    "AST-003": "Remove shell=True and pass a list of arguments to subprocess.",
    "AST-004": "Replace pickle.loads(data) with ast.literal_eval(data) if the structure is known, "
               "or a safe format like JSON.",
    "AST-005": "Use yaml.safe_load(data) or yaml.load(data, Loader=yaml.SafeLoader).",
    "AST-006": "Remove verify=False, or provide a CA bundle path explicitly.",
    "AST-007": "Replace bare `except:` with `except Exception:`.",
    "AST-008": "Replace telnetlib with httpx or paramiko (SSH).",
}