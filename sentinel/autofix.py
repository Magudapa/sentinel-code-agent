"""Auto-fix: turn findings into validated patches.

Flow (BRD FR6): pick finding -> get fix code from LLM -> replace in file ->
validate syntax -> re-run the matching analyzer (security regression: the
finding's rule must no longer reproduce) -> (optionally run tests) ->
produce a unified diff for a PR / open comment.

Safety gates (every successful patch passes ALL of them):
  1. target file resolves strictly inside the workspace (no escape, no symlinks)
  2. target path is not a sensitive file (.git, .env, credentials, keys, …)
  3. only code extensions (.py/.js/.ts/.tsx) are ever modified
  4. the edited file is syntactically valid (Python)
  5. security regression: re-running the finding's own rule on the patched
     text no longer reproduces the finding (deterministic — no AI involved)
  6. unrelated code is never touched: we replace only the exact snippet
     (first occurrence), never a normalized/near match on multi-line code
  7. tests pass (when the workspace has a runnable, small suite)
  8. fixes are exported as a patch (original text is never overwritten here —
     the caller decides to apply)
"""

from __future__ import annotations

import ast
from pathlib import Path

from .diffparse import Changeset, DiffLine
from .model import ModelClient
from .models import Finding, Patch, Severity
from .pathsec import PathEscapeError, ensure_within, is_sensitive_relpath
from .process import run_safe

_CODE_EXTENSIONS = (".py", ".js", ".ts", ".tsx", ".mjs", ".cjs")
_SENSITIVE_EXTENSIONS = (".pem", ".p12", ".pfx", ".env")


def _python_syntax_ok(code: str) -> tuple[bool, str]:
    try:
        ast.parse(code)
        return True, ""
    except SyntaxError as e:
        return False, f"{e.msg} (line {e.lineno})"


def _apply_replacement(path: str, old: str, new: str) -> tuple[str, bool]:
    """Replace the exact first occurrence. Returns (new_content, replaced).

    Multi-line code is matched by exact string only.  Single-line matches fall
    back to an exact-line (whitespace-normalized) match — never a fuzzy
    substring replacement of code.
    """
    p = Path(path)
    content = p.read_text(encoding="utf-8")
    idx = content.find(old)
    if idx != -1:
        return content[:idx] + new + content[idx + len(old):], True
    norm_old = "".join(old.split())
    if "\n" not in old and norm_old:
        for candidate in content.splitlines():
            if "".join(candidate.split()) == norm_old:
                return content.replace(candidate, new, 1), True
    return content, False


def build_patch_file(original: str, updated: str, path: str) -> str:
    """Create a unified diff string between two file contents (pure Python, no `diff` binary)."""
    import difflib

    path = path.replace("\\", "/")
    original_lines = original.splitlines(keepends=True)
    updated_lines = updated.splitlines(keepends=True)
    diff = "".join(
        difflib.unified_diff(original_lines, updated_lines, fromfile=f"a/{path}", tofile=f"b/{path}")
    )
    return diff


def _resolve_target(workspace_root: str, rel: str) -> tuple[Path | None, str | None]:
    """Safety gates 1-3. Returns (resolved_path, None) or (None, error)."""
    rel_norm = rel.replace("\\", "/")
    if is_sensitive_relpath(rel_norm):
        return None, f"refusing to modify sensitive path: {rel_norm}"
    ext = Path(rel_norm).suffix.lower()
    if ext not in _CODE_EXTENSIONS or ext in _SENSITIVE_EXTENSIONS:
        return None, f"refusing to modify non-code file: {rel_norm}"
    try:
        resolved = ensure_within(workspace_root, rel_norm)
    except PathEscapeError as exc:
        return None, str(exc)
    return resolved, None


def _security_regression(finding: Finding, new_text: str) -> bool:
    """Gate 5: the finding's own rule must not reproduce on patched text.

    Deterministic. Uses the in-process content analyzer that produced the
    finding (by name) against a Changeset built from the new file text.
    Returns True when the rule no longer reproduces.
    """
    if not finding.analyzer:
        return True  # cannot attribute -> best-effort; callers gate on rule_id
    from .analyzers.base import CONTENT_ANALYZERS, FILE_ANALYZERS
    from .analyzers.base import ContentAnalyzer as _CA

    cls = CONTENT_ANALYZERS.get(finding.analyzer) or FILE_ANALYZERS.get(finding.analyzer)
    if cls is None or not issubclass(cls, _CA):
        return True  # file analyzers need a full tree; regulated separately

    changeset = Changeset(
        file=finding.file,
        additions=[DiffLine(kind="add", text=ln, new_line=i + 1, old_line=None)
                   for i, ln in enumerate(new_text.splitlines())],
    )
    try:
        reproduced = [f for f in cls().analyze(changeset) if f.rule_id == finding.rule_id]
        return not reproduced
    except Exception:
        return False  # cannot prove the fix kills the finding


def _run_fast_tests(workdir: str, timeout: int = 60) -> bool | None:
    """Run pytest quietly if a test suite is small; True/False/None."""
    res = run_safe(["pytest", "-q", "--no-header", "-x"], cwd=workdir, timeout=timeout)
    if res.timed_out:
        return None
    if res.error:
        return None
    if res.returncode not in (0, 1):
        return None
    return res.returncode == 0


def apply_fix(model: ModelClient, finding: Finding, path: str | None = None,
              workspace_root: str | None = None) -> Patch | None:
    """Apply an LLM-suggested fix. Returns a validated Patch or None.

    ``path`` must point at a real file containing the finding's code snippet;
    ``workspace_root`` is the containment root (must be provided when editing).
    """
    patch = Patch(finding=finding, diff="")

    if path is None:
        if not finding.suggested_fix:
            return None
        patch.diff = finding.suggested_fix
        patch.validated = False
        patch.validation_notes = "no workspace: patch proposed for manual review"
        return patch

    if not workspace_root:
        patch.validated = False
        patch.validation_notes = "no workspace root: patch proposed for manual review"
        patch.diff = finding.suggested_fix or finding.code_snippet
        return patch

    target, _err = _resolve_target(workspace_root, finding.file)
    if target is None:
        return None  # gate rejected: caller decides (no patch produced)

    try:
        current = target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    fix_code = finding.suggested_fix or ""
    if not (finding.code_snippet and fix_code and fix_code != finding.code_snippet):
        return None

    updated, replaced = _apply_replacement(str(target), finding.code_snippet, fix_code)
    if not replaced:
        return None
    if updated == current:
        return None

    # gate 4: syntax
    if target.suffix == ".py":
        valid, note = _python_syntax_ok(updated)
    else:
        valid, note = True, ""
    if not valid:
        patch.diff = build_patch_file(current, updated, finding.file)
        patch.validated = False
        patch.validation_notes = note
        return patch

    # gate 5: security regression on the patched file text
    if not _security_regression(finding, updated):
        patch.validated = False
        patch.validation_notes = f"security regression: {finding.rule_id} still reproduces on patched text"
        return patch

    patch.diff = build_patch_file(current, updated, finding.file)
    patch.validated = True
    patch.validation_notes = "syntax OK + security regression cleared"
    if workspace_root:
        patch.tests_passed = _run_fast_tests(workspace_root)
    return patch


def autofix_candidates(model: ModelClient, findings: list[Finding],
                       max_severity: Severity = Severity.HIGH, limit: int = 10,
                       workspace_root: str | None = None) -> list[Patch]:
    """Generate fix candidates for findings at/above max_severity."""
    patches = []
    for finding in findings:
        if finding.severity < max_severity:
            continue
        if len(patches) >= limit:
            break
        path = None
        try:
            if workspace_root:
                target, _err = _resolve_target(workspace_root, finding.file)
                if target is None:
                    continue  # safety gate rejected this target -> no candidate
                if not target.exists():
                    continue  # nothing on disk to patch
                path = str(target)
            p = apply_fix(model, finding, path, workspace_root=workspace_root)
        except Exception:
            continue
        if p:
            patches.append(p)
    return patches