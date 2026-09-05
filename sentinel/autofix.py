"""Auto-fix: turn findings into validated patches.

Flow (BRD FR6): pick finding -> get fix code from LLM -> replace in file ->
validate syntax -> re-run the matching analyzer -> (optionally run tests) ->
produce a unified diff for a PR/open comment.
"""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path

from .model import ModelClient
from .models import Finding, Patch, Severity


def _python_syntax_ok(code: str) -> tuple[bool, str]:
    try:
        ast.parse(code)
        return True, ""
    except SyntaxError as e:
        return False, f"{e.msg} (line {e.lineno})"


def _apply_replacement(path: str, old: str, new: str) -> str:
    """Replace one occurrence; returns the new file contents."""
    p = Path(path)
    content = p.read_text(encoding="utf-8")
    idx = content.find(old)
    if idx == -1:
        # fall back to whitespace-normalized match
        norm_old = "".join(old.split())
        for candidate in content.splitlines():
            if "".join(candidate.split()) == norm_old:
                return content.replace(candidate, new, 1)
        return content
    return content[:idx] + new + content[idx + len(old):]


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


def apply_fix(model: ModelClient, finding: Finding, path: str | None = None) -> Patch | None:
    """Apply an LLM-suggested fix. Returns a validated Patch or None.

    ``path`` must point at a real file containing the finding's code snippet;
    otherwise only the re-suggested code is returned (unvalidated).
    """
    patch = Patch(finding=finding, diff="")

    if path:
        current = Path(path).read_text(encoding="utf-8", errors="replace")
    else:
        current = ""

    fix_code = finding.suggested_fix or ""

    if path and finding.code_snippet and fix_code and fix_code != finding.code_snippet:
        updated = _apply_replacement(path, finding.code_snippet, fix_code)
        if updated != current:
            valid, note = _python_syntax_ok(updated) if path.endswith(".py") else (True, "")
            patch.diff = build_patch_file(current, updated, finding.file)
            patch.validated = valid
            patch.validation_notes = note or ("syntax OK" if valid else "")
            if valid:
                patch.tests_passed = _run_fast_tests(Path(path).parent)
            return patch

    # No file/diff context: return the suggested code snippet as a patch candidate
    if fix_code:
        patch.diff = fix_code
        patch.validated = False
        patch.validation_notes = "no workspace: patch proposed for manual review"
        return patch
    return None


def _run_fast_tests(workdir: Path, timeout: int = 30) -> bool | None:
    """Run pytest quietly if a test suite is small; returns True/False/None."""
    try:
        res = subprocess.run(
            ["pytest", "-q", "--no-header", "-x", "--timeout=10"],
            cwd=workdir, capture_output=True, text=True, check=False, timeout=timeout,
        )
        return res.returncode == 0
    except Exception:
        return None


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
        path = finding.file
        if workspace_root:
            path = str(Path(workspace_root) / finding.file)
            if not Path(path).exists():
                path = str(Path(workspace_root) / Path(finding.file).name)
        try:
            p = apply_fix(model, finding, path if Path(path).exists() else None)
        except Exception:
            continue
        if p:
            patches.append(p)
    return patches