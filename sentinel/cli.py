"""Command-line interface for Sentinel.

Usage examples:
  sentinel review --provider local --path . --range main..feature
  sentinel review --provider github --repo owner/repo --pr 42
  git diff | sentinel review --provider local --diff -
  sentinel review --provider local --path . --format sarif
"""

from __future__ import annotations

import argparse
import sys

from .config import SentinelConfig, load_config
from .output import format_json, format_markdown, format_sarif
from .pipeline import Reviewer
from .providers import get_provider


def _read_stdin() -> str:
    return sys.stdin.read()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinel", description="Autonomous security & code review agent")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("review", help="Review a PR, diff, or local working tree")
    r.add_argument("--provider", default="local", choices=["local", "github", "gitlab"],
                   help="Where the code lives")
    r.add_argument("--repo", help="GitHub/GitLab repo, e.g. Magudapa/sentinel")
    r.add_argument("--pr", type=int, help="PR/MR number")
    r.add_argument("--path", default=".", help="Local repo path (for local provider)")
    r.add_argument("--range", default="", help="Commit range, e.g. main..feature")
    r.add_argument("--diff", help="Path to a diff file, or '-' for stdin")
    r.add_argument("--config", default="", help="Path to .sentinel.yml")
    r.add_argument("--no-explain", action="store_true", help="Skip LLM explanations (analyzers only)")
    r.add_argument("--format", default="markdown", choices=["markdown", "json", "sarif"],
                   help="Output format")
    r.add_argument("--output", default="", help="Write to file instead of stdout")
    r.add_argument("--post", action="store_true", help="Post findings as comments (GitHub/GitLab)")
    r.add_argument("--working-dir", default="", help="Working tree dir for bandit/ruff on changed files")

    f = sub.add_parser("fix", help="Auto-fix: export patched files (or open a GitHub fix PR)")
    f.add_argument("--provider", default="local", choices=["local", "github"],
                   help="Where the code lives")
    f.add_argument("--repo", help="GitHub repo, e.g. Magudapa/sentinel")
    f.add_argument("--pr", type=int, help="PR number (for GitHub provider)")
    f.add_argument("--path", default=".", help="Repo path (for local provider)")
    f.add_argument("--range", default="", help="Commit range, e.g. main..feature")
    f.add_argument("--diff", help="Path to a diff file, or '-' for stdin")
    f.add_argument("--config", default="", help="Path to .sentinel.yml")
    f.add_argument("--branch", default="sentinel/fix", help="Fix branch name (GitHub)")
    f.add_argument("--target", choices=["export", "pr"], default="export",
                   help="export patched files locally, or open a remote fix PR")
    f.add_argument("--workspace", default="", help="Working tree to apply fixes against")
    return p


def main(argv: list[str] | None = None) -> int:
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    args = build_parser().parse_args(argv)
    config = load_config(args.config or None)

    if args.cmd == "fix":
        return _cmd_fix(args, config)

    provider = get_provider(args.provider)

    try:
        if args.provider == "github":
            if not args.repo or not args.pr:
                print("--repo and --pr are required for GitHub", file=sys.stderr)
                return 2
            context = provider.fetch_context(args.repo, args.pr)
        elif args.provider == "gitlab":
            if not args.repo or not args.pr:
                print("--repo and --pr are required for GitLab", file=sys.stderr)
                return 2
            context = provider.fetch_context(args.repo, args.pr)
        else:  # local
            diff_text = ""
            if args.diff == "-":
                diff_text = _read_stdin()
            elif args.diff:
                with open(args.diff, encoding="utf-8") as fh:
                    diff_text = fh.read()
            context = provider.fetch_context(args.path, commit_range=args.range, diff=diff_text)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    if not context.diff.strip():
        print("No diff to review (nothing changed). Nothing to do.", file=sys.stderr)
        return 0

    reviewer = Reviewer(config)
    report = reviewer.review(provider, context, explain=not args.no_explain,
                             working_dir=args.working_dir or (args.path if args.provider == "local" and not args.range else ""))

    formatter = {"markdown": format_markdown, "json": format_json, "sarif": format_sarif}[args.format]
    out = formatter(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"Report written to {args.output}")
    else:
        print(out)

    if args.post and args.provider in ("github", "gitlab"):
        try:
            provider.post_comments(context, report.findings)
            print(f"\nPosted {len(report.findings)} inline comment(s) -> {context.repo} #{context.target}")
        except Exception as e:
            print(f"WARN: could not post comments: {e}", file=sys.stderr)

    # Exit code: 1 if critical findings, 0 otherwise
    crit = any(f.severity.name == "CRITICAL" for f in report.findings)
    return 1 if crit else 0


def _cmd_fix(args, config: SentinelConfig) -> int:
    """Auto-fix command: analyze like `review`, then export patched files or open a GitHub PR."""
    from .autofix import autofix_candidates
    from .model import ModelClient

    provider = get_provider(args.provider)

    try:
        if args.provider == "github":
            if not args.repo or not args.pr:
                print("--repo and --pr are required for GitHub fix PR", file=sys.stderr)
                return 2
            context = provider.fetch_context(args.repo, args.pr)
        else:
            diff_text = ""
            if args.diff == "-":
                diff_text = _read_stdin()
            elif args.diff:
                with open(args.diff, encoding="utf-8") as fh:
                    diff_text = fh.read()
            context = provider.fetch_context(args.path, commit_range=args.range, diff=diff_text)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    reviewer = Reviewer(config)
    report = reviewer.review(provider, context, explain=True,
                             working_dir=args.workspace)

    model = ModelClient(config.model)
    patches = autofix_candidates(model, report.findings, workspace_root=args.workspace or None)

    if not patches:
        print("No auto-fix candidates (no findings at/above the fix threshold, or no LLM available).")
        return 0

    print(f"Generated {len(patches)} fix candidate(s).")

    if args.target == "export":
        from pathlib import Path

        out_root = Path("sentinel-fixes")
        out_root.mkdir(exist_ok=True)
        for i, p in enumerate(patches, 1):
            dest = out_root / f"{i:02d}-{Path(p.finding.file).name}"
            dest.write_text(p.diff, encoding="utf-8")
            status = "VALIDATED" if p.validated else "unvalidated"
            print(f"  -> {dest}  [{status}]  {p.finding.rule_id} {p.finding.file}:{p.finding.line}")
        print("\nExport patched files under ./sentinel-fixes — review, apply, and commit them yourself, or run again with --target pr.")
        return 0

    # GitHub PR flow
    if args.provider != "github":
        print("Fix PR creation currently supported on GitHub only.", file=sys.stderr)
        return 2
    if args.workspace:
        file_changes = {}
        for p in patches:
            if p.validated and p.diff and p.diff.startswith("--- a/"):
                path = p.finding.file.replace("\\", "/")
                file_changes[path] = p.diff
        try:
            provider.create_fix_branch(context, args.branch, file_changes)
            url = provider.open_fix_pr(context, args.branch, " ".join(f"{f.rule_id}" for f in report.findings),
                                       f"Sentinel: auto-fix {len(patches)} finding(s) in #{context.target}")
            print(f"Fix PR opened: {url}")
        except Exception as e:
            print(f"ERROR: could not open fix PR: {e}", file=sys.stderr)
            print("Tip: run with a local --workspace and --target export to get the patches.")
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())