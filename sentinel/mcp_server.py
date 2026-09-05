"""MCP server exposing Sentinel as tools for other agents.

Other agents (Claude, Langflow, custom MCP clients) can call:

  review_diff   - review a raw diff string
  review_pr     - review a GitHub PR by owner/repo/number
  audit_repo    - review a local repo working tree
  list_rules    - list available analyzer rules
"""

from __future__ import annotations

import sys

from .analyzers import RULES, analyze_changesets
from .config import load_config
from .diffparse import parse_diff
from .pipeline import Reviewer


def _rule_specs() -> list[dict]:
    return [
        {"id": r.rule_id, "name": r.name, "severity": r.severity.name.lower()}
        for r in RULES if r.language == "*"
    ]


def list_rules() -> str:
    """Return the list of available analyzer rules as JSON."""
    return format_json_object(_rule_specs())


def review_diff_tool(diff: str, explain: bool = False) -> str:
    """Review a unified diff string. Returns a JSON report."""
    changesets = parse_diff(diff)
    findings = analyze_changesets(changesets)
    for f in findings:
        pass
    report = {
        "file_count": len(changesets),
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in sorted(findings, key=lambda x: x.severity, reverse=True)],
    }
    return format_json_object(report)


def review_pr_tool(repo: str, pr: int, token: str = "", explain: bool = True) -> str:
    """Review a GitHub PR. ``GITHUB_TOKEN`` env or ``token`` used for private repos."""
    from .providers.github import GitHubProvider

    provider = GitHubProvider(token=token)
    context = provider.fetch_context(repo, pr)
    reviewer = Reviewer(load_config())
    report = reviewer.review(provider, context, explain=explain)
    return format_json_object(report.to_dict())


def audit_repo_tool(path: str, explain: bool = True) -> str:
    """Review a local git repo's working tree or a real directory full of code."""
    from .providers.local import LocalProvider

    provider = LocalProvider()
    try:
        context = provider.fetch_context(path)
    except Exception:
        # Not a git repo: scan the directory with file analyzers directly
        import os

        from .analyzers import analyze_files
        from .models import ReviewReport

        findings = []
        for root, _dirs, files in os.walk(path):
            if any(skip in root for skip in (".git", "node_modules", "__pycache__", ".venv")):
                continue
            for fn in files:
                if fn.endswith(".py"):
                    findings += analyze_files(root, [os.path.join(root, fn)])
        report = ReviewReport(provider="local", repo=os.path.basename(path.rstrip("/\\")),
                              target=path, findings=findings)
        return format_json_object(report.to_dict())

    reviewer = Reviewer(load_config())
    report = reviewer.review(provider, context, explain=explain, working_dir=path)
    return format_json_object(report.to_dict())


def format_json_object(obj) -> str:
    import json

    return json.dumps(obj, indent=2, default=str)


def main() -> None:
    """Console entry point: run the MCP server over stdio."""
    serve_stdio()


TOOLS = {
    "review_diff": {
        "description": "Review a unified git diff string for security issues and bugs.",
        "arguments": {
            "diff": {"type": "string", "description": "Unified diff text (git diff output)."},
            "explain": {"type": "boolean", "default": False},  
        },
        "handler": lambda a: review_diff_tool(a.get("diff", ""), a.get("explain", False)),
    },
    "review_pr": {
        "description": "Review a GitHub pull request by number.",
        "arguments": {
            "repo": {"type": "string", "description": "owner/repo e.g. Magudapa/sentinel"},
            "pr": {"type": "integer"},
            "token": {"type": "string", "default": ""},
            "explain": {"type": "boolean", "default": True},
        },
        "handler": lambda a: review_pr_tool(a.get("repo", ""), a.get("pr", 0), a.get("token", ""), a.get("explain", True)),
    },
    "audit_repo": {
        "description": "Audit a local directory or git repo for vulnerabilities.",
        "arguments": {
            "path": {"type": "string"},
            "explain": {"type": "boolean", "default": True},
        },
        "handler": lambda a: audit_repo_tool(a.get("path", ""), a.get("explain", True)),
    },
    "list_rules": {
        "description": "List all Sentinel analyzer rules.",
        "arguments": {},
        "handler": lambda a: format_json_object(_rule_specs()),
    },
}


def serve_stdio() -> None:
    """Run the MCP server over stdio using the `mcp` package if installed."""
    try:
        import asyncio

        from mcp.server import Server
        from mcp.server.stdio import stdio_server
    except ImportError:
        # Minimal text-protocol fallback: read JSON lines, write JSON lines
        import json as _json

        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = _json.loads(line)
                tool = req.get("tool")
                args = req.get("arguments", {})
                spec = TOOLS.get(tool)
                if spec:
                    out = {"ok": True, "result": spec["handler"](args)}
                else:
                    out = {"ok": False, "error": f"unknown tool {tool}"}
            except Exception as e:
                out = {"ok": False, "error": str(e)}
            print(_json.dumps(out), flush=True)
        return

    app = Server("sentinel")

    @app.list_tools()
    async def list_tools():
        from mcp.types import Tool

        return [
            Tool(
                name=name,
                description=spec["description"],
                inputSchema={
                    "type": "object",
                    "properties": {k: v for k, v in spec["arguments"].items() if k != "default"},
                },
            )
            for name, spec in TOOLS.items()
        ]

    @app.call_tool()
    async def call_tool(name: str, arguments: dict):
        from mcp.types import TextContent

        spec = TOOLS.get(name)
        if not spec:
            raise ValueError(f"Unknown tool: {name}")
        result = spec["handler"](arguments or {})
        return [TextContent(type="text", text=result)]

    async def _run():
        async with stdio_server() as (read, write):
            await app.run(read, write)

    asyncio.run(_run())


if __name__ == "__main__":
    serve_stdio()

if __name__ == "__main__":
    serve_stdio()
