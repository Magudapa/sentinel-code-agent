"""GitHub cloud/enterprise provider (reads PR diffs, posts comments, opens fix PRs)."""

from __future__ import annotations

import os

from ..diffparse import parse_diff
from .base import BaseProvider, ProviderContext, ProviderError, register


def _http_error(url: str, exc: Exception) -> ProviderError:
    """Turn a requests HTTPError into a clean, leak-free ProviderError.

    The exception message may embed the request URL (fine) but never the token
    (headers are not part of the message). Credential/session problems get
    actionable text instead of a raw traceback.
    """
    status = getattr(exc, "response", None)
    code = status.status_code if status is not None else None
    hint = {
        401: "authentication failed (bad or missing token). Read-only reviews work without a token.",
        403: "permission denied (token lacks access to this repository, or rate limit).",
        404: "not found (repo/PR does not exist, or token cannot see it).",
        429: "rate limited by the provider — retry later.",
    }.get(code)
    if hint:
        return ProviderError(f"GitHub API {code} on {url}: {hint}")
    return ProviderError(f"GitHub API error on {url}: {type(exc).__name__}: {exc}")


@register
class GitHubProvider(BaseProvider):
    name = "github"

    def __init__(self, token: str = "", base_url: str = "https://api.github.com"):
        self.token = token or os.environ.get("GITHUB_TOKEN", "")
        self.base_url = base_url

    # --- HTTP helpers -------------------------------------------------
    def _get(self, url: str):
        import requests

        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            r = requests.get(f"{self.base_url}{url}", headers=headers, timeout=30)
            r.raise_for_status()
            return r.json()
        except requests.HTTPError as exc:
            raise _http_error(url, exc) from exc
        except requests.RequestException as exc:
            raise ProviderError(f"GitHub network error on {url}: {type(exc).__name__}") from exc

    def _post(self, url: str, payload: dict):
        import requests

        headers = {"Accept": "application/vnd.github+json", "Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            r = requests.post(f"{self.base_url}{url}", headers=headers, json=payload, timeout=30)
            r.raise_for_status()
            return r.json()
        except requests.HTTPError as exc:
            raise _http_error(url, exc) from exc
        except requests.RequestException as exc:
            raise ProviderError(f"GitHub network error on {url}: {type(exc).__name__}") from exc

    # --- Fetching ------------------------------------------------------
    def fetch_context(self, repo: str, pr: int) -> ProviderContext:
        pr_data = self._get(f"/repos/{repo}/pulls/{pr}")
        diff = self._get_diff(repo, pr)
        return ProviderContext(
            provider=self.name,
            repo=repo,
            target=str(pr),
            diff=diff,
            base_sha=pr_data["base"]["sha"],
            head_sha=pr_data["head"]["sha"],
            base_ref=pr_data.get("base", {}).get("ref", "") or "",
            title=pr_data.get("title", ""),
            description=pr_data.get("body", "") or "",
            files=parse_diff(diff),
        )

    def _get_diff(self, repo: str, pr: int) -> str:
        import requests

        headers = {"Accept": "application/vnd.github.diff"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            r = requests.get(f"{self.base_url}/repos/{repo}/pulls/{pr}", headers=headers, timeout=60)
            r.raise_for_status()
            return r.text
        except requests.HTTPError as exc:
            raise _http_error(f"/repos/{repo}/pulls/{pr} (diff)", exc) from exc
        except requests.RequestException as exc:
            raise ProviderError(f"GitHub network error fetching diff for {repo}#{pr}: {type(exc).__name__}") from exc

    # --- Output --------------------------------------------------------
    def post_comments(self, context: ProviderContext, findings) -> None:
        if not self.token:
            raise RuntimeError("GITHUB_TOKEN required to post PR review comments")
        if context.target.isdigit():
            pr_number = int(context.target)
        else:
            raise RuntimeError("post_comments requires a numeric PR target")

        comments = []
        for f in findings:
            if not f.line or f.line <= 0:
                continue
            body = f"**[{f.severity_name}] `{f.rule_id}`** — {f.description}\n\n"
            if f.model_explanation:
                body += f"{f.model_explanation}\n\n"
            if f.suggested_fix:
                body += f"*Proposed fix:*\n```diff\n{f.suggested_fix}\n```"
            comments.append({"path": f.file, "line": f.line, "side": "RIGHT", "body": body})

        self._post(f"/repos/{context.repo}/pulls/{pr_number}/reviews", {
            "commit_id": context.head_sha,
            "event": "COMMENT",
            "comments": comments[:640],  # GitHub cap on inline comments per review
        })

    def open_fix_pr(self, context: ProviderContext, branch_name: str, diff: str, message: str) -> str:
        """Open a PR containing a diff (from a remote branch the user pushed).

        Because Sentinel is read-only by default, the user must first create the
        branch with ``sentinel fix-export`` and push it, then call
        ``sentinel fix-pr`` with ``--branch``. This method only creates the PR itself.
        """
        if not self.token:
            raise RuntimeError("GITHUB_TOKEN required to open a fix PR")
        pr_data = self._post(f"/repos/{context.repo}/pulls", {
            "title": message[:100],
            "head": branch_name,
            "base": context.base_ref or "main",
            "body": (
                "This PR was auto-generated by **Sentinel** — the autonomous security & "
                "code review agent.\n\n"
                f"Fixes findings from a review of **{context.target}**.\n\n"
                "```diff\n" + (diff[:4000] if len(diff) > 4000 else diff) + "\n```\n\n"
                "_Sentinel validates every patch before proposing it. Please review before merging._"
            ),
        })
        return pr_data["html_url"]

    def create_fix_branch(self, context: ProviderContext, branch_name: str, file_changes: dict[str, str]) -> str:
        """Create a remote branch with patched files via the Git Data API."""
        if not self.token:
            raise RuntimeError("GITHUB_TOKEN required to create a fix branch")
        repo = context.repo
        base_sha = context.base_sha or self._get(f"/repos/{repo}/git/ref/heads/main")["object"]["sha"]

        # Create branch from base SHA
        self._post(f"/repos/{repo}/git/refs", {
            "ref": f"refs/heads/{branch_name}",
            "sha": base_sha,
        })
        for path, new_content in file_changes.items():
            try:
                blob = self._post(f"/repos/{repo}/git/blobs", {"content": new_content, "encoding": "utf-8"})
            except Exception:
                import base64 as b64

                blob = self._post(f"/repos/{repo}/git/blobs", {
                    "content": b64.b64encode(new_content.encode("utf-8")).decode(), "encoding": "base64",
                })
            blob_sha = blob["sha"]
            # Get current tree on the new branch
            head = self._get(f"/repos/{repo}/git/ref/heads/{branch_name}")
            commit = self._get(f"/repos/{repo}/git/commits/{head['object']['sha']}")
            tree = self._post(f"/repos/{repo}/git/trees", {
                "base_tree": commit["tree"]["sha"],
                "tree": [{"path": path, "mode": "100644", "type": "blob", "sha": blob_sha}],
            })
            new_commit = self._post(f"/repos/{repo}/git/commits", {
                "message": f"Sentinel: automated fix for {path}",
                "tree": tree["sha"],
                "parents": [head["object"]["sha"]],
            })
            self._post(f"/repos/{repo}/git/refs/heads/{branch_name}", {
                "sha": new_commit["sha"], "force": True,
            })
        return f"refs/heads/{branch_name}"