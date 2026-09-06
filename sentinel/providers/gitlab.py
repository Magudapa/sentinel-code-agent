"""GitLab provider (reads MR diffs and posts comments)."""

from __future__ import annotations

import os

from .base import BaseProvider, ProviderContext, ProviderError, register


def _http_error(url: str, exc: Exception) -> ProviderError:
    status = getattr(exc, "response", None)
    code = status.status_code if status is not None else None
    hint = {
        401: "authentication failed (bad or missing token).",
        403: "permission denied (token lacks access to this project, or rate limit).",
        404: "not found (project/MR does not exist, or token cannot see it).",
        429: "rate limited by GitLab — retry later.",
    }.get(code)
    if hint:
        return ProviderError(f"GitLab API {code} on {url}: {hint}")
    return ProviderError(f"GitLab API error on {url}: {type(exc).__name__}: {exc}")


@register
class GitLabProvider(BaseProvider):
    name = "gitlab"

    def __init__(self, token: str = "", base_url: str = "https://gitlab.com/api/v4"):
        self.token = token or os.environ.get("GITLAB_TOKEN", "")
        self.base_url = base_url

    def _get(self, url: str):
        import requests

        headers = {}
        if self.token:
            headers["PRIVATE-TOKEN"] = self.token
        try:
            r = requests.get(f"{self.base_url}{url}", headers=headers, timeout=30)
            r.raise_for_status()
            return r.json()
        except requests.HTTPError as exc:
            raise _http_error(url, exc) from exc
        except requests.RequestException as exc:
            raise ProviderError(f"GitLab network error on {url}: {type(exc).__name__}") from exc

    def fetch_context(self, repo: str, mr: int) -> ProviderContext:
        # repo as "group/project" (URL-encoded for GitLab)
        proj = repo.replace("/", "%2F")
        changes = self._get(f"/projects/{proj}/merge_requests/{mr}/changes")

        # GitLab supplies per-file diff strings; concatenate them
        raw_diff_parts = [c["diff"] for c in changes.get("changes", [])]

        mr_data = changes
        return ProviderContext(
            provider=self.name,
            repo=repo,
            target=str(mr),
            diff="\n".join(raw_diff_parts),
            base_sha="",
            head_sha="",
            title=mr_data.get("title", ""),
            description=mr_data.get("description", "") or "",
            files={},
        )

    def post_comments(self, context: ProviderContext, findings) -> None:
        if not self.token:
            raise RuntimeError("GITLAB_TOKEN required to post MR comments")
        proj = context.repo.replace("/", "%2F")
        for f in findings:
            if not f.line or f.line <= 0:
                continue
            body = f"**[{f.severity_name}] `{f.rule_id}`** — {f.description}"
            if f.model_explanation:
                body += f"\n\n{f.model_explanation}"
            # GitLab discussion on MR diff line
            self._post_discussion(
                f"/projects/{proj}/merge_requests/{int(context.target)}/discussions",
                {"position[position_type]": "text",
                 "position[new_path]": f.file,
                 "position[new_line]": f.line,
                 "body": body},
            )

    def _post_discussion(self, url: str, payload: dict):
        import requests

        headers = {"PRIVATE-TOKEN": self.token}
        r = requests.post(f"{self.base_url}{url}", headers=headers, data=payload, timeout=30)
        r.raise_for_status()