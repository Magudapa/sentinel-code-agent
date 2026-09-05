"""Sentinel providers: get diffs from GitHub, GitLab, Bitbucket, or local repos."""

from .base import BaseProvider, ProviderContext, get_provider, register
from .github import GitHubProvider
from .gitlab import GitLabProvider
from .local import LocalProvider

__all__ = [
    "BaseProvider",
    "GitHubProvider",
    "GitLabProvider",
    "LocalProvider",
    "ProviderContext",
    "get_provider",
    "register",
]