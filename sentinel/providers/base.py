"""Provider base class and registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ProviderContext:
    """Info describing what is being reviewed."""

    provider: str
    repo: str
    target: str
    diff: str = ""
    base_sha: str = ""
    head_sha: str = ""
    title: str = ""
    description: str = ""
    files: dict = field(default_factory=dict)


class BaseProvider(ABC):
    name = "base"

    @abstractmethod
    def fetch_context(self, *args, **kwargs) -> ProviderContext:
        """Fetch the diff + metadata for the unit being reviewed."""

    def post_comments(self, context: ProviderContext, findings) -> None:
        """Post line-level review comments (default: no-op for local)."""

    def open_fix_pr(self, context: ProviderContext, branch_name: str, diff: str, message: str) -> str:
        """Open a PR containing the fix (default: NotImplemented for local)."""
        raise NotImplementedError(f"{self.name} does not support opening PRs")


PROVIDERS: dict[str, type[BaseProvider]] = {}


def register(cls: type[BaseProvider]) -> type[BaseProvider]:
    PROVIDERS[cls.name] = cls
    return cls


def get_provider(name: str) -> BaseProvider:
    if name not in PROVIDERS:
        raise ValueError(
            f"Unknown provider '{name}'. Available: {', '.join(sorted(PROVIDERS))}"
        )
    return PROVIDERS[name]()