"""Sentinel — autonomous security & code review agent. Free, local-first, MCP-ready."""

__version__ = "0.1.0"

from .models import Finding, ReviewReport, Severity
from .pipeline import Reviewer, run_review

__all__ = ["Finding", "ReviewReport", "Reviewer", "Severity", "__version__", "run_review"]