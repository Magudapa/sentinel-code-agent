"""FastAPI REST server — Phase 0 API-first surface.

Principles (see SENTINEL_SECURITY_MODEL / API_SPEC):
- Binds localhost by default (no accidental exposure).
- Local scans are confined to a configured workspace root (path-traversal guard).
- Every response is machine-readable; no fabricated VERIFIED status (vision §116–117).
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from ..config import SentinelConfig, load_config
from ..rules import available_books, known_languages, load_book
from ..rules.verify import verify_rule
from ._models import RuleVerifyRequest

try:
    from importlib.metadata import version as _pkg_version

    VERSION = _pkg_version("sentinel-code-agent")
except Exception:  # pragma: no cover - dev/editable installs
    VERSION = "0.1.0"


class ReviewRequest(BaseModel):
    provider: str = "local"
    repo: str = ""
    pr: int | None = None
    path: str = ""
    range: str = ""
    diff: str = ""              # raw unified diff, or base64 when contains binary-safe bytes
    explain: bool = False
    config: str = ""


class HealthResponse(BaseModel):
    ok: bool = True
    version: str = VERSION
    model: dict[str, Any]


def _status_for(report: Any) -> tuple[str, int, str]:
    """Surface the deterministic trust-layer verdict + policy.

    Never fabricates VERIFIED: the report verdict is produced by
    ``trust.report_verdict`` from the analyzer status map (a check only counts
    if it actually ran and passed).  ``policy`` mirrors ``status`` (kept for
    backward-compat with the original response shape — both derive from the
    same source of truth now).
    """
    return report.verdict, 0, report.verdict


def create_app(config_path: str = "", workspace_root: str | None = None) -> FastAPI:
    config: SentinelConfig = load_config(config_path or None)
    root = Path(
        workspace_root or os.environ.get("SENTINEL_WORKSPACE") or os.getcwd()
    ).resolve()

    app = FastAPI(title="Sentinel", version=VERSION, docs_url="/docs", redoc_url=None)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost", "http://127.0.0.1"],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    @app.get("/api/v1/health")
    def health() -> HealthResponse:
        from ..model import ModelClient

        model = ModelClient(config.model)
        return HealthResponse(model={
            "provider": config.model.provider,
            "model": config.model.model,
            "available": model.is_available(),
        })

    @app.get("/api/v1/rulesets")
    def rulesets(language: str = "") -> dict:
        langs = [language] if language else known_languages()
        languages = {}
        for lang in langs:
            rules = load_book(lang)
            if not rules:
                continue
            languages[lang] = {
                "rules": len(rules),
                "verified": sum(1 for r in rules if r.ai_verified),
                "authors": sorted({r.author for r in rules if r.author}),
                "ids": [r.id for r in rules],
            }
        return {"languages": languages, "books_available": available_books()}

    @app.post("/api/v1/rulesets/verify")
    def rulesets_verify(body: RuleVerifyRequest) -> dict:
        from ..model import ModelClient

        langs = [body.language] if body.language else known_languages()
        model = ModelClient(config.model)
        model_ok = model.is_available()
        results = []
        for lang in langs:
            for rule in load_book(lang):
                res = verify_rule(rule, model if model_ok else None)
                results.append({
                    "rule_id": rule.id,
                    "language": rule.language,
                    "empirical_passed": res.empirical_passed,
                    "empirical_notes": res.empirical_notes,
                    "ai_verdict": res.ai_verdict,
                    "ai_reason": res.ai_reason[:300],
                    "verified": res.verified,
                })
        return {"model_available": model_ok, "ai_used": model_ok, "results": results}

    @app.post("/api/v1/review")
    def review(body: ReviewRequest) -> dict:
        from ..pipeline import run_review
        from ..providers import get_provider

        if body.provider not in ("local", "github", "gitlab"):
            raise HTTPException(400, f"unknown provider: {body.provider}")
        provider = get_provider(body.provider)
        try:
            if body.provider in ("github", "gitlab"):
                if not body.repo or not body.pr:
                    raise HTTPException(422, "--repo and --pr required for this provider")
                context = provider.fetch_context(body.repo, body.pr)
            else:
                if not body.path:
                    raise HTTPException(422, "provider 'local' requires a path")
                target = Path(body.path).expanduser().resolve()
                if root != target and root not in target.parents:
                    raise HTTPException(400, "path is outside the configured workspace root")
                diff_text = ""
                if body.diff:
                    try:
                        diff_text = base64.b64decode(body.diff).decode("utf-8", "replace")
                    except Exception:
                        diff_text = body.diff
                context = provider.fetch_context(str(target), commit_range=body.range, diff=diff_text)
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(500, str(e))

        if not context.diff.strip():
            return {
                "status": "VERIFIED",
                "trust_score": 100,
                "verdict_score": 100,
                "provider": provider.name,
                "target": context.target,
                "counts": {},
                "blocking_findings": 0,
                "findings": [],
                "policy": "PASSED",
                "message": "No diff to review — nothing changed.",
            }

        report = run_review(
            provider, context, config=config, explain=body.explain,
            working_dir=str(root) if body.provider == "local" else "",
        )
        status, _blocking, policy = _status_for(report)
        return {
            "status": status,
            "trust_score": report.verdict_score,
            "verdict_score": report.verdict_score,
            "provider": report.provider,
            "target": report.target,
            "counts": report.counts,
            "blocking_findings": report.counts.get("critical", 0),
            "policy": policy,
            "findings": [f.to_dict() for f in report.findings],
            "created_at": report.created_at,
            "verdict_reason": report.verdict_reason,
            "analyzers": report.analyzer_status,
            "verification": report.verification,
        }

    return app


app = create_app()