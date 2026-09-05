"""API request/response schemas (Pydantic v2)."""

from __future__ import annotations

from pydantic import BaseModel


class RuleVerifyRequest(BaseModel):
    language: str = ""
    write: bool = False