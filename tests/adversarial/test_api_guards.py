"""Adversarial tests for the REST API guards.

The review endpoint must return proper status codes for hostile inputs:
generic 4xx, never a traceback, and never more than the workspace allows.
"""

from __future__ import annotations

import base64
import subprocess

import pytest
from fastapi.testclient import TestClient

from sentinel.api.server import create_app
from sentinel.diffparse import MAX_DIFF_BYTES


@pytest.fixture
def guarded_client(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.py").write_text("print(1)\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=root, check=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "baseline"], cwd=root, check=True)
    return TestClient(create_app(workspace_root=str(root)))


def test_review_gigantic_diff_is_413(guarded_client):
    from pathlib import Path

    root = Path(guarded_client.get("/api/v1/health").json()["security"]["workspace_root"])
    # base64 of ~1.4x the raw diff limit must exceed the request-size guard
    body = {
        "provider": "local",
        "path": str(root / "a.py"),
        "range": "",
        "diff": base64.b64encode(b"+" * int(MAX_DIFF_BYTES * 1.1)).decode(),
    }
    r = guarded_client.post("/api/v1/review", json=body)
    assert r.status_code == 413


def test_review_missing_pr_for_github_is_422(guarded_client):
    r = guarded_client.post(
        "/api/v1/review",
        json={"provider": "github", "repo": "x/y", "pr": None, "path": "", "range": "", "diff": ""},
    )
    assert r.status_code == 422


def test_rulesets_verify_no_model_still_returns_dict(guarded_client):
    # verify_rule with no model (offline) must not raise; endpoint returns results.
    r = guarded_client.post("/api/v1/rulesets/verify", json={"language": ""})
    assert r.status_code == 200
    assert "results" in r.json()