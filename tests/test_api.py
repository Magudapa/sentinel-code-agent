"""Tests for the Phase-0 REST API (FastAPI TestClient). Requires a real git repo fixture."""

from __future__ import annotations

import subprocess

import pytest
from fastapi.testclient import TestClient

from sentinel.api.server import VERSION, create_app


@pytest.fixture
def git_workspace(tmp_path):
    """A real git repo with baseline commit + uncommitted vulnerable change."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
    (root / "good.py").write_text("SECRET_PREFIX = 'x'\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=root, check=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "baseline"], cwd=root, check=True)
    (root / "bad.py").write_text(
        "import requests\n"
        "requests.post('http://api.example.com/login', data=creds)\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    return root


@pytest.fixture
def client(git_workspace):
    return TestClient(create_app(workspace_root=str(git_workspace)))


def test_health(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["version"] == VERSION
    assert body["model"]["provider"] == "ollama"


def test_rulesets_lists_generated_books(client):
    r = client.get("/api/v1/rulesets")
    assert r.status_code == 200
    langs = r.json()["languages"]
    assert "python" in langs
    assert langs["python"]["authors"] == ["Magudapa"]


def test_rulesets_language_filter(client):
    r = client.get("/api/v1/rulesets", params={"language": "sql"})
    assert r.status_code == 200
    langs = r.json()["languages"]
    assert list(langs) == ["sql"]
    assert langs["sql"]["rules"] >= 8


def test_review_local_workspace(client, git_workspace):
    r = client.post("/api/v1/review", json={"provider": "local", "path": str(git_workspace)})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] in ("VERIFIED", "FAILED", "INCOMPLETE")
    rules = {f["rule_id"] for f in body["findings"]}
    assert rules, "expected at least one finding on the vulnerable diff"
    assert any(r_ in rules for r_ in ("PY-001", "BANDIT-", "S001"))
    assert body["verdict_score"] <= 100


def test_review_blocks_path_outside_workspace(client, tmp_path):
    other = tmp_path / "elsewhere"
    other.mkdir()
    (other / "evil.txt").write_text("x", encoding="utf-8")
    r = client.post("/api/v1/review", json={"provider": "local", "path": str(other)})
    assert r.status_code == 400


def test_review_requires_path_or_pr(client):
    r = client.post("/api/v1/review", json={"provider": "local", "path": ""})
    assert r.status_code == 422


def test_rulesets_verify_empirical(client):
    r = client.post("/api/v1/rulesets/verify", json={"language": "python"})
    assert r.status_code == 200
    body = r.json()
    results = body["results"]
    assert len(results) == 11
    assert all(res["empirical_passed"] for res in results)
    assert all(res["rule_id"].startswith("PY-") for res in results)


def test_unknown_provider_returns_error(client):
    r = client.post("/api/v1/review", json={"provider": "nope", "path": "."})
    assert r.status_code == 400