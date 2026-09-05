import subprocess
from pathlib import Path

from sentinel.config import SentinelConfig, load_config
from sentinel.models import Finding, Severity
from sentinel.output import format_json, format_markdown, format_sarif
from sentinel.pipeline import Reviewer
from sentinel.providers import LocalProvider

FIXTURE = Path(__file__).parent / "fixtures" / "vulnerable_app.py"


def _diff_of_fixture() -> str:
    rel = str(FIXTURE.relative_to(Path.cwd())) if FIXTURE.is_relative_to(Path.cwd()) else str(FIXTURE)
    res = subprocess.run(
        ["git", "diff", "--no-index", "/dev/null", rel],
        capture_output=True, text=True, check=False,
    )
    return res.stdout


def test_reviewer_offline_still_finds_issues():
    cfg = SentinelConfig()
    cfg.model.base_url = "http://localhost:1"  # unreachable -> model offline
    reviewer = Reviewer(cfg)
    provider = LocalProvider()
    context = provider.fetch_context(str(FIXTURE.parent), diff=_diff_of_fixture())
    report = reviewer.review(provider, context, explain=True)
    assert report.findings
    assert report.verdict_score >= 0
    assert report.counts.get("critical", 0) >= 2


def test_ignore_paths_respected(tmp_path):
    cfg = SentinelConfig()
    cfg.ignore_paths = ["tests/fixtures/*"]
    reviewer = Reviewer(cfg)
    provider = LocalProvider()
    context = provider.fetch_context(str(FIXTURE.parent), diff=_diff_of_fixture())
    report = reviewer.review(provider, context, explain=False)
    assert report.findings == []


def test_summary_includes_verdict():
    cfg = SentinelConfig()
    reviewer = Reviewer(cfg)
    provider = LocalProvider()
    context = provider.fetch_context(str(FIXTURE.parent), diff=_diff_of_fixture())
    report = reviewer.review(provider, context, explain=False)
    assert report.summary_md
    assert "Verdict" in report.summary_md


def test_markdown_output():
    f = Finding(rule_id="S001", severity=Severity.HIGH, file="a.py", line=2,
                code_snippet='x = 1', description="secret found")
    report = build_report([f])
    md = format_markdown(report)
    assert "S001" in md
    assert "high" in md.lower() or "High" in md


def test_json_roundtrip():
    f = Finding(rule_id="S001", severity=Severity.HIGH, file="a.py", line=2,
                code_snippet='x = 1', description="secret found")
    report = build_report([f])
    import json

    d = json.loads(format_json(report))
    assert d["findings"][0]["rule_id"] == "S001"
    assert d["verdict_score"] == 85


def test_sarif_output():
    f = Finding(rule_id="S001", severity=Severity.CRITICAL, file="a.py", line=2,
                code_snippet='x', description="secret found")
    report = build_report([f])
    sarif = format_sarif(report)
    assert '"version": "2.1.0"' in sarif
    assert "S001" in sarif
    assert '"level": "error"' in sarif


def test_load_config_defaults():
    cfg = load_config()
    assert cfg.model.provider == "ollama"
    assert cfg.auto_fix.enabled is False


def test_load_config_from_yaml(tmp_path):
    yml = tmp_path / ".sentinel.yml"
    yml.write_text(
        "model:\n  provider: openai\n  base_url: http://localhost:8000/v1\n"
        "auto_fix:\n  enabled: true\n  max_severity: medium\n",
        encoding="utf-8",
    )

    cfg = load_config(str(yml))
    assert cfg.model.provider == "openai"
    assert cfg.auto_fix.enabled is True
    assert cfg.auto_fix.max_severity == "medium"


def build_report(findings, repo="test/repo", target="1"):
    from sentinel.models import ReviewReport, compute_verdict_score

    r = ReviewReport(provider="local", repo=repo, target=target,
                     findings=findings, verdict_score=compute_verdict_score(findings))
    r.summary_md = "summary"
    return r