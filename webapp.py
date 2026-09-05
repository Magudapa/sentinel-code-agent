"""Sentinel Streamlit web UI — review PRs, diffs, and local repos in the browser."""

from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from sentinel.config import load_config
from sentinel.model import ModelClient
from sentinel.output import format_json, format_markdown, format_sarif
from sentinel.pipeline import Reviewer
from sentinel.providers import get_provider

st.set_page_config(page_title="Sentinel — Code Review Agent", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
    .stApp { background: #f8fafc; }
    .hero {
        background: linear-gradient(135deg, #0f172a, #334155);
        padding: 26px 30px; border-radius: 16px; color: white; margin-bottom: 22px;
    }
    .hero h1 { margin: 0; font-size: 30px; font-weight: 800; }
    .hero p { margin: 6px 0 0; opacity: .85; }
    .score-ring { font-size: 54px; font-weight: 900; text-align: center; }
    .metric-card {
        background: white; padding: 14px; border-radius: 12px;
        box-shadow: 0 2px 4px rgba(0,0,0,.05); border: 1px solid #e2e8f0;
    }
    .finding-rule { font-family: monospace; color: #0f172a; font-weight: 700; }
    .sev-critical { color:#ef4444; font-weight:700; }
    .sev-high { color:#f97316; font-weight:700; }
    .sev-medium { color:#f59e0b; font-weight:700; }
    .sev-low { color:#3b82f6; font-weight:700; }
    .sev-info { color:#64748b; }
    .knowagel {}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="hero">
  <h1>🛡️ Sentinel</h1>
  <p>Autonomous security &amp; code review agent — free, local-first. Catches bugs, explains them, and (optionally) fixes them.</p>
</div>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------- config
cfg = load_config()

with st.sidebar:
    st.header("⚙️ Review source")
    source = st.radio("Choose where to review from:", [
        "📄 Local diff / repo", "🐙 GitHub PR", "🦊 GitLab MR", "🧪 Sample vulnerable code",
    ])

    explain = st.checkbox("Explain findings with local LLM (Ollama)", value=True)
    if explain:
        st.caption(f"Model: {cfg.model.model}  ·  Ollama at {cfg.model.base_url}")

    provider_name = "local"
    extra = {}

    if source.startswith("🐙"):
        provider_name = "github"
        with st.form("gh_form"):
            repo = st.text_input("owner/repo", key="gh_repo")
            pr = st.number_input("PR number", min_value=1, step=1, key="gh_pr")
            token = st.text_input("GITHUB_TOKEN (optional for public)", type="password", key="gh_token")
            # store token for the provider
        source_btn = st.button("Run GitHub review", type="primary", use_container_width=True,
                               key="gh_run")
        extra = {"repo": repo, "pr": int(pr or 0), "token": token}

    elif source.startswith("🦊"):
        provider_name = "gitlab"
        with st.form("gl_form"):
            repo = st.text_input("group/project", key="gl_repo")
            mr = st.number_input("MR number", min_value=1, step=1, key="gl_mr")
            token = st.text_input("GITLAB_TOKEN", type="password", key="gl_token")
        source_btn = st.button("Run GitLab review", type="primary", use_container_width=True,
                               key="gl_run")
        extra = {"repo": repo, "pr": int(mr or 0), "token": token}

    elif source.startswith("🧪"):
        with st.form("sample_form"):
            st.caption("Runs against the repo's own vulnerable fixture — a great first demo.")
        source_btn = st.button("Run sample review", type="primary", use_container_width=True,
                               key="sample_run")

    else:
        with st.form("local_form"):
            path = st.text_input("Repo or file path", value=".", key="local_path")
            diff_text = st.text_area("Or paste a raw git diff here (leave blank to use local git diff):",
                                     height=160, key="local_diff")
        source_btn = st.button("Run local review", type="primary", use_container_width=True,
                               key="local_run")

# ------------------------------------------------------------------ run
if source_btn:
    model_status = "online"
    if explain:
        try:
            model_status = "online" if ModelClient(cfg.model).is_available() else "offline"
        except Exception:
            model_status = "offline"

    st.session_state["status"] = model_status
    import os

    from sentinel.providers.github import GitHubProvider
    from sentinel.providers.gitlab import GitLabProvider

    try:
        with st.spinner("Reviewing… running analyzers" + (" + local LLM" if explain and model_status == "online" else "") + ""):
            if source.startswith("🐙"):
                if not extra.get("repo") or not extra.get("pr"):
                    st.error("Enter owner/repo and PR number.")
                    st.stop()
                os.environ["GITHUB_TOKEN"] = extra.get("token") or os.environ.get("GITHUB_TOKEN", "")
                provider = GitHubProvider()
                context = provider.fetch_context(extra["repo"], extra["pr"])
            elif source.startswith("🦊"):
                if not extra.get("repo") or not extra.get("pr"):
                    st.error("Enter group/project and MR number.")
                    st.stop()
                os.environ["GITLAB_TOKEN"] = extra.get("token") or os.environ.get("GITLAB_TOKEN", "")
                provider = GitLabProvider()
                context = provider.fetch_context(extra["repo"], extra["pr"])
            elif source.startswith("🧪"):
                provider = get_provider("local")
                fixture = Path(__file__).parent / "tests" / "fixtures" / "vulnerable_app.py"
                import subprocess

                res = subprocess.run(["git", "diff", "--no-index", "/dev/null", str(fixture)],
                                     capture_output=True, text=True, check=False)
                context = provider.fetch_context(str(fixture.parent), diff=res.stdout)
            else:
                provider = get_provider("local")
                if diff_text.strip():
                    context = provider.fetch_context(path, diff=diff_text)
                else:
                    context = provider.fetch_context(path)

            report = Reviewer(cfg).review(provider, context, explain=(explain and model_status == "online"),
                                          working_dir=(path if source.startswith("📄") and not diff_text.strip() else ""))

        st.session_state["report"] = report
    except Exception as e:
        st.error(f"Review failed: {e}")
        st.stop()

if "report" in st.session_state:
    report = st.session_state["report"]
    counts = report.counts
    score = report.verdict_score

    def _label(s):
        if s >= 90: return "🟢 Excellent — merge confidently"
        if s >= 75: return "🟡 Good — a few minor issues"
        if s >= 55: return "🟠 Needs attention — fix before merge"
        return "🔴 Critical — do not merge"

    c1, c2, c3, c4 = st.columns([1.4, 1, 1, 1])
    with c1:
        st.markdown(
            f"<div class='metric-card'><div class='score-ring'>{score}</div>"
            f"<div style='text-align:center;font-weight:600'>{_label(score)}</div></div>",
            unsafe_allow_html=True)
    with c2:
        st.markdown(f"<div class='metric-card'><h3>🔴 Critical</h3><div style='font-size:34px;font-weight:800;color:#ef4444'>{counts.get('critical', 0)}</div></div>", unsafe_allow_html=True)
    with c3:
        st.markdown(f"<div class='metric-card'><h3>🟠 High</h3><div style='font-size:34px;font-weight:800;color:#f97316'>{counts.get('high', 0)}</div></div>", unsafe_allow_html=True)
    with c4:
        st.markdown(f"<div class='metric-card'><h3>📊 Medium</h3><div style='font-size:34px;font-weight:800;color:#f59e0b'>{counts.get('medium', 0)}</div></div>", unsafe_allow_html=True)

    st.markdown(f"**Reviewing** `{report.repo}` → `{report.target}` · {len(report.findings)} finding(s)")

    tab_summary, tab_table, tab_fix, tab_export = st.tabs(["📋 Report", "🗂️ Findings table", "🔧 Suggested fixes", "💾 Export"])

    with tab_summary:
        st.markdown(report.summary_md)
        if report.findings:
            order = ["critical", "high", "medium", "low", "info"]
            labels = [s for s in order if counts.get(s, 0)]
            values = [counts.get(s, 0) for s in labels]
            fig = px.bar(x=labels, y=values, title="Findings by severity",
                         color=labels, color_discrete_sequence=["#ef4444", "#f97316", "#f59e0b", "#3b82f6", "#64748b"])
            st.plotly_chart(fig, use_container_width=True)
            for f in sorted(report.findings, key=lambda x: x.severity, reverse=True):
                sev_cls = f"sev-{f.severity_name}"
                st.markdown(
                    f"<div class='metric-card'><span class='{sev_cls}'>[{f.severity_name.upper()}]</span> "
                    f"<span class='finding-rule'>{f.rule_id}</span> — {f.description}<br>"
                    f"<code>{f.file}:{f.line}</code>"
                    + (f"<br>💾 <i>{f.memory_hint}</i>" if f.memory_hint else "")
                    + (f"<br><i>{f.model_explanation}</i>" if f.model_explanation else "")
                    + "</div>",
                    unsafe_allow_html=True)

    with tab_table:
        if report.findings:
            rows = [{
                "Rule": f.rule_id, "Severity": f.severity_name, "File": f.file,
                "Line": f.line, "Description": f.description,
            } for f in report.findings]
            st.dataframe(pd.DataFrame(rows), use_container_width=True, height=420)
        else:
            st.success("No findings. Nice work! 🎉")

    with tab_fix:
        if report.patches:
            for i, p in enumerate(report.patches):
                st.markdown(f"**{i+1}. {p.finding.file}** — {p.finding.rule_id} "
                            f"({'✅ validated' if p.validated else '⚠️ unvalidated'})")
                st.code(p.diff, language="diff")
        else:
            st.info("No auto-fix candidates shown. Run with Ollama online to get LLM-generated, validated patches, "
                    "or use `sentinel fix --target export` in a checkout.")

    with tab_export:
        st.download_button("Download Markdown report", format_markdown(report), file_name="sentinel-report.md")
        st.download_button("Download JSON report", format_json(report), file_name="sentinel-report.json")
        st.download_button("Download SARIF (GitHub code scanning)", format_sarif(report), file_name="sentinel.sarif")

else:
    st.info("Select a review source in the sidebar and click run. No external service needed — Sentinel runs on your machine.")
    st.caption("Pick **🧪 Sample vulnerable code** for an instant demo.")