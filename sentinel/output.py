"""Output formatting: human Markdown, JSON, and SARIF (GitHub code scanning compatible)."""

from __future__ import annotations

import json

from .models import ReviewReport, compute_verdict_score

SEVERITY_EMOJI = {
    "info": "ℹ️",
    "low": "🔵",
    "medium": "🟡",
    "high": "🟠",
    "critical": "🔴",
}


def _verdict_label(score: int) -> str:
    if score >= 90:
        return "Excellent — merge confidently"
    if score >= 75:
        return "Good — a few minor issues"
    if score >= 55:
        return "Needs attention — fix before merge"
    return "Critical — do not merge"


def format_markdown(report: ReviewReport) -> str:
    score = report.verdict_score or compute_verdict_score(report.findings)
    lines = [
        f"## 🛡️ Sentinel Review — {report.repo}",
        "",
        f"**Target:** {report.target}  **Verdict score:** {score}/100 ({_verdict_label(score)})",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    order = ["critical", "high", "medium", "low", "info"]
    for sev in order:
        n = report.counts.get(sev, 0)
        if n:
            lines.append(f"| {SEVERITY_EMOJI[sev]} {sev} | {n} |")
    lines.append("")

    if not report.findings:
        lines.append("**No issues found. Nice work!** 🎉")
        return "\n".join(lines)

    lines.append("### Findings")
    sorted_findings = sorted(
        report.findings, key=lambda f: (f.severity_name, f.file, f.line), reverse=True
    )
    for i, f in enumerate(sorted_findings, 1):
        lines.append(f"{i}. **[`{f.rule_id}`]** {SEVERITY_EMOJI[f.severity_name]} {f.description}")
        lines.append(f"   - **Location:** `{f.file}:{f.line}`")
        if f.code_snippet:
            lines.append(f"   - ```python\n     {f.code_snippet}\n     ```")
        if f.model_explanation:
            lines.append(f"   - **Why:** {f.model_explanation}")
        if f.memory_hint:
            lines.append(f"   - 💾 {f.memory_hint}")
        if f.suggested_fix and f.suggested_fix != f.code_snippet:
            lines.append(f"   - **Fix suggestion:** {f.suggested_fix}")
        lines.append("")

    if report.patches:
        lines.append("### Auto-fixes proposed")
        for p in report.patches:
            status = "✅ validated" if p.validated else "❌ not validated"
            lines.append(f"- `{p.finding.file}` — {status} {('(tests passed)' if p.tests_passed else '')}")

    return "\n".join(lines)


def format_json(report: ReviewReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def format_sarif(report: ReviewReport) -> str:
    """SARIF 2.1.0 — importable by GitHub code scanning."""
    rules = []
    results = []
    seen_rules = set()

    for f in report.findings:
        rule_id = f.rule_id
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f.description[:200]},
                "defaultConfiguration": {"level": _sarif_level(f.severity_name)},
                "help": {"text": f.suggested_fix or "See Sentinel docs."},
            })
        uri = f.file.replace("\\", "/")
        results.append({
            "ruleId": rule_id,
            "level": _sarif_level(f.severity_name),
            "message": {"text": f.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {
                        "startLine": f.line,
                        "endLine": f.end_line or f.line,
                        "snippet": {"text": f.code_snippet},
                    },
                }
            }],
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Sentinel", "informationUri": "https://github.com/Magudapa/sentinel", "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def _sarif_level(sev: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(sev, "note")