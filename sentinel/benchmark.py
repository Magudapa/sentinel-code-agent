"""Benchmark: quantify rule quality on an adversarial corpus.

Loads the packaged ``security_cases`` corpus (rule id -> {vulnerable, safe,
category}) and runs every applicable content analyzer against each sample,
then prints aggregate + per-rule + per-category precision / recall / F1.

Output is deterministic (no AI) so improvements/regressions are trackable in CI.
"""

from __future__ import annotations

from pathlib import Path

from .analyzers import analyze_changesets_full
from .diffparse import Changeset, DiffLine
from .yamlsafe import load_yaml_strict

SECURITY_CASES_DIR = Path(__file__).resolve().parent / "security_cases"

DEFAULT_CATEGORY = "General"

#: Categories the corpus is organized around (master hardening spec §33).
CATEGORIES = [
    "Secrets", "SQL injection", "Command injection", "XSS", "Path traversal",
    "SSRF", "Authentication", "Authorization", "Cryptography", "Deserialization",
    "File handling", "Network security", "Configuration", "Dependency security",
]


def _load_cases() -> dict[str, dict]:
    """Load {rule_id: {"vulnerable": [...], "safe": [...], "category": str}}."""
    cases: dict[str, dict] = {}
    root = SECURITY_CASES_DIR
    if not root.exists():
        return cases
    for lang_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        for yml in sorted(lang_dir.glob("*.yml")):
            data = load_yaml_strict(yml.read_text(encoding="utf-8")) or {}
            _ingest(data, lang_dir.name, cases)
    return cases


def _ingest(data: dict, lang: str, cases: dict[str, dict]) -> None:
    for entry in data.get("cases", []) or []:
        rid = (entry or {}).get("rule_id", "") if isinstance(entry, dict) else ""
        if not rid:
            continue
        category = str((entry or {}).get("category") or DEFAULT_CATEGORY)
        if isinstance(entry, dict) and isinstance(entry.get("category"), list):
            category = DEFAULT_CATEGORY
        cases.setdefault(rid, {"vulnerable": [], "safe": [], "category": category})
        cases[rid]["vulnerable"].extend((entry or {}).get("vulnerable", []) or [])
        cases[rid]["safe"].extend((entry or {}).get("safe", []) or [])


def analyze_text(text: str, file: str = "sample.py") -> list[str]:
    """Run all content analyzers on a snippet; return matched rule_ids."""
    changeset = Changeset(
        file=file,
        additions=[DiffLine(kind="add", text=ln, new_line=i + 1, old_line=None)
                   for i, ln in enumerate(text.splitlines())],
    )
    findings, _status = analyze_changesets_full({file: changeset})
    return [f.rule_id for f in findings]


def run_benchmark(cases_dir: str | None = None) -> dict:
    cases = _load_cases() if cases_dir is None else _load_from(cases_dir)
    if not cases:
        return {"cases": 0, "total": {"tp": 0, "fp": 0, "fn": 0, "tn": 0}}

    rows = []
    totals = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    aggregated = {}
    by_category: dict[str, dict] = {}
    covered_categories = set()

    for rid in sorted(cases):
        info = cases[rid]
        vuln = info.get("vulnerable", [])
        safe = info.get("safe", [])
        category = str(info.get("category") or DEFAULT_CATEGORY)
        if vuln or safe:
            covered_categories.add(category)
        tp = sum(1 for s in vuln if rid in analyze_text(s))
        fn = len(vuln) - tp
        fp = sum(1 for s in safe if rid in analyze_text(s))
        tn = len(safe) - fp
        row = {"rule_id": rid, "category": category, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
               "precision": _prec(tp, fp), "recall": _recall(tp, fn)}
        rows.append(row)
        for k in totals:
            totals[k] += row[k]
        agg_key = rid.split("-")[0] if "-" in rid else rid
        aggregated.setdefault(agg_key, {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
        for k in ("tp", "fp", "fn", "tn"):
            aggregated[agg_key][k] += row[k]

    # Per-category metrics are computed on the samples' own categories so a
    # rule is counted under exactly the category its cases were filed under.
    per_category = _recompute_categories(cases)

    for cat in sorted(per_category, key=str.lower):
        g = per_category[cat]
        by_category[cat] = {
            "tp": g["tp"], "fp": g["fp"], "fn": g["fn"], "tn": g["tn"],
            "samples": g["tp"] + g["fp"] + g["fn"] + g["tn"],
            "precision": _prec(g["tp"], g["fp"]),
            "recall": _recall(g["tp"], g["fn"]),
            "covered": cat in covered_categories,
        }

    return {
        "cases": len(cases),
        "total_samples": totals["tp"] + totals["fp"] + totals["fn"] + totals["tn"],
        "total": totals,
        "aggregate_precision": _prec(totals["tp"], totals["fp"]),
        "aggregate_recall": _recall(totals["tp"], totals["fn"]),
        "rows": rows,
        "by_prefix": aggregated,
        "by_category": by_category,
        "categories": sorted(c for c in by_category),
    }


def _recompute_categories(cases: dict[str, dict]) -> dict[str, dict]:
    """Rebuild per-category tallies from scratch."""
    out: dict[str, dict] = {}
    for rid, info in cases.items():
        category = str(info.get("category") or DEFAULT_CATEGORY)
        vuln, safe = info.get("vulnerable", []), info.get("safe", [])
        g = out.setdefault(category, {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
        for s in vuln:
            if rid in analyze_text(s):
                g["tp"] += 1
            else:
                g["fn"] += 1
        for s in safe:
            if rid in analyze_text(s):
                g["fp"] += 1
            else:
                g["tn"] += 1
    return out


def _prec(tp: int, fp: int) -> float:
    return round(tp / (tp + fp), 3) if (tp + fp) else 0.0


def _recall(tp: int, fn: int) -> float:
    return round(tp / (tp + fn), 3) if (tp + fn) else 0.0


def _load_from(cases_dir: str) -> dict:
    cases: dict[str, dict] = {}
    root = Path(cases_dir)
    for yml in root.rglob("*.yml"):
        data = load_yaml_strict(yml.read_text(encoding="utf-8")) or {}
        _ingest(data, root.name, cases)
    return cases


def format_benchmark(result: dict) -> str:
    out = [
        f"Cases: {result['cases']}  Samples: {result['total_samples']}",
        f"Aggregate precision: {result['aggregate_precision']}  recall: {result['aggregate_recall']}",
        "",
        f"{'rule_id':16} {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3} {'precision':>10} {'recall':>7}",
    ]
    for row in result["rows"]:
        out.append(
            f"{row['rule_id']:16} {row['tp']:>3} {row['fp']:>3} {row['fn']:>3} {row['tn']:>3} "
            f"{row['precision']:>10} {row['recall']:>7}"
        )
    if result.get("by_category"):
        out.append("")
        out.append(f"{'category':24} {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3} {'precision':>10} {'recall':>7}")
        for cat, g in sorted(result["by_category"].items(), key=lambda kv: kv[0].lower()):
            out.append(
                f"{cat[:24]:24} {g['tp']:>3} {g['fp']:>3} {g['fn']:>3} {g['tn']:>3} "
                f"{g['precision']:>10} {g['recall']:>7}"
            )
    return "\n".join(out)