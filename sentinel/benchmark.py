"""Benchmark: quantify rule quality on an adversarial corpus.

Loads ``tests/security_cases/*/*.yml`` (rule id -> {vulnerable: [..], safe: [..]})
and runs every applicable content analyzer against each sample, then prints:

    precision / recall / F1 per rule-book
    true positives, false positives, false negatives, true negatives counts

Output is deterministic (no AI) so improvements/regressions are trackable in CI.
"""

from __future__ import annotations

from pathlib import Path

from .analyzers import analyze_changesets_full
from .diffparse import Changeset, DiffLine

SECURITY_CASES_DIR = Path(__file__).resolve().parent / "security_cases"


def _load_cases() -> dict[str, dict]:
    """Load {rule_id: {"vulnerable": [text, ...], "safe": [text, ...]}}."""
    cases: dict[str, dict] = {}
    root = SECURITY_CASES_DIR
    if not root.exists():
        return cases
    for lang_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        for yml in sorted(lang_dir.glob("*.yml")):
            import yaml

            data = yaml.safe_load(yml.read_text(encoding="utf-8")) or {}
            for entry in data.get("cases", []):
                rid = entry.get("rule_id", "")
                if not rid:
                    continue
                cases.setdefault(rid, {"vulnerable": [], "safe": []})
                cases[rid]["vulnerable"].extend(entry.get("vulnerable", []) or [])
                cases[rid]["safe"].extend(entry.get("safe", []) or [])
    return cases


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

    for rid in sorted(cases):
        vuln = cases[rid].get("vulnerable", [])
        safe = cases[rid].get("safe", [])
        tp = sum(1 for s in vuln if rid in analyze_text(s))
        fn = len(vuln) - tp
        fp = sum(1 for s in safe if rid in analyze_text(s))
        tn = len(safe) - fp
        row = {"rule_id": rid, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
               "precision": _prec(tp, fp), "recall": _recall(tp, fn)}
        rows.append(row)
        for k in totals:
            totals[k] += row[k]
        agg_key = rid.split("-")[0] if "-" in rid else rid
        aggregated.setdefault(agg_key, {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
        for k in totals:
            aggregated[agg_key][k] += row[k]

    return {
        "cases": len(cases),
        "total_samples": totals["tp"] + totals["fp"] + totals["fn"] + totals["tn"],
        "total": totals,
        "aggregate_precision": _prec(totals["tp"], totals["fp"]),
        "aggregate_recall": _recall(totals["tp"], totals["fn"]),
        "rows": rows,
        "by_prefix": aggregated,
    }


def _prec(tp: int, fp: int) -> float:
    return round(tp / (tp + fp), 3) if (tp + fp) else 0.0


def _recall(tp: int, fn: int) -> float:
    return round(tp / (tp + fn), 3) if (tp + fn) else 0.0


def _load_from(cases_dir: str) -> dict:
    import yaml

    cases: dict[str, dict] = {}
    root = Path(cases_dir)
    for yml in root.rglob("*.yml"):
        data = yaml.safe_load(yml.read_text(encoding="utf-8")) or {}
        for entry in data.get("cases", []):
            rid = entry.get("rule_id", "")
            if not rid:
                continue
            cases.setdefault(rid, {"vulnerable": [], "safe": []})
            cases[rid]["vulnerable"].extend(entry.get("vulnerable", []) or [])
            cases[rid]["safe"].extend(entry.get("safe", []) or [])
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
    return "\n".join(out)