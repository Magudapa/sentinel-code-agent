"""Benchmark regression tests — rule quality must never silently degrade."""

from __future__ import annotations

from sentinel.benchmark import SECURITY_CASES_DIR, format_benchmark, run_benchmark


def test_benchmark_runs_against_embedded_corpus():
    assert SECURITY_CASES_DIR.exists(), SECURITY_CASES_DIR
    result = run_benchmark()
    assert result["cases"] >= 8
    assert result["total_samples"] > 20


def test_security_regression_recall_holds():
    result = run_benchmark()
    # vulnerable samples MUST be caught (recall 1.0) — a regression here means
    # a rule stopped firing and this test fails loudly.
    assert result["aggregate_recall"] == 1.0, result["total"]


def test_zero_case_empty_corpus_is_safe(tmp_path):
    result = run_benchmark(str(tmp_path))
    assert result["cases"] == 0
    assert result["total"]["tp"] == 0


def test_format_benchmark_prints_rows():
    result = run_benchmark()
    text = format_benchmark(result)
    assert "precision" in text
    assert "recall" in text


def test_negative_corpus_low_false_positives():
    result = run_benchmark()
    # clean samples must not trigger their target rules (FP == 0) for the
    # safety cases; a false positive is a noise regression.
    assert result["total"]["fp"] == 0, result["rows"]