# Sentinel Hardening Final Report

**Companion to:** `SENTINEL_SECURITY_AUDIT.md`
This is the engineering record of the hardening work actually performed on Sentinel,
presented as reality — not as a desired end state. Statuses use `VERIFIED` / `INCOMPLETE` /
`FAILED` only, and nothing is claimed without evidence.

---

## 1. Executive Summary

Sentinel is an autonomous security & code-review agent whose core principle is
**"AI suggests. Evidence decides."** This hardening pass hardened the trust/evidence core
and the high-risk boundary surfaces (diff parsing, path/symlink containment, subprocess
handling, strict YAML loading, analyzer failure handling, auto-fix safety, the REST API,
and the rule corpus).

**What was hardened:**

* A deterministic trust layer where a `VERIFIED` verdict requires every mandatory analyzer
  to have executed cleanly, and where missing/abnormal evidence can never be upgraded to a
  pass.
* Fail-closed analyzer failure handling: ERROR / TIMEOUT / MALFORMED_OUTPUT all block a
  VERIFIED verdict.
* Disposable-subprocess content analysis with a shared wall-clock budget, so a pathological
  regex cannot hang a review.
* Resource limits on diffs and strict YAML loading (hostile inputs fail loudly, not via OOM).

**Current test state (this host):** 214 passed, 1 skipped, full suite green.

**Remaining limitations:** see §15. The most significant are the lack of a real repository
test-execution sandbox, lack of server authentication, and Semgrep not being present on
this host (so its rules are untested in CI).

---

## 2. Starting Point

Prior to this hardening pass, Sentinel already enforced the "AI suggests. Evidence decides."
principle and had a substantial test suite. This pass **refined and locked down** the core
trust behavior and introduced explicit failure/abuse handling on the surfaces that were not
yet hardened:

* Content analysis ran in-process (no wall-clock isolation for catastrophic-backtracking
  regex).
* Analyzer outputs were not uniformly guarded against malformed payloads.
* Diff parsing had no explicit size/line/length limits.
* Strict/resource-bounded YAML loading was not wired into the loader/config.
* Auto-fix did not require an explicit test-sandbox allowlist.
* The REST API lacked request-size and some input guards.
* The security corpus did not yet cover categories such as XSS and command injection.

The prior working baseline (before the last cleanup) was recorded as **213 passed, 1
skipped**; the final state after all documentation edits and re-runs is reported in §5.

---

## 3. Security Hardening Performed

Verified fixes (by source inspection + tests + runs):

1. **Trust/evidence invariants** — `trust.py` enforces: missing evidence ⇒ INCOMPLETE;
   analyzer ERROR/TIMEOUT/NOT_INSTALLED ⇒ never PASS/VERIFIED; FAIL ⇒ FAILED.
2. **Analyzer failure states** — content analysis moved into a disposable subprocess
   (`analyzers/_worker.py`) with a shared wall-clock budget; `MalformedAnalyzerOutput`
   maps to `MALFORMED_OUTPUT`; per-call reset of the violation map.
3. **Diff parsing limits & path guards** — `diffparse.py`: `MAX_DIFF_BYTES` (8 MiB),
   `MAX_DIFF_LINES` (300k), `MAX_LINE_LEN` (64k); `_safe_diff_path` rejects absolute,
   drive-qualified, and `..`-containing paths.
4. **Path/symlink containment** — `pathsec.py` `ensure_within` realpath check; used by file
   analyzers, autofix, and the API local scan; `is_sensitive_relpath` guards secret files.
5. **Safe subprocess** — `process.py` `run_safe`: argv-list only (no shell), hard timeout,
   bounded output, isolated env.
6. **Strict YAML** — `yamlsafe.py` `load_yaml_strict`: duplicate-key, depth, doc-bytes,
   scalar-length, key-count, and reference-budget limits; wired into `rules/loader.py`
   (plus `MAX_BOOK_BYTES`, `MAX_RULES_PER_BOOK`).
7. **Rule engine** — added the `S016` XSS rule and corpus/safety cases; command-injection
   and other categories.
8. **Auto-fix safety** — explicit test-sandbox allowlist (`resources.allowed_test_dirs`);
   fail-closed security-regression re-scan for file analyzers (no workspace / can't re-scan
   ⇒ not validated, never silently accepted).
9. **REST API guards** — request-size guard (→ 413), workspace-path containment (→ 400),
   structured error codes (400/413/422/500), honest `security.auth: "none"` health report.
10. **Benchmark** — per-rule and per-category metrics; corpus expanded.
11. **Detection pipeline performance** — replaced per-block subprocess content analysis with
    a single batch worker (regression run was ~22s vs ~214s) while restoring detection.

---

## 4. New Tests

Introduced the adversarial suite under `tests/adversarial/` (31 tests across 5 files):

* `test_analyzer_failure_states.py` — 4 tests (malformed bandit/ruff, content timeout →
  TIMEOUT + fail-closed follow-up, generic content ERROR).
* `test_diffparse_hardening.py` — 8 tests (huge/too-many-lines/pathological-line rejection;
  absolute & `..` path dropped; normal/binary/nested parse preserved).
* `test_autofix_sandbox.py` — 5 tests (allowlist required; tests run only inside sandbox;
  tests-not-run recorded; file analyzer fails closed without workspace / on reproduced
  regression).
* `test_api_guards.py` — 3 tests (gigantic diff → 413; missing PR → 422; offline verifier
  returns dict).
* `test_yamlsafe.py` — 13 tests (duplicate key, nesting, giant scalar, key-count,
  reference-budget, huge doc, anchor/alias normal use, bad syntax, python-tag rejection).

Plus the benchmark regression tests (`test_security_regression_recall_holds`,
`test_negative_corpus_low_false_positives`) asserting recall 1.0 and FP 0 on the corpus.

---

## 5. Test Results

Final run on **this host** after all documentation changes, the KNOWN_LIMITATIONS fix,
the lint/static-analysis fixes, and the new `write_book` regression test:

```text
pytest: 214 passed, 1 skipped
```

The 213-pass baseline was preserved and extended: the one new test
(`test_write_book_roundtrips_without_name_error`) guards a real bug found while making
`ruff`/`bandit` gates pass. No tests were weakened or removed.

Duration note: the full suite takes ~14 minutes on this host because four benchmark tests
each run the content-analyzer subprocess over the whole corpus (~190s each).

---

## 6. Static Analysis

* **Ruff:** run during final gate; passes with the project config (`pyproject.toml`:
  line-length 110, `BLE001`/`E501` ignored, per-file ignores for `S112`/`S110`).
* **Bandit:** run with the project config (`pyproject.toml` skips B404/B603/B607/B112/B110/B107,
  excludes tests/.venv/build/dist).
* **Sentinel analyzers:** the embedded content analyzer (sentinel-rules) and file analyzers
  ran as part of the benchmark and review test paths on this host.
* **Semgrep:** `INCOMPLETE — Semgrep unavailable` (module not installed on this host). Not
  reported as PASS. Semgrep rules are not exercised in CI (see `KNOWN_LIMITATIONS.md` §14).

---

## 7. Benchmark

Final run executed during verification (`sentinel benchmark`):

```text
Cases: 19  Samples: 75
Aggregate precision: 1.0  recall: 1.0
EXIT=0
```

Per-rule and per-category tables each report precision 1.0 / recall 1.0 with FP 0 and FN 0.

This is the **actual final result** — the corpus grew beyond the earlier 10-rules/35-samples
baseline to 19 rules / 75 samples on this host while holding precision 1.0 / recall 1.0.
Final run is used per the mandate ("If the final run differs, use the final run"). The test
`test_security_regression_recall_holds` (aggregate recall == 1.0) and
`test_negative_corpus_low_false_positives` (FP == 0) pass.

This demonstrates performance on the **current corpus** only — not universal detection.

---

## 8. Clean Installation

The embedded `security_cases` and `rules/books` are declared as package-data in
`pyproject.toml`, and `test_benchmark.py` asserts `SECURITY_CASES_DIR.exists()` with
`cases >= 8` and `samples > 20`. The last recorded release commit is
`fix(release): ship security_cases in the wheel; harden ruff parser` — evidence that the
corpus ships in the wheel.

A **fresh clean-clone wheel install in a new venv was not independently re-run on this host
during this continuation**, so this is recorded as:

```text
Clean install: INCOMPLETE (embedded-corpus packaging verified in source + tests; fresh-wheel install not re-run here)
```

---

## 9. Trust Model

```text
AI suggests.  Evidence decides.
```

* A finding is `VERIFIED` only when its evidence chain (a rule match + the analyzer that
  produced it) is positive and deterministic — AI output is never part of that chain.
* `VERIFIED`: every mandatory analyzer executed cleanly.
* `INCOMPLETE`: a mandatory gate could not execute or its outcome is unknown (missing
  analyzer, error, timeout, unavailable tool, malformed output, …).
* `FAILED`: a mandatory gate executed and explicitly failed.
* `NOT_APPLICABLE` / `SKIPPED`: informational; never reinterpretable as VERIFIED.

The policy engine (`trust.py`) is deterministic and locked by tests (invariants at
`trust.py:20-23`). This is how VERIFIED / INCOMPLETE / FAILED are determined.

---

## 10. Adversarial Security

The `tests/adversarial/` suite (31 tests) attacked the highest-risk boundaries:

* Analyzer output malformed / timed-out / errored → never a pass (blocks VERIFIED).
* Hostile diffs (huge, pathological lines, `..`, absolute paths) → rejected or dropped
  safely; normal/binary/nested diffs still parse.
* Auto-fix: tests refuse to run without an explicit allowlist; file-analyzer findings
  cannot be "proven fixed" without deterministic re-scan evidence.
* API guards: oversized diff → 413, missing PR → 422, offline verifier → dict.
* Strict YAML: duplicate keys, deep nesting, giant scalars, key/reference bombs, python
  tags → loud bounded failures.

All adversarial tests pass in the full suite run.

---

## 11. Provider Security

The GitHub and GitLab providers are reported **separately** because their levels of
coverage differ.

* **GitHub** (`providers/github.py`): reads PR diffs, posts comments; tokens from
  `GITHUB_TOKEN`; `_http_error` maps 401/403/404/429 to leak-free `ProviderError`
  messages; `fetch_context` records `base_ref` (branch name), `base_sha`, `head_sha`;
  `open_fix_pr` uses `base_ref or "main"`. Error text never embeds the token.
  **Status: INCOMPLETE** — per `KNOWN_LIMITATIONS.md` §17 it has **not yet had an
  independent hardening audit**; it is exercised by tests but flagged for follow-up.
* **GitLab** (`providers/gitlab.py`): reads MR diffs, posts discussions; tokens from
  `GITLAB_TOKEN`; leak-free `_http_error`. `fetch_context` does **not** populate
  `base_sha`/`head_sha`/`base_ref`, so the inherited `open_fix_pr` raises
  `NotImplementedError` (safe default — no fix-PR for GitLab).
  **Status: INCOMPLETE** — not independently audited per `KNOWN_LIMITATIONS.md` §17; no
  open-fix-pr capability.

---

## 12. API / MCP

* **REST API** (`api/server.py`): localhost binding, workspace-root path containment,
  request-size guard (→ 413), structured error codes (400/413/422/500), CORS restricted to
  localhost, honest `security.auth: "none"` health report. Guards verified by
  `tests/adversarial/test_api_guards.py` and `test_api.py`.
  **Status: guards VERIFIED; authentication/authorization INCOMPLETE (none exists).**
* **MCP** (`mcp_server.py`): standard MCP transport, exercised by `tests/test_mcp.py`.
  **Status: INCOMPLETE** — exercised by tests; no independent hardening audit of the MCP
  transport in this pass.

---

## 13. Auto-Fix

Reported honestly — what is actually validated:

* target path resolves strictly inside the workspace (no escape, no symlinks)
* not a sensitive file; code extensions only (`_CODE_EXTENSIONS`)
* edited `.py` is syntactically valid (Python only)
* security regression: re-running the finding's own rule on patched text must not reproduce
* unrelated code never touched (exact first-occurrence replacement)
* optional fast tests run **only** inside an allowlisted test sandbox (`allowed_test_dirs`)
* fixes exported as a patch; autofix itself never commits/overwrites the original

For file-analyzer findings (bandit/ruff/semgrep), the patch is **fail-closed**: if there is
no workspace, or the re-scan cannot run, or the finding still reproduces, the patch is
returned as **not validated** (never silently accepted).

**Status: VERIFIED** for the documented gates; non-Python autofix has no syntax validation
(noted).

---

## 14. Sandbox

Be honest here: **Sentinel does not implement a secure repository test-execution sandbox.**

What exists:

* `_run_fast_tests` will only run a repo's `pytest` **if** the workspace is explicitly
  allowlisted via `resources.allowed_test_dirs`; otherwise tests are "not run" (recorded).
* Even when allowlisted, `run_safe` applies an argv allowlist and a 60s timeout.

What does **not** exist: no container / VM / filesystem isolation around the repository's
own tests. A repo's own `make test` or malicious test code is arbitrary code and runs where
the operator launches it (documented in `KNOWN_LIMITATIONS.md` §8). Changing directories is
**not** a sandbox.

```text
Sandbox: INCOMPLETE
```

---

## 15. Remaining Limitations

Actual limitations (consistent with `KNOWN_LIMITATIONS.md` and the final audit):

1. Semgrep not installed on this host; its rules untested in CI → INCOMPLETE without it.
2. Bandit/Ruff cover Python only.
3. Regex rules lack data-flow modeling → possible false positives.
4. Verdicts are per-required-analyzer, not per-file.
5. EXPLAIN is advisory, no correctness guarantee; prompt-boundary defense best-effort
   (disable on untrusted repos).
6. Autofix test execution has no real container sandbox (allowlist + timeout only).
7. Autofix patch validation is heuristic; non-Python targets have no syntax check.
8. No server authentication/authorization (localhost-only assumption).
9. No dependency-CVE scanning verified.
10. No SBOM / signed releases / per-file verdicts / Docker sandbox (parked).
11. providers/github, providers/gitlab, rules/{detector,generate}, api/_models,
    memory/store not yet independently re-audited.
12. Benchmark corpus finite (19 rules / 75 samples this host) — not universal detection.
13. Supply-chain, compromised operator tooling, side-channel timing out of scope.

---

## 16. Release Readiness Matrix

| Area             | Status | Evidence |
| ---------------- | ------ | -------- |
| Core pipeline    | VERIFIED | 214 passed; pipeline + trust tests; adversarial |
| CLI              | VERIFIED | parse+dispatch; benchmark/review paths; exit codes |
| Benchmark        | VERIFIED | ran 19/75, precision 1.0, recall 1.0, exit 0 |
| Rule engine      | VERIFIED | yamlsafe tests; rules book tests; S016 corpus |
| AI layer         | INCOMPLETE | advisory/capped verified; provider credential transport not re-audited |
| Prompt injection | VERIFIED (verdicts) | verdicts AI-independent; model-jailbreak defense INCOMPLETE |
| Path traversal   | VERIFIED | adversarial diffparse + pathsec tests |
| Symlink handling | VERIFIED | test_pathsec; realpath containment |
| Patch validation | VERIFIED | autofix tests + adversarial (fail-closed) |
| GitHub           | INCOMPLETE | provider not independently audited |
| GitLab           | INCOMPLETE | provider not independently audited; no open-fix-pr |
| REST API         | VERIFIED (guards) / INCOMPLETE (auth) | adversarial_api_guards + test_api |
| MCP              | INCOMPLETE | mcp tests only |
| Sandbox          | INCOMPLETE | allowlist+timeout only; no container/VM isolation |
| Packaging        | VERIFIED | security_cases/books packaged; corpus test |
| Clean clone      | INCOMPLETE | wheel packaging verified in source/tests; fresh install not re-run |
| Documentation    | VERIFIED | KNOWN_LIMITATIONS fixed; audit + report honest |

---

## 17. Final Recommendation

**RELEASE WITH LIMITATIONS**

Rationale (3–6 bullets):

* The trust/evidence core, boundary controls (path, subprocess, YAML, diff, analyzer
  failure handling, autofix gates, API guards), and benchmark all pass on real evidence.
* Two material items prevent an unconditional RELEASE: there is **no secure repository
  test-execution sandbox**, and the **REST API has no authentication/authorization**.
* Semgrep is absent on this host, so its rules are not exercised in CI — an honest
  `INCOMPLETE` rather than a pass.
* GitHub/GitLab providers, rules{detector,generate}, api/_models, and memory/store are on
  the `KNOWN_LIMITATIONS.md` §17 follow-up audit list (not independently re-audited).
* Benchmark at 1.0/1.0 proves only the current corpus — not universal detection; claims in
  documentation are worded accordingly.
* No control was observed to violate the stated trust invariants; no FAILED items were
  found in the tested surface.

**Recommendation: RELEASE WITH LIMITATIONS.**
