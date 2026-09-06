# Sentinel Security Audit

**Companion to:** `SENTINEL_HARDENING_FINAL_REPORT.md`
**Evidence basis:** source inspection + test results + benchmark + analyzer execution on this host.
**Status scale:** `VERIFIED` (sufficient evidence) · `INCOMPLETE` (not independently verified / partial) · `FAILED` (a control did not hold).

This audit records what was **actually** verified. A requirement is only `VERIFIED` when there is reproducible evidence. Anything not proven is marked `INCOMPLETE`, never upgraded to a pass.

---

## 1. Executive Summary

Sentinel is an autonomous security & code-review agent. Its central design principle is
**"AI suggests. Evidence decides."** — no finding is `VERIFIED` without deterministic
evidence (a rule match + an analyzer that executed cleanly), and AI explanations are
advisory only.

This hardening pass delivered:

* Deterministic trust/evidence layer with strict invariants (`trust.py`).
* Fail-closed analyzer failure handling (ERROR / TIMEOUT / MALFORMED_OUTPUT can never yield VERIFIED).
* Disposable-subprocess content analysis with a shared wall-clock budget (ReDoS/hang containment).
* Path-traversal and symlink containment (`pathsec.py`, `diffparse.py` hardening).
* Safe subprocess wrapper (argv-list only, timeouts, bounded output, isolated env).
* Strict, resource-bounded YAML loading (hostile rulebooks/config cannot DoS).
* Auto-fix safety gates incl. fail-closed security-regression re-scan and test-sandbox allowlist.
* REST API request-size / path-containment guards; honest "no auth" reporting.
* Expanded security corpus (19 rules / 75 samples on this host) at precision 1.0 / recall 1.0.

**Test baseline on this host:** 214 passed, 1 skipped (see Final Report §5).

**Primary residual limitation:** no secure repository *test-execution* sandbox and no
server authentication/authorization. These are explicitly `INCOMPLETE`, not claimed.

---

## 2. Scope

**In scope:**

* Core pipeline (`pipeline.py`), trust/evidence layer (`trust.py`), models.
* Analyzer framework + bundled analyzers + content subprocess worker.
* Diff parsing, path containment, subprocess handling.
* Auto-fix / patch validation.
* Rule engine (definitions, loader, detector, verifier) + strict YAML loader.
* REST API, CLI, MCP surface (design & guards), providers (GitHub / GitLab / local).
* Benchmark + adversarial + regression test suites.
* Packaging (wheel includes security_cases).

**Out of scope (documented elsewhere / parked):** malicious model weights and tampered
lockfiles, compromised operator tooling, side-channel timing on untrusted API networks.

---

## 3. Architecture Reviewed

Verified against source:

* **`sentinel/pipeline.py`** — Reviewer stages: diff→changesets, content analyzers, file
  analyzers, memory recall, LLM explanation (advisory, capped), ranking, trust verdict.
* **`sentinel/trust.py`** — central evidence & verdict policy.
* **`sentinel/analyzers/`** — content (custom/sentinel-rules) + file (bandit/ruff/semgrep).
* **`sentinel/analyzers/_worker.py`** — bounded content subprocess.
* **`sentinel/diffparse.py`, `pathsec.py`, `process.py`** — parsing/path/subprocess guards.
* **`sentinel/autofix.py`** — patch safety gates.
* **`sentinel/rules/`** (loader/detector/defs/verify), **`sentinel/yamlsafe.py`**.
* **`sentinel/api/server.py`, `_models.py`**, **`sentinel/cli.py`**, **`sentinel/mcp_server.py`**.
* **`sentinel/providers/`** (base/github/gitlab/local), **`sentinel/config.py`**, **`sentinel/model.py`**.
* **`sentinel/trust.py`, `sentinel/redact.py`, `sentinel/memory/`**.

SKIPPED for independent re-audit (exercised by tests, flagged in `KNOWN_LIMITATIONS.md`):
`providers/github.py`, `providers/gitlab.py`, `rules/{detector,generate}.py`,
`api/_models.py`, `memory/store.py`.

---

## 4. Security Objectives

| Objective | Status |
|-----------|--------|
| AI cannot set a verdict | VERIFIED |
| Missing evidence ⇒ INCOMPLETE (never VERIFIED) | VERIFIED |
| Analyzer crash/hang/malformed output never reads as PASS | VERIFIED |
| No path traversal out of workspace | VERIFIED |
| No symlink escape out of workspace | VERIFIED |
| No shell/command injection via subprocess | VERIFIED |
| Secrets never echoed in reports | VERIFIED (see §14) |
| Hostile diffs/rulebooks/config cannot DoS the host | VERIFIED |
| Auto-fix cannot edit outside a whitelist or escape the workspace | VERIFIED |
| Repo tests only run in an explicit sandbox allowlist | VERIFIED (code) / see §14 sandbox INCOMPLETE |
| API cannot be called without binding localhost | VERIFIED |
| API authentication/authorization | INCOMPLETE (none exists) |
| Secure repo test-isolation sandbox (real container/etc.) | INCOMPLETE |

---

## 5. Threat Model

Reference: `SENTINEL_THREAT_MODEL.md`. Primary threats considered (consistent with
`KNOWN_LIMITATIONS.md` §"Threats not in scope"):

* Hostile repository content (rules, diffs, code, YAML) attempting DoS, path escape,
  command injection, prompt injection, or misleading Sentinel into a false pass.
* Malicious PR / MR reviewed by an operator running Sentinel locally or via API.
* A compromised or malicious external analyzer producing garbage output.
* Untrusted network for provider/API calls.

---

## 6. Trust Model

```
AI suggests. Evidence decides.
```

* `Verdict` is produced by the deterministic policy engine in `trust.py`, never by AI
  and never from free-form strings.
* `Verdict`: `VERIFIED` (all mandatory gates passed), `INCOMPLETE` (a gate could not
  execute / outcome unknown), `FAILED` (a gate explicitly failed), plus
  `NOT_APPLICABLE` / `SKIPPED` (informational; never reinterpretable as VERIFIED).
* Enforced invariants (locked by tests):
  1. missing evidence can never produce VERIFIED
  2. analyzer ERROR / TIMEOUT / NOT_INSTALLED can never produce PASS or VERIFIED
  3. a FAIL evidence item always makes the verdict FAILED

**Status: VERIFIED.** The policy engine is deterministic and tested
(`tests/test_trust.py`, adversarial analyzer-failure tests).

---

## 7. Attack Surface

* CLI (`sentinel review|benchmark|ruleset|serve|fix-export|fix-pr` …).
* REST API (`/api/v1/health`, `/api/v1/rulesets`, `/api/v1/rulesets/verify`, `/api/v1/review`).
* MCP server.
* Providers (GitHub / GitLab network calls).
* Analyzer subprocesses (custom worker, bandit, ruff, semgrep when present).
* Rulebook / config / security-case YAML loading.
* Diff parsing from PRs / MRs / API bodies.

---

## 8. CLI Security

Evidence:

* `cli.py` routes every command through a small parser; benchmark and other subcommands
  return an exit code and print errors to stderr.
* The `serve` subcommand binds localhost by default (see §27).

Tests: CLI exercised via `test_pipeline.py`, `test_api.py`, and the benchmark.

Current Protection: parse + explicit command dispatch; errors surfaced, not swallowed.

Remaining Risk: none material observed on the reviewed path.

**Status: VERIFIED** (for the reviewed review/benchmark/serve paths; the MCP/CLI
interaction is covered under §28).

---

## 9. Workspace Isolation

Evidence:

* `api/server.py` resolves a `workspace_root` (explicit arg, `SENTINEL_WORKSPACE`, or cwd)
  and rejects any local `path` outside it (HTTP 400) — `server.py:153-155`.
* `pipeline.py` only runs file analyzers on files that pass `is_within(working_dir, f)`
  and are not absolute (`pipeline.py:131-138`).
* `pathsec.ensure_within` performs a realpath resolution so symlink tricks cannot escape.

Tests: `tests/test_pathsec.py`; `test_api.py::test_review_local_workspace`;
`tests/adversarial/test_api_guards.py` (path-outside-workspace returns 400).

Current Protection: realpath-containment for file analyzers and API local scans.

Remaining Risk: the API binds localhost with **no authentication**; a local process that
can reach the port can submit a review (see §27). Containment is per-request, not
per-authenticated-user.

**Status: VERIFIED** (workspace path containment); auth is separately INCOMPLETE.

---

## 10. Path Traversal

Evidence:

* `diffparse.py` defines `_safe_diff_path` rejecting absolute, drive-qualified, and
  `..`-containing paths; `_ABS_PATH` and `_TRAVERSAL_SEG` regexes.
* `pathsec.ensure_within` / `resolve_within` / `is_within` enforce strict containment via
  realpath.
* `autofix._resolve_target` uses `ensure_within` and refuses sensitive/non-code paths.

Tests:
* `test_diffparse_hardening.py::test_absolute_path_in_diff_header_dropped`
* `test_diffparse_hardening.py::test_dotdot_path_in_diff_header_dropped`
* `test_diffparse_hardening.py::test_nested_subdir_path_kept_relative`
* `test_pathsec.py`, `test_autofix_safety.py`
* `test_api_guards.py::test_review_outside_workspace_rejected` (400)

Current Protection: diff-header path rejection + realpath-based containment at every
filesystem-using boundary (file analyzers, autofix, API local scan).

Remaining Risk: normalization correctness depends on test coverage; no fuzzing or
property-based testing of the path parser was performed.

**Status: VERIFIED** (crafted hostile inputs handled; adversarial tests green).

---

## 11. Symlink Handling

Evidence: `pathsec.ensure_within` resolves the candidate with `.resolve()` and compares the
realpath against the realpath of the root; a symlink pointing outside the root therefore
fails containment (raises `PathEscapeError`).

Tests: `tests/test_pathsec.py` covers symlink-escape rejection.

Current Protection: realpath-based containment in pathsec and autofix.

Remaining Risk: none material observed; relies on `Path.resolve()` (non-strict) semantics on
the host platform.

**Status: VERIFIED.**

---

## 12. Subprocess Security

Evidence: `process.run_safe` (`process.py`):

* argv **lists only** — string/bytes argv raises `CommandSafetyError` (no `shell=True`).
* hard timeout on every invocation; `TimeoutExpired` becomes a `timed_out` result (no hang).
* bounded output capture (default 1MB/stream, clip).
* isolated environment: only `ENV_ALLOWLIST` variables pass through; secrets must be
  passed explicitly via `extra_env` for the tool that needs them.
* `cwd` validated to exist.

Tests: `tests/test_process.py` (CommandSafetyError on string argv, missing cwd, timeouts,
env isolation); adversarial analyzer-timeout test.

Current Protection: no shell interpretation path; bounded resource use; minimal env.

Remaining Risk: allowlist includes `PYTHON*`/`OLLAMA_*`/site-config vars which are machine
paths, not secrets — reviewed as acceptable, but a future dependency could read more from
env than intended.

**Status: VERIFIED.**

---

## 13. Command Injection

Evidence: subprocess invocations pass argv lists only; the codebase does not construct
shell command strings for execution. `shell_split` exists solely for display/logging and
is never executed. Diff paths are passed as separate argv elements (never concatenated into
a shell string) and are validated by `_safe_diff_path` before being used.

Tests: `tests/test_process.py`; adversarial analyzer-worker tests.

Current Protection: list-based subprocess + path validation + no shell interpreter.

Remaining Risk: no residual until a future code path uses `shell=True` (none found in this
audit).

**Status: VERIFIED.**

---

## 14. Secret Handling

Evidence:

* `redact.py` and the report pipeline never emit token *values* (recorded in
  `KNOWN_LIMITATIONS.md` item 3).
* Provider tokens are read from env (`GITHUB_TOKEN`, `GITLAB_TOKEN`) and passed as HTTP
  headers only; they are never embedded in diff/finding text.
* `autofix._resolve_target` refuses sensitive paths (`.git`, `.env`, credentials, keys).
* `pathsec.is_sensitive_relpath` flags `.env`, secret/credential segments, and key suffixes.
* No `.env` file or committed credentials exist in the repo (`git status` confirmed none).

Tests: `tests/test_redaction.py`; `test_autofix_safety.py`.

Current Protection: token values redacted from output; sensitive files never modified by
autofix; secret-bearing paths not emitted.

Remaining Risk: token values could appear in finding text if the *reviewed code itself*
contains a hardcoded secret — that is a legitimate finding, and redaction is tested for the
report path. Scope of redaction is the report/evidence emission, not the input code.

**Status: VERIFIED** (for report/evidence redaction and sensitive-path refusal).

---

## 15. Prompt Injection

Evidence:

* AI explanations are advisory only and never set verdicts (`pipeline.py:_explain`,
  trust policy) — a hostile repo's injected instructions cannot force a false PASS.
* Repository text is treated as *data*; attempts to jailbreak the model remain "best-effort"
  (documented honestly in `KNOWN_LIMITATIONS.md` item 7).

Tests: `test_pipeline.py::test_explain_does_not_affect_verdict` (and related).

Current Protection: verdicts are AI-independent; injection cannot change them.

Remaining Risk: **model prompt-boundary defense is best-effort, not an airtight sandbox.**
`KNOWN_LIMITATIONS.md` explicitly recommends disabling `explain` for untrusted repos.

**Status: VERIFIED** (verdicts immune to prompt injection); full model-jailbreak defense
**INCOMPLETE** (best-effort only).

---

## 16. AI Provider Security

Evidence: `model.py` is exercised by tests; the API surface reports `advisory_only` in
`verification.ai` (`pipeline.py:104-117`). Explanations are capped
(`_MAX_EXPLANATIONS`, `_AI_TIME_SECONDS`) so a slow/model partner cannot hang a review.

Tests: pipeline tests cover explanation skip on offline model and advisory nature.

Current Protection: advisory, capped, offline-tolerant.

Remaining Risk: verified model/provider reachability and secret handling of API keys was not
independently re-audited in this pass (uses local/env config). Marked accordingly.

**Status: INCOMPLETE** (advisory/capping verified; provider credential transport not
independently re-verified here).

---

## 17. Analyzer Security

Evidence:

* Analyzers split into deterministic content analyzers (no disk) and file analyzers
  (bandit/ruff/semgrep).
* `analyze_changesets_full` runs content analyzers in a **disposable subprocess**
  (`analyzers._worker`) with a single shared wall-clock budget (`CONTENT_TIMEOUT=60`), so a
  pathological regex cannot hang the review.
* Every analyzer returns a status-map entry: PASS / ERROR / TIMEOUT / NOT_INSTALLED /
  MALFORMED_OUTPUT / SKIPPED / MISSING.
* `MalformedAnalyzerOutput` maps to `EvidenceStatus.MALFORMED_OUTPUT` — never a pass.

Tests: adversarial `test_analyzer_failure_states.py` (5 tests: bandit malformed, content
timeout → TIMEOUT + fail-closed follow-up, ruff malformed, generic content ERROR).

Current Protection: subprocess isolation + wall-clock budget + explicit status semantics.

Remaining Risk: a file analyzer (bandit/ruff) with a pathological input would be bounded by
`analyze_files_full`'s per-analyzer timeout, but file analyzers are external tools; their
internal resource behavior is not fully under Sentinel's control (bounded by the timeout).

**Status: VERIFIED** (content phase); file-analyzer subset behavior bounded by timeout.

---

## 18. Rule Engine Security

Evidence:

* `yamlsafe.load_yaml_strict` enforces: duplicate-key rejection, max nesting depth, max
  document bytes, max scalar length, max keys, and a reference budget (alias/billion-laughs
  containment).
* `rules/loader.py` applies `MAX_BOOK_BYTES` and `MAX_RULES_PER_BOOK`, requires required
  fields, and skips malformed books with a **visible** warning (never silent).
* Rules are regex-based and run inside the disposable content worker (bounded).
* The new `S016` XSS rule was added and covered by corpus/safety cases.

Tests: adversarial `test_yamlsafe.py` (13 tests incl. duplicate key, deep nesting, giant
scalar, too-many-keys, reference-budget, huge-document, bad-syntax, python-tag rejection);
`test_rules_book.py`.

Current Protection: strict bounded loading; regex scanning bounded by the worker; malformed
book isolation.

Remaining Risk: regex rules cannot model data flow (documented, `KNOWN_LIMITATIONS.md` §3-4);
false positives remain possible; the bench corpus is finite.

**Status: VERIFIED** (loading/resource restrictions + bounded execution); data-flow
limitations are documented, not a defect of the guards.

---

## 19. Regex / ReDoS Considerations

Evidence:

* Content rules run regex scanning inside a bounded subprocess with a wall-clock budget; a
  catastrophic-backtracking rule times out and is recorded as TIMEOUT (never a silent pass).
* `KNOWN_LIMITATIONS.md` §3-4 note regex limits (no data-flow modeling).
* Diff-size / line-length limits prevent a giant input from amplifying scan cost.

Tests: adversarial content-timeout test; diffparse resource-limit tests.

Current Protection: process isolation + budget + input-size limits.

Remaining Risk: no per-rule static ReDoS analysis is performed; protection is operational
(timeout), not proof that no rule can backtrack badly.

**Status: VERIFIED** (operational containment verified); static ReDoS audit **INCOMPLETE**.

---

## 20. Rule Verification Gates

Evidence:

* `rules/defs.py`, `rules/verify.py` implement an `ai_verified` gate: a rule is marked
  `ai_verified: true` **only by the verifier**, never by hand (`loader.write_book` header /
  `KNOWN_LIMITATIONS` / `api/server.py` uses `rule.ai_verified`).
* The API `/api/v1/rulesets/verify` reports `model_available`, `ai_used`, and per-rule
  empirical + AI verdicts; the CLI verifier gates rule admission.

Tests: `test_pipeline.py::test_reviewer_offline_still_finds_issues`;
`test_api_guards.py::test_rulesets_verify_no_model_still_returns_dict`; `test_rules_book.py`.

Current Protection: empirical verification before marking `ai_verified`; verifier offline
still returns structured results.

Remaining Risk: the corpus for `rules verify` is at review-scale, not enterprise integration
scale (parked, `KNOWN_LIMITATIONS.md` §62).

**Status: VERIFIED** (admission-gate logic + offline robustness); corpus scale INCOMPLETE.

---

## 21. Patch / Auto-Fix Security

Evidence: `autofix.py` documents and enforces 8 safety gates:
1. target resolves strictly inside the workspace (no escape, no symlinks)
2. not a sensitive file
3. code extensions only (`_CODE_EXTENSIONS`)
4. edited file is syntactically valid Python
5. security regression: re-running the finding's own rule on patched text must not reproduce
6. unrelated code never touched (exact first-occurrence replacement)
7. tests pass **only** inside an allowlisted test sandbox
8. fixes exported as a patch; original file never overwritten by autofix itself

Tests: `tests/test_autofix.py`, `tests/test_autofix_safety.py`,
`tests/adversarial/test_autofix_sandbox.py` (5 tests incl. tests-not-run recorded, file
analyzer fails closed without workspace / on reproduced regression).

Current Protection: layered deterministic + AI-independent gates; fail-closed when proof of
regression-clearance is unavailable.

Remaining Risk: for non-Python extensions, no syntax validation exists (gate 4 only covers
`.py`) — noted. Heuristic validation cannot prove absence of regressions in untested paths
(`KNOWN_LIMITATIONS.md` §9).

**Status: VERIFIED** (for the documented gates); non-Python syntax-validation gap noted.

---

## 22. Generated Code Validation

Evidence: autofix validates generated code by (a) Python syntax check, (b) deterministic
re-scan of the patched text with the finding's own rule (regression must clear), (c) opt-in
fast tests only inside an allowlisted sandbox. Validation is per-patch and AI-independent.

Tests: `test_autofix.py`, `test_autofix_safety.py`, adversarial autofix tests.

Current Protection: syntax + security-regression + opt-in sandboxed tests.

Remaining Risk: for `.js/.ts` no AST syntax check (documented); semantic correctness beyond
"rule no longer reproduces" is not proven.

**Status: VERIFIED** (validation performed); full semantic validation INCOMPLETE.

---

## 23. Verification State Machine

Evidence: `trust.py` implements a deterministic policy engine. `verdict_of` evaluates in
fixed order: FAIL → FAILED; missing required evidence → INCOMPLETE; blockers
(ERROR/TIMEOUT/MALFORMED/NOT_INSTALLED/MISSING/SKIPPED) → INCOMPLETE; all-positive →
VERIFIED. `report_verdict` applies the same rules per-report from the analyzer status map.

Tests: `tests/test_trust.py` (invariant tests), adversarial analyzer-failure tests.

Current Protection: strict monotonic downgrade; no path from missing evidence to VERIFIED.

Remaining Risk: none observed.

**Status: VERIFIED.**

---

## 24. VERIFIED / INCOMPLETE / FAILED Guarantees

Evidence: the three invariants in `trust.py:20-23` are enforced by the policy engine and
locked by tests:

1. missing evidence can never produce VERIFIED
2. analyzer ERROR / TIMEOUT / NOT_INSTALLED can never produce PASS or VERIFIED
3. a FAIL evidence item always makes the verdict FAILED

Tests: `tests/test_trust.py`, `tests/adversarial/test_analyzer_failure_states.py`
(bandit/ruff/content malformed & timeout each assert verdict != VERIFIED).

Current Protection: deterministic policy; guaranteed downgrades.

Remaining Risk: correctness depends on every analyzer surface returning proper status —
guard rails in `analyze_files_full`/`_run_batch_worker` cover this; audits flagged
`rules/{detector,generate}.py` and providers for follow-up.

**Status: VERIFIED.**

---

## 25. GitHub Provider

Evidence:

* Reads PR diffs and posts comments; tokens from `GITHUB_TOKEN`.
* `_http_error` maps 401/403/404/429 to leak-free, actionable `ProviderError` messages
  (token never embedded in the message).
* `fetch_context` records `base_ref` (PR base branch name, not a SHA) and `base_sha`/`head_sha`.
* `open_fix_pr` uses `context.base_ref or "main"` for `base` (no fabricated SHA).
* `create_fix_branch` builds commits/trees via the Git Data API; new_content submitted as
  blobs.
* Errors surface as `ProviderError` (clean), mapped by the API layer to HTTP 400.

Tests: provider is exercised in `test_pipeline.py`/`test_api.py` path as available; the API
guards test validates the missing-pr → 422 and provider-error mapping at the API edge.

Current Protection: token-based auth, leak-free error text, base-ref handling, read-only
default with explicit token for writes.

Remaining Risk: marked in `KNOWN_LIMITATIONS.md` item 17 — `providers/github.py` has **not yet
had an independent hardening audit** in the trust/evidence pass; it is exercised by tests but
flagged for follow-up. Its error messages and open_fix_pr base handling were reviewed here.

**Status: INCOMPLETE** (working + partially reviewed; independent hardening audit still
outstanding per KNOWN_LIMITATIONS).

---

## 26. GitLab Provider

Evidence:

* Reads MR diffs (`/projects/{proj}/merge_requests/{mr}/changes`) and posts discussion
  comments; tokens from `GITLAB_TOKEN`.
* `_http_error` maps 401/403/404/429 to leak-free messages.
* `fetch_context` concatenates per-file diff strings; `base_sha`/`head_sha`/`base_ref` are
  not populated (empty).

Tests: exercised in provider path where available; API guard test covers provider-error
mapping at the API edge.

Current Protection: token-based auth, leak-free error text.

Remaining Risk: **GitLab provider is not independently audited** per `KNOWN_LIMITATIONS.md`
item 17. It does not populate base_ref/base_sha, so open_fix_pr (inherited default raises
NotImplementedError) is not available for GitLab — safe default. Marked for follow-up audit.

**Status: INCOMPLETE** (independent hardening audit outstanding; no open-fix-pr capability).

---

## 27. REST API

Evidence (`api/server.py`):

* Binds localhost by default (no automatic network exposure).
* CORS restricted to `http://localhost`, `http://127.0.0.1`.
* Local scans confined to a configured workspace root (path-outside-workspace → HTTP 400).
* Request-size guard: diff body larger than ~8 MiB × 1.34 → HTTP 413.
* `DiffTooLargeError` → 413; `ProviderError` → 400; unknown provider → 400; missing repo/pr
  → 422; other exceptions → 500 (no raw traceback to client).
* No empty-diff review fabricates status: it returns status from `report.verdict` via
  `_status_for`.
* `/api/v1/health` **explicitly** reports `security.auth: "none"` with a note not to expose
  the server on a network.

Tests: `tests/adversarial/test_api_guards.py` (gigantic diff → 413 by 1.4× base64; missing
PR → 422; rulesets verify offline returns dict), `test_api.py`.

Current Protection: localhost binding + request-size + path-containment + honest no-auth
reporting + structured error codes.

Remaining Risk: **there is no authentication or authorization.** Any process able to reach
the localhost port can submit reviews (with the workspace root it controls). This is
intentional for a localhost tool and documented, but multi-user/auth is parked.

**Status: VERIFIED** (request-size, path-containment, no-fabricated-verdict); auth
**INCOMPLETE**/N/A.

---

## 28. MCP

Evidence: `sentinel/mcp_server.py` exists (`sentinel-mcp` entry point) and exposes review
capabilities over MCP; MCP surface is tested (`tests/test_mcp.py`).

Tests: `tests/test_mcp.py`.

Current Protection: standard MCP transport; no independent network-exposure hardening
certification performed here.

Remaining Risk: not independently re-audited in this pass beyond its tests.

**Status: INCOMPLETE** (exercised by tests; no independent hardening audit of the MCP
transport in this pass).

---

## 29. SARIF Output

Evidence: report/model support SARIF-shaped findings serialization via `Finding.to_dict` /
`ReviewReport.to_dict`. (SARIF-complete schema not independently validated in this pass.)

Tests: exercised through report/serialization tests (`test_api.py`, `test_models.py`).

Current Protection: structured serialization; verdict surfaced via `status`/`verification`.

Remaining Risk: no SARIF-schema conformance test was independently run here.

**Status: INCOMPLETE** (serialization exists; schema conformance not independently verified).

---

## 30. JSON / Markdown Reports

Evidence: `ReviewReport.to_dict`, `Finding.to_dict`, `summary_md` (Markdown), and the API
responses emit machine-readable JSON; redaction applies to report/evidence emission.

Tests: `test_api.py` asserts JSON shape; `test_redaction.py` covers secret redaction;
pipeline tests assert summary includes verdict.

Current Protection: structured output; redaction; verdict honesty.

Remaining Risk: none material observed.

**Status: VERIFIED.**

---

## 31. Input Validation

Evidence:

* Diff size/line/length limits (`diffparse.py`).
* Workspace-path containment (`pathsec.py` + API).
* Strict YAML loading (`yamlsafe.py`).
* Request-size guard and provider/path validation in the API.
* autofix path/extension/sensitive-file gates.

Tests: adversarial diffparse/yamlsafe/api tests; `test_pathsec.py`; config validation tests.

Current Protection: layered input guards at every boundary.

Remaining Risk: none material beyond the documented INCOMPLETE areas.

**Status: VERIFIED.**

---

## 32. Resource Exhaustion / DoS

Evidence:

* Diff: `MAX_DIFF_BYTES`, `MAX_DIFF_LINES`, `MAX_LINE_LEN` → loud `DiffTooLargeError`.
* Content analyzers: disposable subprocess + shared wall-clock budget → TIMEOUT.
* YAML: doc bytes, depth, scalar length, keys, reference budget.
* Rulebooks: `MAX_BOOK_BYTES`, `MAX_RULES_PER_BOOK`.
* Subprocess: timeout + bounded output capture.
* API: request-size guard → 413.

Tests: adversarial diffparse/yamlsafe/analyzer-timeout/api tests.

Current Protection: bounded resource use at every input boundary; fail-loud not OOM/hang.

Remaining Risk: file analyzers are external binaries bounded only by timeout; pathological
internal behavior is not fully controlled (mitigated by timeout). Semgrep absent on this host.

**Status: VERIFIED** (for the input-boundary paths reviewed).

---

## 33. Dependency Security

Evidence: `pyproject.toml` pins minimum versions for core deps (bandit, ruff, requests,
PyYAML) and optional extras. No automated dependency-vulnerability scanning (e.g. Dependabot
/ pip-audit) was observed running in CI on this host.

Tests: none in-repo for dependency CVEs.

Current Protection: version floors; no lockfile CVE gate verified.

Remaining Risk: no dependency-CVE scanning confirmed. Supply-chain vetting of install
artifacts is out of scope per `KNOWN_LIMITATIONS.md` §11-12.

**Status: INCOMPLETE** (dependency CVE scanning not verified).

---

## 34. Package Security

Evidence: `pyproject.toml` ships `security_cases/**/*.yml` and `books/*.yml` as package-data
(so the benchmark/rules work from the installed wheel). The last commit (on record:
`51c5061`) is `fix(release): ship security_cases in the wheel; harden ruff parser`.

Tests: `test_benchmark.py` asserts the embedded corpus exists (`SECURITY_CASES_DIR.exists()`
and `cases >= 8`, `samples > 20`).

Current Protection: embedded corpus packaged; regression test guards it.

Remaining Risk: no signed-release / SBOM gate (parked, `KNOWN_LIMITATIONS.md` §16).

**Status: VERIFIED** (corpus packaged + guarded); SBOM/signed releases INCOMPLETE.

---

## 35. Git Security

Evidence:

* Local provider reads diffs from the repo; diff paths validated by `_safe_diff_path`.
* No `git` command is executed with attacker-influenced shell strings; `run_safe` is list-only.
* Fix-push is an explicit opt-in (`fix-export`/`fix-pr` with user-pushed branch); autofix
  never commits.
* Provider `open_fix_pr` uses base_ref (branch name) not a fabricated SHA.

Tests: local provider path in `test_pipeline.py`/`test_api.py`; API guard tests.

Current Protection: path-validated diffs; no shell string construction; explicit push steps.

Remaining Risk: a malicious `git` binary on PATH is out of scope (supply-chain, `KNOWN_LIMITATIONS` §12).

**Status: VERIFIED** (for the reviewed local-provider path).

---

## 36. Benchmark

Evidence: `sentinel benchmark` (CLI, deterministic, no AI) ran on this host:

```
Cases: 19  Samples: 75
Aggregate precision: 1.0  recall: 1.0
EXIT=0
```

Per-rule and per-category tables each show 1.0 / 1.0 with FP=0, FN=0.

Regression test `test_benchmark.py::test_security_regression_recall_holds` asserts
`aggregate_recall == 1.0`, and `test_negative_corpus_low_false_positives` asserts FP==0.

Current Protection: deterministic corpus guard at 1.0/1.0 on the current corpus.

Remaining Risk: this proves the current 19-rule corpus (75 samples), **not** universal
detection. `KNOWN_LIMITATIONS.md` §15 caps the corpus; expanding it hardens further.
No absolute security guarantee is implied.

**Status: VERIFIED** (benchmark runs, exit 0, 1.0/1.0 on current corpus).

---

## 37. Regression Tests

Evidence: full suite baseline **214 passed, 1 skipped** on this host (the 213-pass baseline
was preserved and extended by a new `write_book` regression test). This includes:
`test_analyzers.py`, `test_analyzer_tuning.py`, `test_api.py`, `test_ast_analyzer.py`,
`test_autofix.py`, `test_autofix_safety.py`, `test_benchmark.py`, `test_config_validation.py`,
`test_diffparse.py`, `test_mcp.py`, `test_memory.py`, `test_models.py`, `test_pathsec.py`,
`test_pipeline.py`, `test_process.py`, `test_redaction.py`, `test_rules_book.py`,
`test_trust.py`, plus the `tests/adversarial/` suite.

Current Protection: broad regression coverage of pipeline, trust, analyzers, autofix,
pathsec, process, redaction, rules, API, MCP.

Remaining Risk: semgrep rules are not exercised (binary absent — `KNOWN_LIMITATIONS` §14);
the audit-flagged modules (providers, rules detector/generate, api/_models, memory/store)
are covered by tests but not independently re-audited.

**Status: VERIFIED** (for the executed suite on this host).

---

## 38. Adversarial Tests

Evidence: `tests/adversarial/` contains 31 tests across 5 files:

* `test_analyzer_failure_states.py` — malformed output / timeout / generic-error → never a pass.
* `test_diffparse_hardening.py` — huge/too-long/pathological diffs rejected; absolute and
  `..` paths dropped; normal/binary/nested diffs still parse.
* `test_autofix_sandbox.py` — tests require allowlist; file analyzer fails closed without
  workspace / on reproduced regression.
* `test_api_guards.py` — gigantic diff → 413; missing PR → 422; offline verifier returns dict.
* `test_yamlsafe.py` — duplicate key, deep nesting, giant scalar, too-many-keys,
  reference-budget, huge document, bad syntax, python-tag rejection.

All green in the full suite run.

Current Protection: hostile-input coverage across the trust-layer, diffparser, yamlsafe,
autofix, and API boundaries.

Remaining Risk: adversarial coverage is not exhaustive (no fuzzing of path parser or regex
corpus beyond documented cases).

**Status: VERIFIED.**

---

## 39. Clean-Clone Verification

Evidence: the last recorded release commit is `fix(release): ship security_cases in the
wheel; harden ruff parser for ruff>=0.5 null-fix JSON`, and `test_benchmark.py` verifies the
embedded corpus is present at runtime. A clean install should therefore have the corpus.

Current Protection: package-data includes security_cases + books; guarded by tests.

Remaining Risk: a **clean install from the wheel in a fresh venv** was not independently
re-run on this host during this continuation. This is recorded honestly.

**Status: INCOMPLETE** (embedded-corpus packaging verified in source + tests; fresh-wheel
install not independently re-executed here).

---

## 40. Self-Review

Evidence: a GitHub Actions self-review workflow exists and reports with `|| true`, uploading
artifacts; it does not gate CI (`KNOWN_LIMITATIONS.md` §18). The report is evidence, not a
merge block.

Current Protection: self-review produces an artifact.

Remaining Risk: because it uses `|| true`, it cannot fail CI on findings — deliberate, but a
finding does not block a merge automatically.

**Status: INCOMPLETE** (workflow exists; not a CI gate; not independently executed here).

---

## 41. Documentation Honesty

Evidence: `KNOWN_LIMITATIONS.md` was corrected this continuation (stale `webapp.py` →
removed; `memory.py` → `memory/store.py`). The threat/security docs (`SENTINEL_THREAT_MODEL.md`,
`SENTINEL_SECURITY_MODEL.md`) are present. This audit and the Final Report use ONLY
VERIFIED / INCOMPLETE / FAILED and never claim 100% security.

Current Protection: honest downgrades over quiet passes; no marketing overclaim.

Remaining Risk: documentation is only as accurate as the last edit; ongoing maintenance required.

**Status: VERIFIED** (audit-status section corrected and consistent).

---

## 42. Remaining Limitations

From `KNOWN_LIMITATIONS.md` (unchanged substance after the 2-line fix):

1. Semgrep requires a local binary; absent here → INCOMPLETE without it.
2. Bandit/Ruff cover Python only.
3. S001–S007, PY-0xx are regex-based; no data-flow modeling → possible FPs.
4. S004 interpolation/concatenation focus only.
5. Verdicts are per-required-analyzer, not per-file.
6. EXPLAIN is advisory with no correctness guarantee.
7. Model prompt-boundary defense is best-effort.
8-10. Autofix runs tests on a scratch copy (allowlisted), validation is heuristic, never commits.
11-13. Supply-chain, compromised operator tooling, side-channel timing out of scope.
14. Semgrep rules not exercised in CI.
15. Benchmark corpus is finite (19 rules / 75 samples on this host).
16. Docker sandbox, serve auth token, per-file verdicts, SBOM/signed releases parked.
17. providers/github, providers/gitlab, rules/{loader,detector,generate}, api/_models,
    memory/store not yet independently re-audited.

**Status: documented (INCOMPLETE where applicable).**

---

## 43. Security Risks Not Yet Fully Mitigated

* **No server authentication/authorization** on the REST API (localhost-only assumption).
* **No secure test-execution sandbox** (see §14 sandbox / §42 §8 — a repo's own `make test`
  is arbitrary code; container isolation parked).
* **No dependency-CVE scanning** verified.
* **Semgrep absent** on this host; semgrep rules untested in CI.
* **Prompt-jailbreak defense best-effort** (disable `explain` on untrusted repos).
* **Non-Python autofix has no syntax validation.**
* **Regex rules lack data-flow modeling** → possible false positives.

**Status: all are INCOMPLETE (or out-of-scope) — none are claimed as mitigated.**

---

## 44. Recommended Future Hardening

1. Container/sandbox for autofix test execution (Docker Phase 5).
2. Auth token / API key for `serve` when multi-user is needed.
3. Dependency-CVE scanning (pip-audit / Dependabot) in CI.
4. Semgrep in CI + a rule verification corpus at integration scale.
5. Per-file verdict computation.
6. Independent hardening audits of providers, rules{detector,generate}, api/_models,
   memory/store (per KNOWN_LIMITATIONS §17).
7. Static ReDoS analysis of regex rules.
8. Syntax validation for non-Python autofix targets.
9. SBOM + signed releases.
10. Fuzz the diff-path parser and rule-regex corpus.

---

## 45. Evidence Matrix

| Area (section) | Status | Evidence |
|----------------|--------|----------|
| 9 Workspace isolation | VERIFIED | pathsec + API guards + tests |
| 10 Path traversal | VERIFIED | adversarial diffparse tests |
| 11 Symlinks | VERIFIED | test_pathsec |
| 12 Subprocess | VERIFIED | process.py + test_process |
| 13 Command injection | VERIFIED | list-only subprocess |
| 14 Secrets | VERIFIED | redaction + sensitive-path refusal |
| 15 Prompt injection (verdicts) | VERIFIED / best-effort model defense | pipeline + trust tests |
| 17 Analyzer security | VERIFIED | adversarial failure tests |
| 18 Rule engine | VERIFIED | yamlsafe tests |
| 19 ReDoS | VERIFIED (operational) / INCOMPLETE (static) | content-timeout tests |
| 21-22 Patch/autofix | VERIFIED | autofix tests + adversarial |
| 23-24 Trust/verdict | VERIFIED | test_trust |
| 25 GitHub | INCOMPLETE | provider not independently audited |
| 26 GitLab | INCOMPLETE | provider not independently audited |
| 27 REST API | VERIFIED (guards) / INCOMPLETE (auth) | adversarial_api_guards |
| 28 MCP | INCOMPLETE | mcp tests only |
| 29 SARIF | INCOMPLETE | no schema conformance test |
| 32 DoS | VERIFIED | diffparse/yamlsafe/timeout tests |
| 33 Dependencies | INCOMPLETE | no CVE scan verified |
| 36 Benchmark | VERIFIED | ran 1.0/1.0 exit 0 |
| 37 Regression | VERIFIED | 214 passed / 1 skipped |
| 38 Adversarial | VERIFIED | 31 tests green |
| 39 Clean clone | INCOMPLETE | not independently re-run here |

---

## 46. Final Security Assessment

Sentinel demonstrates a principled, deterministic trust model where evidence (not AI)
decides, and where missing or abnormal evidence always downgrades rather than falsely
passes. The boundary controls audited here — path containment, subprocess isolation,
strict YAML parsing, diff/dos limits, analyzer failure handling, autofix gates, API guards —
each held under adversarial test.

The system is **not** claimed to be 100% secure. The most significant gap is the absence of
a real repository test-execution sandbox (a repo's own tests can run arbitrary code, only
bounded by allowlist+timeout) and the absence of server authentication. Multiple
out-of-scope and parked items remain.

---

## 47. Release Recommendation

**RELEASE WITH LIMITATIONS** (see Final Report §16-17 for the matrix and rationale).

---

## 48. Audit Conclusion

The audited trust/evidence core and boundary controls are sound and verified by real tests
and runs. The honest state is: strong, principled security on the reviewed core with
clearly-documented, unmitigated limitations (sandbox, auth, semgrep absence, dependency
scanning, provider re-audits). No security control is overstated; every not-proven item is
recorded `INCOMPLETE`.
