# Sentinel Known Limitations

Honest inventory of what Sentinel does **not** do (yet), so operators never mistake
scope for safety. Parked items reference the roadmap/BRD where applicable.

## Analyzer coverage

1. **Semgrep requires a local binary.** `analyzer_status["semgrep"]=NOT_INSTALLED` on
   hosts without it; the default required set then downgrades the verdict to
   `INCOMPLETE` even on clean trees. Install semgrep (`pip install semgrep`) to restore
   full `VERIFIED` reporting.
2. **Bandit / Ruff only cover Python.** Projects in other languages get rule-book plus
   AST/S2-style regex coverage only; other analyzers are worktree analyzers.
3. **S001â€“S007 and PY-0xx rules are regex-based.** They produce true positives/negatives
   recorded in `sentinel/security_cases/` (benchmark holds them at 1.0/1.0), but regex
   cannot model data flow: a value assigned then overwritten, or built from `os.getenv`
   at runtime but flagged by assignment order, may be a false positive. `redact.py` and
   the report pipeline never emit token *values*.
4. **S004 focuses on interpolation + concatenation**, not full taint tracking; exotic
   drivers (ORM builders) are not analyzed.

## Verification scope

5. **Verdicts are per-required-analyzer, not per-file.** A required analyzer covering a
   subset of the changed files still gates the whole report. Per-file verdicts are
   future work ([roadmap]).
6. **EXPLAIN (AI) is advisory and has no correctness guarantee.** Explanations can be
   wrong or truncated (`_MAX_EXPLANATIONS`, `_AI_TIME_SECONDS`); they are evidence with
   status `PASS`/`SKIPPED`/`ERROR` only and never influence the verdict.
7. **Model prompt-boundary defense is best-effort**, not an airtight sandbox. Repository
   text is marked as *data*, but a hostile repo can still try to jailbreak the model
   inside its own context. Disable `explain` for untrusted repos.

## Autofix

8. **Autofix runs tests on a scratch copy, not in isolation.** `run_safe` enforces a
   command allowlist and 60s timeouts; a repo's own `make test` is arbitrary code and
   runs where the operator launches it. Docker isolation is Phase 5 (parked).
9. **Autofix patch validation is heuristic** (syntax check + analyzer re-run + fast
   tests). It cannot prove absence of regressions in untested paths.
10. **Fixes never commit or push.** Patches are exported for human review.

## Threats not in scope (from the threat model)

11. **Malicious model weights / tampered lockfiles** â€” supply-chain vetting of the
    model/install artifacts is out of scope.
12. **Compromised operator tooling** (e.g. a malicious `git`) â€” we call the binaries on
    PATH; supply-chain pinning is future work.
13. **Side-channel attacks via timing of scan results** on an untrusted API network â€”
    `serve` binds localhost by default; multi-user auth is parked.

## Test gaps / known noise

14. **Semgrep rules are not exercised in CI** (binary absent on the dev host). The
    `SemgrepAnalyzer` path is unit-tested only up to `available()`/`NOT_INSTALLED`.
15. **Benchmark is capped at 35 samples / 10 rules.** It guards regressions on the
    corpus, not absolute security; expand `sentinel/security_cases/` to harden further.

## Deferred / parked

16. Docker sandbox for autofix (Phase 5), auth token for `serve` multi-user, per-file
    verdicts, SBOM + signed releases, `rules verify` corpus at integration scale.

## Audit status

17. The trust/evidence pass fully reviewed the core path (`pipeline`, `trust`, analyzers,
    `autofix`, `model`, `api/server`, `mcp_server`, `cli`, `config`, `rules/{defs,verify}`).
    The following modules have **not yet had an independent hardening audit** in that
    pass â€” they are exercised by tests but flagged for follow-up:
    `providers/github.py`, `providers/gitlab.py`, `rules/{loader,detector,generate}.py`,
    `api/_models.py`, `memory/store.py`.
18. The GitHub Actions self-review workflow reports with `|| true` and uploads artifacts;
    it does not gate CI on findings (deliberate â€” the report is evidence, not a merge block).

Everything above is recorded as `INCOMPLETE` (with the reason) whenever it would
otherwise mask a claim â€” Sentinel prefers an honest downgrade over a quiet PASS.