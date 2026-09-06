# Sentinel Trust & Evidence Invariants

This document is the contract between Sentinel's **evidence model** and its consumers
(pipeline, API, autofix, MCP, tests). It is enforced by `tests/test_trust.py`,
`sentinel/trust.py`, and the verdict logic in `sentinel/pipeline.py`.

## The model

Every decision that claims "this is safe" must trace to *evidence items* — small,
named observations each carrying one of these statuses:

| Status          | Meaning                                             |
|-----------------|-----------------------------------------------------|
| `PASS`          | A check ran and found nothing wrong                 |
| `FINDINGS`      | A check ran and produced findings                   |
| `FAIL`          | A check ran but could not complete (crash)          |
| `ERROR`         | Execution failed (e.g. subprocess error)            |
| `TIMEOUT`       | Execution exceeded its time budget                  |
| `NOT_INSTALLED` | The tool is not installed on this host              |
| `NOT_SUPPORTED` | Not applicable in this mode (e.g. no working tree)  |
| `SKIPPED`       | Intentionally not run (config)                      |
| `MISSING`       | No evidence was recorded for an expected check      |

Evidence items are created with `ev(source, kind, status)`; findings get their own
evidence via `finding_evidence(finding, status=...)`.

## Invariant rules (test-enforced)

1. **No evidence → not VERIFIED.** `verdict_of` on an empty evidence set, or one that
   lacks required sources, returns `INCOMPLETE` — never `VERIFIED`, never a PASS.
2. **A FAIL / ERROR / TIMEOUT / NOT_INSTALLED anywhere can never yield VERIFIED.** Any
   of these statuses for a *required* source forces the verdict away from VERIFIED.
3. **FINDINGS is proof of a problem.** `verdict_of` returns `FAILED` when findings are
   recorded for required sources ([#13] passes: "issues found").
4. **Only PASS/FINDINGS can contribute to VERIFIED.** Everything else (including
   `NOT_SUPPORTED`/`MISSING`) is neutral-to-negative.
5. **AI output is advisory.** Model explanations and candidate fixes are recorded as
   evidence with status `SKIPPED`/`ERROR`/`PASS` but must *never* set a verdict by
   themselves; deterministic analyzers decide ([#61]).
6. **Unknown required analyzer → INCOMPLETE, not PASS.** If an analyzer was requested
   but no evidence of *any* kind was recorded for it, the report is `INCOMPLETE`
   (`MISSING`), giving operators an explicit "not fully verified" signal.
7. **Pure-diff mode cannot claim worktree verification.** With no working tree,
   worktree analyzers report `NOT_SUPPORTED` and never block the verdict; the summary
   says which checks did not apply.
8. **`FAILED` is terminal.** Once any required source is `FAILED`, the verdict is
   `FAILED` regardless of how many others passed.

## Pipeline wiring

- `pipeline.Reviewer` builds one `EvidenceItem` per analyzer (by name) and per block of
  AI explanations, then calls `report_verdict(evidence, required=...)`.
- `DEFAULT_REQUIRED_ANALYZERS = ("bandit", "ruff", "semgrep")` when a working tree is
  present; `semgrep` is only `required` when installed, otherwise recorded
  `NOT_INSTALLED` and non-blocking.
- `--verdict`/exit code: `cli.py` returns 0 only on `VERIFIED` with no critical
  findings; `INCOMPLETE`/`FAILED` → non-zero with an explicit stderr reason.
- `api/server.py` `GET /review/{id}` returns `verdict` from `report.verdict` — it never
  fabricates a verified result.

## What a "VERIFIED" report means

Every required deterministic check **ran**, **completed**, and **found no issues** on
the reviewed changes. It is a conservative claim: if any required check could not run,
the report says so (`INCOMPLETE`) rather than implying verified.