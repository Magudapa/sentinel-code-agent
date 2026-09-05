# Sentinel Threat Model

Threat actors and mitigations. Continuously re-tested (vision §139). Read-only tool: this is the
adversary catalog, not a formal certification claim.

## Actors

| Actor | Capability | Sentinel mitigations |
|---|---|---|
| Malicious repo content | Files/diffs contain poisoned code | Analyzer sandboxing; untrusted code never runs on host; scanning is read-only |
| Compromised developer account | Push code / PRs / comments | Evidence-based findings; deterministic replay; decisions reproducible offline |
| Malicious dependency | Bundled analyzer or runtime dep | Pinned mins + own CI scans; supply-chain (OSV/Syft) planned |
| Prompt injection via code | Code/text steers the LLM | LLM only *explains evidence*; it never decides severity or verdict (score is deterministic); fix validation re-runs analyzers |
| Malicious MCP tool | Fake analyzer result | Tools allowlisted; audit tools fixed-arg; results re-verified vs. re-runs |
| Compromised CI | Alters scan output | Scans run on clean runners (GitHub Actions); results not writable by targets |
| Supply-chain attacker | Tampers with rules/books | Rules are plaintext YAML, verified via two gates, always authored and versioned in git |
| Tenant escape attacker | Reach other tenants | Multi-tenancy deferred to Phase 8; single-tenant today = no cross-tenant surface yet |

## Prompt-injection defense (the LLM threat)

Our core guard: the AI is **not** a decision-maker in the trust path.

1. Deterministic analyzers produce findings and severity (rules/bandit/ruff/books).
2. `rules/verify.py` Gate 2 asks an *independent* model for a verdict on a **rule**, and the result
   only flips a `verified` flag; the finding pipeline still runs without it.
3. `explain_finding` returns JSON; any malformed/unexpected response is treated as **not verified**.
4. Auto-fix patches must pass syntax + analyzer re-runs before they are proposed — a poisoned
   "fix" cannot pass validation silently.

## Exfiltration control

- Data leaves the machine only when: (a) an OpenAI-compatible endpoint is configured, or
  (b) scanning remote GitHub/GitLab. Local-first default sends nothing.
- No telemetry. Cost records are local-only when configured.

## Fuzz/escape test backlog (vision §91)

- Property that `verify_rule` never returns PASS without both gates (unit tested).
- Path traversal over the API (tested at Phase 0 API).
- Analyzer isolation: broken analyzer → scan completes (tested).
- Secret redaction unit tests before any report-exporter feature lands.

## When we must not mislead

- `INCOMPLETE` when any configured analyzer/analyzer-gate did not run (vision §116–117).
  CLI already exits nonzero on critical findings and reports "No finding" honestly for empty diffs.