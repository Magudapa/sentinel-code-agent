# Sentinel Architecture

**Status:** living document. Mirrors the product vision (SENTINEL_VISION) against the shipped
code in this repository. Phase-gated: nothing lands until the phase before it is tested and green.

```
SOFTWARE CHANGE
      │
      ▼
 ┌──────────────────────────────  PLAN  ──────────────────────────────┐
 │  sentinel plan "refund workflow" → portable plan for any agent     │
 └──────────────────────────────┬─────────────────────────────────────┘
      │
      ▼
 ┌────────────────────────────── CODE  ───────────────────────────────┐
 │  Providers: local | github | gitlab | bitbucket | raw diff/SSE     │
 └──────────────────────────────┬─────────────────────────────────────┘
      │
      ▼
 ┌────────────────────── CODE UNDERSTANDING ──────────────────────────┐
 │  diff parse → changesets → language detection → rule books         │
 └──────┬────────────────────────────────────────────────┬────────────┘
        ▼                                                ▼
 QUALITY/SECURITY                                   SUPPLY CHAIN / IaC
  analyzers: custom S-rules, bandit, ruff,          adapters: semgrep, gitleaks,
  rule books (PY/JS/SQL/…) + code quality          sqlfluff, gosec, trivy, syft
        └──────────────────┬─────────────────────────┘
                           ▼
               AI VERIFICATION (evidence-based)
        deterministic analyzers first → LLM explains only when needed
                           ▼
                    RISK ENGINE (0–100)  +  ATTACK-PATH ENGINE (later)
                           ▼
                ┌──────────┴─────────┐
                ▼                    ▼
             PASS                 BLOCK      (policy gate → quality gate)
```

## 1. Modules in this repo today

```
sentinel/
├── analyzers/   base.py(registry) custom_rules(S001–S015,B001–B006)
│                bandit_analyzer.py, ruff_analyzer.py, book_analyzer.py
├── rules/       defs.py detector.py loader.py verify.py generate.py
│                books/{python,javascript,sql}.yml   ← OUR DIFFERENTIATOR
├── model/       client.py — Ollama + OpenAI-compatible (LLMGateway, thin)
├── providers/   local, github, gitlab (+ bitbucket planned)
├── autofix.py   fix → sandbox-style validate → export / GitHub PR
├── memory.py    fixed-before recall (local JSON) → codebase memory
├── pipeline.py  Reviewer: evidence → explain → classify → report
├── output.py    markdown / JSON / SARIF
├── cli.py       review | fix | ruleset | (serve)
├── mcp_server.py        MCP tools: scan, review_diff, audit_repo, …
├── tools/semgrep_analyzer.py   optional adapter, skips when binary
│                              absent (resilient scanner)
└── api/         FastAPI REST (this phase)
```

## 2. The Verified Rule Marketplace — our "unbeatable edge"

Existing tools (Snyk/SonarQube/CodeRabbit) ship closed, un-auditable rules. Our rule books are:

- **Open** (`rules/books/*.yml`) — the seed of the Community Rule Marketplace.
- **Attributed** — every rule carries `author`; community submissions get credit.
- **Two-gate verified** — `sentinel/rules/verify.py`:
  1. **Empirical gate**: regex MUST fire on `vulnerable_example` and stay silent on `safe_example`.
  2. **AI cross-review gate**: an *independent* model applies a rubric and returns
     PASS / REVISE / REJECT. `ai_verified: true` is **only stamped by the verifier**, never hand-written.
- **Tested as truth** — `tests/test_rules_book.py` parameterizes the empirical gate over every
  shipped rule, so a bad submission can never silently enter a book.

All future rule packs (framework packs, DB rules, IaC, containers) go through the same gate.
This is what makes Sentinel trustworthy where closed vendors cannot be inspected.

## 3. Evidence-based AI (no black box)

- Deterministic analyzers run **first**; the LLM explains *found evidence*, never invents it.
- `explain_finding` demands **JSON** `{explanation, suggested_fix}`; `verify_rule` demands **JSON**
  `{verdict, reason}`. Anything non-JSON is treated as REVISE/unknown — never PASS.
- If Ollama/API is down → review still runs (analyzers only) and `status` reports `INCOMPLETE#` for
  the AI gate. Sentinel **never** claims `VERIFIED` when something did not execute.
- Cost-aware by construction: model is only invoked for explanation / consensus / drafting.

## 4. Trust pipeline (final object)

Every scan ends with a machine-readable object (see API_SPEC):

```json
{ "status": "VERIFIED|INCOMPLETE|FAILED", "trust_score": 0-100,
  "blocking_findings": 0, "findings": [ ... ], "policy": "PASSED" }
```

`trust_score` starts at 100 and subtracts per evidence-backed finding by severity — the inverse of
`verdict_score`. Later replaced by the weighted Risk Engine (severity × confidence × exploitability
× exposure × business impact × criticality × reachability = 0–100).

## 5. Security-first defaults

- Read-only analysis by default. No auto-merge, no auto-deploy, no arbitrary shell/network.
- Secret redaction on output; secrets never logged.
- Autonomous fixes run against a working copy / sandbox (Docker later); patches are validated
  (syntax + analyzer re-run + tests) before being proposed.
- MCP server is tool-allowlisted; arbitrary shell/fs/network requires explicit grant.
- Self-hostable, offline-capable: only local process + optional local Ollama required.

## 6. Future phases (see ROADMAP)

Attack-path engine · supply-chain (gitleaks/trivy/syft/osv) · architecture graph ·
business-logic engine · API security · DAST/fuzzing · runtime telemetry · agent security ·
MCP security · policy engine · compliance mapping · RBAC/SSO/tenancy · Web UI · VS Code ext ·
GitHub App · benchmark suite.