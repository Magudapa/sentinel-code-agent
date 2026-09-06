# Sentinel Security Model

Control objectives mapped to shipped code. Every control is implemented+tested, or explicitly
parked with a reason — nothing silently claimed.

## Secure defaults (vision §138)

| Default | Current state |
|---|---|
| Read-only analysis | ✅ `sentinel review`/`scan` never write to scan targets |
| No auto-merge / auto-deploy | ✅ fixes require human approval (export or PR) |
| No arbitrary shell | ✅ subprocess calls are fixed-arg or allowlisted analyzers |
| No unrestricted network | ✅ default provider = local; remote needs explicit flags |
| No secret output | ✅ token values never printed — `****` redaction policy |
| Local-only / offline | ✅ works with no model; Ollama optional, air-gap capable |

## Secrets handling

- `api_key` comes from env or `.sentinel.yml` (git-ignored); never logged.
- Findings carry code evidence as snippets, never credential values.
- MCP audit tools run allowlisted commands only.

## Analyzer & model resilience

- `analyze_changesets` / `analyze_files` wrap every analyzer — one failure never kills a scan.
- Optional binaries (semgrep) probed with `shutil.which`, skipped quietly; report stays truthful.
- LLM down → review completes without explanations; AI-gate reported as **SKIPPED**, never PASS.

## Evidence integrity (no AI black box)

- Every finding has deterministic provenance: `rule_id` + analyzer + file + line + `evidence`.
- Every report has a **verdict** (`VERIFIED` / `INCOMPLETE` / `FAILED`) derived only from
  deterministic analyzer evidence (`sentinel/trust.py`, `report_verdict`), plus a
  `VerificationReport` and per-run `analyzer_status`. Semantics are pinned in
  `tests/test_trust.py` and documented in `SENTINEL_TRUST_INVARIANTS.md`.
- Missing/not-run required checks force `INCOMPLETE` — never a fabricated PASS
  ([#9/#56]); a clean report is only `VERIFIED` when every required analyzer ran clean.
- Book rules get `ai_verified` only via `rules/verify.py` (empirical + independent model verdict).
- `verdict_score` is computed from findings, never from model opinion.
- AI explanations are advisory evidence; the model is treated as a prompt-aware,
  untrusted data channel (prompt-boundary defense + redaction in `model/client.py`).

## API security

- `sentinel serve` binds 127.0.0.1 by default.
- Local `path` must resolve inside the configured workspace root → path-traversal guard (tested).
- JSON in/out; no arbitrary command endpoints.
- Auth token planned for multi-user; MCP stays localhost-first.

## Sandbox roadmap

- Autofix today: patch → scratch working tree → syntax check → analyzer re-run → tests (when a
  workspace is provided).
- Phase 5: Docker isolation (rootless, network-off, CPU/mem limits, timeouts) so untrusted repo
  code never executes on the Sentinel host.

## Own-repo dogfooding

- CI dies on `bandit`/`ruff` failures; scan this repo regularly; SBOM + signed releases in Phase 1/8.
- `sentinel benchmark` runs the deterministic regression corpus
  (`tests/security_cases/`, currently 10 rules / 35 samples at 1.0 precision & recall);
  a rule regression fails CI before it reaches users.
- Known gaps are listed in `KNOWN_LIMITATIONS.md`; the roadmap parks Docker autofix
  isolation and token auth as future phases.