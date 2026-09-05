# Sentinel Roadmap — dependency-aware, verified slices

Rule: **IMPLEMENT → TEST → SCAN → VERIFY → DOCUMENT → COMMIT**, in small stages (vision §142–143).
No phase starts until the previous one is green locally **and** in CI.

Legend: ✅ shipped · 🔜 next · ☑ planned · ⛔ consciously parked.

## Phase 0 — Foundation ✅ (mostly)
- ✅ Repo, LICENSE (MIT), CI (ruff/bandit/pytest), packaging (`pyproject.toml`)
- ✅ Unified finding model (`models.py`), severity enum, verdict score
- ✅ CLI (`review | fix | ruleset`), output (markdown/JSON/SARIF)
- ✅ Config (`load_config`, `.sentinel.example.yml`), ignore paths
- ✅ Analyzer registry (`base.py` CONTENT/FILE analyzers)
- 🔜 `sentinel serve` — FastAPI REST (this phase, API-first)
- ⛔ PostgreSQL/Redis/Celery — swap when multi-repo scale demands it; the modular monolith
  boundary (providers/analyzers/model) already keeps this reversible
- 🔜 Plugin API (SENTINEL_PLUGIN_SPEC) — freeze stable interfaces before community rules land

## Phase 1 — Core scanner ✅ / 🔜
- ✅ SAST: Bandit, Ruff, custom rules, **rule books (python/javascript/sql)**
- ✅ Secrets baseline (S-rules) → 🔜 gitleaks adapter + entropy scanning + git-history scan
- ✅ Semgrep adapter (auto-skip when binary missing)
- 🔜 SCA: OSV / pip-audit / Grype → dependency graph; SBOM (SPDX/CycloneDX) via Syft
- 🔜 IaC: tfsec/semgrep IaC; container: Trivy/Hadolint; SARIF export already ✅

## Phase 2 — Quality ☑
- Complexity (cyclomatic/cognitive), duplication, technical debt, maintainability index
- Quality gates + baselines (new-code-only, legacy suppression with who/why/expiry)
- Reference scan of own repo; fix its own findings before shipping (eat-own-dogfood)

## Phase 3 — Git integration ✅ / 🔜
- ✅ GitHub PR fetch/review/post-comments; ✅ GitLab MR fetch/review
- ✅ CI GitHub Action (`sentinel-review`) + `sentinel review` exits nonzero on critical
- 🔜 Branch-level checks/annotations, Jenkins/GitLab native CI, webhook daemon (`sentinel watch`)

## Phase 4 — AI review ✅ → 🔜 (evidence-based consensus)
- ✅ Local-first LLM gateway (Ollama + OpenAI-compatible), explanations, ruleset AI-gate
- 🔜 Multi-agent review (Security/Quality/Architecture/Performance/Testing… agents) with
  **max_iterations / token / time / tool-call budgets** and a Consensus Engine
  (Confirmed / Likely / Needs Review / False Positive)
- 🔜 Evidence model upgrade: every AI finding carries claim + evidence + reasoning + confidence;
  `NEEDS_VERIFICATION` when evidence is thin
- 🔜 Prompt versioning + regression harness for prompts
- 🔜 Model router: cheap model → simple review; local model → sensitive code (privacy)

## Phase 5 — Autonomous remediation ✅ → 🔜
- ✅ `sentinel fix` — validated patches (syntax + analyzer re-run + tests) → export / GitHub PR
- 🔜 Docker sandbox for running untrusted code + project tests; patch safety: accept only when
  risk_after < risk_before and tests pass
- 🔜 Generated-code verification (`sentinel verify`) + AI test generation with executed results

## Phase 6 — Agent & MCP security ⛔/🔜 (OUR EDGE)
- ✅ MCP server (review_diff/audit_repo/…) — already tool-allowlisted by design
- 🔜 `sentinel agent verify` — the **OpenCode/Claude/Codex verification loop** (iteration K: N
  findings → 0; STATUS=VERIFIED), machine-readable handoff JSON (status/risk/blocking/actions)
- 🔜 Agent identity, permissions, tool/file/network grant model, MCP server trust scoring
- 🔜 AI-generated-code detection (hallucinated APIs, nonexistent deps, AI-origin likelihood —
  never absolute claims)
- 🔜 `sentinel plan` — portable implementation plans consumable by any coding agent

## Phase 7 — Advanced security ☑
- Attack-path engine (join findings into exploitable chains, path-level risk) — differentiator
- Business-logic engine (authorization, workflow bypass, price/qty manipulation, IDOR, race)
- API security (OpenAPI/GraphQL, missing auth, mass assignment, rate limits) + auto API tests
- DAST (safe-by-default: local/staging only, explicit authorization) + fuzzing/property tests

## Phase 8 — Enterprise ☑
- RBAC/audit log/multi-tenancy (organization_id on every row), SSO
- Policy engine (YAML rules: severities → block/warn; exemptions w/ expiry) + quality gates
- Compliance mapping (OWASP 2025, CWE, NIST SSDF/CSF, SOC2, ISO27001, PCI, GDPR/HIPAA)
- Air-gapped: offline rule bundles + vuln DB updates + local model endpoints

## Horizontal
- Identity: **Verified Rule Marketplace** (two-gate book system) grows with framework packs
  (FastAPI/Django/React/Next/Java Spring/iOS…), DB rules, IaC, containers
- Docs: API spec, plugin spec, test strategy, stress-fix demo repo, benchmark repos, README badges
- Packaging: PyPI release (blocked on nothing — SemVer `0.x`), Docker Compose, GitHub App later