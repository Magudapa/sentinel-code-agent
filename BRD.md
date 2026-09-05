# Sentinel — BRD
**Autonomous Security & Code Review Agent for Developers**

| | |
|---|---|
| Version | 1.0 (Draft) |
| Status | Approved for development |
| Owner | Magudapa |
| License | MIT (open source) |
| Target | GitHub / GitLab / Bitbucket / local repos |
| Cost model | 100% free — local-first models (Ollama), no paid APIs required |

---

## 1. Executive Summary

Sentinel is an **open-source, local-first AI agent** that reviews pull requests for security
vulnerabilities, bugs, and performance problems — and, when safe, **fixes them automatically**
by opening its own pull request. It is the free, privacy-preserving alternative to paid review
bots (CodeRabbit, Snyk, SonarQube) and to sending your code to third-party clouds.

Because it runs **air-gapped** (models via Ollama/vLLM on your own machine + static analyzers
locally), businesses that cannot share proprietary code with SaaS vendors get enterprise-grade
review for $0.

**Why now:** Every company has an AI assistant; almost none has an AI that *reads their actual
source code and proposes tested fixes*. Static analyzers (Bandit, Ruff, Semgrep) find issues but
don't explain them; LLM chat bots explain issues but don't verify them against the repo. Sentinel
combines both — analyzer *evidence* + model *explanation* + machine-checked *patch*.

---

## 2. Problem Statement

| Problem | Evidence / Cost |
|---|---|
| Code review skipped in startups | Reviews are the #1 gap; PRs merge unreviewed under velocity pressure |
| Paid review tools cost $100–200/dev/yr | CodeRabbit ~$19/dev/mo; Snyk enterprise much more |
| Code leaves the building | SaaS tools upload proprietary source to US/EU clouds — blocked by regulated firms |
| False positives drown developers | Naive linter output ignored; no one reads 300 warnings |
| Repeated mistakes | The same vuln (SQL-injection, hardcoded secrets, `eval()`) recurs across repos |

---

## 3. Goals & Non-Goals

### 3.1 Goals
1. Review a PR and produce **actionable, line-level, severity-ranked** comments.
2. **Explain** each finding in plain English (why it matters, how to exploit it).
3. **Auto-fix** straightforward findings and post the patch as a PR/comment (human approves).
4. Run **fully local** (Ollama/vLLM) or against any OpenAI-compatible model (Bring Your Own Key).
5. Support GitHub (cloud + Enterprise), GitLab, Bitbucket, and plain local checkouts.
6. **Remember** your codebase: a vector store of "fixed before" patterns stops repeat findings.
7. Expose everything as a **CLI** and an **MCP server** so other agents can use Sentinel.

### 3.2 Non-Goals (v1)
- No deployment platform (self-host via `pip install` / Docker later).
- No CI webhook hosting (we provide CLI/docker images; users wire their own cron/webhooks).
- No support for compiled-language security beyond linting (focus: Python/JS/TS/YAML first).
- No license compliance / dependency SBOM (v2).

---

## 4. Target Users & Personas

| Persona | Need |
|---|---|
| **Solo dev / indie hacker** | Free PR reviews without leaking code to cloud |
| **Startup eng team** | Catch bugs & security issues before merge, keep velocity |
| **Agency working on client repos** | NDA-safe review; report per client repo |
| **Regulated firm (fintech/health)** | Air-gapped review of proprietary code |
| **OSS maintainer** | Bot that reviews community PRs 24/7 |

---

## 5. Functional Requirements

Label — Feature — Detail

- **FR1 — PR review (Cloud):** Fetch a PR diff from GitHub/GitLab → run analyzers + model → post line-level comments and a summary.
- **FR2 — Diff/commit review (Local):** `sentinel review --diff` accepts a git diff or a commit range for local checkouts — no network needed.
- **FR3 — Static analysis:** Run Bandit (security), Ruff (bugs/lint), Babel (JS/TS checks optional), plus custom rule-sets (SQL ctrl+stmt, `eval`/`exec`/`pickle`, hardcoded secrets regex, dangerous `os.system`/`subprocess shell=True`, weak crypto).
- **FR4 — LLM explanation:** For every analyzer hit, ask the model to (a) explain the risk, (b) propose a concrete patch. Results cached.
- **FR5 — Severity ranking:** Findings classified Critical / High / Medium / Low / Info with a verdict score (0–100).
- **FR6 — Auto-fix:** For selected severities, generate a patch, **validate it** (syntax + re-run analyzer + run repo tests if fast), and produce a GitHub PR.
- **FR7 — Memory:** Store fixes in Chroma; future violations of a *previously fixed pattern* produce "you fixed this before in file X" references.
- **FR8 — MCP server:** Expose `review_pr`, `review_diff`, `list_findings` as MCP tools so Claude/Langflow/other agents can call Sentinel.
- **FR9 — Config:** `.sentinel.yml` per repo — model, severity thresholds, ignore paths, custom rules, auto-fix policy.
- **FR10 — CLI UX:** `sentinel review --pr <n>` / `--diff` / `--repo path`; outputs human Markdown, JSON, and SARIF (industry standard for GitHub code-scanning integration).

---

## 6. Non-Functional Requirements

- **Cost:** $0 in default mode (local Ollama + free analyzers). Optional BYOK cloud model.
- **Security:** Code stays local unless user opts in; never send code to unknown endpoints.
- **Performance:** PR of ≤500 changed lines reviewed within 60s on a laptop.
- **Compatibility:** Python ≥3.10; Windows, macOS, Linux.
- **Quality gates:** ≥80% unit-test coverage of core analyzer & classifier modules; `pytest` + `ruff` green in CI.
- **Extensibility:** Plug-in analyzers and models via a small registry (registry allows community PRs).

---

## 7. System Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         Sentinel Core                            │
│                                                                  │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │  Providers  │  │  Analyzers   │  │  Model Layer (Lite)    │  │
│  │  GitHub     │  │  Bandit      │  │  Ollama (default)     │  │
│  │  GitLab     │  │  Ruff        │  │  OpenAI-compatible API│  │
│  │  Bitbucket  │  │  Custom rules│  └────────────────────────┘  │
│  │  Local      │  │  Secrets/crypto                            │
│  └─────────────┘  └──────────────┘  ┌────────────────────────┐  │
│           │                │        │  Memory (Chroma)       │  │
│           ▼                ▼        │  fixed-before patterns │  │
│  ┌───────────────────────────────┐  └────────────────────────┘  │
│  │  Reviewer Pipeline            │                              │
│  │  evidence → explain → classify│                              │
│  │  → comment → patch → validate │                              │
│  └───────────────────────────────┘                              │
│            │                    │                               │
│            ▼                    ▼                               │
│   ┌─────────────┐       ┌──────────────┐                       │
│   │   CLI       │       │  MCP Server  │── other agents         │
│   │   JSON/SARIF│       └──────────────┘                       │
│   └─────────────┘                                             │
└──────────────────────────────────────────────────────────────────┘
```

**Reference architecture informed by the 20-repo study:**
- Agent loop ← OpenHands / AutoGPT (autonomous cycles: analyze → plan → act)
- Orchestration ← LangGraph-style DAG (pipeline above)
- Integration layer ← MCP Python SDK + MCP Servers (we are an MCP *server*)
- Models ← Ollama (local) + LiteLLM-style router (fallback order: Ollama → OpenAI-compatible)
- Memory ← Qdrant/Chroma (we ship Chroma for zero-config)
- Coding extra context ← LlamaIndex-style code index (v1.5)

---

## 8. Data Model

- **Finding** `{rule_id, severity, file, line, end_line, code_snippet, description, evidence, model_explanation, suggested_fix}` 
- **ReviewReport** `{provider, repo, pr|diff_key, verdict_score, summary_md, findings[], created_at}`
- **Patch** `{finding_id, diff, validated: bool, tests_passed, pr_url?}`
- **MemoryEntry** `{embedding, file, pattern_class, fix_summary}`
- **Config (.sentinel.yml)** `{model:{provider,model,base_url}, thresholds:{max_severity_posted}, ignore:[paths/globs], auto_fix:{enabled, max_severity, target_branch}}`

---

## 9. Milestones (BRD → Production)

| # | Milestone | Deliverable | Done |
|---|---|---|---|
| M1 | BRD | This document | ✅ |
| M2 | Scaffold | Repo structure, LICENSE, README, CI | |
| M3 | Core: providers+analyzers | `sentinel` package, local analysis works | |
| M4 | Model layer + explainer | Issue explanations from Ollama | |
| M5 | Reviewer pipeline + CLI | `sentinel review` end-to-end, JSON/SARIF | |
| M6 | Auto-fix + PR | Patches validated and posted to GitHub | |
| M7 | Memory (Chroma) | Repeat-fix detection | |
| M8 | MCP server | Other agents call Sentinel | |
| M9 | Web UI (Streamlit) | Human dashboard | |
| M10 | Tests+docs+release | ≥80% coverage, README, PyPI-ready, GitHub push | |

---

## 10. Out of Scope / Future

- Dependency SVMs (pip-audit as an analyzer plugin — v2)
- Semgrep community rules pack (plugin — v2)
- Webhooks-as-a-service / hosted SaaS
- JavaScript deep analysis (v2, Babel-based)
- Docker distribution (M11)

---

## 11. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Local model quality below GPT-4 on hard logic bugs | Dual mode: local default, BYOK cloud optional; analyzers provide evidence so model only *explains* |
| Auto-fix breaking code | Every patch is syntax-checked + analyzer re-run + repo test run before PR; fixes are proposals, human merges |
| False positives annoy users | Severity thresholds + `.sentinel.yml` ignore + per-file suppression comments |
| Secrets in code must exist to detect | Analyzer matches on patterns in diff only; results stay local |
| Monetization desire conflicts w/ free promise | Free core forever; future = hosted luxury tier for CI (keep OSS core free) |