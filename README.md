# Sentinel 🛡️

### AI can suggest. Evidence decides.

Sentinel is an open-source, local-first security and code-review agent for repositories, pull requests, and merge requests.

It detects security issues, explains them using AI, proposes fixes, validates those fixes, and produces evidence-backed results.

```text
DETECT → EXPLAIN → FIX → VERIFY → SHIP
```

### The difference

Sentinel does not allow an AI model to decide whether a security finding is fixed.

AI can:

* explain a finding
* reason about potential impact
* suggest remediation
* generate a candidate patch

But AI cannot manufacture the final verdict.

Sentinel uses evidence to determine:

```text
VERIFIED
INCOMPLETE
FAILED
```

If required evidence is unavailable, Sentinel reports:

```text
INCOMPLETE
```

It never converts missing evidence into a fake PASS.

---

## Why Sentinel?

AI-generated code is becoming increasingly common.

That creates a new problem:

**How do we verify that an AI-generated security fix actually works?**

Sentinel approaches the problem as an evidence pipeline:

```text
Repository / PR
       ↓
    DETECT
       ↓
    EXPLAIN
       ↓
      FIX
       ↓
    VERIFY
       ↓
     SHIP
```

Verification can include:

* static analysis
* security rules
* syntax validation
* test execution
* security regression checks
* analyzer results
* rule verification
* patch validation

The final verdict is produced by the evidence engine — not by the LLM.

## Local-first AI

Sentinel can use local LLMs through Ollama.

Your source code does not need to leave your machine for the AI explanation layer when using a local provider.

OpenAI-compatible providers can also be configured when remote inference is appropriate.

## Current analyzers

Sentinel currently supports:

* Bandit
* Ruff
* Sentinel custom security rules
* optional Semgrep
* rule-book verification
* AST-based analysis where supported

Analyzer availability is explicit.

For example:

```text
✓ Bandit
✓ Ruff
✓ Sentinel Rules
✗ Semgrep

Result:
INCOMPLETE
```

Sentinel does not treat an unavailable analyzer as a successful security check.

## Rule books

Sentinel currently includes open rule books for:

* Python
* JavaScript
* SQL

Rules contain:

* author attribution
* explanation
* vulnerable examples
* safe examples
* detection logic
* verification metadata

A rule is not considered verified simply because it was written.

It must pass its verification gates.

## Benchmark

Sentinel includes a security benchmark and regression corpus.

The benchmark currently contains:

```text
10 security rules
35 security samples
```

The benchmark itself found real defects in Sentinel's security rules.

For example:

* a secret-detection rule missed specific modern API-key formats
* an SQL-injection rule produced false positives for parameterized queries while missing a string-concatenation case

Those issues were fixed and pinned with regression tests.

Current benchmark result:

```text
Precision: 1.00
Recall:    1.00
```

The benchmark is continuously tested so regressions fail CI.

## Trust model

Sentinel follows a simple principle:

> **Missing evidence is not evidence of success.**

Therefore:

```text
VERIFIED
```

means the required verification gates passed.

```text
INCOMPLETE
```

means required evidence was unavailable or could not be collected.

```text
FAILED
```

means a validation or verification step explicitly failed.

Sentinel does not turn uncertainty into confidence.

## Open source

Sentinel is being developed openly.

The goal is not to build another black-box AI security reviewer.

The goal is to build a security agent where developers can inspect:

* detection rules
* evidence
* verification logic
* generated patches
* test cases
* benchmarks
* security assumptions
* known limitations

and challenge them.

## Current limitations

Sentinel is actively evolving.

Known limitations include areas such as:

* deeper interprocedural data-flow analysis
* additional programming languages
* container security
* infrastructure-as-code analysis
* dependency security
* sandboxed test execution
* enterprise authentication
* expanded rule marketplace capabilities

These limitations are documented rather than hidden.

See [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) for the detailed, honest inventory.

## The principle

AI can suggest a fix.

AI can explain a vulnerability.

AI can generate code.

But before Sentinel says:

```text
VERIFIED
```

it asks:

**Where is the evidence?**

---

## Quick start

```bash
# Install from source
git clone https://github.com/Magudapa/sentinel-code-agent.git
cd sentinel-code-agent
pip install -e ".[dev]"

# 1. Pull a local model (free, offline-capable)
ollama pull qwen2.5-coder:7b

# 2. Review a pull request
sentinel review --provider github --repo owner/repo --pr 42

# 3. Review a local diff (no network at all)
git diff HEAD~1 | sentinel review --diff -

# 4. Benchmark rule quality against the regression corpus
sentinel benchmark
```

Output: human Markdown, JSON, and standard **SARIF** (works with GitHub code scanning).

## Docs

- [SENTINEL_TRUST_INVARIANTS.md](SENTINEL_TRUST_INVARIANTS.md) — the evidence/verdict contract, test-enforced
- [SENTINEL_SECURITY_MODEL.md](SENTINEL_SECURITY_MODEL.md) — security & trust model, implemented controls
- [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) — honest inventory of what Sentinel does not do (yet)
- [SENTINEL_API_SPEC.md](SENTINEL_API_SPEC.md) — REST API spec (`sentinel serve`, FastAPI, localhost-first)
- [SENTINEL_THREAT_MODEL.md](SENTINEL_THREAT_MODEL.md) — threat model and our core guard
- [BRD.md](BRD.md) — design decisions & full backlog
- [ARCHITECTURE.md](ARCHITECTURE.md) — architecture (informed by 20+ leading open-source AI repos)

## Development

```bash
pip install -e ".[dev]"
pytest            # run tests
ruff check .      # lint
bandit -q -r sentinel -x sentinel/tests -c pyproject.toml   # security lint (CI config)
sentinel benchmark   # regression corpus: precision/recall gates
```

## Roadmap

Status of the BRD → production milestones:

| # | Milestone | Status |
|---|---|---|
| M1 | BRD | ✅ |
| M2 | Scaffold (LICENSE, CI, packaging) | ✅ |
| M3 | Providers (GitHub/GitLab/local) + analyzers (custom rules, Bandit, Ruff) | ✅ |
| M4 | Local-first model layer (Ollama + OpenAI-compatible) | ✅ |
| M5 | Reviewer pipeline + CLI (markdown/JSON/SARIF) | ✅ |
| M6 | Auto-fix (validated patches, export + GitHub fix PR) | ✅ |
| M7 | Codebase memory (fixed-before recall) | ✅ |
| M8 | MCP server (`sentinel-mcp`) | ✅ |
| M9 | Streamlit web UI (`streamlit run webapp.py`) | ✅ |
| M10 | Tests + docs + lint/bandit green | ✅ |
| M11 | Docker image + GitHub Action + `sentinel watch` CI | 🔜 |
| M12 | PyPI release | 🔜 |
| M13 | AI-verified rule books (Python/JS/SQL) + `sentinel ruleset` | ✅ |
| M14 | Phase-0 REST API (`sentinel serve`, FastAPI) + strategy docs | ✅ |
| M15 | Trust verdict (`VERIFIED`/`INCOMPLETE`/`FAILED`) + security modules + benchmark | ✅ |

## Contributing

Open issues/PRs. Ideas wanted: Bitbucket provider, Semgrep rules plugin, pip-audit
dependency analysis, Chrome-extension-like IDE hints, webhook daemon (`sentinel watch`).