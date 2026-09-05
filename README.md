# Sentinel

**Autonomous Security & Code Review Agent** — review your pull requests, catch bugs and security
issues, and (optionally) fix them automatically. 100% free and local-first.

[License: MIT](LICENSE) · Roadmap/design: [BRD.md](BRD.md)

---

## Why Sentinel?

| | Sentinel | CodeRabbit / Snyk / SonarQube |
|---|---|---|
| Price | **Free** | $100–$200 / developer / year |
| Code leaves your machine | **Never** (air-gapped) | Always (their cloud) |
| Auto-fix with validation | ✅ machine-checked patches | Limited / paid |
| Learn from past fixes | ✅ local memory | Rarely |
| Other agents can call it | ✅ MCP server | No |

Sentinel combines three things no single tool offers for free:

1. **Static analyzer evidence** (Bandit, Ruff, custom rules) — hard facts, zero hallucinations.
2. **Local LLM explanation** (Ollama default) — *why* it's dangerous, *how* it could be exploited.
3. **Validated auto-fix** — a patch that passes syntax checks, analyzer re-runs, and your tests before it's proposed.

## Quick start

```bash
# Install
pip install sentinel-code-agent            # (coming soon to PyPI)
# or from source:
git clone https://github.com/Magudapa/sentinel && cd sentinel && pip install -e ".[dev]"

# 1. Pull a local model (free, offline-capable)
ollama pull qwen2.5-coder:7b

# 2. Review a pull request
sentinel review --provider github --repo owner/repo --pr 42

# 3. Review a local diff (no network at all)
git diff HEAD~1 | sentinel review --diff -
```

Output: human Markdown, JSON, and standard **SARIF** (works with GitHub code scanning).

## Features

- ✅ Review PRs from GitHub / GitLab / Bitbucket or raw diffs and local repos
- ✅ Security scan: secrets, SQL, command injection, unsafe `eval`/`pickle`, weak crypto
- ✅ Bug & style scan: Ruff (Python), plus custom repo rules (` .sentinel.yml`)
- ✅ Plain-English explanations from **your local model** (Ollama) or any OpenAI-compatible API
- ✅ Severity-ranked verdict with a 0–100 score
- ✅ Auto-fix: generates validated patches and opens a PR (human always approves)
- ✅ Codebase memory: Chroma vector store reminds you where you fixed the same thing before
- ✅ **MCP server** — Claude, Langflow, or any MCP client can call `review_pr` / `review_diff`
- ✅ SARIF export for GitHub code scanning integration

## Architecture

```
Providers (GitHub/GitLab/Bitbucket/Local)
        │  diff
        ▼
Analyzers (Bandit/Ruff/Custom) ── evidence
        │                         │
        ▼                         ▼
   Reviewer Pipeline  ──►  Model Layer (Ollama default)
   classify → explain             │
        │                         │
        ▼                         ▼
   Findings ──► CLI / JSON / SARIF / MCP ◄── Chroma memory (fixed-before)
        │
        ▼
   Auto-fix loop: patch → validate → tests → open PR
```

Design decisions and full backlog are in [BRD.md](BRD.md). This project's architecture was
informed by studying 20+ leading open-source AI repos (OpenHands, MCP SDK/Servers, Ollama,
LiteLLM, Qdrant/Chroma, LangGraph and friends) — see [ARCHITECTURE.md](ARCHITECTURE.md).

## Development

```bash
pip install -e ".[dev]"
pytest            # run tests
ruff check .      # lint
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
| M10 | Tests (42 passing) + docs + lint/bandit green | ✅ |
| M11 | Docker image + GitHub Action + `sentinel watch` CI | 🔜 |
| M12 | PyPI release | 🔜 |

## Contributing

Open issues/PRs. Ideas wanted: Bitbucket provider, Semgrep rules plugin, pip-audit
dependency analysis, Chrome-extension-like IDE hints, webhook daemon (`sentinel watch`).