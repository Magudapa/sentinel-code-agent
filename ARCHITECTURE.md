# Sentinel — Architecture

This document explains *how* Sentinel is built and *why* — including the research behind it.
Sentinel's design was informed by a study of 20+ leading open-source AI repositories. We did
not clone them; we borrowed the patterns that matter, kept the stack 100% free, and aimed for
something a solo developer can self-host with zero cost.

## The 20-repo map

| Layer | Repos studied | How Sentinel applies it |
|---|---|---|
| Agent loop / autonomy | OpenHands, AutoGPT | The **review pipeline is a DAG**: evidence → explain → classify → patch → validate. Every step has a tool and a result that can be re-run, mirroring OpenHands' observe–plan–act cycle. Auto-fix is an independent second loop (`sentinel fix`). |
| Orchestration | Langflow, Dify, Flowise, Semantic Kernel (LangGraph-style) | `sentinel/pipeline.py` is a small orchestration engine. Each stage is a function so future visual wiring (a Flowise-style canvas) is feasible. |
| Agent ↔ software integration | MCP Python SDK, MCP Servers, Composio | Sentinel **is an MCP server** (`sentinel/mcp_server.py`). Protocol connectors for GitHub/GitLab live in `sentinel/providers/`; any tool that speaks MCP (Claude Desktop, Langflow…) can call `review_pr`, `review_diff`, `audit_repo`, `list_rules`. |
| Local/free AI models | Ollama, vLLM, LiteLLM | `sentinel/model/client.py` is a **zero-dependency** router: local Ollama by default, any OpenAI-compatible API as a fallback. No SDK dependency, no vendor lock-in, $0 default. |
| Data / RAG / memory | LlamaIndex, Haystack, Qdrant, Chroma, Milvus | `sentinel/memory/` stores "fixed-before" patterns. Ship default is a tiny JSON store (zero install); a Chroma adapter slots in without API changes. Findings become searchable context, exactly like RAG memory in agents. |
| Coding-agent architecture | Aider, Continue, CodeRabbit-inspired UX | PR comments are line-anchored and severity-ranked, and auto-fix patches are **validated** (syntax + analyzer re-run + fast tests) before being proposed — the Aider/CodeRabbit discipline. |

## System layout

```
sentinel/
├── cli.py            # `sentinel review` / `sentinel fix`
├── api/server.py     # Phase-0 REST API (`sentinel serve`, FastAPI)
├── config.py         # .sentinel.yml loader (model, thresholds, auto_fix, memory)
├── models.py         # Finding / ReviewReport / Patch / severity + scoring
├── providers/        # diff + metadata sources
│   ├── local.py      #   local git repo (no network)
│   ├── github.py     #   GitHub PR (REST + diff + inline review comments)
│   └── gitlab.py     #   GitLab MR (REST + discussions)
├── analyzers/        # detection engines
│   ├── custom_rules.py   # regex safety net (18 rules, diff-only friendly)
│   ├── bandit_analyzer.py# subprocess Bandit on a working tree
│   └── ruff_analyzer.py  # subprocess Ruff on a working tree
├── model/client.py   # Ollama / OpenAI-compatible chat + JSON-parse explanations
├── memory/store.py   # "fixed before" recall (JSON now, Chroma-ready)
├── diffparse.py      # unified diff → line-accurate Changeset
├── autofix.py        # patch generation + syntax/tests validation
├── output.py         # Markdown / JSON / SARIF exporters
└── mcp_server.py     # MCP tools for other agents
```

## Review pipeline

```
provider.fetch_context(repo, pr)         # diff + base/head SHA
        │
        ▼
parse_diff → Changesets (file → added lines + new-file line numbers)
        │
        ▼
┌─────────────────────────────────────────────┐
│  Stage 1  ANALYZE (analyzers/)              │
│   • custom_rules on every added line        │   ← works on PRs with no checkout
│   • Bandit + Ruff when a working tree exists│   ← deeper, free, just subprocesses
└─────────────────────────────────────────────┘
        │ findings
        ▼
┌─────────────────────────────────────────────┐
│  Stage 2  EXPLAIN (model/, optional)        │
│   • local Ollama explains WHY + proposes fix│   ← skipped gracefully when offline
└─────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────┐
│  Stage 3  RECALL (memory/)                  │
│   • did we fix this exact pattern before?   │
└─────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────┐
│  Stage 4  RANK + SCORE (models.py)          │
│   severity sort → verdict 0-100             │
└─────────────────────────────────────────────┘
        │
        ├──→ CLI (markdown/JSON/SARIF) · Streamlit UI · MCP tools
        └──→ POST inline comments (GitHub review API / GitLab discussions)

AUTO-FIX LOOP (optional, `sentinel fix`):
   findings → LLM patch → replace in file → syntax check →
   re-run analyzer → fast pytest → export OR create GitHub fix PR
```

## Design decisions

1. **Analyzers first, LLM second.** The model never *invents* an issue: it explains and fixes
   analyzer-produced evidence. This kills hallucinated findings — the #1 complaint about LLM review bots.
2. **Zero heavy dependencies.** Core = `requests` + `bandit` + `ruff` + `PyYAML`. Optional extras for
   GitHub/GitLab clients, memory (chromadb), and MCP. Installs fast, works anywhere.
3. **Degrades gracefully.** No Ollama? No network? No token? Sentinel still reviews with analyzers
   alone and tells you what the model would add.
4. **Air-gapped by default.** Code never leaves the machine unless you `--post` comments or open a fix PR.
5. **Windows/Unix tolerant.** Pure-Python unified-diff generation (no `diff` binary), paths normalized,
   UTF-8-safe console output.

## Roadmap → v1.0

- [ ] Bitbucket provider
- [ ] Chroma-backed memory by default (with bundled embeddings)
- [ ] `sentinel watch` (local webhook/daemon for CI)
- [ ] Semgrep rules plugin, pip-audit dependency analyzer
- [ ] Docker image + GitHub Action
- [ ] SCREAM-level noise filters (dedupe across PRs, blame-aware suppression)