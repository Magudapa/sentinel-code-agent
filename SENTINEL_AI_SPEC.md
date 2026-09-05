# Sentinel AI Specification

Guiding law (vision §90, §115–117): **the AI may recommend; deterministic systems verify.**
An AI message on its own is a hypothesis — it only becomes a finding when evidence supports it,
and it only becomes "verified" when a deterministic gate agrees.

## Architecture

```
Deterministic analyzers → findings (severity/confidence deterministic)
        │
        ▼
  LLM Gateway (provider/model config, cost & privacy aware)
        │
        ├─ explain_finding    → explanation + suggested_fix  (JSON contract)
        ├─ verify_rule (Gate2) → verdict PASS/REVISE/REJECT  (JSON contract)
        └─ (Phase 4) multi-agent + consensus
        │
        ▼
  Trust decision: verdict_score / trust_score are ALWAYS computed from findings,
  never from the model's opinion.
```

## Provider abstraction (vision §53–54)

`sentinel/config.py:ModelConfig` + `sentinel/model/client.py:ModelClient`:

- `provider: ollama | openai` (OpenAI-compatible). Base URL + model switch freely.
- Local-first: Ollama is default; no model → analyzers-only mode (truthful `INCOMPLETE`).
- `is_available()` is a fast `/api/tags` probe — it never loads the model just to answer metadata.
- Phase 4 adds the **model router**: cheap model → simple explanations, local model → sensitive
  code, strong model → complex security reasoning. Keyed on task, risk, cost, latency, privacy,
  availability.

## Evidence-based findings (vision §9)

Every AI-backed finding uses the contract:

```
claim | evidence | reasoning summary | affected code | potential impact
recommended fix | verification method | confidence
```

When evidence is insufficient the finding status becomes **NEEDS_VERIFICATION** — we never present
speculation as a confirmed vulnerability.

## Rule verification gate (OUR DIFFERENTIATOR — live today)

`sentinel/rules/verify.py` implements the only path to `ai_verified: true`:

1. Empirical: regex against `vulnerable_example`/`safe_example` (deterministic).
2. Independent-model rubric: real vuln? right severity? false-positive risk? safe fix? → JSON
   `{verdict, reason}`; malformed JSON auto-falls to **REVISE** (fail-closed).
3. `stamp()` sets `ai_verified` only on PASS with model id + timestamp + notes.

## Multi-agent review plan (vision §10–11)

Specialized agents (Security/Quality/Architecture/Performance/Testing/Dependency/API/BusinessLogic/
Privacy/Compliance/AITrust), an Orchestrator with hard budgets —

```
max_iterations      (default 3)
max_tokens          (per agent)
max_execution_time  (per review)
max_tool_calls      (per agent)
```

— and a Consensus Engine emitting `Confirmed | Likely | Needs Review | False Positive`.
No unbounded agent-to-agent chatter.

## AI-generated-code detection (vision §12)

Report **AI-origin likelihood** with evidence (comment language mix, hallucinated API patterns,
nonexistent deps, boilerplate signatures) — never an absolute "this was written by AI" claim.

## Prompt & quality controls

- Prompts are versioned at call sites; prompt regressions are caught by the test suite
  (`tests/` verify JSON contracts, not prose).
- Any non-JSON or empty response → treated as *not verified* (fail-closed), matching the
  zero-hallucination rule.
- AI quality benchmarks (TP/FP/FN, fix-success, regression rate) are a Phase 4 deliverable with a
  reproducible methodology — no unverifiable accuracy percentages.