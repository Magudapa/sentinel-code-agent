# Sentinel API Specification

**Version:** v1 (unit versioned endpoints). Phase-0 surface; more endpoints land with each vendor
phase. Returns JSON everywhere; errors use RFC-7807-ish `{detail}` (FastAPI default).

Base path: `/api/v1`. The server must be started with `sentinel serve` (binds `127.0.0.1`).

## Conventions

- `severity`: `info | low | medium | high | critical`
- `verdict_score`: 0–100 (higher = healthier), from `compute_verdict_score`
- `trust_score`: 0–100 final trust value (Phase-0 ≈ verdict_score; weighted risk engine later)
- All POST bodies are JSON. Unknown fields are ignored; missing required fields → 422 via Pydantic.

## Endpoints (implemented in this phase)

### `GET /api/v1/health`
Probe. Returns runtime + model reachability without loading the model.

```json
{ "ok": true, "version": "0.1.0", "model": { "provider": "ollama", "model": "qwen2.5-coder:3b", "available": false } }
```

### `POST /api/v1/review`
Run a review. `provider` `local` scans a workspace (`path` + optional `range`/`diff`); `github`/
`gitlab` scan `repo` + `pr`. `config` optional path to a `.sentinel.yml`.

```json
{ "provider": "local", "path": "/abs/workspace", "range": "main..feature", "diff": "optional raw unified diff or base64", "explain": false, "config": "" }
```

Response:

```json
{
  "status": "VERIFIED",                    // VERIFIED | INCOMPLETE (AI skipped) | FAILED
  "trust_score": 87, "verdict_score": 87,
  "provider": "local", "target": "main..feature",
  "counts": {"high": 0, "medium": 1},
  "blocking_findings": 0,                  // critical count (fail gate)
  "findings": [ { "rule_id": "PY-001", "severity": "medium", "file": "api.py", "line": 3,
                   "description": "Cleartext HTTP request", "evidence": "regex", "suggested_fix": "…" } ],
  "policy": "PASSED",                      // FAILED when any critical finding
  "created_at": "…Z"
}
```

Security: `path` must resolve within the configured `workspace_root` (default: `~/.sentinel`).
Absolute paths outside root → 400. No arbitrary command endpoints.

### `GET /api/v1/rulesets?language=python`
Inventory of the verified rule books (OUR DIFFERENTIATOR — open, attributed, gated).

```json
{ "languages": { "python": { "rules": 11, "verified": 0, "authors": ["Magudapa"] } } }
```

### `POST /api/v1/rulesets/verify`
Run the two-gate verification. `language` optional (all books if empty). Default performs the
deterministic empirical gate always + AI gate only when the configured model is reachable; never
mutates books unless `write: true`.

```json
{ "language": "python", "write": false }
```

```json
{ "results": [ { "rule_id": "PY-001", "empirical_passed": true, "ai_verdict": "PASS", "verified": true } ] }
```

## Verification object (vision §125)

`status` semantics (vision §116–117):
- `VERIFIED` — every configured analyzer and AI gate executed successfully and no blocking finding.
- `INCOMPLETE` — one or more analyzers/model did not run (e.g., Ollama down); never a silent pass.
- `FAILED` — blocking findings (≥1 critical) or hard pipeline error.

## Future (per phase)

| Area | Planned endpoints |
|---|---|
| SCA/SBOM | `POST /scan{sbom,sca}`, `GET /sboms/{id}`, `GET /dependencies` |
| Secrets | `POST /scan/secrets` (git history too), redacted findings |
| Quality | `POST /scan/quality`, `GET /quality-gates` |
| Policies | `PUT /policies`, `POST /policies/eval`, `GET /policy-results` |
| Attack paths | `GET /attack-paths/{repo}`, `POST /attack-paths/analyze` |
| Agent loop | `POST /agent/verify`, `GET /agent/handoff/{scan}` (vision §45) |
| MCP | same actions via MCP server (`mcp_server.py`) not HTTP |
| Events | `GET /events` SSE stream as scans complete |
| Flatten | REST ⊇ CLI ⊇ MCP ⊇ Plugin — one behavior, many surfaces |

## Error codes

`400` bad target/path-traversal · `404` provider/repo · `422` schema · `500` pipeline failure
(never returns a fabricated VERIFIED).