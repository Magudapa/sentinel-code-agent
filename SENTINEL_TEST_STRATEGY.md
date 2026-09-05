# Sentinel Test Strategy

Goal (vision §91–92, §147): no feature is *done* until it is implemented, tested, documented,
secured, observable, integrated, verified. Sentinel scans itself; its CI must die on real problems.

## Layers

| Layer | Tool | Scope |
|---|---|---|
| Unit | pytest | models, diffparse, config, rules, verifier, detectors, analyzers |
| Integration | pytest | providers (local), reviewer pipeline, API (FastAPI TestClient) |
| Gate | pytest-cov (later) | coverage floor, added for Phase 2 quality gates |
| SAST | bandit | own repo; CI dies on findings |
| Lint | ruff | formatting/imports; CI dies on findings |
| E2E | GitHub Actions | `sentinel review` on a fixture repo (e2e) |
| Security gates | built-in | empirical rule gate, secret redaction, path-traversal guard, fail-closed AI |

## Rule books must be tested as truth

`tests/test_rules_book.py` parameterizes the **empirical gate over every shipped rule**:

- fires on `vulnerable_example`, silent on `safe_example`
- duplicate IDs rejected across books; author required; `ai_verified` never hand-set
- `ai_verified: true` can only be produced by `verify_rule` passing BOTH gates

A bot/contributor rule that fails Gate 1 fails CI → the marketplace is self-policing.

## API (Phase 0) test matrix

- `GET /health` → ok + model availability (no model load)
- `POST /review` local happy path → findings + `verdict_score` + `status`
- path-traversal guard → absolute path outside workspace root → 400 (security test)
- schema errors → 422 (missing required fields)
- rulesets endpoints → inventory + verify results shape

## AI correctness guarantees

Fail-closed assertions (must never regress):

1. `verify_rule` returns `verified=True` only when empirical **and** model verdict PASS.
2. A garbage/non-JSON model response → `REVISE`, never PASS (test with a fake ModelClient).
3. LOk model `is_available()` false → explain skipped, status INCOMPLETE, no fabricated success.
4. Auto-fix patch must be syntactically valid before `validated=True`.

## Security tests (grow with the project)

- Tenant isolation (Phase 8): cross-tenant reads denied at service layer.
- Prompt injection: adversarial text in code snippets cannot flip verdicts (verdict is
  deterministic); test the gate with injected examples as `vulnerable_example` content.
- Sandbox escape (Phase 5): untrusted repo code cannot reach host FS/network.
- Secret redaction: exporter never prints configured secrets.

## E2E fixture repo

`tests/fixtures/e2e-repo` (also demos `D:\AI\Temp\opencode\e2e-repo`):
baseline commit + staged `vulnerable_app.py`; run full `review` including bandit/ruff and
expect known finding set. Guarded as a smoke test in CI (fast, no network).

## Failure honesty

A test that cannot run (e.g., analyzer binary missing) is **skipped**, never passed. Any place that
would otherwise lie about verification must assert `INCOMPLETE` instead (vision §116–117).

## Definition of done checklist (per feature)

- [ ] tests added (positive + negative)
- [ ] `pytest -q` green
- [ ] `ruff check .` clean
- [ ] `bandit -q -r sentinel -x sentinel/tests -c pyproject.toml` rc=0
- [ ] docs updated (API_SPEC/ROADMAP as applicable)
- [ ] committed & pushed; CI workflows green