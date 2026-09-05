# Sentinel Plugin Specification

Stable, tiny interfaces so third parties and the Community Rule Marketplace plug in without forks.
Zero new dependencies to *use* Sentinel; plugins are normal Python packages discovered by entry
points (via `importlib.metadata`) so they work offline and in air-gapped installs.

## Discovery

Plugins register via `[project.entry-points."sentinel.plugins"]`:

```toml
[project.entry-points."sentinel.plugins"]
my-analyzers = "myplugin:MyAnalyzerPack"
```

`SentinelPlugin` is the base capability each pack may implement:

```python
class SentinelPlugin:
    name = "my-pack"
    version = "0.1.0"

    def initialize(self, context):  # sentinel.config.SentinelConfig, logger, workspace
        ...

    def analyzers(self) -> list:      # Content/FileAnalyzer instances
        return []

    def report(self, report) -> str:  # optional extra report section
        return ""
```

## Analyzer plugins (fast path)

Implement the existing interfaces in `sentinel/analyzers/base.py`:

- `ContentAnalyzer.analyze(changeset) -> list[Finding]` — line/text analysis, no disk needed.
- `FileAnalyzer.analyze_files(path, files) -> list[Finding]` — needs a working tree.

Both get the unified `Finding` model. Nothing else to do: the plugin's analyzers are automatically
`register_content` / `register_file`-wired and participate in resilience wrappers (one bad plugin
never kills a scan — same guarantee as first-party analyzers).

## Rule-book plugins (Community Rule Marketplace)

The *primary* plugin surface (vision §73, SENTINEL_ARCHITECTURE §2). A contributor submission is a
single `rules/books/<language>.yml` entry OR a full book PR. Submission contract:

1. `id`, `language`, `description`, `severity`, `regex` (required); `message`, `fix`,
   `author` (required for community), `source`, `vulnerable_example`, `safe_example`, `category`.
2. **Empirical gate** must pass: regex fires on `vulnerable_example`, silent on `safe_example`
   (`rulesset verify` / `tests/test_rules_book.py`).
3. **AI gate** must pass: independent model rubric → `PASS`; then and only then
   `ai_verified: true` is stamped server-side. `author` is preserved and displayed.
4. Submissions can never set `ai_verified` by hand.

## LLM plugins

`sentinel/model/client.py` is already adapter-shaped: any provider implementing the same
`chat(system, user) -> str` contract can be added without touching the pipeline. Future:
`LLMProvider` interface + model router (cheap/strong/local/specialized) — see SENTINEL_AI_SPEC.

## Integration / report / policy / runtime plugins (later phases)

- **Integration** — webhook → handlers (GitHub/GitLab/Slack/Teams/Jira/Slack) POST findings.
- **Report** — add Markdown/JSON/SARIF exporters (SARIF already core).
- **Policy** — YAML policy rules evaluated against a report (roadmap Phase 8).
- **Runtime** — receive runtime events, produce findings (roadmap Phase 7).

## Contract rules

- No plugin may mutate scanning behavior silently: initializers get an explicit enable flag.
- Secrets are never logged; plugin output passes through the same redaction.
- Versioned entry points → safe upgrades; a broken plugin degrades to `INCOMPLETE`, never blocks
  other analyzers, and is never reported as a silent PASS (vision §116).