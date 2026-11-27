# nox-plugin-triage-agent

[![nox security grade](.github/nox-badge.svg)](https://github.com/nox-hq/nox)

**Prioritises the findings a nox scan already produced.**

## Overview

`nox-plugin-triage-agent` runs *after* a nox scan and answers the question detection cannot: what should be looked at first. It sorts the scan's findings into four review queues — **immediate**, **scheduled**, **backlog** and **informational** — and attaches that verdict to each finding.

Scanners produce findings; triage decides which ones matter right now. Severity alone does not settle it. Severity describes how bad a *class* of bug is, while the review order also depends on how sure the scanner is and on whether the code runs in production at all. A critical finding the engine flagged with low confidence, sitting in a test fixture, is not the first thing anyone should read.

The plugin emits **enrichments keyed by finding fingerprint, never findings of its own**. A triage verdict is a statement *about* a finding, so it annotates the queue rather than lengthening it — installing this plugin does not change how many findings a scan reports.

The priority classification is deterministic, offline and read-only. An opt-in LLM pass can additionally judge each finding as a likely true or false positive against its source. That pass sends redacted code snippets to the provider you configure, is off by default, and only ever annotates: it never changes a finding or its severity.

> **Changed in 0.3.0.** Earlier versions ran their own regex sweep over the source tree and emitted `TRIAGE-001`–`TRIAGE-004` findings. That duplicated detection nox core already does, more crudely than a real taint engine, and every improvement to the core scanner made the duplication worse. The `scan` tool is gone; the tool is now `triage`. See [CHANGELOG.md](CHANGELOG.md) for the migration.

## Use Cases

### Security team review queue management

A team receiving hundreds of findings per sprint cannot review them all. Triage classifies each one so the immediate queue gets attention first and the backlog stays visible without competing for it — maximising security impact per hour of review time.

### Agent-assisted security review

Agents using nox over MCP get structured priority metadata they can summarise ("3 immediate findings, 12 scheduled for next sprint") and turn into prioritised work items.

### Developer self-service checks

Developers scanning before a pull request can see which findings to fix before merging, which to ticket, and which are context rather than defects.

### Security posture trending

Consistent priority classification makes trending possible: whether immediate-priority findings are falling sprint over sprint, and whether the backlog is being worked.

## How priorities are assigned

The baseline comes from the finding's severity and the scanner's confidence:

| Severity | Confidence | Priority |
|---|---|---|
| Critical | any | immediate |
| High | high / medium | immediate |
| High | low | scheduled |
| Medium | high | scheduled |
| Medium | low / medium | backlog |
| Low | any | backlog |
| Info | any | informational |
| Unspecified | any | backlog |

Two adjustments then apply, each moving the finding one step down the queue:

- **Low confidence on an immediate finding.** The scanner is saying it might be wrong; that belongs behind the findings it is sure about.
- **Non-production code.** Test, fixture and example code does not run in production. Still worth fixing — a vulnerable test helper misleads, and fixtures get copied — but it does not compete with live code for attention.

Non-production detection matches **whole path segments** (`testdata/`, `__tests__/`, `e2e/`, `examples/`, …) and filename conventions (`_test.go`, `.spec.ts`, `test_*.py`, `*Test.java`, …). It deliberately does not substring-match: directories named `latest`, `contest` or `attestation` contain production code, and a substring check would quietly demote real findings in them.

An **unspecified** severity is treated as a gap in the rule that produced the finding, not as evidence the finding is unimportant — it lands in backlog, where it stays visible enough to be noticed.

## Output

One enrichment per finding:

| Field | Value |
|---|---|
| `kind` | `triage` |
| `finding_fingerprint` | the fingerprint of the finding being triaged |
| `title` | `Triage: <priority>` |
| `body` | markdown: the priority, why it was assigned, and the location |
| `metadata.priority` | `immediate` \| `scheduled` \| `backlog` \| `informational` |
| `metadata.rank` | `0`–`3`, most to least urgent — sortable without parsing names |
| `metadata.rationale` | the sentence explaining the verdict |

## Configuration

No configuration required for prioritisation. The plugin receives findings from nox's post-scan phase and takes no scan path. It reads the source tree only when the AI pass is enabled, and then only the lines around a finding.

### Optional: AI verdicts on each finding (off by default)

Setting `NOX_AI_TRIAGE=true` (or the `ai_triage` input, where the caller can pass one) asks an LLM to judge each finding against the code around it. Read this before enabling it:

- **Source code leaves your machine.** For every judged finding the plugin sends the rule ID, CWE, message, file path and line, and a snippet of roughly 20 lines either side (capped at 6 KiB) to the provider you configured. Nothing is sent unless you opt in. nox's `--offline` flag does not stop this call; see [Offline](#offline).
- **Secrets are redacted before anything is sent.** For a secrets rule (`SEC-*`) the matched line's string literals and values are masked. In every snippet, common credential shapes (`AKIA…`, `ghp_…`, `xox[abp]-…`, `sk-…`, JWTs, bearer tokens, URL credentials, PEM private-key blocks and long high-entropy quoted strings) are masked. Redaction is best effort: treat the snippet as code you are choosing to share.
- **Paths are confined to the workspace.** The snippet reader rejects absolute paths, `..` escapes and symlinks that resolve outside the workspace root. A finding whose file cannot be read safely is not sent at all and gets an `uncertain` verdict.
- **Verdicts are annotations.** The result is a second enrichment per judged finding (`kind: ai-triage`). The plugin never changes a finding's severity or confidence, never drops a finding, and never adds one. Scan results, counts and gates are identical with and without it. The deterministic `triage` priority enrichment is unchanged.
- **Verdicts are cached.** Each verdict is stored under `os.UserCacheDir()/nox/triage-agent/`, keyed by the finding fingerprint, a hash of the redacted snippet, the pack version, the provider and the model. A re-run with the same inputs makes no call (`cached: true`). Only the verdict and a one-sentence rationale are stored, never source. Set `ai_cache: false` (or `NOX_AI_CACHE=false`) to disable.
- **The key stays in the environment.** `NOX_AI_API_KEY` is read from the environment only and is never logged, echoed in an error or written to an enrichment. A failed call becomes `ai_verdict=uncertain` with an error class (`timeout`, `rate_limited`, `auth`, `connection`, `http_<status>`), never the provider's response text.

Enrichment metadata on each judged finding:

| Field | Value |
|---|---|
| `ai_verdict` | `true_positive` \| `false_positive` \| `uncertain` |
| `ai_rationale` | one short sentence |
| `ai_provider`, `ai_model` | what answered |
| `pack_version` | version of the embedded triage pack |
| `cached` | `true` when answered from the cache |

| Setting (input / environment) | Default | Purpose |
|---|---|---|
| `ai_triage` / `NOX_AI_TRIAGE` | `false` | enable the AI pass |
| `ai_cache` / `NOX_AI_CACHE` | `true` | verdict cache |
| `ai_max_findings` / `NOX_AI_MAX_FINDINGS` | `200` | most urgent N findings are judged |
| `ai_concurrency` / `NOX_AI_CONCURRENCY` | `4` (max 16) | parallel calls |
| `ai_timeout` / `NOX_AI_TIMEOUT` | `60` | seconds per call |
| `ai_min_severity`, `ai_skip_high_confidence`, `ai_only_rules`, `ai_skip_rules` | none | route only the findings that need a second opinion (input only) |

nox's post-scan host sends scan context but no tool input, so in a normal `nox scan` the environment variables are the way to configure this.

| Variable | Purpose |
|---|---|
| `NOX_AI_PROVIDER` | `openai` (default), `anthropic`, `gemini`, `ollama`, `cohere`, `bedrock`, `copilot` |
| `NOX_AI_API_KEY` | provider credential |
| `NOX_AI_MODEL` | model name (Anthropic default: `claude-sonnet-5-5`) |
| `NOX_AI_BASE_URL` | override endpoint (self-hosted, proxies) |

If the AI pass cannot run (no key, unknown provider), a warning diagnostic says so and every finding keeps its deterministic priority.

#### The triage pack

Prompts come from a versioned pack embedded in the binary (`pack/`): a base system prompt plus short instructions for the finding's class (injection, crypto/secrets/config, authentication/session, authorization, information exposure, mass assignment, other), chosen from its CWE. The pack version is recorded on every verdict and is part of the cache key. `pack/examples/` is a hook for worked examples and is empty for now.

#### Offline

The AI pass is a network call made by this plugin process. As of nox 1.70 the post-scan host does not gate plugins on `--offline` and does not sandbox their sockets; the declared `network_hosts` are checked against policy when the plugin is registered, not enforced on connections. If you need a guarantee of zero network, do not set `NOX_AI_TRIAGE`, or do not install the plugin.

## Installation

### Via nox (recommended)

```bash
nox plugin install Nox-HQ/nox-plugin-triage-agent
```

### Standalone

```bash
git clone https://github.com/Nox-HQ/nox-plugin-triage-agent.git
cd nox-plugin-triage-agent
make build
```

## Development

```bash
make build   # build the plugin binary
make test    # run tests with race detection
make lint    # run the linter
make clean   # clean build artifacts

docker build -t nox-plugin-triage-agent .
```

## Architecture

The plugin speaks the nox Plugin SDK over stdio and declares a single tool, `triage`, with `requires_scan_context: true`.

1. **Post-scan invocation.** nox completes its scan, then hands the plugin a `ScanContext` carrying the findings, packages and AI components it produced. The plugin never walks the workspace; with the AI pass on it reads only the window around each judged finding.

2. **Deterministic classification.** Each finding is classified from its severity, the scanner's confidence and its location, as described above. The same finding always receives the same priority.

3. **Optional AI verdicts.** With `NOX_AI_TRIAGE=true`, each finding is judged on its own prompt with a redacted, workspace-confined snippet; answers are cached and failures degrade to `uncertain`. Severities are never touched.

4. **Enrichment output.** Priorities and verdicts are emitted as enrichments linked to findings by fingerprint. Nothing is added to the finding set, so the scan's finding count is independent of whether triage ran.

## Contributing

Contributions welcome — open an issue or a pull request on the [GitHub repository](https://github.com/Nox-HQ/nox-plugin-triage-agent).

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for your changes
4. Ensure `make test` and `make lint` pass
5. Submit a pull request

## License

Apache-2.0
