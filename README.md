# nox-plugin-triage-agent

**Prioritises the findings a nox scan already produced.**

## Overview

`nox-plugin-triage-agent` runs *after* a nox scan and answers the question detection cannot: what should be looked at first. It sorts the scan's findings into four review queues — **immediate**, **scheduled**, **backlog** and **informational** — and attaches that verdict to each finding.

Scanners produce findings; triage decides which ones matter right now. Severity alone does not settle it. Severity describes how bad a *class* of bug is, while the review order also depends on how sure the scanner is and on whether the code runs in production at all. A critical finding the engine flagged with low confidence, sitting in a test fixture, is not the first thing anyone should read.

The plugin emits **enrichments keyed by finding fingerprint, never findings of its own**. A triage verdict is a statement *about* a finding, so it annotates the queue rather than lengthening it — installing this plugin does not change how many findings a scan reports.

All classification is deterministic, offline and read-only. An opt-in LLM pass can refine severities on top, and is never required.

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

No configuration required. The plugin receives findings from nox's post-scan phase; it does not read the source tree and takes no scan path.

### Optional: LLM-assisted refinement

Set `ai_triage: true` to layer an LLM severity review on top of the deterministic classification. If the provider is unreachable or answers with nonsense, every finding keeps the rule-based priority it would have had anyway — the LLM can only refine, never replace.

| Variable | Purpose |
|---|---|
| `NOX_AI_PROVIDER` | `openai`, `anthropic`, `gemini`, `ollama`, `cohere` |
| `NOX_AI_API_KEY` | provider credential |
| `NOX_AI_MODEL` | model name |
| `NOX_AI_BASE_URL` | override endpoint (self-hosted, proxies) |

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

1. **Post-scan invocation.** nox completes its scan, then hands the plugin a `ScanContext` carrying the findings, packages and AI components it produced. The plugin never walks the workspace.

2. **Deterministic classification.** Each finding is classified from its severity, the scanner's confidence and its location, as described above. The same finding always receives the same priority.

3. **Optional LLM refinement.** With `ai_triage: true`, an LLM pass may adjust severities; failures degrade to the deterministic result.

4. **Enrichment output.** Verdicts are emitted as enrichments linked to findings by fingerprint. Nothing is added to the finding set, so the scan's finding count is independent of whether triage ran.

## Contributing

Contributions welcome — open an issue or a pull request on the [GitHub repository](https://github.com/Nox-HQ/nox-plugin-triage-agent).

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for your changes
4. Ensure `make test` and `make lint` pass
5. Submit a pull request

## License

Apache-2.0
