# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Breaking: the plugin prioritises findings instead of re-deriving them.**
  It used to run its own regex sweep over the source tree and emit
  `TRIAGE-001`–`TRIAGE-004` findings. That duplicated detection nox core already
  does — more crudely than a real taint engine — so every improvement to the
  core scanner made the duplication worse rather than better, and the plugin's
  output had to be de-duplicated against core findings describing the same code.
  Today's `0.2.3` false-positive fixes were patching a shape that should not
  have existed.

  The plugin is now a **post-scan** tool (`requires_scan_context: true`). nox
  hands it the completed scan's findings and it answers what detection cannot:
  what to look at first.

  **Migration.** The tool is renamed `scan` → `triage`, and it takes no
  `workspace_root`. It emits **enrichments keyed by finding fingerprint, never
  findings** — so installing the plugin no longer changes how many findings a
  scan reports. Anything consuming `TRIAGE-00x` findings should read
  `metadata.priority` (or the sortable `metadata.rank`) off the enrichment
  attached to the core finding instead.

- Priority now derives from severity, the scanner's confidence, and whether the
  code runs in production, rather than from which regex matched. A finding the
  engine flagged with low confidence, or one located in test/fixture/example
  code, is demoted one queue — it is still worth fixing, but it does not
  outrank live code the scanner is sure about.

### Removed
- The `scan` tool, the four `TRIAGE-00x` regex rule families, the workspace
  walker, and the comment/sanitizer/auto-escape guards they needed. The guards
  existed to stop the regex sweep firing on prose and mitigated code; with no
  sweep there is nothing for them to guard.

## [0.2.3] - 2026-08-02

### Fixed
- Stop flagging prose, sanitized input and auto-escaped output. Rules matched
  anywhere in a file, so comments and documentation were reported as findings;
  input passed through a sanitizer and output rendered by an auto-escaping
  template are now recognised as mitigated rather than flagged.

### Changed
- nox SDK and the CI action pin both move to v1.26.0, so the plugin builds
  against the same nox that scans it.

## [0.2.2] - 2026-07-20

### Changed
- nox SDK v1.13.0 (loopback bind + gRPC token auth), grpc 1.82.1.

## [0.2.1] - 2026-07-05

### Fixed
- TRIAGE-001 no longer flags identifiers that merely contain `eval`/`exec` as a
  substring (`retrieval()`, `medieval()`, `execute_plan()`, `evaluateScore()`)
  as dangerous code execution — the patterns are now word-anchored (`\beval\(`,
  `\bexec\(`).

### Added
- `testdata/clean/` negative fixtures and `TestCleanCodeNoFindings` asserting
  ordinary business logic produces zero triage findings.

## [0.2.0]

### Added
- Opt-in LLM-assisted severity adjustment via `ai_triage: true` input parameter (Phase 7d)
- Multi-provider support via agent-go `plannerllm.Provider` interface (OpenAI, Anthropic, Gemini, Ollama, Cohere)
- Environment-based provider config: `NOX_AI_PROVIDER`, `NOX_AI_API_KEY`, `NOX_AI_MODEL`, `NOX_AI_BASE_URL`
- Structured JSON triage response with true/false positive classification and reasoning
- Graceful degradation: returns original findings unchanged on LLM failure
- `provider.go`, `ai_triage.go`, `ai_triage_test.go` — 9 new tests (20 total)

## [0.1.0] - 2026-02-22

### Added
- Initial plugin implementation with 4 deterministic triage rules (TRIAGE-001–004)
- Priority classification: immediate, scheduled, backlog, informational
- File scanning for Go, Python, JavaScript, TypeScript
- SDK conformance and track conformance tests
- CI/CD, lint config, pre-commit hooks
