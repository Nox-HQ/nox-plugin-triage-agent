# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
