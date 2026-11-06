# Changelog

All notable changes to this project are documented here.

## [0.1.0] - 2026-11-06

### Added

- Local FastAPI proxy for OpenAI-compatible `/v1/chat/completions` and `/v1/models`.
- Regex/validator detection for common PII and Indian identifiers, plus common provider credential formats and entropy fallback.
- Per-request reversible typed placeholders, TTL vault, and split-chunk SSE restoration.
- YAML entity actions, exact allowlist, custom regex rules, optional spaCy NER, and value-free JSONL auditing.
- CLI (`serve`, `scan`, `bench`), Dockerfile, Compose example, CI workflow, threat model, benchmark harness, and launch drafts.

### Limitations

- Alpha release. Public OpenPII, Presidio and Ollama utility benchmark execution was not completed in the initial offline environment; see `bench/results/summary.json` and `bench/METHODOLOGY.md`.
- No multimodal/file scanning, authentication layer, TLS termination, or production security review.
