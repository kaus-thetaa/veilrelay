# Architecture and implementation decisions

This document records choices made for the initial MVP. Revisit these before treating the software as production-ready.

## Naming

- Working name: **VeilRelay**; Python distribution: `veilrelay`; import package: `veilrelay`; CLI: `veil`.
- The requested `llm-veil`/`llmveil` namespace was not used because PyPI listed an existing `llmveil` package at the time of implementation. `PromptVeil` and `Veilgate` were also already used by projects in the same broad space. A PyPI JSON request for `veilrelay` returned 404 during the check, but this does not reserve the name or guarantee GitHub/social/domain availability.

## Scope and design

- Python 3.11+ with FastAPI, httpx, PyYAML and Uvicorn; the core detector has no model downloads or hosted service dependency.
- Default bind address is `127.0.0.1`. Default upstream is OpenAI's `/v1` endpoint; the configured hostname is the default allowlisted hostname. Alternate upstreams (including local Ollama) require explicit configuration and host allowlisting.
- Only `/v1/chat/completions` and `/v1/models` are in MVP scope. The proxy transforms text content in chat messages. It does not claim coverage of images, audio, tool execution, embeddings, or other API routes.
- Detection layers are deterministic and pluggable. Checksums are used where practical. The UPI validator recognizes a curated set of common PSP handles to avoid classifying arbitrary `name@host` strings as payment IDs; unfamiliar handles can be covered with custom rules. Entropy detection is conservative and intended as a fallback, not a complete secret detector.
- The base install is deliberately light. NER is opt-in and depends on spaCy plus a separately installed language model; VeilRelay does not download a model at runtime.
- Policy defaults to `redact` for detected entities; `fail_mode` defaults to `closed`. `allow` is explicit. `mask` emits a non-reversible display mask; `block` rejects the request.
- Vault scope is per request by default. An optional conversation manager enables consistent placeholders across requests only when a trusted caller supplies a conversation ID. Conversation IDs are not authentication; shared vault namespaces also include a one-way digest of the caller Authorization credential, and anonymous calls stay request-scoped.
- The audit schema contains only entity types/counts and non-sensitive operational metadata. Request bodies, match values, and mappings are forbidden from logs.
- Upstream requests do not follow redirects; host allowlisting is enforced against the configured URL. Operators should also use OS/container egress restrictions. A host allowlist is not a substitute for network isolation or protection against all DNS-rebinding scenarios.

## Benchmark integrity

- Do not publish guessed or extrapolated scores. Every result table must be generated from committed raw files by the harness.
- The benchmark supports a local synthetic labelled corpus and an optional public-data adapter. Ai4Privacy's OpenPII 1M page advertises CC-BY-4.0; earlier Ai4Privacy releases have materially different terms, including academic-only and tiered licenses. The optional `ai4privacy/pii-masking-nano-1k` card identifies the sample as CC-BY-4.0 and synthetic; the benchmark must cite the exact dataset version/card and retain attribution when used. No dataset payload is checked into this repository unless its redistribution terms are confirmed.
- Presidio is an optional benchmark dependency and is evaluated with its default Analyzer configuration when installed. The default baseline is a deliberately simple regex matcher. Missing optional dependencies or unavailable datasets are recorded as skipped, not represented as zero scores.
- Utility evaluation uses deterministic exact-match/extractive tasks. It measures whether placeholders preserve answerability for a small controlled set; it does not establish semantic quality for arbitrary LLMs.

## Release posture

- This is an alpha MVP and not a certified DLP system. Security review, dependency audit, test results and benchmark outputs must be considered independently from marketing copy.
