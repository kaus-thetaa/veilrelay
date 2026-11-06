# Show HN draft

**Title:** Show HN: VeilRelay – a self-hosted OpenAI-compatible proxy for local PII redaction

**Body:**

VeilRelay sits between an application and an OpenAI-compatible chat API. The application changes its `base_url`; VeilRelay detects supported PII and common secrets before forwarding, substitutes typed placeholders, and restores values in returned text, including streamed SSE responses.

The project is MIT-licensed, self-hosted, and has no accounts, hosted tier, or telemetry. It binds to loopback by default, is fail-closed by default, restricts the configured upstream host with an allowlist, and writes audit records containing only entity types and counts.

I built it because “don't send sensitive data to an LLM” is good advice but often difficult to enforce consistently in developer workflows. A local proxy creates a reviewable control point.

The benchmark is deliberately preliminary: a small synthetic regression set has been run; Presidio comparison, the optional CC-BY-4.0 OpenPII sample, and Ollama utility testing are currently marked skipped. I am not claiming production detection quality or that placeholder redaction preserves answer quality.

I am especially interested in feedback on threat-model gaps, false-positive handling, streaming behavior, and whether the benchmark methodology is useful.

Repo: https://github.com/OWNER/veilrelay
