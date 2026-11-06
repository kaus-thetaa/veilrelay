# r/Python draft

**Title:** FastAPI middleware-style project: reversible PII tokenization, chunk-safe SSE rewriting, and tests

I am sharing a Python project for review: a self-hosted FastAPI proxy that scans OpenAI-compatible chat messages, replaces supported PII/credential patterns with typed placeholders, forwards to an allowlisted upstream, and restores known placeholders in the response.

A few implementation details Python folks may find interesting:

- Detector plugins return span metadata rather than source values.
- Luhn, Verhoeff and IBAN checks sit behind regex candidate extraction.
- The token vault is in-memory with a TTL and best-effort reference clearing.
- The SSE rewriter buffers a possible placeholder suffix so `<EMA` followed by `IL_1>` is restored correctly.
- Hypothesis round-trip tests are included, but Hypothesis could not be installed in the offline build environment; those tests are marked skipped locally and will run in CI.
- Audit records contain only entity types and counts.

The initial benchmark is synthetic-only. Presidio and the Ollama utility benchmark are marked skipped, so the README avoids comparative or utility claims.

Repo: https://github.com/OWNER/veilrelay (replace after publishing)

I'd particularly welcome code review around the SSE parser boundary conditions, FastAPI resource cleanup, type checking, and packaging.
