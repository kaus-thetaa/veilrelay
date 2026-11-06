# LinkedIn draft

A small but important lesson from building an LLM privacy proxy: a perfect score on a tiny synthetic PII fixture proves that the fixture is useful for regression tests. It does not prove real-world detection quality.

I have been working on VeilRelay, a self-hosted OpenAI-compatible proxy that detects supported PII and common credentials locally, replaces them with typed placeholders, and restores echoed values in the model response—including streamed SSE chunks.

The MVP includes checksum-aware identifiers (Luhn, Verhoeff and IBAN), Indian PAN/IFSC/UPI patterns, common provider credentials, configurable YAML actions, fail-closed defaults, request limits, upstream host allowlisting, and value-free audit logs.

The benchmark is intentionally honest about what's not measured yet: Presidio could not initialize because its optional dependency was unavailable; the public Ai4Privacy sample was not downloaded; and utility preservation has not been run against a configured Ollama model. Those states are reported as skipped, not guessed.

The threat model is equally explicit: this reduces accidental leakage of recognized patterns. It does not stop deliberate obfuscation, protect a compromised host, or control provider-side retention and attacks.

I would appreciate security and benchmark-methodology review ahead of a v0.1.0 release.

Repository: https://github.com/OWNER/veilrelay
