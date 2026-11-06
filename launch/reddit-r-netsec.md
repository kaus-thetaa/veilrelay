# r/netsec draft

**Title:** A first benchmark pass for LLM prompt PII redaction is much less conclusive than a leaderboard

I have been testing a small, self-hosted OpenAI-compatible proxy that detects common PII and credentials before a chat request leaves a developer's machine, substitutes typed placeholders, and restores values locally when the model echoes them.

The useful finding so far is methodological: a 24-row synthetic fixture is good for catching implementation mistakes, but it is not evidence of production detection quality. The initial fixture run matched its annotated spans, while the Presidio comparison could not run in the offline environment, the optional Ai4Privacy sample was not downloaded, and the Ollama utility tasks were not configured. Those are explicitly recorded as skipped rather than converted into zeroes or fabricated estimates.

The implementation currently includes checksum validators for Luhn/Verhoeff/IBAN, Indian PAN/IFSC/UPI patterns, credential patterns, a conservative entropy fallback, a request-scoped in-memory mapping, and a buffered SSE rewriter for tokens split across chunks. The default behavior is fail-closed. Audit JSONL contains types/counts only.

Repository: https://github.com/OWNER/veilrelay (replace after publishing)

I would especially value review of the threat model, detector false-positive traps, and the benchmark's exact-span methodology. Known limits: no image/audio/file/tool-call scanning, no protection from deliberate obfuscation or a compromised host, and no evidence yet that placeholders preserve model utility on a real local model.
