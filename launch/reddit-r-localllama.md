# r/LocalLLaMA draft

**Title:** Does reversible placeholder redaction preserve task utility? I have the harness, but not the evidence yet

A privacy proxy can remove an email or credential from a prompt and send `<EMAIL_1>` instead. The unresolved question is whether a model still completes the user's task when the real identifier is replaced, and whether restoration makes the final answer useful.

I have a small local-first proxy and an Ollama utility harness covering summarization, extraction and Q&A. The harness compares answers for the same prompt before and after redaction with a simple expected-term rubric. I have deliberately not published a utility score: no `OLLAMA_MODEL` was configured in the current run, so the results file says `skipped`.

The detector smoke benchmark covers synthetic Indian identifiers, email/phone, payment/account numbers, secrets, and mixed prompts. It is not representative data and the all-matches result is not a general recall claim. The public Ai4Privacy OpenPII Nano dataset is an optional CC-BY-4.0 input; it is not included in the repo.

Project: https://github.com/OWNER/veilrelay (replace after publishing)

I'd appreciate feedback on the utility-task design. What would be a sensible local model matrix and what kinds of tasks best expose placeholder-related failures without turning this into a model leaderboard?
