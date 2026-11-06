# r/selfhosted draft

**Title:** Self-hosted OpenAI-compatible privacy proxy: current deployment and the caveats

There is a gap between “use a local model” and “I sometimes send prompts to a hosted model but want obvious identifiers removed first.” I have been prototyping a small FastAPI proxy for that second case.

It listens on loopback by default, accepts `/v1/chat/completions` and `/v1/models`, and is intended to work with the OpenAI Python SDK after changing `base_url`. It can forward to an allowlisted OpenAI-compatible upstream. For detected values it substitutes typed tokens such as `<EMAIL_1>`, then restores known tokens in normal and SSE responses. The token map is in memory and request-scoped by default; conversation scope is opt-in and TTL-bound.

The Docker Compose example binds the host port to `127.0.0.1`, runs read-only with dropped capabilities, and stores only value-free audit metadata. No account, hosted tier, telemetry, or external control plane.

Important caveat: the committed benchmark is currently a synthetic smoke test, not a claim of real-world recall. Presidio, public OpenPII rows and Ollama utility evaluation are marked skipped until those optional dependencies/data/model are available. The proxy also does not inspect image/audio/tool payloads or defeat deliberate encoding/obfuscation.

Code: https://github.com/OWNER/veilrelay (replace after publishing)

Feedback on the Compose hardening, upstream allowlist model, and practical deployment risks would be useful.
