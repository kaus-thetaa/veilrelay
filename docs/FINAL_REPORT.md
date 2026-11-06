# VeilRelay v0.1.0 — build report

**Build date:** 2026-11-06  
**Repository state:** local Git repository on `main`; no remote configured  
**License:** MIT

## Delivered

- FastAPI proxy routes for `/v1/chat/completions` (JSON and SSE) and `/v1/models`, with an OpenAI-compatible request shape and configurable upstream.
- Pluggable span-based detection for email, phone, IP, Luhn card numbers, IBAN, SSN, Aadhaar/Verhoeff, PAN, IFSC, UPI, provider credential formats, JWTs, PEM private keys, database URLs, and a conservative entropy fallback.
- In-memory reversible typed placeholders, request-scoped by default, optional credential-namespaced conversation reuse, TTL enforcement, and best-effort clearing.
- Buffered placeholder restoration that handles transport splits across SSE chunks and keeps JSON valid when restored strings contain quotes or newlines.
- YAML policy actions (`redact`, `mask`, `block`, `allow`), exact allowlists, custom regex rules, fail-closed defaults, optional noisy fail-open, and opt-in spaCy NER.
- Request size/time limits, loopback default bind, configured-upstream host allowlist, HTTPS enforcement for non-loopback upstreams, redirect disabling, environment-proxy disabling, and value-free JSONL audit events.
- `veil serve`, `veil scan`, and `veil bench`; Dockerfile and hardened Compose example; pinned project/development dependencies; CI workflow for Python 3.11–3.13 with tests, coverage, Ruff, mypy, Bandit, pip-audit, repository scan, benchmark smoke run and Docker build.
- MIT license, threat model, decisions/scope docs, security disclosure policy, contribution guide, issue/PR templates, changelog, generated README benchmark tables, 600-word blog post, four Reddit drafts, LinkedIn and Show HN drafts, repository topics, social-preview brief, and an explicitly simulated demo GIF.

## Verification performed in this environment

| Check | Result |
|---|---|
| `python -m pytest -q` | 79 passed, 1 skipped |
| Selected core coverage (`detectors`, models, policy, vault, stream) | 92.09% total; configured threshold 85% |
| Core stream module coverage | 94% |
| `python -m compileall -q src tests bench launch scripts` | Passed |
| `python -m pip wheel . --no-build-isolation --no-deps` | Built `veilrelay-0.1.0-py3-none-any.whl` (30,530 bytes) |
| `veil scan` smoke check | Replaced the synthetic email and AWS-key examples with typed placeholders |
| Own repository scan | `clean`; zero source/docs findings; report records `raw_values_recorded: false` |
| Synthetic benchmark | 24 rows, 26 annotated spans; raw CSV/JSON committed |

### Benchmark output from this machine

- VeilRelay micro precision/recall/F1: **1.000 / 1.000 / 1.000** on this small synthetic regression fixture.
- Plain-regex micro precision/recall/F1: **0.733 / 0.423 / 0.537** on the same fixture.
- Added detector-only latency: **0.020040 ms p50 / 0.041111 ms p95**, from 240 paired samples.
- Presidio: **skipped** (`ModuleNotFoundError`).
- Ai4Privacy OpenPII Nano validation split: **not downloaded**.
- Ollama utility benchmark: **skipped** (`OLLAMA_MODEL` not configured).

These synthetic scores are not estimates of production detection quality, and the detector timing excludes network/upstream latency. The skipped comparisons are missing measurements, not zero scores. Reproduce or replace them using `bench/METHODOLOGY.md` before making broader claims.

## Not verified / cut from this environment

- Docker was not installed, so the image and Compose deployment were authored but not built or run here.
- Ruff, mypy, Bandit, pip-audit, `gh`, Hypothesis, and Presidio were unavailable in the offline runtime. Their CI/configuration and dependencies are committed, but those tools' checks are not claimed as locally passed. The Hypothesis property tests are present and were the one skipped test module.
- No public dataset payload was downloaded; the optional adapter targets the CC-BY-4.0 Ai4Privacy Nano validation split and records attribution in `bench/ATTRIBUTION.md`.
- No local Ollama model was configured; utility quality remains unmeasured.
- No live provider credential, production provider, or installed OpenAI SDK integration was used. The proxy was exercised end-to-end with an `httpx` mock upstream and FastAPI ASGI client.
- GitHub repository creation/push and PyPI publication were left to the project owner. No remote is configured and no package was uploaded.

## Known limitations and residual risk

- Detection is pattern-based and incomplete. It does not reliably identify arbitrary names, context-only identifiers, unknown formats, or deliberately encoded/obfuscated values. Optional NER is off by default and depends on an operator-installed spaCy model.
- The MVP scans textual chat message content only; it does not inspect images, audio, video, files, tool/function payloads, embeddings, fine-tuning requests, or other API routes.
- Placeholders preserve type and identity, but a task can lose information when the literal value matters. Utility preservation needs real local-model runs and human evaluation.
- The proxy does not protect a compromised host or control provider-side retention/attacks. Python cannot guarantee zeroization of immutable strings; clearing vault references is best-effort.
- Conversation-scope mapping is opt-in and requires both an Authorization credential and `x-veilrelay-conversation-id`; anonymous callers stay request-scoped.
- Custom regex rules are operator-supplied trusted configuration. Avoid pathological patterns that can consume excessive CPU.
- Upstream host allowlisting is a configuration guard, not complete network isolation or a defense against every DNS/routing attack. Operators should apply egress restrictions and keep deployments on loopback unless they add their own authentication and TLS.
- This alpha has not had an independent security review. It must not be treated as a compliance certification or a guarantee that sensitive data cannot leave a host.

## Next release gate

Before describing this as production-ready, run the Hypothesis suite in a dependency-complete environment, execute Ruff/mypy/Bandit/pip-audit, build and smoke-test Docker, run Presidio defaults and the public dataset adapter, execute the utility tasks against one or more documented local Ollama models, and obtain independent security review.
