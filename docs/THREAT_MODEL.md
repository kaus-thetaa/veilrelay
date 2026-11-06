# Threat Model — VeilRelay

## Purpose and security claim

VeilRelay is a self-hosted, best-effort privacy proxy intended to reduce **accidental** disclosure of personally identifiable information (PII), credentials, and common secrets in prompts sent to third-party LLM providers. It detects supported patterns locally, replaces detected values with reversible placeholders, forwards the transformed request, and restores known placeholders in the response.

This is a risk-reduction control, **not a guarantee that prompts contain no sensitive data**. Detection is heuristic and incomplete. Do not describe or rely on VeilRelay as “100% safe”, a compliance certification, or a substitute for data governance and provider controls.

## Assets

- Sensitive strings present in prompts and completion responses.
- The in-memory mapping between typed placeholders and original values.
- Upstream API credentials and configured upstream endpoint.
- Audit metadata (entity types/counts, timestamps, request identifiers).

## Trust boundaries and data flow

1. A developer's application sends an OpenAI-compatible request to the local proxy.
2. Request bodies are size-limited and parsed locally.
3. Detection and policy decisions happen in-process before any upstream connection.
4. For redact actions, values are substituted with typed placeholders. The mapping stays in process memory, scoped to the request by default (or to an explicitly configured conversation scope with a TTL).
5. Only the transformed request is forwarded to the configured, allowlisted upstream.
6. Known placeholders in the upstream response are restored locally. The vault is cleared after the request unless conversation scope is explicitly enabled.
7. Audit output contains entity types and counts only. It must not contain source text, matched values, placeholders that encode originals, request bodies, or vault mappings.

## Protected against

- Accidental prompt leakage of values recognized by enabled detectors, including common email addresses, phone numbers, IP addresses, validated payment/account identifiers, Indian identifiers, and common API-key/credential formats.
- Accidental disclosure of detected values where a configured policy blocks the request or replaces the value before forwarding.
- Accidental disclosure through ordinary JSON and SSE response paths when the model echoes a placeholder that this request's vault issued.

## Not protected against

- A malicious or determined user deliberately encoding, encrypting, splitting, translating, or obfuscating sensitive data to evade detection.
- A compromised host, kernel, Python runtime, process memory, debugger, administrator, dependency, or local application. The in-memory vault is not protected from a host-level attacker.
- Provider-side attacks, provider retention, model training, abuse by the upstream, or a compromised upstream account. The proxy only reduces what is sent; it cannot control the provider.
- Sensitive values in images, audio, video, files, tool calls, non-chat endpoints, embeddings, fine-tuning payloads, or arbitrary binary/multimodal content unless a future detector explicitly handles them. The MVP handles text fields in chat-completion messages.
- Unknown identifiers, unseen secret formats, low-entropy secrets, contextual identifiers that lack reliable patterns, or false negatives caused by incomplete detection.
- Sensitive data already disclosed elsewhere or reintroduced by the model independently of a placeholder.
- De-anonymization by inference from surrounding context. Placeholders preserve entity type and identity consistency, which can itself reveal structure.

## Fail-closed behavior

The default mode is **fail closed**: detector/policy processing errors prevent forwarding and return an error to the client. Operators may explicitly select `fail_mode: open`; startup logs must then emit a prominent warning. Fail-open is a deliberate reduction in protection and should not be used for sensitive workloads.

## Vault handling

- Raw values are stored only in process memory in a short-lived vault.
- Default scope is per request. Conversation-scoped mappings are opt-in and require a caller-provided conversation identifier; the identifier is not trusted as an authentication mechanism.
- Vault entries expire after a configurable TTL. Request-scoped vaults are cleared in `finally` paths after completion, disconnect, or error.
- Vault values must never be logged, written to disk, serialized into audit events, or exposed in metrics or exception messages.
- Python cannot guarantee secure zeroization of immutable strings or copies. Clearing references is best-effort and does not prevent memory forensic recovery on a compromised host.

## Network and deployment assumptions

- Bind to `127.0.0.1` by default. Exposing the proxy to a network requires an operator-managed access-control layer and TLS termination.
- The upstream URL is operator configuration, not user input. Its hostname must match an explicit allowlist. Only HTTP(S) schemes are accepted; URL credentials, fragments, and query strings are rejected.
- The proxy does not follow redirects. This prevents an allowlisted origin from redirecting requests to an unapproved destination.
- Operators should restrict outbound network access at the OS/container level and avoid exposing administrative configuration to untrusted clients.
- A configured loopback Ollama host is allowed only when explicitly present in the upstream host allowlist.

## Logging and telemetry

There is no telemetry or hosted service. Audit JSONL records only request ID, timestamp, entity type counts, action counts, detector errors as non-sensitive class names, and outcome. The proxy must not log request/response bodies, authorization headers, matched text, or vault contents. Operators control local audit file permissions and retention.

## Residual risks and operator guidance

Detection can miss data; checksum validators do not prove ownership; entropy heuristics can miss low-entropy credentials and flag harmless tokens; NER can be ambiguous. Keep allowlists narrow, review policy changes, patch dependencies, run local tests with representative synthetic data, and do not use this proxy as the sole control for regulated or high-impact workloads. Validate every deployment against its own data and threat model.
