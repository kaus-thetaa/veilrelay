# Project scope

VeilRelay is an OpenAI-compatible local reverse proxy for chat-completion requests. It inspects text locally, detects supported PII/secrets, applies policy before egress, and restores recognized placeholders in model output.

## MVP endpoints

- `POST /v1/chat/completions`: JSON request forwarding, with SSE streaming support.
- `GET /v1/models`: upstream passthrough.
- `GET /healthz`: local health check, does not reveal upstream credentials.

## Explicit exclusions

No hosted service, accounts, telemetry, request-body persistence, image/audio/file OCR, embeddings, fine-tuning endpoints, tool-call policy enforcement, identity provider, or authentication layer is included in v0.1.0. Bind to loopback unless another access-control layer is in place.
