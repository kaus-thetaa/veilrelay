"""FastAPI OpenAI-compatible privacy proxy."""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from veilrelay.audit import AuditLogger
from veilrelay.config import Settings, _validate_url_shape
from veilrelay.detectors import BuiltinDetector, SecretDetector
from veilrelay.exceptions import DetectionError, PolicyBlocked, UpstreamConfigurationError
from veilrelay.ner import SpacyNerDetector
from veilrelay.policy import PrivacyEngine
from veilrelay.stream import SSEStreamRewriter, restore_json_body
from veilrelay.vault import ConversationVaults, TokenVault

_LOG = logging.getLogger("veilrelay")


def validate_upstream(settings: Settings) -> str:
    parsed = _validate_url_shape(settings.upstream_base_url)
    if parsed.hostname is None or parsed.hostname.lower() not in settings.allowed_upstream_hosts:
        raise UpstreamConfigurationError("configured upstream host is not allowlisted")
    return settings.upstream_base_url


def _make_engine(settings: Settings) -> PrivacyEngine:
    detectors: list[Any] = [BuiltinDetector(), SecretDetector()]
    if settings.policy.ner_enabled:
        detectors.append(SpacyNerDetector(settings.policy.ner_model))
    return PrivacyEngine(detectors, settings.policy)


def _target_url(base: str, endpoint: str) -> str:
    return base.rstrip("/") + "/" + endpoint.lstrip("/")


def _forward_headers(request: Request) -> dict[str, str]:
    allowed = {"authorization", "content-type", "accept", "openai-organization", "openai-project"}
    return {key: value for key, value in request.headers.items() if key.lower() in allowed}


async def _read_limited(request: Request, limit: int) -> bytes:
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > limit:
                raise ValueError("request too large")
        except ValueError as exc:
            raise ValueError("request size limit exceeded") from exc
    data = bytearray()
    async for chunk in request.stream():
        data.extend(chunk)
        if len(data) > limit:
            raise ValueError("request size limit exceeded")
    return bytes(data)


def _sanitize_messages(
    payload: dict[str, Any], engine: PrivacyEngine, vault: TokenVault
) -> tuple[dict[str, Any], dict[str, int], dict[str, int]]:
    messages = payload.get("messages")
    if not isinstance(messages, list):
        raise ValueError("messages must be an array")
    counts: dict[str, int] = {}
    actions: dict[str, int] = {}
    for message in messages:
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, str):
            summary = engine.scan(content, vault)
            message["content"] = summary.safe_text
            _merge_counts(counts, summary.counts)
            _merge_counts(actions, summary.actions)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    summary = engine.scan(part["text"], vault)
                    part["text"] = summary.safe_text
                    _merge_counts(counts, summary.counts)
                    _merge_counts(actions, summary.actions)
    return payload, counts, actions


def _merge_counts(target: dict[str, int], source: dict[str, int]) -> None:
    for key, value in source.items():
        target[key] = target.get(key, 0) + value


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    upstream = validate_upstream(settings)
    engine = _make_engine(settings)
    audit = AuditLogger(settings.audit_path)
    conversations = ConversationVaults(ttl_seconds=settings.vault_ttl_seconds)

    if settings.policy.fail_mode == "open":
        _LOG.critical("FAIL-OPEN ENABLED: detection failures may send unredacted prompts upstream")

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield

    app = FastAPI(title="VeilRelay", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.engine = engine
    app.state.audit = audit

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/models")
    async def models(request: Request) -> Response:
        headers = _forward_headers(request)
        timeout = httpx.Timeout(settings.timeout_seconds)
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False) as client:
                upstream_response = await client.get(_target_url(upstream, "models"), headers=headers)
            return Response(
                content=upstream_response.content,
                status_code=upstream_response.status_code,
                headers=_response_headers(upstream_response.headers),
                media_type=upstream_response.headers.get("content-type"),
            )
        except httpx.HTTPError:
            return JSONResponse({"error": {"message": "upstream request failed", "type": "upstream_error"}}, status_code=502)

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> Response:
        request_id = uuid.uuid4().hex
        vault: TokenVault | None = None
        conversation_id = request.headers.get("x-veilrelay-conversation-id")
        persistent = settings.conversation_scope_enabled and bool(conversation_id)
        try:
            raw_body = await _read_limited(request, settings.max_request_bytes)
            payload = json.loads(raw_body)
            if not isinstance(payload, dict):
                raise ValueError("request JSON must be an object")
            auth_identity = request.headers.get("authorization", "")
            # Namespace shared vaults by a non-reversible digest of the caller credential.
            # If no credential is present, use a request-scoped vault rather than share across anonymous clients.
            if persistent and conversation_id and auth_identity:
                namespace_material = f"{auth_identity}\0{conversation_id}".encode("utf-8")
                namespace = hashlib.sha256(namespace_material).hexdigest()
                vault = conversations.get(namespace)
            else:
                persistent = False
                vault = TokenVault(settings.vault_ttl_seconds)
            payload, counts, actions = _sanitize_messages(payload, engine, vault)
            request_body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        except PolicyBlocked as exc:
            audit.write(request_id, exc.counts, exc.actions, "blocked", type(exc).__name__)
            if vault and not persistent:
                vault.clear()
            return JSONResponse({"error": {"message": str(exc), "type": "privacy_policy_error"}}, status_code=403)
        except (DetectionError, RuntimeError) as exc:
            audit.write(request_id, {}, {}, "blocked", type(exc).__name__)
            if vault and not persistent:
                vault.clear()
            return JSONResponse({"error": {"message": "privacy inspection failed; request not forwarded", "type": "privacy_error"}}, status_code=503)
        except ValueError as exc:
            if vault and not persistent:
                vault.clear()
            status = 413 if "size limit" in str(exc) or "too large" in str(exc) else 400
            return JSONResponse({"error": {"message": "invalid or oversized request", "type": "invalid_request_error"}}, status_code=status)
        except Exception as exc:
            audit.write(request_id, {}, {}, "blocked", type(exc).__name__)
            if vault and not persistent:
                vault.clear()
            if settings.policy.fail_mode == "closed":
                return JSONResponse({"error": {"message": "privacy inspection failed; request not forwarded", "type": "privacy_error"}}, status_code=503)
            # fail-open is deliberately explicit; retrying without the engine is a conscious policy choice.
            _LOG.critical("Fail-open request bypassed privacy inspection (exception class: %s)", type(exc).__name__)
            return JSONResponse({"error": {"message": "internal privacy proxy error", "type": "proxy_error"}}, status_code=500)

        audit.write(request_id, counts, actions, "forwarded")
        assert vault is not None
        stream_requested = bool(payload.get("stream", False))
        headers = _forward_headers(request)
        headers["content-type"] = "application/json"
        timeout = httpx.Timeout(settings.timeout_seconds)

        if stream_requested:
            client = httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False)
            try:
                upstream_request = client.build_request(
                    "POST", _target_url(upstream, "chat/completions"), content=request_body, headers=headers
                )
                upstream_stream = await client.send(upstream_request, stream=True)
            except httpx.HTTPError:
                await client.aclose()
                if not persistent:
                    vault.clear()
                _LOG.error("upstream streaming request failed (request_id=%s)", request_id)
                return JSONResponse({"error": {"message": "upstream request failed", "type": "upstream_error"}}, status_code=502)

            async def stream_body() -> AsyncIterator[bytes]:
                rewriter = SSEStreamRewriter(vault)
                try:
                    async for chunk in upstream_stream.aiter_text():
                        transformed = rewriter.feed(chunk)
                        if transformed:
                            yield transformed.encode("utf-8")
                    remainder = rewriter.finish()
                    if remainder:
                        yield remainder.encode("utf-8")
                except Exception:
                    _LOG.error("upstream streaming request failed (request_id=%s)", request_id)
                    yield b"data: {\"error\":{\"message\":\"upstream request failed\"}}\n\n"
                finally:
                    await upstream_stream.aclose()
                    await client.aclose()
                    if not persistent:
                        vault.clear()

            response_headers = _response_headers(upstream_stream.headers)
            response_headers.setdefault("cache-control", "no-cache")
            response_headers["x-accel-buffering"] = "no"
            return StreamingResponse(
                stream_body(),
                status_code=upstream_stream.status_code,
                headers=response_headers,
            )

        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False) as client:
                upstream_response = await client.post(
                    _target_url(upstream, "chat/completions"), content=request_body, headers=headers
                )
            body = upstream_response.content
            if body:
                body = restore_json_body(body, vault)
            return Response(
                content=body,
                status_code=upstream_response.status_code,
                headers=_response_headers(upstream_response.headers),
                media_type=upstream_response.headers.get("content-type"),
            )
        except httpx.HTTPError:
            _LOG.error("upstream request failed (request_id=%s)", request_id)
            return JSONResponse({"error": {"message": "upstream request failed", "type": "upstream_error"}}, status_code=502)
        finally:
            if not persistent:
                vault.clear()

    return app


def _response_headers(headers: httpx.Headers) -> dict[str, str]:
    allowed = {"content-type", "cache-control", "x-request-id", "openai-processing-ms"}
    return {key: value for key, value in headers.items() if key.lower() in allowed}


app = create_app()
