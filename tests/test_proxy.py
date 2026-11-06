from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from veilrelay import proxy
from veilrelay.config import Settings, _validate_url_shape
from veilrelay.exceptions import UpstreamConfigurationError
from veilrelay.policy import PolicyConfig


class SplitStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks

    async def __aiter__(self):
        for chunk in self.chunks:
            yield chunk

    async def aclose(self) -> None:
        return None


def make_settings(tmp_path: Path, **overrides) -> Settings:
    values = {
        "upstream_base_url": "https://unit.test/v1",
        "allowed_upstream_hosts": frozenset({"unit.test"}),
        "max_request_bytes": 1_000_000,
        "timeout_seconds": 3.0,
        "host": "127.0.0.1",
        "port": 8080,
        "audit_path": str(tmp_path / "audit.jsonl"),
        "conversation_scope_enabled": False,
        "vault_ttl_seconds": 300.0,
        "policy": PolicyConfig(),
    }
    values.update(overrides)
    return Settings(**values)


@pytest.mark.asyncio
async def test_non_stream_proxy_redacts_upstream_and_restores_response(monkeypatch, tmp_path) -> None:
    captured: list[dict] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(await request.aread())
        captured.append(body)
        assert body["messages"][0]["content"] == "Email <EMAIL_1>"
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "I will email <EMAIL_1>"}}]},
            headers={"x-request-id": "upstream-id"},
        )

    real_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(proxy.httpx, "AsyncClient", lambda *args, **kwargs: real_async_client(transport=transport, **kwargs))
    app = proxy.create_app(make_settings(tmp_path))
    async with real_async_client(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
        response = await client.post(
            "/v1/chat/completions",
            headers={"authorization": "Bearer test-key"},
            json={"model": "unit", "messages": [{"role": "user", "content": "Email alice@example.com"}]},
        )
    assert response.status_code == 200
    assert "alice@example.com" in response.text
    assert len(captured) == 1
    assert "alice@example.com" not in json.dumps(captured[0])
    audit = (tmp_path / "audit.jsonl").read_text()
    assert "EMAIL" in audit
    assert "alice@example.com" not in audit
    assert "test-key" not in audit


@pytest.mark.asyncio
async def test_stream_proxy_restores_placeholder_split_across_chunks(monkeypatch, tmp_path) -> None:
    sent: list[dict] = []
    sse1 = b'data: {"choices":[{"delta":{"content":"Email <EMA'
    sse2 = b'IL_1> now"}}]}\n\ndata: [DONE]\n\n'

    async def handler(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(await request.aread()))
        return httpx.Response(200, stream=SplitStream([sse1, sse2]), headers={"content-type": "text/event-stream"})

    real_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(proxy.httpx, "AsyncClient", lambda *args, **kwargs: real_async_client(transport=transport, **kwargs))
    app = proxy.create_app(make_settings(tmp_path))
    async with real_async_client(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
        response = await client.post(
            "/v1/chat/completions",
            json={"model": "unit", "stream": True, "messages": [{"role": "user", "content": "Email alice@example.com"}]},
        )
    assert response.status_code == 200
    assert "alice@example.com" in response.text
    assert "<EMAIL_1>" not in response.text
    assert sent[0]["messages"][0]["content"] == "Email <EMAIL_1>"


@pytest.mark.asyncio
async def test_models_passthrough(monkeypatch, tmp_path) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/models"
        assert request.headers["authorization"] == "Bearer upstream-key"
        return httpx.Response(200, json={"data": [{"id": "local-model"}]})

    real_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(proxy.httpx, "AsyncClient", lambda *args, **kwargs: real_async_client(transport=transport, **kwargs))
    app = proxy.create_app(make_settings(tmp_path))
    async with real_async_client(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
        response = await client.get("/v1/models", headers={"authorization": "Bearer upstream-key"})
    assert response.status_code == 200
    assert response.json()["data"][0]["id"] == "local-model"


@pytest.mark.asyncio
async def test_policy_block_prevents_upstream_request(monkeypatch, tmp_path) -> None:
    called = False

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200)

    real_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(proxy.httpx, "AsyncClient", lambda *args, **kwargs: real_async_client(transport=transport, **kwargs))
    policy = PolicyConfig.from_dict({"actions": {"EMAIL": "block"}})
    app = proxy.create_app(make_settings(tmp_path, policy=policy))
    async with real_async_client(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
        response = await client.post("/v1/chat/completions", json={"messages": [{"role": "user", "content": "alice@example.com"}]})
    assert response.status_code == 403
    assert not called
    audit = (tmp_path / "audit.jsonl").read_text()
    assert '"EMAIL":1' in audit
    assert '"block":1' in audit
    assert "alice@example.com" not in audit


@pytest.mark.asyncio
async def test_request_size_limit(monkeypatch, tmp_path) -> None:
    called = False

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200)

    real_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(proxy.httpx, "AsyncClient", lambda *args, **kwargs: real_async_client(transport=transport, **kwargs))
    app = proxy.create_app(make_settings(tmp_path, max_request_bytes=30))
    async with real_async_client(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
        response = await client.post("/v1/chat/completions", content=b'{"messages":' + b' ' * 100)
    assert response.status_code == 413
    assert not called


@pytest.mark.asyncio
async def test_detector_error_fails_closed(monkeypatch, tmp_path) -> None:
    called = False

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200)

    real_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(proxy.httpx, "AsyncClient", lambda *args, **kwargs: real_async_client(transport=transport, **kwargs))
    app = proxy.create_app(make_settings(tmp_path))

    class Broken:
        name = "broken"

        def detect(self, text: str):
            raise RuntimeError("sensitive string must not enter logs")

    app.state.engine.detectors = [Broken()]
    async with real_async_client(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
        response = await client.post("/v1/chat/completions", json={"messages": [{"role": "user", "content": "secret@example.com"}]})
    assert response.status_code == 503
    assert not called
    assert "secret@example.com" not in response.text


def test_upstream_url_validation_and_host_allowlist() -> None:
    with pytest.raises(UpstreamConfigurationError):
        _validate_url_shape("file:///etc/passwd")
    with pytest.raises(UpstreamConfigurationError):
        _validate_url_shape("http://example.com/v1")
    with pytest.raises(UpstreamConfigurationError):
        _validate_url_shape("https://user:pass@example.com/v1")
    with pytest.raises(UpstreamConfigurationError):
        _validate_url_shape("https://example.com/v1?foo=bar")
    settings = make_settings(Path("/tmp"), upstream_base_url="https://bad.test/v1")
    with pytest.raises(UpstreamConfigurationError):
        proxy.validate_upstream(settings)


def test_settings_environment_default(monkeypatch) -> None:
    from veilrelay.config import Settings

    for key in ["UPSTREAM_BASE_URL", "UPSTREAM_ALLOWED_HOSTS", "VEIL_POLICY_FILE", "VEIL_HOST", "VEIL_PORT"]:
        monkeypatch.delenv(key, raising=False)
    settings = Settings.from_env()
    assert settings.upstream_base_url == "https://api.openai.com/v1"
    assert settings.host == "127.0.0.1"
    assert "api.openai.com" in settings.allowed_upstream_hosts
