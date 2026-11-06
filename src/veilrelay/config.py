"""Runtime settings loaded from environment and optional YAML policy."""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit

from veilrelay.exceptions import UpstreamConfigurationError
from veilrelay.policy import PolicyConfig


@dataclass(frozen=True, slots=True)
class Settings:
    upstream_base_url: str
    allowed_upstream_hosts: frozenset[str]
    max_request_bytes: int
    timeout_seconds: float
    host: str
    port: int
    audit_path: str | None
    conversation_scope_enabled: bool
    vault_ttl_seconds: float
    policy: PolicyConfig

    def __post_init__(self) -> None:
        if self.max_request_bytes < 1 or self.timeout_seconds <= 0 or self.vault_ttl_seconds <= 0:
            raise ValueError("request limit, timeout and vault TTL must be positive")
        if not 1 <= self.port <= 65535:
            raise ValueError("port must be between 1 and 65535")

    @classmethod
    def from_env(cls) -> "Settings":
        upstream = os.getenv("UPSTREAM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        parsed = _validate_url_shape(upstream)
        configured_hosts = os.getenv("UPSTREAM_ALLOWED_HOSTS", "api.openai.com")
        allowed = frozenset(host.strip().lower() for host in configured_hosts.split(",") if host.strip())
        if parsed.hostname is None or parsed.hostname.lower() not in allowed:
            raise UpstreamConfigurationError("configured upstream host is not allowlisted")
        policy_path = os.getenv("VEIL_POLICY_FILE")
        policy = PolicyConfig.from_yaml(policy_path) if policy_path else PolicyConfig()
        return cls(
            upstream_base_url=upstream,
            allowed_upstream_hosts=allowed,
            max_request_bytes=int(os.getenv("MAX_REQUEST_BYTES", policy.max_request_bytes)),
            timeout_seconds=float(os.getenv("UPSTREAM_TIMEOUT_SECONDS", policy.timeout_seconds)),
            host=os.getenv("VEIL_HOST", "127.0.0.1"),
            port=int(os.getenv("VEIL_PORT", "8080")),
            audit_path=os.getenv("AUDIT_LOG_PATH"),
            conversation_scope_enabled=os.getenv("CONVERSATION_SCOPE", "false").lower() == "true",
            vault_ttl_seconds=float(os.getenv("VAULT_TTL_SECONDS", policy.ttl_seconds)),
            policy=policy,
        )


def _validate_url_shape(url: str) -> SplitResult:
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise UpstreamConfigurationError("invalid upstream URL configuration")
    if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise UpstreamConfigurationError("non-loopback upstreams must use HTTPS")
    return parsed
