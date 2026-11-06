"""Short-lived in-memory placeholder vault. Values are never exposed via repr."""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field


_TOKEN_RE = re.compile(r"<([A-Z][A-Z0-9_]*)_(\d+)>")


@dataclass(slots=True)
class TokenVault:
    ttl_seconds: float = 300.0
    _token_to_value: dict[str, str] = field(default_factory=dict, repr=False)
    _value_to_token: dict[tuple[str, str], str] = field(default_factory=dict, repr=False)
    _expires_at: float = field(default=0.0, repr=False)
    _sequence: dict[str, int] = field(default_factory=dict, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def __post_init__(self) -> None:
        if self.ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._expires_at = time.monotonic() + self.ttl_seconds

    def issue(self, entity_type: str, value: str) -> str:
        """Return a stable typed token for this value within this vault."""
        with self._lock:
            self._ensure_live()
            key = (entity_type.upper(), value)
            existing = self._value_to_token.get(key)
            if existing is not None:
                return existing
            number = self._sequence.get(entity_type.upper(), 0) + 1
            self._sequence[entity_type.upper()] = number
            token = f"<{entity_type.upper()}_{number}>"
            self._token_to_value[token] = value
            self._value_to_token[key] = token
            return token

    def refresh(self) -> None:
        """Extend a live vault TTL, used when an existing conversation is reused."""
        with self._lock:
            self._ensure_live()
            self._expires_at = time.monotonic() + self.ttl_seconds

    def restore(self, text: str) -> str:
        """Restore only tokens issued by this vault; unknown placeholders remain untouched."""
        with self._lock:
            self._ensure_live()
            return _TOKEN_RE.sub(lambda match: self._token_to_value.get(match.group(0), match.group(0)), text)

    def known_tokens(self) -> tuple[str, ...]:
        with self._lock:
            self._ensure_live()
            return tuple(self._token_to_value)

    def clear(self) -> None:
        """Drop references to mapping values (best-effort; Python cannot guarantee zeroization)."""
        with self._lock:
            self._token_to_value.clear()
            self._value_to_token.clear()
            self._sequence.clear()
            self._expires_at = 0.0

    def _ensure_live(self) -> None:
        if time.monotonic() >= self._expires_at:
            self.clear()
            raise RuntimeError("vault expired")


class ConversationVaults:
    """Opt-in TTL manager for consistent per-conversation placeholders."""

    def __init__(self, ttl_seconds: float = 900.0, max_conversations: int = 1024) -> None:
        if ttl_seconds <= 0 or max_conversations < 1:
            raise ValueError("invalid conversation vault limits")
        self.ttl_seconds = ttl_seconds
        self.max_conversations = max_conversations
        self._vaults: dict[str, tuple[TokenVault, float]] = {}
        self._lock = threading.RLock()

    def get(self, conversation_id: str) -> TokenVault:
        if not conversation_id or len(conversation_id) > 256:
            raise ValueError("invalid conversation identifier")
        with self._lock:
            self._purge()
            current = self._vaults.get(conversation_id)
            if current:
                vault, _ = current
                vault.refresh()
                self._vaults[conversation_id] = (vault, time.monotonic() + self.ttl_seconds)
                return vault
            if len(self._vaults) >= self.max_conversations:
                oldest = min(self._vaults, key=lambda key: self._vaults[key][1])
                self._vaults.pop(oldest)[0].clear()
            vault = TokenVault(ttl_seconds=self.ttl_seconds)
            self._vaults[conversation_id] = (vault, time.monotonic() + self.ttl_seconds)
            return vault

    def clear(self, conversation_id: str) -> None:
        with self._lock:
            item = self._vaults.pop(conversation_id, None)
            if item:
                item[0].clear()

    def _purge(self) -> None:
        now = time.monotonic()
        expired = [key for key, (_, deadline) in self._vaults.items() if now >= deadline]
        for key in expired:
            self._vaults.pop(key)[0].clear()
