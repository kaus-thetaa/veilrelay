"""Exceptions with deliberately value-free messages."""


class VeilRelayError(Exception):
    """Base exception."""


class DetectionError(VeilRelayError):
    """Raised when detection cannot be completed safely."""


class PolicyBlocked(VeilRelayError):
    """Raised when a policy blocks a request; metadata contains counts, never values."""

    def __init__(self, message: str, counts: dict[str, int] | None = None, actions: dict[str, int] | None = None) -> None:
        super().__init__(message)
        self.counts = counts or {}
        self.actions = actions or {}


class UpstreamConfigurationError(VeilRelayError):
    """Raised when an upstream URL violates configuration policy."""
