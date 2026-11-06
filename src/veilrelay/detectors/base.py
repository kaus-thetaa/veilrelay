"""Pluggable detector interface."""

from __future__ import annotations

from typing import Protocol

from veilrelay.models import Entity


class Detector(Protocol):
    """A detector returns spans only; it must not put matched values in metadata."""

    name: str

    def detect(self, text: str) -> list[Entity]: ...
