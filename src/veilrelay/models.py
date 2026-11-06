"""Shared data models. Entity objects deliberately never include matched values."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Action(StrEnum):
    REDACT = "redact"
    MASK = "mask"
    BLOCK = "block"
    ALLOW = "allow"


@dataclass(frozen=True, slots=True)
class Entity:
    start: int
    end: int
    entity_type: str
    detector: str
    confidence: float = 1.0

    def __post_init__(self) -> None:
        if self.start < 0 or self.end <= self.start:
            raise ValueError("invalid entity span")
        if not self.entity_type or not self.detector:
            raise ValueError("entity type and detector are required")


@dataclass(frozen=True, slots=True)
class ScanSummary:
    safe_text: str
    counts: dict[str, int]
    actions: dict[str, int]
    entity_count: int
