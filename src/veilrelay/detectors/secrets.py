"""Credential and secret pattern detectors, with conservative entropy fallback."""

from __future__ import annotations

import math
import re
from collections import Counter

from veilrelay.detectors.base import Detector
from veilrelay.models import Entity


class SecretDetector:
    name = "secret-patterns"

    _patterns: tuple[tuple[str, re.Pattern[str]], ...] = (
        ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
        ("GITHUB_TOKEN", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{50,255})\b")),
        ("GITLAB_TOKEN", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
        ("OPENAI_KEY", re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
        ("ANTHROPIC_KEY", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
        ("STRIPE_KEY", re.compile(r"\b(?:sk_live|rk_live)_[A-Za-z0-9]{16,}\b")),
        ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")),
        ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]{20,}?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----")),
        ("DB_CONNECTION", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s/'\"]+:[^\s/'\"]+@[^\s]+", re.I)),
    )
    _generic_token = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_+/-=]{28,}(?![A-Za-z0-9])")

    def __init__(self, entropy_threshold: float = 4.2, min_length: int = 32) -> None:
        if not 3.0 <= entropy_threshold <= 5.5:
            raise ValueError("entropy threshold outside supported range")
        self.entropy_threshold = entropy_threshold
        self.min_length = min_length

    def detect(self, text: str) -> list[Entity]:
        results: list[Entity] = []
        occupied: list[tuple[int, int]] = []
        for entity_type, pattern in self._patterns:
            for match in pattern.finditer(text):
                end = match.end()
                if entity_type == "DB_CONNECTION":
                    end = match.start() + len(match.group(0).rstrip(".,;!?"))
                if end <= match.start():
                    continue
                results.append(Entity(match.start(), end, entity_type, self.name, 1.0))
                occupied.append((match.start(), end))
        for match in self._generic_token.finditer(text):
            if any(match.start() < end and start < match.end() for start, end in occupied):
                continue
            candidate = match.group(0)
            if len(candidate) < self.min_length or not _looks_like_entropy_candidate(candidate):
                continue
            entropy = shannon_entropy(candidate)
            if entropy >= self.entropy_threshold:
                results.append(Entity(match.start(), match.end(), "HIGH_ENTROPY_SECRET", self.name, 0.65))
        return sorted(results, key=lambda item: item.start)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in Counter(value).values())


def _looks_like_entropy_candidate(value: str) -> bool:
    if value.startswith("http") or "=" in value[:4]:
        return False
    return any(char.isdigit() for char in value) and any(char.isalpha() for char in value)
