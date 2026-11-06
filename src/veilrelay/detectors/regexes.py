"""Regex + validator detector for PII and identifiers."""

from __future__ import annotations

import re

from veilrelay.detectors.validators import (
    iban_valid,
    ifsc_valid,
    ip_valid,
    luhn_valid,
    pan_valid,
    ssn_valid,
    upi_valid,
    verhoeff_valid,
)
from veilrelay.models import Entity


class BuiltinDetector:
    name = "builtin-regex-validator"

    _patterns: tuple[tuple[str, re.Pattern[str], object], ...] = (
        ("EMAIL", re.compile(r"(?i)(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w-])"), None),
        ("CREDIT_CARD", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"), luhn_valid),
        ("AADHAAR", re.compile(r"(?<!\d)(?:\d{4}[ -]?){2}\d{4}(?!\d)"), verhoeff_valid),
        ("IBAN", re.compile(r"(?i)(?<![A-Z0-9])[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]){11,30}(?![A-Z0-9])"), iban_valid),
        ("SSN", re.compile(r"(?<!\d)(?:\d{3}-\d{2}-\d{4}|\d{9})(?!\d)"), ssn_valid),
        ("PAN", re.compile(r"(?i)(?<![A-Z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Z0-9])"), pan_valid),
        ("IFSC", re.compile(r"(?i)(?<![A-Z0-9])[A-Z]{4}0[A-Z0-9]{6}(?![A-Z0-9])"), ifsc_valid),
        ("UPI_ID", re.compile(r"(?i)(?<![\w.+-])[A-Z0-9._-]{2,64}@[A-Z][A-Z0-9.-]*[A-Z0-9](?![\w-])"), upi_valid),
        ("IP_ADDRESS", re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])|(?<![A-F0-9:])[A-F0-9:]{3,39}(?![A-F0-9:])", re.I), ip_valid),
        ("PHONE", re.compile(r"(?<!\w)(?:\+?\d{1,3}[ .-]?)?(?:\(?[6-9]\d{4}\)?[ .-]?\d{5}|\d{3}[ .-]\d{3}[ .-]\d{4})(?!\w)"), None),
    )

    _priority = {
        "AADHAAR": 100, "CREDIT_CARD": 95, "IBAN": 90, "SSN": 85,
        "PAN": 80, "IFSC": 75, "UPI_ID": 70, "EMAIL": 65,
        "IP_ADDRESS": 60, "PHONE": 20,
    }

    def detect(self, text: str) -> list[Entity]:
        found: list[Entity] = []
        for entity_type, pattern, validator in self._patterns:
            for match in pattern.finditer(text):
                value = match.group(0)
                if entity_type == "UPI_ID" and "." in value.rsplit("@", 1)[-1]:
                    # A dotted domain is treated as an email address, not a VPA.
                    continue
                if validator is not None and not validator(value):
                    continue
                if entity_type == "PHONE":
                    digits = re.sub(r"\D", "", value)
                    if not (10 <= len(digits) <= 13):
                        continue
                    if len(digits) == 10 and digits[0] not in "6789":
                        continue
                found.append(
                    Entity(match.start(), match.end(), entity_type, self.name, 0.99 if validator else 0.9)
                )
        return _resolve_overlaps(found, self._priority)


def _resolve_overlaps(entities: list[Entity], priority: dict[str, int]) -> list[Entity]:
    ordered = sorted(
        entities,
        key=lambda item: (item.start, -priority.get(item.entity_type, 0), -(item.end - item.start)),
    )
    selected: list[Entity] = []
    for candidate in ordered:
        if any(candidate.start < item.end and item.start < candidate.end for item in selected):
            continue
        selected.append(candidate)
    return sorted(selected, key=lambda item: item.start)
