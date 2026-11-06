from __future__ import annotations

import pytest

from veilrelay.detectors import BuiltinDetector, SecretDetector


@pytest.mark.parametrize(
    "text",
    [
        "alice@localhost",
        "alice@example",
        "alice@@example.com",
        "Year 2024 and meeting at 12:30",
        "Call 12345 or extension 0000",
        "Card 4111 1111 1111 1112",
        "Repeated digits 1111111111111111",
        "Invalid Aadhaar checksum 234567890123",
        "Invalid PAN ABCDD1234F",
        "Invalid IFSC ABCD1234567",
        "GitHub actions/checkout@v4 are not payment VPAs",
        "IPv4 999.999.999.999 is invalid",
        "IBAN GB82 WEST 1234 5698 7654 33 has a bad check digit",
        "SSN 000-05-1120 has an invalid area",
        "Ordinary prose with punctuation and a date 2025-01-01",
    ],
)
def test_builtin_detector_false_positive_traps(text: str) -> None:
    assert BuiltinDetector().detect(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "A normal sentence with no credentials should not match.",
        "The phrase sk- is not a complete provider key.",
        "-----BEGIN PRIVATE KEY----- without a complete block",
        "postgres://db.example.test/no-password-is-not-a-credential",
        "https://example.test/path/with/a/long/identifier/that/is/not/a/key",
        "short=Ab2!",
    ],
)
def test_secret_detector_false_positive_traps(text: str) -> None:
    assert SecretDetector().detect(text) == []


def test_upi_detector_uses_known_psp_handles() -> None:
    detector = BuiltinDetector()
    assert any(item.entity_type == "UPI_ID" for item in detector.detect("alice@okaxis"))
    for invalid in ["alice@localhost", "alice@example", "checkout@v4", "alice@example.test"]:
        assert all(item.entity_type != "UPI_ID" for item in detector.detect(invalid))
