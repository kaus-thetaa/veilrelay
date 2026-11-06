from __future__ import annotations

from veilrelay.detectors import BuiltinDetector, SecretDetector
from veilrelay.detectors.secrets import shannon_entropy


def types(text: str) -> set[str]:
    return {entity.entity_type for entity in BuiltinDetector().detect(text)}


def test_email_positive_and_false_positive_traps() -> None:
    assert "EMAIL" in types("Contact alice.smith+dev@example.co.uk today")
    assert "EMAIL" not in types("alice@localhost and alice@example")


def test_phone_indian_international_and_false_positives() -> None:
    detected = BuiltinDetector().detect("Call +91 98765 43210 or 9876543210")
    assert sum(entity.entity_type == "PHONE" for entity in detected) == 2
    assert "PHONE" not in types("Year 2024; time 12:30; code 1234567890")


def test_credit_card_uses_luhn() -> None:
    assert "CREDIT_CARD" in types("Card 4111-1111-1111-1111")
    assert "CREDIT_CARD" not in types("Card 4111-1111-1111-1112")


def test_aadhaar_uses_verhoeff() -> None:
    # Search a check digit without storing or logging a real identifier.
    from tests.test_validators import _aadhaar_with_valid_checksum

    valid = _aadhaar_with_valid_checksum()
    assert "AADHAAR" in types(valid)
    assert "AADHAAR" not in types(valid[:-1] + str((int(valid[-1]) + 1) % 10))


def test_pan_ifsc_upi() -> None:
    found = types("PAN ABCPD1234F; IFSC HDFC0001234; UPI alice@okaxis")
    assert {"PAN", "IFSC", "UPI_ID"} <= found
    assert "PAN" not in types("Not a PAN: ABCDD1234F")
    assert "IFSC" not in types("ABCD1234567")
    assert "UPI_ID" not in types("GitHub Actions use actions/checkout@v4 and setup-python@v5")


def test_ip_iban_ssn() -> None:
    found = types("IP 192.168.1.15; IBAN GB82 WEST 1234 5698 7654 32; SSN 078-05-1120")
    assert {"IP_ADDRESS", "IBAN", "SSN"} <= found
    assert "IP_ADDRESS" not in types("999.999.999.999")
    assert "IBAN" not in types("GB82 WEST 1234 5698 7654 33")
    assert "SSN" not in types("000-05-1120")
