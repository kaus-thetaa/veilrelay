from __future__ import annotations

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


def _aadhaar_with_valid_checksum(prefix: str = "23456789012") -> str:
    from veilrelay.detectors.validators import _VERHOEFF_D, _VERHOEFF_P

    for check_digit in "0123456789":
        digits = [int(char) for char in prefix + check_digit]
        check = 0
        for index, digit in enumerate(reversed(digits)):
            check = _VERHOEFF_D[check][_VERHOEFF_P[index % 8][digit]]
        if check == 0:
            return prefix + check_digit
    raise AssertionError("no Verhoeff checksum digit")


def test_luhn_positive_negative_and_traps() -> None:
    assert luhn_valid("4111 1111 1111 1111")
    assert not luhn_valid("4111 1111 1111 1112")
    assert not luhn_valid("0000000000000000")
    assert not luhn_valid("12345678901")


def test_verhoeff_positive_negative() -> None:
    valid = _aadhaar_with_valid_checksum()
    assert verhoeff_valid(valid)
    assert not verhoeff_valid(valid[:-1] + str((int(valid[-1]) + 1) % 10))
    assert not verhoeff_valid("111111111111")


def test_iban_positive_negative_and_country_length() -> None:
    assert iban_valid("GB82 WEST 1234 5698 7654 32")
    assert not iban_valid("GB82 WEST 1234 5698 7654 33")
    assert not iban_valid("ZZ82 WEST 1234 5698 7654 32")


def test_ssn_validation_traps() -> None:
    assert ssn_valid("078-05-1120")
    assert not ssn_valid("000-05-1120")
    assert not ssn_valid("666-05-1120")
    assert not ssn_valid("900-05-1120")
    assert not ssn_valid("078-00-1120")
    assert not ssn_valid("078-05-0000")


def test_ip_validation() -> None:
    assert ip_valid("127.0.0.1")
    assert ip_valid("2001:db8::1")
    assert not ip_valid("999.1.1.1")
    assert not ip_valid("hello.example")


def test_indian_identifier_validators() -> None:
    assert pan_valid("ABCPD1234F")
    assert not pan_valid("ABCDD1234F")
    assert not pan_valid("12345ABCDE")
    assert ifsc_valid("HDFC0001234")
    assert not ifsc_valid("HDFC1231234")
    assert upi_valid("alice@okaxis")
    assert not upi_valid("alice@")
    assert not upi_valid("a@b")
