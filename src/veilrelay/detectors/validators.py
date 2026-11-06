"""Checksum and structural validators for common identifiers."""

from __future__ import annotations

import ipaddress
import re


def luhn_valid(value: str) -> bool:
    digits = [int(char) for char in value if char.isdigit()]
    if not 12 <= len(digits) <= 19:
        return False
    if len(set(digits)) == 1:
        return False
    total = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 5, 2, 3, 8),
)


def verhoeff_valid(value: str) -> bool:
    digits = [int(char) for char in value if char.isdigit()]
    if len(digits) != 12 or len(set(digits)) == 1:
        return False
    check = 0
    for index, digit in enumerate(reversed(digits)):
        check = _VERHOEFF_D[check][_VERHOEFF_P[index % 8][digit]]
    return check == 0


_IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20,
    "BE": 16, "BG": 22, "BH": 22, "BR": 29, "BY": 28, "CH": 21,
    "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DK": 18, "DO": 28,
    "EE": 20, "EG": 29, "ES": 24, "FI": 18, "FO": 18, "FR": 27,
    "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28,
    "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26,
    "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32,
    "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27, "MD": 24,
    "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18,
    "NO": 15, "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29,
    "RO": 24, "RS": 22, "SA": 24, "SC": 31, "SE": 24, "SI": 19,
    "SK": 24, "SM": 27, "ST": 25, "SV": 28, "TL": 23, "TN": 24,
    "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
}


def iban_valid(value: str) -> bool:
    compact = re.sub(r"\s+", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}", compact):
        return False
    if _IBAN_LENGTHS.get(compact[:2]) != len(compact):
        return False
    rearranged = compact[4:] + compact[:4]
    remainder = 0
    for char in rearranged:
        expanded = str(ord(char) - 55) if char.isalpha() else char
        for digit in expanded:
            remainder = (remainder * 10 + int(digit)) % 97
    return remainder == 1


def ssn_valid(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    return area not in {"000", "666"} and int(area) < 900 and group != "00" and serial != "0000"


def ip_valid(value: str) -> bool:
    candidate = value.strip("[]")
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def pan_valid(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Z]{5}[0-9]{4}[A-Z]", value.upper())) and value[3].upper() in "ABCFGHLJPT"


def ifsc_valid(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Z]{4}0[A-Z0-9]{6}", value.upper()))


_KNOWN_UPI_HANDLES = frozenset(
    {
        "abfspay", "airtel", "apl", "axl", "axisbank", "bob", "boi", "canara",
        "citi", "dbs", "fbl", "federal", "gpay", "hdfcbank", "hsbc", "ibl",
        "icici", "idfcfirst", "indus", "jio", "kotak", "oksbi", "okaxis",
        "okbizaxis", "okhdfcbank", "okicici", "okyes", "paytm", "paytmqr",
        "pnb", "rbl", "sbi", "saraswat", "unionbank", "upi", "ybl", "yesbank",
    }
)


def upi_valid(value: str) -> bool:
    if len(value) > 100 or value.count("@") != 1:
        return False
    user, handle = value.split("@", 1)
    valid_user = bool(re.fullmatch(r"[A-Za-z0-9._-]{2,64}", user))
    return valid_user and handle.casefold() in _KNOWN_UPI_HANDLES
