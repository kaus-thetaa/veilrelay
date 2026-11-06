"""Generate a fully synthetic labelled dataset for deterministic smoke benchmarks."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from veilrelay.detectors.validators import verhoeff_valid  # noqa: E402

ROOT = Path(__file__).resolve().parent


def make_aadhaar() -> str:
    prefix = "23456789012"
    for digit in "0123456789":
        candidate = prefix + digit
        if verhoeff_valid(candidate):
            return candidate
    raise RuntimeError("could not create checksum-valid synthetic Aadhaar-shaped value")


def build_rows() -> list[dict]:
    examples = [
        ("email", "Send the report to alice@example.test.", "EMAIL", "alice@example.test"),
        ("email_plus", "Reply to bob+alerts@example.org by noon.", "EMAIL", "bob+alerts@example.org"),
        ("phone_india", "Call the support number +91 98765 43210.", "PHONE", "+91 98765 43210"),
        ("phone_local", "Reach the operator at 9876543210.", "PHONE", "9876543210"),
        ("ipv4", "The test server is 203.0.113.9.", "IP_ADDRESS", "203.0.113.9"),
        ("ipv6", "The documentation host is 2001:db8::1.", "IP_ADDRESS", "2001:db8::1"),
        ("credit_card", "Use the sandbox card 4111111111111111.", "CREDIT_CARD", "4111111111111111"),
        ("iban", "Transfer to IBAN GB82 WEST 1234 5698 7654 32.", "IBAN", "GB82 WEST 1234 5698 7654 32"),
        ("ssn", "The fixture SSN is 078-05-1120.", "SSN", "078-05-1120"),
        ("aadhaar", f"Test Aadhaar-shaped value {make_aadhaar()}.", "AADHAAR", make_aadhaar()),
        ("pan", "Fixture PAN is ABCPD1234F.", "PAN", "ABCPD1234F"),
        ("ifsc", "Use bank IFSC HDFC0001234.", "IFSC", "HDFC0001234"),
        ("upi", "Pay the sandbox VPA alice@okaxis.", "UPI_ID", "alice@okaxis"),
        ("aws_key", "Fake AWS access key AKIAIOSFODNN7EXAMPLE.", "AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE"),
        ("github_token", "Fake GitHub token ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL.", "GITHUB_TOKEN", "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL"),
        ("gitlab_token", "Fake GitLab token glpat-abcdefghijklmnopqrstuvwx.", "GITLAB_TOKEN", "glpat-abcdefghijklmnopqrstuvwx"),
        ("openai_key", "Fake provider key sk-proj-abcdefghijklmnopqrstuvwxyz012345.", "OPENAI_KEY", "sk-proj-abcdefghijklmnopqrstuvwxyz012345"),
        ("anthropic_key", "Fake provider key sk-ant-abcdefghijklmnopqrstuvwxyz012345.", "ANTHROPIC_KEY", "sk-ant-abcdefghijklmnopqrstuvwxyz012345"),
        ("stripe_key", "Fake Stripe key sk_live_abcdefghijklmnop123456.", "STRIPE_KEY", "sk_live_abcdefghijklmnop123456"),
        ("jwt", "Fixture token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepayload123456.", "JWT", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepayload123456"),
        ("private_key", "Fixture key -----BEGIN PRIVATE KEY-----\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END PRIVATE KEY-----.", "PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END PRIVATE KEY-----"),
        ("db_connection", "Use postgres://fixture:fakepass@db.example.test:5432/sample.", "DB_CONNECTION", "postgres://fixture:fakepass@db.example.test:5432/sample"),
        ("entropy", "Opaque credential: a8F1cD9kL2mQ7xP4vB6nR0sT5wY3zH1j.", "HIGH_ENTROPY_SECRET", "a8F1cD9kL2mQ7xP4vB6nR0sT5wY3zH1j"),
    ]
    rows: list[dict] = []
    for identifier, text, entity_type, value in examples:
        start = text.index(value)
        rows.append(
            {
                "id": identifier,
                "text": text,
                "entities": [{"start": start, "end": start + len(value), "type": entity_type}],
            }
        )
    # Include mixed examples to measure span selection and multiple detections in context.
    mixed = "Email alice@example.test or call +91 98765 43210; AWS key AKIAIOSFODNN7EXAMPLE."
    mixed_entities = []
    for entity_type, value in [
        ("EMAIL", "alice@example.test"),
        ("PHONE", "+91 98765 43210"),
        ("AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE"),
    ]:
        begin = mixed.index(value)
        mixed_entities.append({"start": begin, "end": begin + len(value), "type": entity_type})
    rows.append({"id": "mixed", "text": mixed, "entities": mixed_entities})
    return rows


def main() -> None:
    path = ROOT / "data" / "synthetic.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in build_rows():
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"Wrote {len(build_rows())} synthetic rows to {path}")


if __name__ == "__main__":
    main()
