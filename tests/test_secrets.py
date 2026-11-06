from __future__ import annotations

from veilrelay.detectors import SecretDetector
from veilrelay.detectors.secrets import shannon_entropy

def test_secret_patterns() -> None:
    content = """AKIA1234567890ABCDEF ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL glpat-abcdefghijklmnopqrst
sk-ant-abcdefghijklmnopqrstuvwxyz1234567890 sk-proj-abcdefghijklmnopqrstuvwxyz1234567890 sk_live_abcdefghijklmnop
"""
    found = {entity.entity_type for entity in SecretDetector().detect(content)}
    assert {"AWS_ACCESS_KEY", "GITHUB_TOKEN", "GITLAB_TOKEN", "ANTHROPIC_KEY", "OPENAI_KEY", "STRIPE_KEY"} <= found


def test_jwt_private_key_and_database_url() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepayload123456"
    pem = "-----BEGIN PRIVATE KEY-----\n" + ("A" * 40) + "\n-----END PRIVATE KEY-----"
    db = "postgres://dbuser:dbpass@db.example.org:5432/app"
    found = {entity.entity_type for entity in SecretDetector().detect(f"{jwt} {pem} {db}")}
    assert {"JWT", "PRIVATE_KEY", "DB_CONNECTION"} <= found


def test_entropy_detector_and_traps() -> None:
    randomish = "a8F1cD9kL2mQ7xP4vB6nR0sT5wY3zH1j"
    assert shannon_entropy(randomish) > 4.0
    found = SecretDetector().detect(f"credential={randomish}")
    assert any(entity.entity_type == "HIGH_ENTROPY_SECRET" for entity in found)
    assert not SecretDetector().detect("This-is-a-normal-lowercase-sentence-with-many-words")
    assert not SecretDetector().detect("https://example.com/path/with/a/long/identifier/that/is/not/a/key")


def test_no_secret_value_in_entity_repr() -> None:
    secret = "AKIA1234567890ABCDEF"
    entity = SecretDetector().detect(secret)[0]
    assert secret not in repr(entity)

