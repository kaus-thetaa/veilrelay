from __future__ import annotations

import pytest

from veilrelay.detectors import BuiltinDetector, SecretDetector
from veilrelay.exceptions import DetectionError, PolicyBlocked
from veilrelay.policy import PolicyConfig, PrivacyEngine
from veilrelay.models import Action
from veilrelay.vault import TokenVault


def test_default_redaction_and_counting() -> None:
    engine = PrivacyEngine([BuiltinDetector(), SecretDetector()], PolicyConfig())
    vault = TokenVault()
    result = engine.scan("Write to alice@example.com", vault)
    assert result.safe_text == "Write to <EMAIL_1>"
    assert result.counts == {"EMAIL": 1}
    assert result.actions == {"redact": 1}
    assert result.entity_count == 1
    vault.clear()


def test_action_mask_block_allow() -> None:
    config = PolicyConfig(actions={"EMAIL": Action.MASK})
    masked = PrivacyEngine([BuiltinDetector()], config).scan("alice@example.com")
    assert masked.safe_text == "a***@example.com"
    blocked = PrivacyEngine(
        [BuiltinDetector()],
        PolicyConfig(actions={"EMAIL": Action.BLOCK}),
    )
    with pytest.raises(PolicyBlocked):
        blocked.scan("alice@example.com")
    allowed = PrivacyEngine(
        [BuiltinDetector()], PolicyConfig(allowlist={"alice@example.com"})
    ).scan("alice@example.com")
    assert allowed.safe_text == "alice@example.com"
    assert allowed.actions == {"allow": 1}


def test_custom_rules() -> None:
    config = PolicyConfig.from_dict(
        {"custom_rules": [{"name": "ticket", "pattern": r"TKT-[0-9]{5}", "entity_type": "TICKET", "action": "mask"}]}
    )
    result = PrivacyEngine([], config).scan("Ticket TKT-12345")
    assert result.safe_text == "Ticket [REDACTED]"
    assert result.counts == {"TICKET": 1}
    assert result.actions == {"mask": 1}


def test_bad_policy_data() -> None:
    with pytest.raises(ValueError):
        PolicyConfig.from_dict({"fail_mode": "mystery"})
    with pytest.raises(ValueError):
        PolicyConfig.from_dict({"default_action": "unknown"})
    with pytest.raises(ValueError):
        PolicyConfig.from_dict({"actions": []})
    with pytest.raises(ValueError):
        PolicyConfig.from_dict({"custom_rules": [{"pattern": "["}]})


class BrokenDetector:
    name = "broken"

    def detect(self, text: str):
        raise RuntimeError("do not leak the input")


def test_fail_closed_and_fail_open() -> None:
    closed = PrivacyEngine([BrokenDetector()], PolicyConfig(fail_mode="closed"))
    with pytest.raises(DetectionError) as error:
        closed.scan("sensitive-value")
    assert "sensitive-value" not in str(error.value)
    opened = PrivacyEngine([BrokenDetector()], PolicyConfig(fail_mode="open"))
    result = opened.scan("sensitive-value")
    assert result.safe_text == "sensitive-value"
    assert result.actions == {"fail_open": 1}


def test_yaml_load(tmp_path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("fail_mode: closed\ndefault_action: redact\nactions:\n  EMAIL: mask\n", encoding="utf-8")
    config = PolicyConfig.from_yaml(policy)
    assert config.action_for("EMAIL").value == "mask"
    assert config.action_for("PHONE").value == "redact"
    policy.write_text("- not-a-mapping", encoding="utf-8")
    with pytest.raises(DetectionError):
        PolicyConfig.from_yaml(policy)


def test_invalid_yaml_path(tmp_path) -> None:
    with pytest.raises(DetectionError):
        PolicyConfig.from_yaml(tmp_path / "missing.yml")
