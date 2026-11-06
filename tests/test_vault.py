from __future__ import annotations

import time

import pytest

from veilrelay.vault import ConversationVaults, TokenVault


def test_tokenize_restore_and_stable_mapping() -> None:
    vault = TokenVault()
    first = vault.issue("EMAIL", "alice@example.com")
    second = vault.issue("EMAIL", "alice@example.com")
    phone = vault.issue("PHONE", "+919876543210")
    assert first == second == "<EMAIL_1>"
    assert phone == "<PHONE_1>"
    assert vault.restore(f"mail {first}; call {phone}") == "mail alice@example.com; call +919876543210"
    assert vault.restore("unknown <EMAIL_99>") == "unknown <EMAIL_99>"
    vault.clear()


def test_expiry_clears_and_rejects() -> None:
    vault = TokenVault(ttl_seconds=0.001)
    vault.issue("EMAIL", "a@example.com")
    time.sleep(0.005)
    with pytest.raises(RuntimeError, match="vault expired"):
        vault.restore("<EMAIL_1>")
    assert vault._token_to_value == {}


def test_conversation_vault_consistency_and_clear() -> None:
    vaults = ConversationVaults(ttl_seconds=30, max_conversations=2)
    first = vaults.get("conversation-a")
    token1 = first.issue("PERSON", "Ada Lovelace")
    token2 = vaults.get("conversation-a").issue("PERSON", "Ada Lovelace")
    assert token1 == token2
    vaults.clear("conversation-a")
    with pytest.raises(RuntimeError):
        first.restore(token1)


def test_conversation_vault_eviction() -> None:
    vaults = ConversationVaults(ttl_seconds=30, max_conversations=1)
    old = vaults.get("one")
    old.issue("EMAIL", "old@example.com")
    vaults.get("two")
    with pytest.raises(RuntimeError):
        old.restore("<EMAIL_1>")


def test_invalid_vault_parameters() -> None:
    with pytest.raises(ValueError):
        TokenVault(ttl_seconds=0)
    with pytest.raises(ValueError):
        ConversationVaults(max_conversations=0)
    with pytest.raises(ValueError):
        ConversationVaults().get("")


def test_conversation_vault_refreshes_underlying_token_ttl() -> None:
    vaults = ConversationVaults(ttl_seconds=0.05)
    original_vault = vaults.get("conversation")
    token = original_vault.issue("EMAIL", "alice@example.test")
    time.sleep(0.03)
    assert vaults.get("conversation") is original_vault
    time.sleep(0.03)  # Past the original vault expiry, but inside the refreshed TTL.
    assert original_vault.restore(token) == "alice@example.test"
