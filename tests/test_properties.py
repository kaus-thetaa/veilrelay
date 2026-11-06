"""Hypothesis properties; skipped in minimal environments without the dev extra."""

from __future__ import annotations

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st

from veilrelay.vault import TokenVault


SAFE_TEXT = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=80)
VALUES = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd", "P", "Zs")),
    min_size=1,
    max_size=40,
)


@settings(max_examples=200, deadline=None)
@given(prefix=SAFE_TEXT, value=VALUES, suffix=SAFE_TEXT)
def test_vault_roundtrip_property(prefix: str, value: str, suffix: str) -> None:
    vault = TokenVault()
    token = vault.issue("CUSTOM", value)
    protected = prefix + token + suffix
    assert vault.restore(protected) == prefix + value + suffix
    vault.clear()


@settings(max_examples=100, deadline=None)
@given(value=VALUES)
def test_vault_reuses_token_for_same_type_and_value(value: str) -> None:
    vault = TokenVault()
    first = vault.issue("PERSON", value)
    second = vault.issue("PERSON", value)
    assert first == second
    assert vault.restore(first) == value
    vault.clear()
