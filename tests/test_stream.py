from __future__ import annotations

import pytest

from veilrelay.stream import StreamRewriter
from veilrelay.vault import TokenVault


@pytest.mark.parametrize("split", range(1, 9))
def test_placeholder_split_at_each_boundary(split: int) -> None:
    vault = TokenVault()
    token = vault.issue("EMAIL", "alice@example.com")
    text = f"prefix {token} suffix"
    rewriter = StreamRewriter(vault)
    out = rewriter.feed(text[:split]) + rewriter.feed(text[split:]) + rewriter.finish()
    assert out == "prefix alice@example.com suffix"
    vault.clear()


def test_split_specific_email_token_boundary() -> None:
    vault = TokenVault()
    vault.issue("EMAIL", "alice@example.com")
    rewriter = StreamRewriter(vault)
    result = rewriter.feed("The address is <EMA")
    result += rewriter.feed("IL_1> and it is private.")
    result += rewriter.finish()
    assert result == "The address is alice@example.com and it is private."


def test_multiple_tokens_and_unknown_placeholder() -> None:
    vault = TokenVault()
    first = vault.issue("EMAIL", "alice@example.com")
    second = vault.issue("PHONE", "+919876543210")
    rewriter = StreamRewriter(vault)
    result = "".join(rewriter.feed(chunk) for chunk in [first[:3], first[3:] + " / ", second[:6], second[6:]])
    result += rewriter.finish()
    assert result == "alice@example.com / +919876543210"
    unknown = StreamRewriter(vault)
    assert unknown.feed("<UNKNOWN_7>") + unknown.finish() == "<UNKNOWN_7>"


def test_partial_known_prefix_flushed_on_final() -> None:
    vault = TokenVault()
    vault.issue("EMAIL", "alice@example.com")
    rewriter = StreamRewriter(vault)
    assert rewriter.feed("literal <EMA") == "literal "
    assert rewriter.finish() == "<EMA"


def test_sse_restoration_keeps_json_valid_for_quoted_multiline_values() -> None:
    import json

    from veilrelay.stream import SSEStreamRewriter, restore_json_body

    vault = TokenVault()
    original = '-----BEGIN KEY-----\nline "quoted"\\value\n-----END KEY-----'
    token = vault.issue("PRIVATE_KEY", original)
    payload = {"choices": [{"delta": {"content": f"key: {token}"}}]}
    event = "data: " + json.dumps(payload, separators=(",", ":")) + "\n\n"
    rewriter = SSEStreamRewriter(vault)
    result = rewriter.feed(event[:19]) + rewriter.feed(event[19:43]) + rewriter.feed(event[43:]) + rewriter.finish()
    restored_event = json.loads(result.removeprefix("data: ").strip())
    assert restored_event["choices"][0]["delta"]["content"] == f"key: {original}"

    response_body = json.dumps({"content": token}).encode()
    restored_body = json.loads(restore_json_body(response_body, vault))
    assert restored_body["content"] == original
    vault.clear()
