"""Boundary-safe placeholder restoration for plain text and SSE events."""

from __future__ import annotations

import json
import re
from typing import Any

from veilrelay.vault import TokenVault


_EVENT_SEPARATOR = re.compile(r"\r?\n\r?\n")


class StreamRewriter:
    """Restore known placeholders in arbitrary text chunks without split leaks."""

    def __init__(self, vault: TokenVault) -> None:
        self.vault = vault
        self._buffer = ""
        self._tokens = tuple(sorted(vault.known_tokens(), key=len, reverse=True))

    def feed(self, chunk: str) -> str:
        self._buffer += chunk
        return self._drain(final=False)

    def finish(self) -> str:
        return self._drain(final=True)

    def _drain(self, final: bool) -> str:
        if not self._tokens:
            output, self._buffer = self._buffer, ""
            return output
        output: list[str] = []
        index = 0
        text = self._buffer
        while index < len(text):
            if text[index] == "<":
                match = next((token for token in self._tokens if text.startswith(token, index)), None)
                if match is not None:
                    output.append(self.vault.restore(match))
                    index += len(match)
                    continue
                remainder = text[index:]
                if not final and any(token.startswith(remainder) for token in self._tokens):
                    break
            output.append(text[index])
            index += 1
        self._buffer = text[index:]
        if final and self._buffer:
            output.append(self._buffer)
            self._buffer = ""
        return "".join(output)


class SSEStreamRewriter:
    """Restore JSON data in complete SSE events, preserving valid JSON escaping.

    SSE event boundaries, rather than transport chunk boundaries, delimit the
    buffer. This lets a value containing quotes, backslashes or newlines be
    reinserted as a JSON string without corrupting the response stream.
    """

    def __init__(self, vault: TokenVault) -> None:
        self.vault = vault
        self._buffer = ""

    def feed(self, chunk: str) -> str:
        self._buffer += chunk
        output: list[str] = []
        while match := _EVENT_SEPARATOR.search(self._buffer):
            frame = self._buffer[: match.start()]
            separator = match.group(0)
            self._buffer = self._buffer[match.end() :]
            output.append(self._rewrite_event(frame) + separator)
        return "".join(output)

    def finish(self) -> str:
        if not self._buffer:
            return ""
        remainder = self._rewrite_event(self._buffer)
        self._buffer = ""
        return remainder

    def _rewrite_event(self, frame: str) -> str:
        lines = frame.splitlines()
        data_values = [line[5:].lstrip(" ") for line in lines if line.startswith("data:")]
        if not data_values:
            return frame
        data = "\n".join(data_values)
        if data == "[DONE]":
            return frame
        try:
            payload = json.loads(data)
        except json.JSONDecodeError:
            restored = self.vault.restore(data)
        else:
            restored_payload = _restore_tree(payload, self.vault)
            restored = json.dumps(restored_payload, ensure_ascii=False, separators=(",", ":"))

        rewritten: list[str] = []
        inserted = False
        for line in lines:
            if line.startswith("data:"):
                if not inserted:
                    rewritten.append("data: " + restored)
                    inserted = True
                continue
            rewritten.append(line)
        return "\n".join(rewritten)


def restore_json_body(body: bytes, vault: TokenVault) -> bytes:
    """Restore placeholders in JSON string values while preserving valid JSON."""
    decoded = body.decode("utf-8", errors="replace")
    try:
        payload = json.loads(decoded)
    except json.JSONDecodeError:
        return vault.restore(decoded).encode("utf-8")
    return json.dumps(_restore_tree(payload, vault), ensure_ascii=False).encode("utf-8")


def _restore_tree(value: Any, vault: TokenVault) -> Any:
    if isinstance(value, str):
        return vault.restore(value)
    if isinstance(value, list):
        return [_restore_tree(item, vault) for item in value]
    if isinstance(value, dict):
        return {key: _restore_tree(item, vault) for key, item in value.items()}
    return value
