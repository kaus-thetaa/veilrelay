from __future__ import annotations

import json
import sys

import pytest

from veilrelay.audit import AuditLogger


def test_audit_log_schema_and_no_values(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    logger = AuditLogger(path)
    logger.write("req-1", {"EMAIL": 1}, {"redact": 1}, "forwarded", "ValueError")
    record = json.loads(path.read_text().strip())
    assert record["entity_counts"] == {"EMAIL": 1}
    assert record["outcome"] == "forwarded"
    assert "raw_value" not in path.read_text()
    assert "alice@example.com" not in path.read_text()


def test_audit_disabled_is_noop() -> None:
    AuditLogger().write("req", {"EMAIL": 1}, {}, "forwarded")
