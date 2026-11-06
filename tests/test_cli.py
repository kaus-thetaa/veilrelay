from __future__ import annotations

import sys

import pytest

from veilrelay.cli import main

def test_cli_scan_redacts_and_prints_counts(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["veil", "scan", "Email alice@example.com"])
    main()
    output = capsys.readouterr().out
    assert "<EMAIL_1>" in output
    assert '"EMAIL": 1' in output
    assert "alice@example.com" not in output


def test_cli_bad_args(monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["veil"])
    with pytest.raises(SystemExit):
        main()

