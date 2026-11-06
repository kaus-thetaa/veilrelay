"""Value-free JSONL audit events."""

from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class AuditLogger:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.touch(mode=0o600, exist_ok=True)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass

    def write(
        self,
        request_id: str,
        counts: dict[str, int],
        actions: dict[str, int],
        outcome: str,
        error_class: str | None = None,
    ) -> None:
        if self.path is None:
            return
        event: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "request_id": request_id,
            "entity_counts": {str(key): int(value) for key, value in counts.items()},
            "action_counts": {str(key): int(value) for key, value in actions.items()},
            "outcome": outcome,
        }
        if error_class:
            event["error_class"] = error_class
        # Whitelist schema fields; no input text, values, headers or mappings can enter.
        line = json.dumps(event, separators=(",", ":"), sort_keys=True)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
