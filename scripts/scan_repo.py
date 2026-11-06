"""Run VeilRelay's own detectors over tracked source-like files.

The output records only paths, entity types and counts. It never includes matched
text, line contents, or offsets. Synthetic tests and benchmark fixtures are
reported separately because they intentionally contain fake credentials/PII.
"""

from __future__ import annotations

import ipaddress
import json
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC_PREFIXES = ("tests/", "bench/", "launch/")
IGNORED_DIRS = {".git", ".pytest_cache", ".mypy_cache", ".ruff_cache", "__pycache__", ".venv"}
EXTENSIONS = {".py", ".md", ".toml", ".yaml", ".yml", ".json", ".jsonl", ".txt", ".sh", ".ini", ".cfg"}


def tracked_files() -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files", "-co", "--exclude-standard"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    paths: list[Path] = []
    for item in completed.stdout.splitlines():
        path = Path(item)
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in EXTENSIONS and (ROOT / path).is_file():
            paths.append(path)
    return paths


def main() -> int:
    sys.path.insert(0, str(ROOT / "src"))
    from veilrelay.detectors import BuiltinDetector, SecretDetector

    detectors = [BuiltinDetector(), SecretDetector()]
    results: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    source_findings: Counter[str] = Counter()
    synthetic_findings: Counter[str] = Counter()
    file_count = 0
    for relative in tracked_files():
        try:
            content = (ROOT / relative).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        file_count += 1
        for detector in detectors:
            for entity in detector.detect(content):
                matched = content[entity.start:entity.end]
                if entity.entity_type == "IP_ADDRESS":
                    try:
                        address = ipaddress.ip_address(matched)
                    except ValueError:
                        address = None
                    if address and (address.is_loopback or address.is_unspecified):
                        continue  # Documented local bind addresses are not embedded secrets.
                target = "synthetic_fixtures" if str(relative).startswith(SYNTHETIC_PREFIXES) else "source_and_docs"
                results[target][entity.entity_type] += 1
                if target == "synthetic_fixtures":
                    synthetic_findings[entity.entity_type] += 1
                else:
                    source_findings[entity.entity_type] += 1
    report: dict[str, Any] = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "files_scanned": file_count,
        "raw_values_recorded": False,
        "source_and_docs": dict(sorted(source_findings.items())),
        "synthetic_fixtures": dict(sorted(synthetic_findings.items())),
        "status": "clean" if not source_findings else "review_required",
    }
    output = ROOT / "bench" / "results" / "repo_scan.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "clean" else 1


if __name__ == "__main__":
    raise SystemExit(main())
