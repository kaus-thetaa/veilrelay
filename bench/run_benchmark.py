"""Benchmark entrypoint; run from the repository root with `python bench/run_benchmark.py`."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from veilrelay.benchmark import main  # noqa: E402


if __name__ == "__main__":
    main()
