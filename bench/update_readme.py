"""Regenerate README benchmark block from committed raw benchmark outputs."""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "bench" / "results"
README = ROOT / "README.md"
SUMMARY_START = "<!-- BENCHMARK-SUMMARY:START -->"
SUMMARY_END = "<!-- BENCHMARK-SUMMARY:END -->"
DETAIL_START = "<!-- BENCHMARK-DETAIL:START -->"
DETAIL_END = "<!-- BENCHMARK-DETAIL:END -->"


def metrics_by_detector() -> dict[str, dict[str, dict[str, int]]]:
    totals: dict[str, dict[str, dict[str, int]]] = defaultdict(
        lambda: defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    )
    with (RESULTS / "detection_metrics.csv").open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            for key in ("tp", "fp", "fn"):
                totals[row["detector"]][row["entity_type"]][key] += int(row[key])
    return totals


def aggregate(per_type: dict[str, dict[str, int]]) -> dict[str, int]:
    return {
        key: sum(counts[key] for counts in per_type.values())
        for key in ("tp", "fp", "fn")
    }


def score(counts: dict[str, int]) -> tuple[float, float, float]:
    tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    return precision, recall, f1


def render_score(value: dict[str, int] | None) -> str:
    if value is None:
        return "—"
    precision, recall, f1 = score(value)
    return f"{precision:.3f} / {recall:.3f} / {f1:.3f}"


def main() -> None:
    summary: dict[str, Any] = json.loads((RESULTS / "summary.json").read_text(encoding="utf-8"))
    latency = summary["latency"]
    totals = metrics_by_detector()
    source_summary = ", ".join(
        f"{item['name']}: {item['rows']} rows ({item['status']})" for item in summary["dataset_sources"]
    )
    veilrelay_micro = aggregate(totals.get("veilrelay", {}))
    regex_micro = aggregate(totals.get("plain_regex", {}))
    veilrelay_gold = veilrelay_micro["tp"] + veilrelay_micro["fn"]
    regex_gold = regex_micro["tp"] + regex_micro["fn"]
    veilrelay_score = " / ".join(f"{item:.3f}" for item in score(veilrelay_micro))
    regex_score = " / ".join(f"{item:.3f}" for item in score(regex_micro))
    presidio_status = summary["presidio"]["status"]
    if presidio_status == "completed" and "presidio_default" in totals:
        counts = aggregate(totals["presidio_default"])
        presidio_summary = " / ".join(f"{item:.3f}" for item in score(counts))
        presidio_gold = counts["tp"] + counts["fn"]
        presidio_row = f"| Presidio defaults | {presidio_summary} | {presidio_gold} | completed |"
        presidio_note = "Presidio defaults ran with the configuration described in the methodology."
    else:
        reason = summary["presidio"].get("reason_class", summary["presidio"].get("reason", "not run"))
        presidio_row = f"| Presidio defaults | — | — | skipped ({reason}) |"
        presidio_note = f"Presidio defaults were skipped ({reason}); no metrics are inferred."
    utility = summary["utility"]
    summary_lines = [
        SUMMARY_START,
        "| Detector | Micro precision / recall / F1 | Gold spans | Run status |",
        "|---|---:|---:|---|",
        f"| VeilRelay | {veilrelay_score} | {veilrelay_gold} | completed |",
        f"| Plain regex | {regex_score} | {regex_gold} | completed |",
        presidio_row,
        "",
        f"- **Dataset:** {source_summary}.",
        f"- **Added local detector latency:** p50 {latency['added_p50_ms']:.6f} ms; p95 {latency['added_p95_ms']:.6f} ms ({latency['samples']} paired samples; plain-regex baseline).",
        f"- **Utility preservation:** {utility['status']}" + (f" — {utility.get('reason', '')}." if utility.get("reason") else "."),
        f"- **Presidio:** {presidio_note}",
        "- **Interpretation:** the current run is a small synthetic regression smoke test, not a real-world accuracy estimate. Exact spans use `(start, end, type)`. See [methodology](bench/METHODOLOGY.md), [raw CSV](bench/results/detection_metrics.csv), [latency JSON](bench/results/latency.json), and [run summary](bench/results/summary.json).",
        SUMMARY_END,
    ]
    entity_types = sorted(totals.get("veilrelay", {}))
    detail_lines = [
        DETAIL_START,
        "| Entity type | VeilRelay P / R / F1 | Plain regex P / R / F1 |",
        "|---|---:|---:|",
    ]
    for entity_type in entity_types:
        detail_lines.append(
            f"| `{entity_type}` | {render_score(totals['veilrelay'].get(entity_type))} | "
            f"{render_score(totals.get('plain_regex', {}).get(entity_type))} |"
        )
    detail_lines.append(DETAIL_END)

    current = README.read_text(encoding="utf-8")
    for marker_start, marker_end, replacement in [
        (SUMMARY_START, SUMMARY_END, "\n".join(summary_lines)),
        (DETAIL_START, DETAIL_END, "\n".join(detail_lines)),
    ]:
        start_index, end_index = current.find(marker_start), current.find(marker_end)
        if start_index < 0 or end_index < 0 or end_index < start_index:
            raise SystemExit(f"README benchmark markers {marker_start} / {marker_end} are missing or malformed")
        end_index += len(marker_end)
        current = current[:start_index] + replacement + current[end_index:]
    README.write_text(current, encoding="utf-8")
    print("Updated README benchmark tables from bench/results/*")


if __name__ == "__main__":
    main()
