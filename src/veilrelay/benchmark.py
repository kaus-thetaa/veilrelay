"""Reproducible local detector, latency and optional Ollama utility benchmark."""

from __future__ import annotations

import csv
import json
import os
import platform
import statistics
import sys
import time
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from veilrelay.detectors import BuiltinDetector, SecretDetector
from veilrelay.policy import PolicyConfig, PrivacyEngine
from veilrelay.vault import TokenVault

ROOT = Path.cwd()
BENCH_DIR = ROOT / "bench"
RESULTS_DIR = BENCH_DIR / "results"


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def _plain_regex_detect(text: str) -> list[tuple[int, int, str]]:
    """Deliberately basic regex-only baseline with no checksum validation."""
    import re

    patterns = {
        "EMAIL": re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
        "PHONE": re.compile(r"(?<!\w)(?:\+?\d{1,3}[ .-]?)?(?:[6-9]\d{4}[ .-]?\d{5}|\d{3}[ -]\d{3}[ -]\d{4})(?!\w)"),
        "IP_ADDRESS": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "CREDIT_CARD": re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"),
        "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "AWS_ACCESS_KEY": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "API_KEY": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    }
    return [
        (match.start(), match.end(), entity_type)
        for entity_type, pattern in patterns.items()
        for match in pattern.finditer(text)
    ]


def _veilrelay_detect(text: str, engine: PrivacyEngine) -> list[tuple[int, int, str]]:
    return [(entity.start, entity.end, entity.entity_type) for entity in engine.detect(text)]


def _presidio_factory():
    from presidio_analyzer import AnalyzerEngine

    return AnalyzerEngine()


def _presidio_detect(text: str, analyzer) -> list[tuple[int, int, str]]:
    label_map = {
        "EMAIL_ADDRESS": "EMAIL",
        "PHONE_NUMBER": "PHONE",
        "CREDIT_CARD": "CREDIT_CARD",
        "IP_ADDRESS": "IP_ADDRESS",
        "US_SSN": "SSN",
        "IBAN_CODE": "IBAN",
    }
    return [
        (item.start, item.end, label_map[item.entity_type])
        for item in analyzer.analyze(text=text, language="en")
        if item.entity_type in label_map
    ]


def _metrics(rows: list[dict[str, Any]], detector_name: str, detector) -> list[dict[str, Any]]:
    totals: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    for row in rows:
        gold = {(int(item["start"]), int(item["end"]), str(item["type"])) for item in row["entities"]}
        predicted = set(detector(row["text"]))
        for item in gold | predicted:
            label = item[2]
            if item in gold and item in predicted:
                totals[label]["tp"] += 1
            elif item in predicted:
                totals[label]["fp"] += 1
            else:
                totals[label]["fn"] += 1
    results: list[dict[str, Any]] = []
    for entity_type in sorted(totals):
        counts = totals[entity_type]
        tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        results.append(
            {
                "detector": detector_name,
                "entity_type": entity_type,
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "precision": round(precision, 6),
                "recall": round(recall, 6),
                "f1": round(f1, 6),
            }
        )
    return results


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def _latency(rows: list[dict[str, Any]], engine: PrivacyEngine, repeats: int = 10) -> dict[str, Any]:
    baseline_ms: list[float] = []
    veilrelay_ms: list[float] = []
    delta_ms: list[float] = []
    for row in rows:
        for _ in range(repeats):
            started = time.perf_counter_ns()
            _plain_regex_detect(row["text"])
            base_elapsed = (time.perf_counter_ns() - started) / 1_000_000
            started = time.perf_counter_ns()
            engine.detect(row["text"])
            veil_elapsed = (time.perf_counter_ns() - started) / 1_000_000
            baseline_ms.append(base_elapsed)
            veilrelay_ms.append(veil_elapsed)
            delta_ms.append(veil_elapsed - base_elapsed)
    return {
        "repeats_per_example": repeats,
        "samples": len(delta_ms),
        "baseline_p50_ms": round(_percentile(baseline_ms, 0.50), 6),
        "baseline_p95_ms": round(_percentile(baseline_ms, 0.95), 6),
        "veilrelay_p50_ms": round(_percentile(veilrelay_ms, 0.50), 6),
        "veilrelay_p95_ms": round(_percentile(veilrelay_ms, 0.95), 6),
        "added_p50_ms": round(_percentile(delta_ms, 0.50), 6),
        "added_p95_ms": round(_percentile(delta_ms, 0.95), 6),
    }


def _utility_benchmark(engine: PrivacyEngine) -> dict[str, Any]:
    model = os.getenv("OLLAMA_MODEL", "").strip()
    if not model:
        return {"status": "skipped", "reason": "OLLAMA_MODEL is not configured", "tasks": []}
    host = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
    task_path = BENCH_DIR / "utility_tasks.json"
    tasks = json.loads(task_path.read_text(encoding="utf-8"))
    results: list[dict[str, Any]] = []
    for task in tasks:
        prompt = f"Text:\n{task['text']}\n\nQuestion: {task['question']}"
        vault = TokenVault()
        try:
            redacted = engine.scan(prompt, vault).safe_text
            task_result: dict[str, Any] = {"id": task["id"], "task": task["task"]}
            for mode, content in [("unredacted", prompt), ("redacted", redacted)]:
                try:
                    response = httpx.post(
                        f"{host}/api/chat",
                        json={
                            "model": model,
                            "stream": False,
                            "messages": [{"role": "user", "content": content}],
                        },
                        timeout=120.0,
                    )
                    response.raise_for_status()
                    payload = response.json()
                    answer = str(payload.get("message", {}).get("content", payload.get("response", "")))
                    if mode == "redacted":
                        answer = vault.restore(answer)
                    lowered = answer.casefold()
                    matched = sum(term.casefold() in lowered for term in task["expected_terms"])
                    task_result[mode] = {
                        "score": matched / len(task["expected_terms"]),
                        "matched_count": matched,
                        "expected_count": len(task["expected_terms"]),
                    }
                except Exception as exc:
                    task_result[mode] = {"error_class": type(exc).__name__}
            results.append(task_result)
        finally:
            vault.clear()
    errors = [
        task[mode]["error_class"]
        for task in results
        for mode in ("unredacted", "redacted")
        if "error_class" in task.get(mode, {})
    ]
    if errors:
        return {"status": "error", "model": model, "host": host, "error_classes": sorted(set(errors)), "tasks": results}
    raw_scores = [task["unredacted"]["score"] for task in results]
    redacted_scores = [task["redacted"]["score"] for task in results]
    return {
        "status": "completed",
        "model": model,
        "host": host,
        "rubric": "fraction of expected exact terms present after placeholder restoration",
        "unredacted_mean_score": round(statistics.mean(raw_scores), 6),
        "redacted_mean_score": round(statistics.mean(redacted_scores), 6),
        "tasks": results,
    }


def main() -> None:
    synthetic_path = BENCH_DIR / "data" / "synthetic.jsonl"
    if not synthetic_path.exists():
        raise SystemExit("Synthetic data missing; run python bench/generate_synthetic.py first")
    rows = _load_jsonl(synthetic_path)
    data_sources = [{"name": "synthetic", "rows": len(rows), "status": "completed"}]
    openpii_path = BENCH_DIR / "data" / "openpii_nano.jsonl"
    if openpii_path.exists():
        openpii = _load_jsonl(openpii_path)
        rows.extend(openpii)
        data_sources.append({"name": "ai4privacy-openpii-nano-validation", "rows": len(openpii), "status": "completed"})
    else:
        data_sources.append({"name": "ai4privacy-openpii-nano-validation", "rows": 0, "status": "not_downloaded"})

    engine = PrivacyEngine([BuiltinDetector(), SecretDetector()], PolicyConfig())
    metrics: list[dict[str, Any]] = []
    metrics.extend(_metrics(rows, "plain_regex", _plain_regex_detect))
    metrics.extend(_metrics(rows, "veilrelay", lambda text: _veilrelay_detect(text, engine)))

    presidio_status: dict[str, str] = {"status": "skipped", "reason": "presidio-analyzer is not installed"}
    try:
        analyzer = _presidio_factory()
        metrics.extend(_metrics(rows, "presidio_default", lambda text: _presidio_detect(text, analyzer)))
        presidio_status = {"status": "completed", "configuration": "AnalyzerEngine defaults; language=en"}
    except Exception as exc:
        presidio_status = {"status": "skipped", "reason_class": type(exc).__name__}

    latency = _latency(rows, engine)
    utility = _utility_benchmark(engine)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with (RESULTS_DIR / "detection_metrics.csv").open("w", newline="", encoding="utf-8") as handle:
        fields = ["detector", "entity_type", "tp", "fp", "fn", "precision", "recall", "f1"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(metrics)
    with (RESULTS_DIR / "latency.json").open("w", encoding="utf-8") as handle:
        json.dump(latency, handle, indent=2, sort_keys=True)
        handle.write("\n")
    with (RESULTS_DIR / "utility.json").open("w", encoding="utf-8") as handle:
        json.dump(utility, handle, indent=2, sort_keys=True)
        handle.write("\n")

    summary = {
        "run_at_utc": datetime.now(UTC).isoformat(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "detector_configuration": "BuiltinDetector + SecretDetector; PolicyConfig defaults",
        "dataset_sources": data_sources,
        "presidio": presidio_status,
        "detection_metrics_file": "detection_metrics.csv",
        "latency": latency,
        "utility": {key: value for key, value in utility.items() if key != "tasks"},
    }
    (RESULTS_DIR / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    print(f"Raw results: {RESULTS_DIR}")


if __name__ == "__main__":
    main()
