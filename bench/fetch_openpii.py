"""Download and normalize the Ai4Privacy OpenPII Nano sample (CC-BY-4.0).

Optional dependency: run `python -m pip install '.[bench]'` from the repository root. No dataset bytes are committed.
"""

from __future__ import annotations

import json
from pathlib import Path

DATASET_ID = "ai4privacy/pii-masking-nano-1k"
LABEL_MAP = {
    "EMAIL": "EMAIL",
    "TELEPHONENUM": "PHONE",
    "CREDITCARDNUMBER": "CREDIT_CARD",
}


def main() -> None:
    try:
        from datasets import load_dataset
    except ImportError as exc:
        raise SystemExit("Install the optional benchmark dependencies: pip install '.[bench]'") from exc
    dataset = load_dataset(DATASET_ID, split="validation")
    target = Path(__file__).resolve().parent / "data" / "openpii_nano.jsonl"
    target.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with target.open("w", encoding="utf-8") as handle:
        for index, row in enumerate(dataset):
            text = row.get("source_text", "")
            entities = []
            for entity in row.get("privacy_mask", []):
                label = LABEL_MAP.get(str(entity.get("label", "")).upper())
                if label is None:
                    continue
                start, end = int(entity["start"]), int(entity["end"])
                if 0 <= start < end <= len(text):
                    entities.append({"start": start, "end": end, "type": label})
            handle.write(json.dumps({"id": f"openpii-{index}", "text": text, "entities": entities}, ensure_ascii=False) + "\n")
            written += 1
    print(f"Normalized {written} validation rows to {target}")
    print("Attribution: Ai4Privacy, OpenPII Nano, CC-BY-4.0; see bench/METHODOLOGY.md")


if __name__ == "__main__":
    main()
