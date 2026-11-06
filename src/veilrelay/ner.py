"""Optional spaCy NER detector. No model download is attempted at runtime."""

from __future__ import annotations

from veilrelay.exceptions import DetectionError
from veilrelay.models import Entity


class SpacyNerDetector:
    name = "spacy-ner"

    def __init__(self, model_name: str = "en_core_web_sm") -> None:
        try:
            import spacy

            self._nlp = spacy.load(model_name)
        except Exception as exc:
            raise DetectionError("optional NER model is unavailable") from exc

    def detect(self, text: str) -> list[Entity]:
        doc = self._nlp(text)
        mapping = {"PERSON": "PERSON", "ORG": "ORG", "GPE": "LOCATION", "LOC": "LOCATION"}
        return [
            Entity(ent.start_char, ent.end_char, mapping[ent.label_], self.name, 0.75)
            for ent in doc.ents
            if ent.label_ in mapping
        ]
