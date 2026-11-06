from __future__ import annotations

import pytest

spacy = pytest.importorskip("spacy")

from veilrelay.ner import SpacyNerDetector


class FakeEntity:
    def __init__(self, start_char: int, end_char: int, label_: str) -> None:
        self.start_char = start_char
        self.end_char = end_char
        self.label_ = label_


class FakeDoc:
    ents = [FakeEntity(0, 9, "PERSON"), FakeEntity(14, 18, "ORG"), FakeEntity(23, 29, "GPE"), FakeEntity(30, 35, "DATE")]


class FakeNLP:
    def __call__(self, text: str) -> FakeDoc:
        assert isinstance(text, str)
        return FakeDoc()


def test_spacy_ner_is_optional_and_maps_supported_types(monkeypatch) -> None:
    monkeypatch.setattr(spacy, "load", lambda model_name: FakeNLP())
    detector = SpacyNerDetector("fake-model")
    entities = detector.detect("Ada Lovelace met NASA in London on Monday")
    assert [entity.entity_type for entity in entities] == ["PERSON", "ORG", "LOCATION"]
