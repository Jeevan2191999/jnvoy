"""
Opt-in medical-term detection (core/medical_terms.py). Off by default, switched on with redact_extra
"medical_term". The measurements live in evaluation/medical_terms_eval.py and tests/test_medical_terms_eval.py.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.detector_v2 import OPTIONAL_ENTITIES, PIIDetectorV2, resolve_entities  # noqa: E402
from core.policy import entities_for, validate_policy  # noqa: E402


@pytest.fixture(scope="module")
def on():
    return PIIDetectorV2(entities=resolve_entities(env={"JNVOY_REDACT_EXTRA": "MEDICAL_TERM"}))


@pytest.fixture(scope="module")
def off():
    return PIIDetectorV2()


def test_it_is_an_optional_type_and_off_by_default(off):
    assert "MEDICAL_TERM" in OPTIONAL_ENTITIES
    assert "MEDICAL_TERM" not in resolve_entities(env={})
    text = "He has diabetes and takes metformin after chemotherapy."
    assert off.detect(text).redacted_text == text


def test_the_policy_can_switch_it_on_and_nothing_else_changes():
    assert validate_policy({"redact_extra": "medical_term"}) == {"redact_extra": "medical_term"}
    assert "MEDICAL_TERM" in entities_for({"redact_extra": "medical_term"})
    assert "MEDICAL_TERM" not in entities_for({"redact_extra": "organization"})
    with pytest.raises(ValueError):
        validate_policy({"redact_extra": "medical_terms_please"})


@pytest.mark.parametrize("text, hidden", [
    ("He has diabetes and takes metformin.", ["diabetes", "metformin"]),
    ("Started chemotherapy last week", ["chemotherapy"]),
    ("Her TYPE 2 DIABETES is stable", ["TYPE 2 DIABETES"]),
    ("Diagnosed with cancer in 2024", ["cancer"]),
    ("a history of severe depression", ["depression"]),
    ("treated for the flu", ["flu"]),
    ("He takes Ramipril 5 mg daily", ["Ramipril"]),
    ("Prescribed rosuvastatin", ["rosuvastatin"]),
    ("bisoprolol and escitalopram", ["bisoprolol", "escitalopram"]),
])
def test_what_it_finds(on, text, hidden):
    red = on.detect(text).redacted_text
    for h in hidden:
        assert h not in red, (text, red)
    assert "[MEDICAL_TERM_" in red


@pytest.mark.parametrize("text", [
    "A cold call about a stroke of luck",
    "The depression of 1929 was global",
    "My cancer horoscope for April",
    "Anxiety about the deadline grew",
    "Take 2 tablets 500 mg after food",
    "The pregnancy of the project was long",
    "Heart disease charities raised money",
    "Falconer and Pelham met in April",
])
def test_everyday_uses_are_left_alone(on, text):
    assert "MEDICAL_TERM" not in on.detect(text).redacted_text


def test_what_it_cannot_find_is_stated_not_hidden(on):
    for text in ("He has gout", "She uses Ventolin", "clopidogrel daily", "heart disease runs in the family"):
        assert "MEDICAL_TERM" not in on.detect(text).redacted_text, text


def test_short_words_that_end_like_a_medicine_are_left_alone(on):
    for text in ("Meet Pril at noon", "April is early", "Capril rose"):
        assert "MEDICAL_TERM" not in on.detect(text).redacted_text, text
