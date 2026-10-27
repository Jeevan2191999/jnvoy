"""Street-address and reference-number patterns found missing by the accuracy evaluation."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.detector_v2 import PIIDetectorV2  # noqa: E402

det = PIIDetectorV2()


def red(text):
    return det.detect(text).redacted_text


@pytest.mark.parametrize("text,leaked", [
    ("Please post it to 42 Rue Saint-Honoré, Paris.", "Honoré"),
    ("Delivery to 12 Boulevard Voltaire, 75011 Paris.", "Voltaire"),
    ("He lives at 19 Calle de Alcalá in Madrid.", "Alcalá"),
    ("Client at 7 Via Giuseppe Verdi, Milano.", "Verdi"),
    ("Post to Hauptstraße 27, Berlin.", "Hauptstraße"),
    ("Parcel for Kerkstraat 15, Utrecht.", "Kerkstraat"),
    ("Our flat is Flat 4C, Rosewood Court, Mill Lane.", "Rosewood"),
    ("Apartment 9B, Elm Mansions, Park Road.", "Mansions"),
    ("Old address was The Old Rectory, Church Lane.", "Rectory"),
    ("Case file ref CF2291/88 was closed.", "CF2291"),
    ("Account holder reference AH9923-77B is overdue.", "AH9923"),
])
def test_missed_address_and_reference_shapes_are_now_hidden(text, leaked):
    assert leaked not in red(text), red(text)


@pytest.mark.parametrize("text,kept", [
    ("We ordered a flat white at the café.", "flat white"),
    ("The Manor House pub does a good roast.", "Manor House"),
    ("The song Boulevard of Broken Dreams came on.", "Boulevard of Broken Dreams"),
    ("Send 3 via email to the team.", "via email"),
    ("The Old Rectory is a famous poem title.", "Old Rectory"),
    ("Unit 4 of the course covers the trial.", "Unit 4"),
])
def test_ordinary_text_with_similar_words_is_left_alone(text, kept):
    assert kept in red(text), red(text)
