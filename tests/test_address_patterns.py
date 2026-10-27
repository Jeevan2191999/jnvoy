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
    # street word first, number last
    ("Morada: Rua do Carmo 31, Faro.", "Carmo"),
    ("Entrega en Calle de Atocha 8, Madrid.", "Atocha"),
    ("Consegna a Via Roma 12, Bologna.", "Roma"),
    ("Sede in Piazza della Libertà 3, Trento.", "Libertà"),
    ("Kantoor aan de Keizersgracht 100, Amsterdam.", "Keizersgracht"),
    # bis / ter after the number
    ("Écrire au 5 bis rue Nationale, Lille.", "Nationale"),
    ("Livraison 2 ter boulevard Gambetta, Nice.", "Gambetta"),
    # named dwellings
    ("Post it to Holly Cottage, Mill Lane, Ripley.", "Holly"),
    ("Return to Fern Barn, Hill Road, Frome.", "Fern"),
    ("Registered at Alder House, 8 Park Road, Truro.", "Alder"),
    ("Write to Pine Lodge, Common Road, Chobham.", "Pine"),
    ("Flat 3, Seaview Heights, Brighton is the address.", "Seaview"),
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
    ("The White House, Washington said no.", "White House"),
    ("We met at Royal Albert Hall, London last night.", "Royal Albert Hall"),
    ("Pizza House, a local chain, opened.", "Pizza House"),
    ("See Via email, 5 rows only", "Via email"),
])
def test_ordinary_text_with_similar_words_is_left_alone(text, kept):
    assert kept in red(text), red(text)


class _R:
    def __init__(self, entity_type, start, end):
        self.entity_type, self.start, self.end = entity_type, start, end


def test_a_town_after_a_street_is_not_called_a_person():
    from core.detector_v2 import _is_town_after_address
    text = "Church Lane, Ludlow."
    assert _is_town_after_address(text, _R("PERSON", 13, 19), [])
    assert _is_town_after_address("5 Mill Road, Milton Keynes, UK", _R("PERSON", 13, 26), [_R("STREET_ADDRESS", 0, 11)])


def test_a_person_in_other_positions_is_still_hidden():
    from core.detector_v2 import _is_town_after_address
    assert not _is_town_after_address("Write to Anna Lee, Ludlow.", _R("PERSON", 9, 17), [])
    assert not _is_town_after_address("Church Lane, Smith wrote it.", _R("PERSON", 13, 18), [])
    assert not _is_town_after_address("Church Lane, Anna Maria Louise.", _R("PERSON", 13, 30), [])
    assert not _is_town_after_address("Church Lane, Ludlow.", _R("ORGANIZATION", 13, 19), [])
