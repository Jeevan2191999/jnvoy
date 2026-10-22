"""
Region packs: national identifiers outside the UK and US.

All numbers are published or generated examples with valid check digits. Nothing real.
Each identifier must be found when valid, ignored when the check digit is wrong, and (for
plain-digit numbers) ignored when nothing nearby says what it is.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.detector_v2 import PIIDetectorV2, resolve_entities  # noqa: E402
from core import regions  # noqa: E402

# (entity, sentence, value that must disappear)
VALID = [
    ("IN_AADHAAR", "My Aadhaar number is 7260 1815 9082.", "7260 1815 9082"),
    ("IN_PAN", "Her PAN is ABCPE1234F on file.", "ABCPE1234F"),
    ("AU_TFN", "Please quote TFN 123 456 782 on the form.", "123 456 782"),
    ("AU_MEDICARE", "Medicare card 6952 89074 9 expires soon.", "6952 89074 9"),
    ("CA_SIN", "Employee SIN 046 454 286 for payroll.", "046 454 286"),
    ("SG_NRIC_FIN", "NRIC S1234567D was verified.", "S1234567D"),
    ("ZA_ID_NUMBER", "South African ID number 8001015009087.", "8001015009087"),
    ("KR_RRN", "Resident registration number 800101-1234560.", "800101-1234560"),
    ("TH_TNIN", "Thai national ID 1101700202232 was checked.", "1101700202232"),
    ("TR_NATIONAL_ID", "TC kimlik no 10000000146 girildi.", "10000000146"),
    ("ES_NIF", "Su DNI es 12345678Z, gracias.", "12345678Z"),
    ("ES_NIE", "Foreign resident NIE X1234567L.", "X1234567L"),
    ("IT_FISCAL_CODE", "Il codice fiscale è RSSMRA85T10A562S.", "RSSMRA85T10A562S"),
    ("PL_PESEL", "Numer PESEL 44051401359 w systemie.", "44051401359"),
    ("SE_PERSONNUMMER", "Personnummer 811218-9876 registrerat.", "811218-9876"),
    ("FI_PERSONAL_IDENTITY_CODE", "Henkilötunnus 131052-308T annettu.", "131052-308T"),
    ("DE_TAX_ID", "Steuer-ID 86095742719 für das Finanzamt.", "86095742719"),
    ("DE_SOCIAL_SECURITY", "Rentenversicherungsnummer 15070649C103 gespeichert.", "15070649C103"),
    ("FR_NIR", "Numéro de sécurité sociale 2 69 05 49 588 157 80.", "2 69 05 49 588 157 80"),
    ("NL_BSN", "Het BSN is 111222333 volgens het dossier.", "111222333"),
    ("BR_CPF", "CPF do cliente: 111.444.777-35.", "111.444.777-35"),
    ("CN_RESIDENT_ID", "Resident ID 11010519491231002X on the contract.", "11010519491231002X"),
    ("AE_EMIRATES_ID", "Emirates ID 784-1985-1234567-3 attached.", "784-1985-1234567-3"),
    ("US_ZIP_CODE", "Ship to Austin, TX 78701 please.", "78701"),
]

# Same shapes with a wrong check digit. These must not be reported as that identifier.
INVALID = [
    ("IN_AADHAAR", "My Aadhaar number is 7260 1815 9083."),
    ("AU_TFN", "Please quote TFN 123 456 783 on the form."),
    ("AU_MEDICARE", "Medicare card 6952 89075 9 expires soon."),
    ("CA_SIN", "Employee SIN 046 454 287 for payroll."),
    ("SG_NRIC_FIN", "NRIC S1234567E was verified."),
    ("ZA_ID_NUMBER", "South African ID number 8001015009088."),
    ("KR_RRN", "Resident registration number 800101-1234561."),
    ("TR_NATIONAL_ID", "TC kimlik no 10000000147 girildi."),
    ("ES_NIF", "Su DNI es 12345678A, gracias."),
    ("PL_PESEL", "Numer PESEL 44051401358 w systemie."),
    ("FR_NIR", "Numéro de sécurité sociale 2 69 05 49 588 157 81."),
    ("NL_BSN", "Het BSN is 111222334 volgens het dossier."),
    ("BR_CPF", "CPF do cliente: 111.444.777-36."),
    ("CN_RESIDENT_ID", "Resident ID 11010519491231002Y on the contract."),
    ("AE_EMIRATES_ID", "Emirates ID 784-1985-1234567-4 attached."),
]

# Plain digits with nothing nearby that says what they are: leave them alone.
AMBIGUOUS_BARE = [
    "The job took 11144477735 ms.",
    "Order 111222333 shipped yesterday.",
    "Record 8001015009087 was archived.",
    "Row 10000000146 in the export.",
    "Batch 44051401359 completed.",
    "Item 86095742719 restocked.",
    "Invoice 046454286 is paid.",
    "Ref 726018159082 closed.",
]


@pytest.fixture(scope="module")
def detector():
    return PIIDetectorV2()


@pytest.mark.parametrize("entity,text,value", VALID, ids=[v[0] for v in VALID])
def test_valid_identifier_is_redacted(detector, entity, text, value):
    result = detector.detect(text)
    assert value not in result.redacted_text
    assert any(m.pii_type == entity for m in result.matches), result.summary


@pytest.mark.parametrize("entity,text", INVALID, ids=[v[0] for v in INVALID])
def test_wrong_check_digit_is_not_reported(detector, entity, text):
    result = detector.detect(text)
    assert not any(m.pii_type == entity for m in result.matches)


@pytest.mark.parametrize("text", AMBIGUOUS_BARE)
def test_plain_digits_without_context_are_left_alone(detector, text):
    result = detector.detect(text)
    regional = set(regions.ALL_REGION_ENTITIES)
    assert not any(m.pii_type in regional for m in result.matches), result.summary


def test_a_canadian_sin_is_not_taken_for_a_phone_number(detector):
    result = detector.detect("SIN 046454286")
    assert [m.pii_type for m in result.matches] == ["CA_SIN"]


def test_us_zip_needs_a_city_and_state_or_the_word_zip(detector):
    assert detector.detect("The IN operator: x IN 12345 is valid.").redacted_text.count("US_ZIP") == 0
    assert "US_ZIP_CODE" in detector.detect("My zip code is 90210").redacted_text


def test_the_surrounding_sentence_stays_readable(detector):
    out = detector.detect("My Aadhaar number is 7260 1815 9082.").redacted_text
    assert out == "My Aadhaar number is [IN_AADHAAR_1]."


# ── choosing regions ──────────────────────────────────────────────────────────

def test_default_is_every_region():
    assert regions.active_regions({}) == list(regions.PACKS)


def test_eu_alias_and_single_countries():
    assert regions.active_regions({"JNVOY_REGIONS": "eu"}) == ["de", "es", "it", "pl", "se", "fi", "fr", "nl"]
    assert regions.active_regions({"JNVOY_REGIONS": "in, au"}) == ["au", "in"] or \
        regions.active_regions({"JNVOY_REGIONS": "in, au"}) == ["in", "au"]


def test_none_switches_regions_off():
    assert regions.region_entities({"JNVOY_REGIONS": "none"}) == []


def test_unknown_region_is_an_error_that_lists_valid_ones():
    with pytest.raises(ValueError) as e:
        regions.active_regions({"JNVOY_REGIONS": "atlantis"})
    assert "atlantis" in str(e.value) and "in" in str(e.value)


def test_resolve_entities_adds_the_chosen_regions_only():
    got = resolve_entities(env={"JNVOY_REGIONS": "in"})
    assert "IN_AADHAAR" in got and "AU_TFN" not in got
    assert "PERSON" in got and "UK_NHS" in got


def test_restricting_regions_stops_those_identifiers_being_redacted():
    d = PIIDetectorV2(entities=resolve_entities(env={"JNVOY_REGIONS": "none"}))
    out = d.detect("My Aadhaar number is 7260 1815 9082.").redacted_text
    assert "IN_AADHAAR" not in out


def test_every_pack_has_a_recogniser_and_a_test():
    built = {e for r in regions.make_region_recognisers() for e in r.supported_entities}
    assert built == set(regions.ALL_REGION_ENTITIES)
    tested = {v[0] for v in VALID}
    assert tested == set(regions.ALL_REGION_ENTITIES)
