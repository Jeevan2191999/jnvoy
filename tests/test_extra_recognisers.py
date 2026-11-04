"""
Tests for core/extra_recognisers.py and the evaluation datasets.

Two jobs:
  * the new rules catch what they should (keys, passwords, dates of birth, passports,
    addresses, labelled references) and redact only the value, not the sentence around it
  * they do NOT fire on everyday text (dates without a birth label, ticket numbers,
    order numbers, "token is expired", commit hashes)

Assertions avoid anything that depends on the spaCy model size.

Run:  pytest tests/test_extra_recognisers.py -q
"""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.detector_v2 import DEFAULT_ENTITIES, PIIDetectorV2  # noqa: E402
from core.extra_recognisers import make_extra_recognisers  # noqa: E402

det = PIIDetectorV2()


def red(text):
    return det.detect(text).redacted_text


# ── secrets ──────────────────────────────────────────────────────────────────

# Stored with a '<>' break so secret scanners do not flag these synthetic values.
SECRETS = [
    "s<>k-ant-api03-Zq9XvT2mLp7WcR4bNe8JdY1uHs6KfAg3OiVx5Ct0Pl2MbQwE",
    "s<>k-proj-Hq7Lm2Xv9Rt4Bn8Wc3Yd6Kf1Pj5Zs0Ua",
    "s<>k-Tq8Vm3Xz7Rl2Bn5Wc9Yd4Kf6Pj1Hs0UaEg2Ni8Ol",
    "A<>KIAIOSFODNN7EXAMPLE",
    "g<>hp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
    "s<>k_live_4eC39HqLyjWDarjtT1zdp7dc",
    "x<>oxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
    "h<>f_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
    "n<>pm_Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0Fe9Dc8",
    "A<>IzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
]


@pytest.mark.parametrize("secret", SECRETS)
def test_provider_keys_are_redacted(secret):
    secret = secret.replace("<>", "")
    assert secret not in red(f"here it is: {secret} thanks")


def test_private_key_block_is_redacted():
    block = "-----B<>EGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7vbqajDw4o6gJy8UtmIbkcpnkO3Kwc4qsEnSZp\n-----END RSA PRIVATE KEY-----"
    block = block.replace("<>", "")
    out = red(block)
    assert "MIIEowIBAAKCAQEA" not in out


@pytest.mark.parametrize("text,secret", [
    ("db password is Tr0ub4dor&3xK9 for staging", "Tr0ub4dor&3xK9"),
    ("the password for the database is Winter2025!Secure", "Winter2025!Secure"),
    ("pw: hunter2hunter2 (rotate it)", "hunter2hunter2"),
    ("postgres://admin:S3cr3tP4ss@db.internal.example.com:5432/prod", "S3cr3tP4ss"),
    ("API_SECRET=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "9f86d081884c7d659a2feaa0c55ad015"),
    ("Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456", "abcdefghijklmnopqrstuvwxyz123456"),
])
def test_passwords_and_credentials(text, secret):
    assert secret not in red(text)


@pytest.mark.parametrize("text,secret", [
    ("pwd 80A_rged!UxDNQ", "80A_rged!UxDNQ"),
    ("login ok, pwd JImhnUlx9F@Z14r, thanks", "JImhnUlx9F@Z14r"),
    ("Contact: bob@example.org pwd 7kbddeuGTTOwVx8Q", "7kbddeuGTTOwVx8Q"),
    ("pwd 'k3y#Stone99'", "k3y#Stone99"),
])
def test_pwd_shorthand_without_a_separator_is_redacted(text, secret):
    assert secret not in red(text)


@pytest.mark.parametrize("text", [
    "run pwd /usr/local/bin/python3 to see where you are",
    "$ pwd\n/home/jeevan/projects",
    "type pwd and press enter",
    "pwd ~/code/notes",
    "use pwd ./scripts/build.sh",
    "pwd is the print working directory command",
    "the pwd command prints a path",
])
def test_pwd_the_unix_command_is_left_alone(text):
    assert red(text) == text


@pytest.mark.parametrize("text,digits", [
    ("visa: 630421613047", "630421613047"),                           # 12 digits (Maestro)
    ("card on file 4248531927806669332", "4248531927806669332"),     # 19 digits
    ("Card number 2720147601757093.", "2720147601757093"),           # Mastercard 2-series
    ("Card number 2712 9307 1519 6492", "2712 9307 1519 6492"),
    ("Please charge 2277 2706 9684 7681.", "2277 2706 9684 7681"),
    ("Paid with card 213173644442400", "213173644442400"),           # 15 digits, JCB range
    ("debit card: 2379-0418-7179-2951 expires 09/28", "2379-0418-7179-2951"),
])
def test_cards_of_any_common_length_are_redacted_after_a_cue(text, digits):
    out = red(text)
    assert digits not in out
    assert out.count("[") == 1 or "expires" in out   # only the number is replaced


def test_a_card_followed_by_another_number_keeps_the_following_number():
    out = red("card 2720147601757093 2024")
    assert "2720147601757093" not in out and out.endswith("2024")


@pytest.mark.parametrize("text", [
    "card 1234 5678 9012 3456",                 # fails the Luhn check, so not a card
    "paid invoice 20240315123456 yesterday",
    "charge code 123456789012",
    "pay 12 days",
    "the card was declined",
    "Order 8841 7732 paid in full",
])
def test_numbers_that_are_not_cards_are_left_alone(text):
    assert red(text) == text


@pytest.mark.parametrize("text,number", [
    ("Call me on +914680861610.", "+914680861610"),
    ("Ring +44292018374 after 5pm.", "+44292018374"),
    ("WhatsApp 001-429-410-1007 - login", "001-429-410-1007"),
    ("His mobile is +61.8.1853.6389.", "+61.8.1853.6389"),
    ("phone 3829.3070", "3829.3070"),
    ("Tel: 00100 87921", "00100 87921"),
    ("Call me on (560)985-1713x00812.", "(560)985-1713x00812"),
    ("WhatsApp +4428 9018407", "+4428 9018407"),
])
def test_a_labelled_phone_number_is_redacted_in_any_layout(text, number):
    assert number not in red(text)


@pytest.mark.parametrize("text", [
    "call 911",
    "call 12.03.2024 meeting",
    "Please call 2024-03-15 for the date",   # a date is not a phone number (another rule may still mark it)
    "ring 2 times then hang up",
    "phone support is open until 17:30",
    "call 20240315123456789012",
])
def test_digits_after_phone_words_that_are_not_phone_numbers_are_left_alone(text):
    out = red(text)
    assert "[PHONE_NUMBER" not in out


@pytest.mark.parametrize("text,street", [
    ("Deliver to 306 Sanchez Hollow, Lake William 82372 before noon.", "306 Sanchez Hollow"),
    ("Home address: 169 Rodney Hills, Lake Kara N1H5H5", "169 Rodney Hills"),
    ("Registered office at Studio 45, Cross Terrace, Waynestad", "Studio 45"),
    ("She lives at 12 Acacia Avenue, Leeds LS1 4AP. Then went home.", "12 Acacia Avenue"),
    ("Lives at 9 Rue de Rivoli, 75001 Paris", "9 Rue de Rivoli"),
    ("Delivered to 7 Spring Garden Road, Halifax NS B3J 3Z5 - signed", "7 Spring Garden Road"),
    ("Home address: chemin de Gaillard, Weiss-sur-Salmon 63883 before noon.", "chemin de Gaillard"),
])
def test_a_labelled_address_is_redacted_whatever_its_layout(text, street):
    out = red(text)
    assert street not in out


@pytest.mark.parametrize("text,city,hidden", [
    ("She lives at 12 Acacia Avenue, Leeds LS1 4AP. Then went home.", "Leeds", "LS1 4AP"),
    ("Lives at 9 Rue de Rivoli, 75001 Paris", "Paris", "75001"),
    ("Delivered to 7 Spring Garden Road, Halifax NS B3J 3Z5 - signed", "Halifax", "B3J 3Z5"),
    ("Her address is 5 Corso Buenos Aires, Milano", "Milano", "Corso Buenos Aires"),
    ("The client lives at 221B Baker Street, London.", "London", "Baker Street"),
])
def test_the_city_in_an_address_stays_readable_as_it_does_everywhere_else(text, city, hidden):
    out = red(text)
    assert city in out and hidden not in out


def test_a_second_street_line_is_not_mistaken_for_a_postcode():
    out = red("Home address: Flat 3, 27 Acacia Avenue")
    assert "Acacia" not in out and "27" not in out


def test_a_number_after_the_words_number_is_is_not_taken_for_a_phone_number():
    # An Aadhaar number, an account number: the labelled-phone rule needs a phone word, not just "number is".
    assert "[PHONE_NUMBER" not in red("My Aadhaar number is 7260 1815 9082.")


def test_the_address_stops_where_the_address_ends():
    out = red("Ship to 4 Elm Road, Leeds LS1 4AP. The Head of Finance will pick this up.")
    assert "The Head of Finance will pick this up." in out
    out = red("Home address: 169 Rodney Hills, Lake Kara N1H5H5 The deadline is 14 March.")
    assert out.endswith("The deadline is 14 March.")


@pytest.mark.parametrize("text", [
    "Ship to the warehouse by 5pm",
    "Ship to 5 boxes of widgets, urgent",
    "Ship to Germany takes about a week.",
    "The address is wrong in the database",
    "address 4 fields are required",
    "lives at home",
    "deliver to 3 customers, then rest",
])
def test_words_like_ship_to_do_not_make_everything_after_them_an_address(text):
    assert red(text) == text


@pytest.mark.parametrize("text,secret", [
    ("pass: b7DwbIfp&PN", "b7DwbIfp&PN"),
    ("pw U4Aorl#S^64", "U4Aorl#S^64"),
    ("The Wi-Fi key is !@eN3ZwqHmmj", "!@eN3ZwqHmmj"),
    ("wifi password is changeme!1", "changeme!1"),
    ("credentials: admin / ssJI8y2WGVhg11", "ssJI8y2WGVhg11"),
])
def test_more_ways_of_writing_a_password_are_redacted(text, secret):
    assert secret not in red(text)


@pytest.mark.parametrize("text", [
    "pass: expired", "pass the salt", "pw reset requested", "pw 2 times",
    "the Wi-Fi key is on the router", "credentials: stored in the vault",
])
def test_pass_pw_and_credentials_in_ordinary_sentences_are_left_alone(text):
    assert red(text) == text


@pytest.mark.parametrize("text,date", [
    ("DOB was 21 July 2002", "21 July 2002"),
    ("Her birth date is 28/08/1948.", "28/08/1948"),
    ("Birthday was 14 March 1985", "14 March 1985"),
    ("DOB was August 11, 1988", "August 11, 1988"),
])
def test_a_date_of_birth_after_is_or_was_is_redacted(text, date):
    assert date not in red(text)


def test_birth_date_with_no_date_after_it_is_left_alone():
    assert red("birth date is unknown") == "birth date is unknown"


@pytest.mark.parametrize("text,ssn", [
    ("Tax ID 270-69-4743", "270-69-4743"),
    ("Social: 829-60-3102", "829-60-3102"),
    ("Employee SSN 123-45-6789 on file", "123-45-6789"),
])
def test_a_dashed_social_security_number_is_hidden_without_a_label(text, ssn):
    out = red(text)
    assert ssn not in out and "270-" not in out and "829-" not in out and "123-" not in out


@pytest.mark.parametrize("text", [
    "number 000-12-3456", "number 666-12-3456", "number 912-12-3456", "number 123-00-3456", "number 123-45-0000",
    "call 555-1234", "version 2024-03-15",
])
def test_dashed_numbers_in_ranges_that_are_not_social_security_numbers_are_not_hidden_as_such(text):
    assert "[US_SSN" not in red(text)


def test_a_dashed_part_number_in_the_ssn_shape_is_hidden_too():
    # Known cost of hiding SSNs without a label: a part or order number written 3-2-4 looks the same.
    assert "[US_SSN" in red("Part number 555-12-3456")


@pytest.mark.parametrize("text,street", [
    ("Parcel for 12 Hill Road, Leeds LS1 4AP. Then lunch.", "12 Hill Road"),
    ("Please post it to Level 7 790 David Riviera, Smithborough 2991.", "David Riviera"),
    ("Her flat is at 129 Brenda Crossing, New Shawnaborough 2661.", "Brenda Crossing"),
    ("Sent to 54249 Mccall Trafficway, Greenehaven 43545 yesterday", "Mccall Trafficway"),
    ("Collection point: 4 Quay Street, Cork T12 AB34.", "Quay Street"),
])
def test_more_address_introductions_are_recognised(text, street):
    assert street not in red(text)


@pytest.mark.parametrize("text", [
    "Sent to 5 customers, then archived", "Sent to the team on Monday", "post it to the usual place",
    "The home is at the end of the road", "Parcel for the office",
])
def test_those_introductions_do_not_make_ordinary_words_an_address(text):
    assert red(text) == text


def test_only_the_value_is_redacted_not_the_sentence():
    out = red("the password is Tr0ub4dor&3xK9 for staging")
    assert out.startswith("the password is ") and out.endswith(" for staging")


# ── labelled personal data ───────────────────────────────────────────────────

@pytest.mark.parametrize("text,value", [
    ("Born on 14/03/1985 in a hospital", "14/03/1985"),
    ("DOB: 03 March 1985", "03 March 1985"),
    ("date of birth 1985-03-14", "1985-03-14"),
    ("her birthday is 22 July 1986", "22 July 1986"),
    ("Her birthday is the 9th of June 1990", "9th of June 1990"),
    ("D.O.B. 14-03-85", "14-03-85"),
    ("UK passport number 533401872 expires 2031", "533401872"),
    ("my passport is 533401872", "533401872"),
    ("Passport No: 925019263", "925019263"),
    ("Flat 3, 27 Acacia Avenue, Leeds", "27 Acacia Avenue"),
    ("Return to 88 Victoria Embankment, London", "88 Victoria Embankment"),
    ("Customer ID CUS-48213-X has a complaint", "CUS-48213-X"),
    ("Patient MRN-0048213 needs a follow up", "MRN-0048213"),
    ("Employee number E00482913 is on leave", "E00482913"),
    ("Policy number PL-2291-8841-GB renews", "PL-2291-8841-GB"),
    ("Tenant reference TNT/2025/00917 is late", "TNT/2025/00917"),
    ("claim CLM-2025-004417 is pending", "CLM-2025-004417"),
])
def test_labelled_values_are_redacted(text, value):
    assert value not in red(text)


# ── must NOT fire on everyday text ───────────────────────────────────────────

HARMLESS = [
    "Our meeting is on 25 December and the release is 3 March 2027.",
    "The policy takes effect on 1 January 2027.",
    "Fix JIRA ticket PROJ-1234 before Friday's release.",
    "Order 20931 and order 20932 shipped.",
    "See reference ISO 27001 clause 5.2.",
    "Checkout commit a1b2c3d4e5f6a7b8c9d0 and rebuild.",
    "The request id is 550e8400-e29b-41d4-a716-446655440000.",
    "Your token is expired, please log in again.",
    "The secret is out, everyone knows.",
    "Passport control was quick at Heathrow.",
    "Born in the USA is a song by Bruce Springsteen.",
    "Plan a birthday party for next Saturday.",
    "Our customer service team handles patient care enquiries.",
    "We use scikit-learn and pandas.",
    "Use the colour #ff8800 for the header.",
    "The case for remote work is strong.",
    "A member of staff will help you.",
    "risk-assessment-framework-for-everyone",
]


@pytest.mark.parametrize("text", HARMLESS)
def test_harmless_text_is_untouched_by_the_extra_rules(text):
    recs = make_extra_recognisers()
    found = [(x.entity_type, text[x.start:x.end]) for r in recs for x in r.analyze(text, r.supported_entities, None)]
    assert found == [], found


# ── wiring ───────────────────────────────────────────────────────────────────

def test_new_entity_types_are_in_the_default_set():
    for name in ("DATE_OF_BIRTH", "STREET_ADDRESS", "ID_NUMBER", "API_KEY", "SECRET_TOKEN", "PASSPORT"):
        assert name in DEFAULT_ENTITIES


def test_new_types_show_up_in_the_summary():
    result = det.detect("Born on 14/03/1985, passport number 533401872")
    assert result.summary.get("DATE_OF_BIRTH") == 1
    assert result.summary.get("PASSPORT") == 1


def test_restore_round_trip_for_new_types():
    text = "Customer ID CUS-48213-X, born on 14/03/1985, password is Tr0ub4dor&3xK9"
    r = det.detect(text)
    assert det.restore(r.redacted_text, r.token_map) == text


# ── evaluation datasets (regression floors) ──────────────────────────────────

def _load_runner():
    spec = importlib.util.spec_from_file_location("run_eval", ROOT / "evaluation" / "run_eval.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


runner = _load_runner()

# Types decided by rules, not by the language model, so the result does not depend on model size.
DETERMINISTIC = ["API_KEY", "DOB", "PASSPORT", "PHONE", "EMAIL", "NHS", "NI", "POSTCODE",
                 "BANK", "CARD", "IBAN", "IP"]


def _scores(name):
    rows = runner.load_rows(ROOT / "evaluation" / name)
    redacted = {r["id"]: det.detect(r["text"]).redacted_text for r in rows}
    return runner.score(rows, redacted)


@pytest.mark.parametrize("dataset", ["dataset.jsonl", "holdout.jsonl", "holdout2.jsonl", "holdout3.jsonl", "holdout4.jsonl", "holdout5.jsonl"])
def test_rule_based_types_are_fully_caught(dataset):
    result = _scores(dataset)
    for t in DETERMINISTIC:
        if t in result["per_type"]:
            p = result["per_type"][t]
            assert p["caught"] == p["n"], (t, [m for m in result["misses"] if m["type"] == t])


@pytest.mark.parametrize("dataset", ["dataset.jsonl", "holdout.jsonl", "holdout2.jsonl", "holdout3.jsonl", "holdout4.jsonl", "holdout5.jsonl"])
def test_most_harmless_text_stays_readable(dataset):
    result = _scores(dataset)
    assert result["keep_kept"] / result["keep_total"] >= 0.85, result["over"]


def test_overall_recall_floor_on_the_development_set():
    result = _scores("dataset.jsonl")
    assert result["caught"] / result["n"] >= 0.9, result["misses"]


# ── the scorer itself ────────────────────────────────────────────────────────

def test_leaked_catches_partial_leaks():
    assert runner.leaked("(01632) 960 001", "Call ([DATE_TIME_1]) 960 001")
    assert runner.leaked("Margaret Thatcher", "Reply to [PERSON_1] Thatcher")
    assert not runner.leaked("Margaret Thatcher", "Reply to [PERSON_1]")
    assert runner.leaked("AB123456C", "NI is AB123456C")
    assert runner.leaked("AB 12 34 56 C", "NI is AB123456C")  # same digits, spacing removed
    assert not runner.leaked("john@acme.com", "mail [EMAIL_ADDRESS_1] now")


def test_score_counts_misses_and_over_redaction():
    rows = [{"id": "1", "text": "x", "sensitive": [{"value": "AB123456C", "type": "NI"}, {"value": "foo@bar.com", "type": "EMAIL"}],
             "keep": ["Paris"]}]
    s = runner.score(rows, {"1": "NI AB123456C and [EMAIL_ADDRESS_1] in [LOCATION_1]"})
    assert s["n"] == 2 and s["caught"] == 1 and s["keep_total"] == 1 and s["keep_kept"] == 0
    assert s["per_type"]["EMAIL"]["caught"] == 1 and s["per_type"]["NI"]["caught"] == 0
