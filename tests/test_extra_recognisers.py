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


@pytest.mark.parametrize("dataset", ["dataset.jsonl", "holdout.jsonl", "holdout2.jsonl", "holdout3.jsonl"])
def test_rule_based_types_are_fully_caught(dataset):
    result = _scores(dataset)
    for t in DETERMINISTIC:
        if t in result["per_type"]:
            p = result["per_type"][t]
            assert p["caught"] == p["n"], (t, [m for m in result["misses"] if m["type"] == t])


@pytest.mark.parametrize("dataset", ["dataset.jsonl", "holdout.jsonl", "holdout2.jsonl", "holdout3.jsonl"])
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
