"""
Tests for core/detector_v2.py after apply_entity_fix.py:
  * phone numbers are really redacted (they used to be dropped at score 0.4)
  * only personal data and identifiers are redacted by default
  * JNVOY_REDACT_EXTRA switches the optional kinds back on

Assertions are written to hold for both en_core_web_sm and en_core_web_lg: they check what
must NOT survive or must NOT be touched, and never depend on how a model tags a made-up word.

Run:  pytest tests/test_entity_filter.py -q
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.detector_v2 import (  # noqa: E402
    DEFAULT_ENTITIES,
    OPTIONAL_ENTITIES,
    PIIDetectorV2,
    resolve_entities,
)

OPTIONAL = set(OPTIONAL_ENTITIES)


@pytest.fixture(scope="module")
def det():
    return PIIDetectorV2()


# ── phone numbers ────────────────────────────────────────────────────────────

PHONE_CASES = [
    ("Call me on 07911 123456 today", "07911 123456"),
    ("Call +44 7911 123456 today", "7911 123456"),
    ("Call 020 7946 0958 today", "7946 0958"),
    ("Call (01632) 960 001 today", "960 001"),
    ("Call +44 (0)20 7946 0958 today", "7946 0958"),
    ("My mobile is 07700 900123.", "900123"),
    ("ring 07911123456 now", "07911123456"),
    ("US office 212-867-5309 please", "867-5309"),
    ("Dublin +353 87 123 4567 please", "123 4567"),
]


@pytest.mark.parametrize("text,fragment", PHONE_CASES)
def test_phone_numbers_leave_no_digits_behind(det, text, fragment):
    out = det.detect(text)
    assert fragment not in out.redacted_text, out.redacted_text
    assert "PHONE_NUMBER" in {m.pii_type for m in out.matches}


def test_phone_is_restored_exactly(det):
    out = det.detect("Call me on 07911 123456 today")
    assert det.restore(out.redacted_text, out.token_map) == "Call me on 07911 123456 today"


def test_ordinary_numbers_are_not_phones(det):
    for text in ["version 3.14.159 build 2024", "year 2024 total 1500000", "Ref 2024 1234 5678"]:
        out = det.detect(text)
        assert "PHONE_NUMBER" not in {m.pii_type for m in out.matches}, text


# ── defaults ─────────────────────────────────────────────────────────────────

GENERIC = [
    "Answer casually",
    "Explain how DNS works",
    "Summarise this in French",
    "Translate to Spanish",
    "The capital of France is Paris",
    "Our meeting is on Monday at 3pm",
    "Tell me about Tesla",
    "Microsoft and Google reported earnings.",
]


@pytest.mark.parametrize("text", GENERIC)
def test_default_leaves_generic_text_alone(det, text):
    out = det.detect(text)
    assert not ({m.pii_type for m in out.matches} & OPTIONAL), out.redacted_text


def test_default_still_catches_the_important_things(det):
    text = ("Mail jane.doe@acme.com, NI number AB123456C, NHS 943 476 5919, "
            "postcode SW1A 1AA, sort code 12-34-56, card 4111 1111 1111 1111")
    out = det.detect(text)
    for secret in ["jane.doe@acme.com", "AB123456C", "943 476 5919", "SW1A 1AA", "4111 1111 1111 1111"]:
        assert secret not in out.redacted_text, out.redacted_text


def test_default_entities_contain_no_optional_kinds():
    assert not (set(DEFAULT_ENTITIES) & OPTIONAL)


def test_person_is_still_redacted_by_default(det):
    out = det.detect("Please reply to Margaret Thatcher about the invoice")
    assert "Margaret Thatcher" not in out.redacted_text


# ── JNVOY_REDACT_EXTRA ───────────────────────────────────────────────────────

def test_resolve_default_without_env():
    # The core list plus every region pack (JNVOY_REGIONS defaults to all).
    from core.regions import ALL_REGION_ENTITIES
    assert resolve_entities(env={}) == DEFAULT_ENTITIES + ALL_REGION_ENTITIES
    assert resolve_entities(env={"JNVOY_REGIONS": "none"}) == DEFAULT_ENTITIES


def test_resolve_adds_extras_after_defaults():
    got = resolve_entities(env={"JNVOY_REGIONS": "none", "JNVOY_REDACT_EXTRA": "organization, location"})
    assert got == DEFAULT_ENTITIES + ["ORGANIZATION", "LOCATION"]


def test_resolve_all_means_no_restriction():
    assert resolve_entities(env={"JNVOY_REDACT_EXTRA": "all"}) is None
    assert resolve_entities(env={"JNVOY_REDACT_EXTRA": "ALL"}) is None


def test_resolve_rejects_typos_loudly():
    with pytest.raises(ValueError) as exc:
        resolve_entities(env={"JNVOY_REDACT_EXTRA": "ORGANISATION"})
    assert "ORGANISATION" in str(exc.value)


def test_resolve_explicit_list_wins_over_env():
    assert resolve_entities(["EMAIL_ADDRESS"], env={"JNVOY_REDACT_EXTRA": "all"}) == ["EMAIL_ADDRESS"]


def test_env_var_is_read_by_the_constructor(monkeypatch):
    monkeypatch.setenv("JNVOY_REDACT_EXTRA", "LOCATION")
    from core.regions import ALL_REGION_ENTITIES
    assert PIIDetectorV2().entities == DEFAULT_ENTITIES + ALL_REGION_ENTITIES + ["LOCATION"]
    monkeypatch.setenv("JNVOY_REDACT_EXTRA", "all")
    assert PIIDetectorV2().entities is None


def test_all_restores_the_old_behaviour(monkeypatch):
    monkeypatch.setenv("JNVOY_REDACT_EXTRA", "all")
    d = PIIDetectorV2()
    out = d.detect("The capital of France is Paris. Our meeting is on Monday.")
    assert {m.pii_type for m in out.matches} & OPTIONAL


def test_location_can_be_switched_on(monkeypatch):
    monkeypatch.setenv("JNVOY_REDACT_EXTRA", "LOCATION")
    d = PIIDetectorV2()
    out = d.detect("The capital of France is Paris")
    assert "Paris" not in out.redacted_text and "France" not in out.redacted_text


def test_only_requested_extras_are_added(monkeypatch):
    monkeypatch.setenv("JNVOY_REDACT_EXTRA", "LOCATION")
    d = PIIDetectorV2()
    out = d.detect("Our meeting is on Monday at 3pm in Paris")
    kinds = {m.pii_type for m in out.matches}
    assert "DATE_TIME" not in kinds and "ORGANIZATION" not in kinds
