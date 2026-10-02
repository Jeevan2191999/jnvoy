"""
Tests for the PrivacyFire PII Detection Engine.
Run with: python -m pytest tests/test_detector.py -v
"""

import sys
sys.path.insert(0, "/home/claude/privacyfire")

from core.detector import PIIDetector


def test_email_detection():
    detector = PIIDetector(use_ner=False)
    result = detector.detect("Contact me at john.smith@example.com for details.")
    assert result.pii_found
    assert any(m.pii_type == "EMAIL" for m in result.matches)
    assert "john.smith@example.com" not in result.redacted_text
    assert "[EMAIL_1]" in result.redacted_text


def test_uk_phone_detection():
    detector = PIIDetector(use_ner=False)
    result = detector.detect("Call me on 07799 408914 anytime.")
    assert result.pii_found
    assert "07799 408914" not in result.redacted_text


def test_credit_card_detection():
    detector = PIIDetector(use_ner=False)
    result = detector.detect("My card number is 4532 1234 5678 9012.")
    assert result.pii_found
    assert any(m.pii_type == "CREDIT_CARD" for m in result.matches)


def test_uk_postcode_detection():
    detector = PIIDetector(use_ner=False)
    result = detector.detect("I live at 10 Downing Street, SW1A 2AA, London.")
    assert result.pii_found
    assert any(m.pii_type == "UK_POSTCODE" for m in result.matches)


def test_ni_number_detection():
    detector = PIIDetector(use_ner=False)
    result = detector.detect("National Insurance number: AB123456C")
    assert result.pii_found
    assert any(m.pii_type == "NI_NUMBER" for m in result.matches)


def test_api_key_detection():
    detector = PIIDetector(use_ner=False)
    result = detector.detect("Use api_key_abc123def456ghi789jkl012mno345 to authenticate.")
    assert result.pii_found
    assert any(m.pii_type == "API_KEY" for m in result.matches)


def test_multiple_pii_types():
    detector = PIIDetector(use_ner=False)
    text = "John can be reached at john@example.com or 07700 900123. His NI is AB123456C."
    result = detector.detect(text)
    assert result.pii_found
    assert len(result.matches) >= 3
    assert "john@example.com" not in result.redacted_text
    assert "07700 900123" not in result.redacted_text
    assert "AB123456C" not in result.redacted_text


def test_restore_original():
    detector = PIIDetector(use_ner=False)
    original = "Email me at test@company.com please."
    result = detector.detect(original)
    restored = detector.restore(result.redacted_text, result.token_map)
    assert restored == original


def test_no_pii():
    detector = PIIDetector(use_ner=False)
    result = detector.detect("The weather in London is nice today.")
    assert not result.pii_found
    assert result.redacted_text == "The weather in London is nice today."


def test_ner_person_detection():
    detector = PIIDetector(use_ner=True)
    result = detector.detect("Elon Musk announced a new product yesterday.")
    assert result.pii_found
    assert "Elon Musk" not in result.redacted_text


def test_summary():
    detector = PIIDetector(use_ner=False)
    result = detector.detect("Email: a@b.com and also c@d.com. Phone: 07700 900123.")
    summary = result.summary
    assert summary.get("EMAIL", 0) == 2
    assert summary.get("PHONE_UK", 0) == 1 or summary.get("PHONE_INTL", 0) >= 1
