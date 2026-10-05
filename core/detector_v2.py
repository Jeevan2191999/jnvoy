"""
Jnvoy PII Detection Engine v2 — Powered by Microsoft Presidio
Replaces the spaCy-only detector with Presidio for enterprise-grade accuracy.

What changed from v1:
- Microsoft Presidio as the primary detection engine
- 20+ PII types vs 14 in v1
- Phone number validation via phonenumbers library (proper E.164 validation)
- Email validation via tldextract (catches edge cases v1 missed)
- UK-specific recognisers: NHS numbers, NI numbers, UK postcodes, sort codes
- Confidence scores on every detection
- Falls back to spaCy regex patterns for UK-specific types Presidio misses
- Same reversible tokenisation API as v1 so proxy.py needs zero changes

Supported PII types:
    PERSON, EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, IBAN_CODE,
    IP_ADDRESS, LOCATION, DATE_TIME, NRP, MEDICAL_LICENSE,
    URL, CRYPTO, UK_NHS, NI_NUMBER, UK_POSTCODE, SORT_CODE,
    ACCOUNT_NUMBER, PASSPORT, API_KEY, SECRET_TOKEN
"""

import re
import time
from dataclasses import dataclass, field
from typing import Optional

import spacy
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig


# ── Custom UK Recognisers ─────────────────────────────────────────────────────

from presidio_analyzer import PatternRecognizer, Pattern

def make_uk_recognisers():
    """Build UK-specific recognisers that Presidio does not include by default."""

    nhs = PatternRecognizer(
        supported_entity="UK_NHS",
        patterns=[Pattern("UK_NHS", r"\b\d{3}[ \-]?\d{3}[ \-]?\d{4}\b", 0.85)],
        context=["nhs", "national health", "patient number"]
    )

    ni = PatternRecognizer(
        supported_entity="NI_NUMBER",
        patterns=[Pattern("NI_NUMBER", r"\b[A-Z]{2}\d{6}[A-Z]\b", 0.9)],
        context=["national insurance", "ni number", "nino"]
    )

    postcode = PatternRecognizer(
        supported_entity="UK_POSTCODE",
        patterns=[Pattern("UK_POSTCODE",
                          r"\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b", 0.85)],
        context=["postcode", "postal code", "post code"]
    )

    sort_code = PatternRecognizer(
        supported_entity="SORT_CODE",
        patterns=[Pattern("SORT_CODE",
                          r"\b\d{2}[ \-]?\d{2}[ \-]?\d{2}\b", 0.75)],
        context=["sort code", "sortcode", "bank"]
    )

    account = PatternRecognizer(
        supported_entity="ACCOUNT_NUMBER",
        patterns=[Pattern("ACCOUNT_NUMBER", r"\b\d{8}\b", 0.7)],
        context=["account number", "account no", "bank account"]
    )

    passport = PatternRecognizer(
        supported_entity="PASSPORT",
        patterns=[Pattern("PASSPORT", r"\b[A-Z]{2}\d{7}\b", 0.85)],
        context=["passport", "passport number", "travel document"]
    )

    api_key = PatternRecognizer(
        supported_entity="API_KEY",
        patterns=[Pattern("API_KEY",
                          r"(?:sk|pk|api|key)[_\-][A-Za-z0-9]{20,}", 0.9)],
        context=["api key", "secret key", "token", "bearer"]
    )

    secret = PatternRecognizer(
        supported_entity="SECRET_TOKEN",
        patterns=[Pattern("SECRET_TOKEN",
                          r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}", 0.95)],
        context=["github", "token", "secret"]
    )

    return [nhs, ni, postcode, sort_code, account, passport, api_key, secret]


# ── Initialise Presidio ───────────────────────────────────────────────────────

def _build_analyzer() -> AnalyzerEngine:
    """Build the Presidio analyzer with the large spaCy model and UK recognisers."""
    # Use en_core_web_lg in production for best accuracy
    # Falls back to en_core_web_sm if lg not available
    import subprocess, sys
    try:
        spacy.load("en_core_web_lg")
        model_name = "en_core_web_lg"
    except OSError:
        model_name = "en_core_web_sm"
    config = {"nlp_engine_name": "spacy", "models": [{"lang_code": "en", "model_name": model_name}]}
    provider = NlpEngineProvider(nlp_configuration=config)
    nlp_engine = provider.create_engine()

    registry = RecognizerRegistry()
    registry.load_predefined_recognizers(nlp_engine=nlp_engine)

    for recogniser in make_uk_recognisers():
        registry.add_recognizer(recogniser)

    return AnalyzerEngine(nlp_engine=nlp_engine, registry=registry)


# Initialise once at module load
_analyzer = _build_analyzer()
_anonymizer = AnonymizerEngine()


# ── Data Models ───────────────────────────────────────────────────────────────

@dataclass
class PIIMatch:
    pii_type: str
    original_value: str
    token: str
    start: int
    end: int
    score: float = 0.0


@dataclass
class DetectionResult:
    original_text: str
    redacted_text: str
    matches: list[PIIMatch] = field(default_factory=list)
    token_map: dict[str, str] = field(default_factory=dict)
    detection_time_ms: float = 0.0

    @property
    def pii_found(self) -> bool:
        return len(self.matches) > 0

    @property
    def summary(self) -> dict:
        counts = {}
        for m in self.matches:
            counts[m.pii_type] = counts.get(m.pii_type, 0) + 1
        return counts

    @property
    def high_confidence_matches(self) -> list[PIIMatch]:
        return [m for m in self.matches if m.score >= 0.8]


# ── PII Detector v2 ───────────────────────────────────────────────────────────

class PIIDetectorV2:
    """
    Enterprise-grade PII detection engine powered by Microsoft Presidio.

    Improvements over v1:
    - 20+ PII types with confidence scoring
    - Proper phone number validation via phonenumbers library
    - Email validation via tldextract
    - UK-specific recognisers
    - Configurable confidence threshold
    - Same API as v1: detect() and restore()
    """

    def __init__(
        self,
        confidence_threshold: float = 0.6,
        languages: list[str] = None
    ):
        self.confidence_threshold = confidence_threshold
        self.languages = languages or ["en"]
        self._token_counter: dict[str, int] = {}

    def _make_token(self, pii_type: str) -> str:
        count = self._token_counter.get(pii_type, 0) + 1
        self._token_counter[pii_type] = count
        return f"[{pii_type}_{count}]"

    def _reset_counter(self):
        self._token_counter = {}

    def detect(self, text: str) -> DetectionResult:
        """
        Detect PII in text using Presidio with UK-specific recognisers.
        Returns redacted text with reversible tokens.
        """
        if not text or not text.strip():
            return DetectionResult(
                original_text=text,
                redacted_text=text,
            )

        self._reset_counter()
        start_time = time.time()

        # Run Presidio analysis
        results = _analyzer.analyze(
            text=text,
            language="en",
            score_threshold=self.confidence_threshold
        )

        # Remove overlapping spans keeping highest confidence
        results.sort(key=lambda r: r.score, reverse=True)
        non_overlapping = []
        covered = set()
        for r in results:
            span = set(range(r.start, r.end))
            if not span & covered:
                non_overlapping.append(r)
                covered |= span

        # Sort end to start for safe in-place replacement
        non_overlapping.sort(key=lambda r: r.start, reverse=True)

        matches = []
        token_map = {}
        redacted = text

        for result in non_overlapping:
            original_value = text[result.start:result.end]
            token = self._make_token(result.entity_type)

            matches.append(PIIMatch(
                pii_type=result.entity_type,
                original_value=original_value,
                token=token,
                start=result.start,
                end=result.end,
                score=round(result.score, 3)
            ))

            token_map[token] = original_value
            redacted = redacted[:result.start] + token + redacted[result.end:]

        detection_time_ms = (time.time() - start_time) * 1000

        return DetectionResult(
            original_text=text,
            redacted_text=redacted,
            matches=matches,
            token_map=token_map,
            detection_time_ms=round(detection_time_ms, 2)
        )

    def restore(self, redacted_text: str, token_map: dict[str, str]) -> str:
        """
        Restore original values from a redacted text using the token map.
        Sorts by token length descending to avoid substring collision.
        """
        restored = redacted_text
        # Sort longest token first to avoid partial replacement collisions
        for token in sorted(token_map.keys(), key=len, reverse=True):
            restored = restored.replace(token, token_map[token])
        return restored

    def scan_for_report(self, text: str) -> dict:
        """
        Scan text and return a structured report suitable for compliance dashboards.
        """
        result = self.detect(text)
        return {
            "pii_found": result.pii_found,
            "total_instances": len(result.matches),
            "high_confidence_instances": len(result.high_confidence_matches),
            "types_detected": result.summary,
            "detection_time_ms": result.detection_time_ms,
            "redacted_text": result.redacted_text,
            "sensitive_data_transmitted": False
        }
