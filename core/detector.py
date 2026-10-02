"""
PrivacyFire PII Detection Engine
Detects sensitive data in text using regex patterns and spaCy NER.
Runs entirely locally. No data ever sent to an external service.
"""

import re
import uuid
import spacy
from dataclasses import dataclass, field
from typing import Optional

# Load spaCy model once at module level
nlp = spacy.load("en_core_web_sm")


@dataclass
class PIIMatch:
    """Represents a single detected PII instance."""
    pii_type: str
    original_value: str
    token: str
    start: int
    end: int


@dataclass
class DetectionResult:
    """Result of running PII detection on a piece of text."""
    original_text: str
    redacted_text: str
    matches: list[PIIMatch] = field(default_factory=list)
    token_map: dict[str, str] = field(default_factory=dict)

    @property
    def pii_found(self) -> bool:
        return len(self.matches) > 0

    @property
    def summary(self) -> dict:
        counts = {}
        for m in self.matches:
            counts[m.pii_type] = counts.get(m.pii_type, 0) + 1
        return counts


# Regex patterns for structured PII
PATTERNS = {
    "EMAIL": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    "PHONE_UK": r"\b(?:(?:\+44\s?|0)(?:7\d{3}|\d{2,4})\s?\d{3,4}\s?\d{3,4})\b",
    "PHONE_INTL": r"\b\+?[1-9]\d{1,14}\b",
    "CREDIT_CARD": r"\b(?:\d[ \-]?){13,16}\b",
    "NHS_NUMBER": r"\b\d{3}[ \-]?\d{3}[ \-]?\d{4}\b",
    "NI_NUMBER": r"\b[A-Z]{2}\d{6}[A-Z]\b",
    "UK_POSTCODE": r"\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b",
    "DATE_OF_BIRTH": r"\b(?:0[1-9]|[12]\d|3[01])[\/\-](?:0[1-9]|1[0-2])[\/\-](?:19|20)\d{2}\b",
    "IP_ADDRESS": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "SORT_CODE": r"\b\d{2}[ \-]?\d{2}[ \-]?\d{2}\b",
    "ACCOUNT_NUMBER": r"\b\d{8}\b",
    "PASSPORT": r"\b[A-Z]{2}\d{7}\b",
    "API_KEY": r"(?:sk|pk|api|key)[_\-][A-Za-z0-9]{20,}",
    "SECRET_TOKEN": r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b",
}


class PIIDetector:
    """
    Core PII detection engine.
    Combines regex patterns for structured PII with spaCy NER for names and organisations.
    All processing is local. Zero external API calls.
    """

    def __init__(self, use_ner: bool = True):
        self.use_ner = use_ner
        self._token_counter: dict[str, int] = {}

    def _make_token(self, pii_type: str) -> str:
        """Generate a reversible token for a PII type."""
        count = self._token_counter.get(pii_type, 0) + 1
        self._token_counter[pii_type] = count
        return f"[{pii_type}_{count}]"

    def _reset_counter(self):
        self._token_counter = {}

    def detect(self, text: str) -> DetectionResult:
        """
        Run PII detection on input text.
        Returns redacted text and a map of tokens to original values.
        """
        self._reset_counter()
        matches: list[PIIMatch] = []

        # Step 1: Regex-based detection for structured PII
        for pii_type, pattern in PATTERNS.items():
            for m in re.finditer(pattern, text, re.IGNORECASE):
                token = self._make_token(pii_type)
                matches.append(PIIMatch(
                    pii_type=pii_type,
                    original_value=m.group(),
                    token=token,
                    start=m.start(),
                    end=m.end()
                ))

        # Step 2: spaCy NER for unstructured PII (names, orgs, locations)
        if self.use_ner:
            doc = nlp(text)
            for ent in doc.ents:
                if ent.label_ in ("PERSON", "ORG", "GPE", "LOC", "FAC"):
                    # Avoid duplicating if already caught by regex
                    overlap = any(
                        m.start <= ent.start_char < m.end or
                        m.start < ent.end_char <= m.end
                        for m in matches
                    )
                    if not overlap:
                        pii_type = f"NER_{ent.label_}"
                        token = self._make_token(pii_type)
                        matches.append(PIIMatch(
                            pii_type=pii_type,
                            original_value=ent.text,
                            token=token,
                            start=ent.start_char,
                            end=ent.end_char
                        ))

        # Step 3: Sort by position (end to start) so we can replace without shifting indices
        matches.sort(key=lambda m: m.start, reverse=True)

        # Step 4: Build redacted text and token map
        redacted = text
        token_map: dict[str, str] = {}

        for match in matches:
            redacted = redacted[:match.start] + match.token + redacted[match.end:]
            token_map[match.token] = match.original_value

        return DetectionResult(
            original_text=text,
            redacted_text=redacted,
            matches=matches,
            token_map=token_map
        )

    def restore(self, redacted_text: str, token_map: dict[str, str]) -> str:
        """Restore original values from a redacted text using the token map."""
        restored = redacted_text
        for token, original in token_map.items():
            restored = restored.replace(token, original)
        return restored
