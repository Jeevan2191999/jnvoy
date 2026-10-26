"""
Extra recognisers for things Presidio and the UK rules did not catch.

Found by evaluation/run_eval.py: provider API keys (Anthropic, OpenAI, AWS, Stripe, Slack,
Google, GitHub), JWTs, passwords and connection strings, dates of birth, UK passport numbers,
street addresses and labelled internal reference numbers were all passing through.

Design rules:
  * Secrets are matched by their published prefixes, so ordinary words are not caught.
  * Dates of birth, passport numbers, passwords and reference numbers are matched only after
    a telling label ("born", "passport number", "password is", "customer ID"), and only the
    value is redacted, so the sentence stays readable. A bare date such as "25 December" is
    never touched.
  * Street addresses need a number, capitalised name words and a street word.
"""

import re
from typing import List, Optional

from presidio_analyzer import EntityRecognizer, Pattern, PatternRecognizer, RecognizerResult

# ── provider keys and secrets ─────────────────────────────────────────────────

_KEY = r"[A-Za-z0-9_\-]"

SECRET_PATTERNS = [
    Pattern("anthropic", rf"\bsk-ant-{_KEY}{{20,}}", 0.95),
    Pattern("openai_project", rf"\bsk-(?:proj|svcacct|admin)-{_KEY}{{20,}}", 0.95),
    Pattern("openai_classic", r"\bsk-[A-Za-z0-9]{20,}", 0.9),
    Pattern("aws_access_key", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b", 0.95),
    Pattern("github_token", r"\bgh[pousr]_[A-Za-z0-9]{30,}", 0.95),
    Pattern("github_pat", r"\bgithub_pat_[A-Za-z0-9_]{22,}", 0.95),
    Pattern("stripe", r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}", 0.95),
    Pattern("slack", r"\bxox[abprs]-[A-Za-z0-9\-]{10,}", 0.95),
    Pattern("google_api", r"\bAIza[0-9A-Za-z_\-]{35}\b", 0.95),
    Pattern("jwt", r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}", 0.95),
    Pattern("huggingface", r"\bhf_[A-Za-z0-9]{30,}", 0.95),
    Pattern("npm", r"\bnpm_[A-Za-z0-9]{30,}", 0.95),
    Pattern("gitlab", r"\bglpat-[A-Za-z0-9_\-]{20,}", 0.95),
    Pattern("pypi", r"\bpypi-[A-Za-z0-9_\-]{40,}", 0.95),
    Pattern("sendgrid", r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}", 0.95),
    Pattern("twilio", r"\bSK[0-9a-f]{32}\b", 0.9),
    Pattern("private_key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{1,8000}?-----END [A-Z ]*PRIVATE KEY-----", 0.99),
]


class ContextualRecognizer(EntityRecognizer):
    """
    Redacts only the named group `v` of a regex, so a label like "password is" stays readable.
    The regex is applied with IGNORECASE unless case_sensitive is set.
    """

    def __init__(self, entity: str, regex: str, score: float, name: str,
                 case_sensitive: bool = False, must_contain_digit: bool = False,
                 digit_or_symbol: bool = False):
        flags = 0 if case_sensitive else re.IGNORECASE
        self._re = re.compile(regex, flags)
        self._score = score
        self._digit = must_contain_digit
        self._digit_or_symbol = digit_or_symbol
        super().__init__(supported_entities=[entity], supported_language="en", name=name)

    def load(self) -> None:  # noqa: D102
        pass

    def analyze(self, text: str, entities: List[str], nlp_artifacts=None) -> List[RecognizerResult]:
        out = []
        for m in self._re.finditer(text):
            value = m.group("v")
            if self._digit and not any(c.isdigit() for c in value):
                continue
            if self._digit_or_symbol and not any(c.isdigit() or c in "!@#$%^&*()+=<>?/\\|~" for c in value):
                continue  # "token is expired" is a sentence, not a secret
            out.append(RecognizerResult(
                entity_type=self.supported_entities[0],
                start=m.start("v"), end=m.end("v"), score=self._score,
            ))
        return out


_MONTH = r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
_DATE = (
    rf"(?:\d{{1,2}}[/\-.]\d{{1,2}}[/\-.]\d{{2,4}}"
    rf"|\d{{4}}[/\-.]\d{{1,2}}[/\-.]\d{{1,2}}"
    rf"|\d{{1,2}}(?:st|nd|rd|th)?\s+(?:of\s+)?{_MONTH}\.?,?\s+\d{{2,4}}"
    rf"|{_MONTH}\.?\s+\d{{1,2}}(?:st|nd|rd|th)?,?\s+\d{{2,4}})"
)
_DOB_LABEL = r"(?:date\s+of\s+birth|d\.?o\.?b\.?|born(?:\s+on)?|birth\s*date|birthday(?:\s+is)?|b-day)"

# Words that introduce a personal or customer reference. Deliberately NOT here: order, ticket,
# file, record, reference. Those are everyday words in developer prompts ("fix ticket PROJ-1234").
_ID_WORDS = (
    r"(?:customer|client|case|claim|employee|staff|patient|policy|tenant|member|"
    r"licen[cs]e|booking|student)"
)
_ID_LABEL = r"(?:\s+(?:id|identifier|number|no\.?|num|ref(?:erence)?|code|#))?"


def make_extra_recognisers() -> list:
    secrets = PatternRecognizer(
        supported_entity="API_KEY", patterns=SECRET_PATTERNS,
        context=["api key", "secret", "token", "bearer", "key"], name="ExtraApiKeyRecognizer",
    )

    passwords = ContextualRecognizer(
        "SECRET_TOKEN",
        r"\b(?:password|passwd|pwd|pw|passphrase|passcode|secret|api[_ ]?key|token)"
        r"(?:\s+(?:for|of|to)\s+(?:the\s+|my\s+|our\s+)?\w+)?\s*(?:is|=|:)\s*['\"]?(?P<v>[^\s'\",;]{6,})",
        0.9, "PasswordRecognizer", digit_or_symbol=True,
    )

    env_assignment = ContextualRecognizer(
        "API_KEY",
        r"\b[A-Z][A-Z0-9_]*(?:SECRET|TOKEN|API_?KEY|PASSWORD|PASSWD|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?)"
        r"[A-Z0-9_]*\s*=\s*['\"]?(?P<v>[^\s'\"]{12,})",
        0.9, "EnvAssignmentSecretRecognizer", case_sensitive=True,
    )

    conn_string = ContextualRecognizer(
        "SECRET_TOKEN",
        r"\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:(?P<v>[^\s@/]{3,})@",
        0.95, "ConnectionStringPasswordRecognizer",
    )

    bearer = ContextualRecognizer(
        "API_KEY", r"\bbearer\s+(?P<v>[A-Za-z0-9\-._~+/]{20,}=*)", 0.95, "BearerRecognizer",
    )

    dob = ContextualRecognizer(
        "DATE_OF_BIRTH", rf"\b{_DOB_LABEL}\s*[:\-]?\s*(?:the\s+)?(?P<v>{_DATE})", 0.9, "DateOfBirthRecognizer",
    )

    passport = ContextualRecognizer(
        "PASSPORT",
        r"\bpassport(?:\s+(?:number|no\.?|num|#|id))?\s*(?:is|was)?\s*[:#\-]?\s*(?P<v>[A-Z0-9]{7,9})\b",
        0.9, "LabelledPassportRecognizer", must_contain_digit=True,
    )

    reference = ContextualRecognizer(
        "ID_NUMBER",
        rf"\b{_ID_WORDS}{_ID_LABEL}\s*[:#]?\s*(?P<v>[A-Z0-9][A-Z0-9\-/]{{4,}})\b",
        0.85, "LabelledReferenceRecognizer", case_sensitive=False, must_contain_digit=True,
    )

    street = PatternRecognizer(
        supported_entity="STREET_ADDRESS",
        patterns=[Pattern(
            "street",
            r"\b\d{1,4}[A-Z]?\s+(?:[A-Z][a-z'\-]+\s+){1,3}"
            r"(?:Street|St|Road|Rd|Avenue|Ave|Lane|Ln|Close|Drive|Dr|Way|Court|Ct|Place|Pl|"
            r"Gardens|Crescent|Terrace|Square|Grove|Hill|Park|Mews|Row|Walk|Boulevard|Parade|"
            r"Embankment|Quay|Wharf|Rise|Green|Gate|Broadway|Highway|Alley)\b",
            0.85,
        )],
        global_regex_flags=re.DOTALL | re.MULTILINE,  # case sensitive: needs capitalised names
        name="StreetAddressRecognizer",
    )

    return [secrets, passwords, env_assignment, conn_string, bearer, dob, passport, reference, street]


EXTRA_ENTITIES = ["DATE_OF_BIRTH", "STREET_ADDRESS", "ID_NUMBER"]
