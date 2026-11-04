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


def _luhn_ok(digits: str) -> bool:
    total, flip = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if flip:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
        flip = not flip
    return total % 10 == 0


class CardCueRecognizer(EntityRecognizer):
    """
    A payment card number announced by a word like "card", "visa" or "charge", of any length from 12 to
    19 digits, that passes the Luhn check. Presidio's own card rule covers the common 13 to 16 digit
    brands and misses 12 and 19 digit cards (Maestro, UnionPay), some 15 digit ranges and the 2-series
    Mastercard numbers (2221 to 2720). Only the digits are redacted. The Luhn check and the cue word
    together keep order numbers and phone numbers out.
    """

    _CUE = re.compile(
        r"\b(?:credit|debit|card|visa|mastercard|master[ \t]+card|amex|american[ \t]+express|maestro|"
        r"discover|diners|jcb|unionpay|cc|pan|charge|charged|pay|paid)\b"
        r"(?:[ \t]+(?:card|number|no\.?|num|on[ \t]+file|with|to|details?))*[ \t]*[:#=\-]?[ \t]*",
        re.IGNORECASE)
    _DIGITS = re.compile(r"(?<![\d.])\d(?:[ -]?\d){11,18}(?![\d])")

    def __init__(self):
        super().__init__(supported_entities=["CREDIT_CARD"], supported_language="en", name="CardCueRecognizer")

    def load(self) -> None:  # noqa: D102
        pass

    def analyze(self, text: str, entities: List[str], nlp_artifacts=None) -> List[RecognizerResult]:
        out = []
        for cue in self._CUE.finditer(text):
            m = self._DIGITS.match(text, cue.end())
            if not m:
                continue
            start, raw = m.start(), m.group(0)
            # The match can run on into a following number ("4111 1111 1111 1111 2024"): shorten it from
            # the right, one group at a time, until the card checks out.
            while raw:
                digits = re.sub(r"\D", "", raw)
                if 12 <= len(digits) <= 19 and _luhn_ok(digits):
                    out.append(RecognizerResult(entity_type="CREDIT_CARD", start=start,
                                                end=start + len(raw), score=0.9))
                    break
                cut = max(raw.rfind(" "), raw.rfind("-"))
                raw = raw[:cut] if cut > 0 else ""
        return out


_DATE_ONLY = re.compile(r"^(?:\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4})$")


class PhoneCueRecognizer(EntityRecognizer):
    """
    A phone number announced by a word such as "phone", "mobile", "WhatsApp", "call" or "ring", in any
    layout (+44 7911 123456, 001-429-410-1007, (560)985-1713x00812, +4428 9018407) with 8 to 15 digits.
    Presidio's phone rule needs a plausible number for a known country. The cue word makes a looser
    layout safe. Dates are not phone numbers.
    """

    _RE = re.compile(
        r"\b(?:phone|tel|telephone|mobile|mob|cell|whatsapp|fax|call(?:[ \t]+me)?(?:[ \t]+(?:on|at))?|ring|"
        r"text[ \t]+me[ \t]+(?:on|at)|reach[ \t]+me[ \t]+(?:on|at)|contact[ \t]+number)"
        r"(?:[ \t]+(?:number|no\.?|is))?[ \t]*[:\-]?[ \t]*"
        r"(?P<v>\+?\(?\d[\d ()./\-]{6,22}\d(?:[ \t]?(?:x|ext\.?)[ \t]?\d{1,6})?)(?![\d])",
        re.IGNORECASE)

    def __init__(self):
        super().__init__(supported_entities=["PHONE_NUMBER"], supported_language="en", name="PhoneCueRecognizer")

    def load(self) -> None:  # noqa: D102
        pass

    def analyze(self, text: str, entities: List[str], nlp_artifacts=None) -> List[RecognizerResult]:
        out = []
        for m in self._RE.finditer(text):
            value = m.group("v")
            number = re.split(r"[ \t]?(?:x|ext)", value, flags=re.IGNORECASE)[0]
            digits = re.sub(r"\D", "", number)
            if not 8 <= len(digits) <= 15 or _DATE_ONLY.match(number.strip()):
                continue
            out.append(RecognizerResult(entity_type="PHONE_NUMBER", start=m.start("v"),
                                        end=m.end("v"), score=0.8))
        return out


_ADDR_ABBREV = "".join(f"(?<!{a})" for a in ("St", "Apt", "Ave", "Rd", "Dr", "Mt", "No", "Ste", "Fl", "Bldg", "Blvd"))
_ADDR_END = (
    rf"(?=\n|$|{_ADDR_ABBREV}\.(?=[ \t]+[A-Z])|[ \t]+[-–—][ \t]|;|[ \t]+(?:before|after|by|please|thanks)\b"
    r"|[ \t]+(?:The|A|An|Her|His|She|He|We|They|It|Our|Please|Thanks|Shipping|Refund|Call|Phone|Tel|"
    r"Email|Contact|DOB|Born|Date|Signed|Name|Login|Reply|Invoice)[ \t:]|[ \t]+[Ii]f[ \t])"
)


class AddressCueRecognizer(EntityRecognizer):
    """
    A postal address announced by a word such as "address", "ship to", "lives at" or "registered
    office at", whatever its layout. The address must start like one (a house number, a flat or suite
    word, or a street word such as "rue") and contain at least two capitalised words, so "Ship to 5
    boxes of widgets" is not an address. The whole address, postcode included, is redacted up to the end
    of the line, the sentence, a dash, or words like "before" and "please".
    """

    _CUE = (r"(?:(?:home|billing|shipping|delivery|postal|mailing|registered|office|work|business|return|"
            r"correspondence)[ \t]+address(?:[ \t]+is)?|address(?:[ \t]+is)?|ship(?:ped)?[ \t]+to|"
            r"deliver(?:ed)?[ \t]+to|lives?[ \t]+at|living[ \t]+at|resides?[ \t]+at|"
            r"(?:registered[ \t]+)?office[ \t]+at|located[ \t]+at|based[ \t]+at|mail[ \t]+to|post[ \t]+(?:it[ \t]+)?to|"
            r"parcel[ \t]+for|sent[ \t]+to|collection[ \t]+point|(?:flat|house|apartment|home|place)[ \t]+is[ \t]+at)")
    _START = (r"(?:\d+[A-Za-z]?(?:[-/]\d+)?\b|(?:Flat|Unit|Suite|Apt\.?|Apartment|Studio|Room|Level|Floor|Box|"
              r"P\.?O\.?[ \t]+Box)\b|(?:rue|avenue|boulevard|chemin|via|viale|calle|carrer|rua|plaza|piazza)\b)")
    _RE = re.compile(rf"\b(?i:{_CUE})[ \t]*[:\-]?[ \t]*(?P<v>{_START}[^\n]{{3,120}}?){_ADDR_END}")
    _CAP = re.compile(r"\b[A-ZÀ-ÖØ-Þ][\w'’-]+")

    def __init__(self):
        super().__init__(supported_entities=["STREET_ADDRESS"], supported_language="en", name="AddressCueRecognizer")

    def load(self) -> None:  # noqa: D102
        pass

    def analyze(self, text: str, entities: List[str], nlp_artifacts=None) -> List[RecognizerResult]:
        out = []
        for m in self._RE.finditer(text):
            value = m.group("v").rstrip(" \t.,")
            if len(self._CAP.findall(value)) < 2 or not (any(c.isdigit() for c in value) or "," in value):
                continue
            base = m.start("v")
            for a, b in self._parts(value):
                out.append(RecognizerResult(entity_type="STREET_ADDRESS", start=base + a, end=base + b, score=0.9))
        return out

    @staticmethod
    def _parts(value: str) -> list:
        """
        The pieces of an address to redact, as (start, end) offsets. Place names stay readable, as everywhere
        else in Jnvoy: "12 Acacia Avenue, Leeds LS1 4AP" gives "12 Acacia Avenue" and "LS1 4AP", and "Leeds"
        is left. When the last part does not look like a city and a postcode, the whole address is redacted.
        """
        whole = [(0, len(value))]
        comma = value.rfind(",")
        if comma < 1:
            return whole
        tail = value[comma + 1:]
        offset = comma + 1
        tokens = [(t.start() + offset, t.end() + offset, t.group(0)) for t in re.finditer(r"\S+", tail)]
        if not tokens:
            return whole
        first_digit = next((i for i, t in enumerate(tokens) if any(c.isdigit() for c in t[2])), None)
        city = tokens if first_digit is None else tokens[:first_digit]
        if len(city) > 4 or not all(re.fullmatch(r"[^\W\d_][\w'’.\-]*", t[2]) and not any(c.isdigit() for c in t[2]) for t in city):
            return whole
        head = (0, comma)
        if first_digit is None:
            return [head] if city else whole
        postcode = []
        for t in tokens[first_digit:]:
            if not any(c.isdigit() for c in t[2]):
                break
            postcode.append(t)   # "75001 Paris": the postcode is only the part with digits
        digits = re.sub(r"\D", "", postcode[0][2])
        if len(postcode[0][2]) < 3 or (not city and len(digits) < 4):
            return whole   # "27 Acacia Avenue": the rest of the street, not a postcode
        return [head, (postcode[0][0], postcode[-1][1])]


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
    r"licen[cs]e|booking|student|account\s+holder)(?:\s+file)?"
)
_ID_LABEL = r"(?:\s+(?:id|identifier|number|no\.?|num|ref(?:erence)?|code|#))?"


def make_extra_recognisers() -> list:
    secrets = PatternRecognizer(
        supported_entity="API_KEY", patterns=SECRET_PATTERNS,
        context=["api key", "secret", "token", "bearer", "key"], name="ExtraApiKeyRecognizer",
    )

    passwords = ContextualRecognizer(
        "SECRET_TOKEN",
        r"\b(?:password|passwd|pwd|pw|pass|passphrase|passcode|secret|api[_ ]?key|token|wi-?fi[ -]?(?:key|password|pass)|wpa[ -]?key)"
        r"(?:\s+(?:for|of|to)\s+(?:the\s+|my\s+|our\s+)?\w+)?\s*(?:is|=|:)\s*['\"]?(?P<v>[^\s'\",;]{6,})",
        0.9, "PasswordRecognizer", digit_or_symbol=True,
    )

    # "pwd hunter2Hunter" or "pw hunter2Hunter" with no "is" or colon, a common shorthand in notes and chat. "pwd" is also the
    # Unix command, so the value must be on the same line, must not start like a path, and must
    # contain a digit or symbol.
    pwd_shorthand = ContextualRecognizer(
        "SECRET_TOKEN",
        r"(?<![\w/.-])(?:pwd|pw)[ \t]+(?![/~.\\])['\"]?(?P<v>[^\s'\",;]{6,})",
        0.85, "PwdShorthandRecognizer", digit_or_symbol=True, case_sensitive=True,
    )

    credentials_pair = ContextualRecognizer(
        "SECRET_TOKEN",
        r"\bcredentials?[ \t]*[:=][ \t]*\S+[ \t]*[/:][ \t]*['\"]?(?P<v>[^\s'\",;]{6,})",
        0.85, "CredentialsPairRecognizer", digit_or_symbol=True,
    )

    # A social security number written 123-45-6789 is distinctive enough to hide without a label. The
    # ranges the Social Security Administration never issues (000, 666, 9xx, group 00, serial 0000) are left alone.
    dashed_ssn = PatternRecognizer(
        supported_entity="US_SSN",
        patterns=[Pattern("dashed_ssn", r"(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])", 0.85)],
        name="DashedSsnRecognizer",
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
        "DATE_OF_BIRTH", rf"\b{_DOB_LABEL}(?:\s+(?:is|was))?\s*[:\-]?\s*(?:the\s+)?(?P<v>{_DATE})", 0.9, "DateOfBirthRecognizer",
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
        ), Pattern(
            # Continental style: number, street word, then a capitalised name
            # ("42 Rue Saint-Honoré", "12 Boulevard Voltaire", "19 Calle de Alcalá").
            "street_continental",
            r"\b\d{1,4}(?:[A-Z]|\s*(?:bis|ter|quater))?,?\s+(?:[Rr]ue|[Bb]oulevard|[Aa]venue|[Cc]hemin|[Aa]llée|[Ii]mpasse|"
            r"[Qq]uai|[Cc]alle|[Aa]venida|[Pp]aseo|[Pp]laza|[Rr]ua|Via|Viale|Piazza|Strada)\s+"
            r"(?:(?:de\s+la|de\s+l['’]|de|du|des|del|della|di|da|dos|d['’])\s*)?"
            r"[A-ZÀ-Ý][\w'’\-]*(?:\s+[A-ZÀ-Ý][\w'’\-]*){0,3}",
            0.85,
        ), Pattern(
            # German and Dutch style: name ending in a street word, then the number
            # ("Hauptstraße 27", "Kerkstraat 15").
            "street_germanic",
            r"\b[A-ZÄÖÜ][a-zäöüß]+(?:straße|strasse|straat|weg|platz|allee|gasse|laan|plein|gracht|kade|singel|dijk|steeg)\s+\d{1,4}[a-z]?\b",
            0.85,
        ), Pattern(
            # A flat or unit followed by a building name ("Flat 4C, Rosewood Court").
            "unit_building",
            r"\b(?:Flat|Apartment|Apt|Unit|Suite)\s+\d{1,4}[A-Z]?,\s*(?:The\s+)?(?:[A-Z][a-z'\-]+\s+){0,3}"
            r"(?:House|Court|Mansions|Lodge|Tower|Towers|Building|Buildings|Apartments|Heights|Villas|"
            r"Cottage|Cottages|Manor|Hall|Gardens|View|Point|Residence|Residences)\b",
            0.85,
        ), Pattern(
            # Street word first, name, then the number ("Via Garibaldi 15", "Calle Mayor 22",
            # "Rua das Flores 88", "Avenida da Liberdade 200").
            "street_first",
            r"\b(?:Rue|Boulevard|Avenue|Chemin|Allée|Impasse|Quai|Calle|Avenida|Paseo|Plaza|Rua|"
            r"Travessa|Alameda|Largo|Praça|Via|Viale|Piazza|Piazzale|Strada|Vicolo|Corso)\s+"
            r"(?:(?:de|del|della|dei|degli|di|da|das|do|dos|du|des|la|le|el|los|las)\s+)*"
            r"[A-ZÀ-Ý][\w'’\-]*(?:\s+(?:(?:de|del|della|dei|degli|di|da|das|do|dos|du|des|la|le|el|los|las)\s+)*"
            r"[A-ZÀ-Ý][\w'’\-]*){0,3},?\s+\d{1,4}[A-Za-z]?\b",
            0.85,
        ), Pattern(
            # A named dwelling at the start of an address line: one or two capitalised words
            # ending in a house word, then a comma and the next line ("Willow Barn, Ashby Road").
            # Words that are also common in landmark and book names (House, Hall, Mill, Farm) need
            # a street after the comma to count, so "Animal Farm, Orwell" and "Royal Albert Hall,
            # London" are left alone.
            "named_dwelling",
            r"\b(?:[A-Z][a-z'\-]+\s+){1,2}"
            r"(?:Cottage|Lodge|Barn|Grange|Priory|Villa|Bungalow|Farmhouse|Rectory|Vicarage)"
            r"(?=,\s*(?:[A-Z]|\d))",
            0.8,
        ), Pattern(
            "named_dwelling_strict",
            r"\b(?:[A-Z][a-z'\-]+\s+){1,2}(?:House|Hall|Mill|Farm|Manor)"
            r"(?=,\s*(?:\d{1,4}[A-Z]?\s+)?(?:[A-Z][a-z'\-]+\s+){1,2}"
            r"(?:Street|Road|Lane|Close|Avenue|Drive|Way|Court|Place|Gardens|Crescent|Terrace|Grove|"
            r"Hill|Park|Mews|Row|Walk)\b)",
            0.8,
        ), Pattern(
            # A named house at the start of an address ("The Old Rectory, Church Lane").
            "named_house",
            r"\bThe\s+(?:Old\s+)?(?:Rectory|Vicarage|Manor|Lodge|Cottage|Farmhouse|Priory|Grange|"
            r"Coach\s+House)(?=,\s*[A-Z])",
            0.8,
        )],
        global_regex_flags=re.DOTALL | re.MULTILINE,  # case sensitive: needs capitalised names
        name="StreetAddressRecognizer",
    )

    return [secrets, passwords, pwd_shorthand, credentials_pair, dashed_ssn, CardCueRecognizer(), PhoneCueRecognizer(), AddressCueRecognizer(), env_assignment, conn_string, bearer, dob, passport, reference, street]


EXTRA_ENTITIES = ["DATE_OF_BIRTH", "STREET_ADDRESS", "ID_NUMBER"]
