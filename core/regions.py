"""
Region packs: national identifiers outside the UK and US.

Jnvoy started with UK identifiers (NHS number, National Insurance, postcode, sort code). This
module adds the national IDs of other countries so the same redaction works wherever the text
came from. Each pack is a country; "eu" and "all" are shortcuts.

    JNVOY_REGIONS=all              (default) every pack below
    JNVOY_REGIONS=in,au,sg         only these countries (UK and US rules are always on)
    JNVOY_REGIONS=eu,us            the EU packs plus the US ZIP code rule
    JNVOY_REGIONS=none             UK and US rules only

Design rules, so that adding countries does not add noise:
  * An identifier is only reported when its own check digit (or published structure) is valid.
    A random run of digits fails the check most of the time.
  * Numbers that are plain digits (no spaces, hyphens or letters) are ambiguous, so they are
    only reported next to a telling word ("Aadhaar", "TFN", "BSN", "CPF"). Formatted numbers
    ("7260 1815 9082", "111.444.777-35") and numbers with letters are reported on their own.
  * Business identifiers, vehicle plates and bare postal codes are not included: they are
    common in ordinary text and are not personal data on their own.
"""

import re
from typing import Callable, Dict, List, Optional

from presidio_analyzer import EntityRecognizer, RecognizerResult


# ── which entity belongs to which country ─────────────────────────────────────

PACKS: Dict[str, List[str]] = {
    "us": ["US_ZIP_CODE"],
    "de": ["DE_TAX_ID", "DE_SOCIAL_SECURITY"],
    "es": ["ES_NIF", "ES_NIE"],
    "it": ["IT_FISCAL_CODE"],
    "pl": ["PL_PESEL"],
    "se": ["SE_PERSONNUMMER"],
    "fi": ["FI_PERSONAL_IDENTITY_CODE"],
    "fr": ["FR_NIR"],
    "nl": ["NL_BSN"],
    "in": ["IN_AADHAAR", "IN_PAN"],
    "au": ["AU_TFN", "AU_MEDICARE"],
    "ca": ["CA_SIN"],
    "sg": ["SG_NRIC_FIN"],
    "za": ["ZA_ID_NUMBER"],
    "kr": ["KR_RRN"],
    "th": ["TH_TNIN"],
    "tr": ["TR_NATIONAL_ID"],
    "br": ["BR_CPF"],
    "cn": ["CN_RESIDENT_ID"],
    "ae": ["AE_EMIRATES_ID"],
}

ALIASES: Dict[str, List[str]] = {
    "eu": ["de", "es", "it", "pl", "se", "fi", "fr", "nl"],
    "uk": [],      # always on
    "none": [],
    "all": list(PACKS),
}

COUNTRY_NAMES = {
    "us": "United States", "de": "Germany", "es": "Spain", "it": "Italy", "pl": "Poland",
    "se": "Sweden", "fi": "Finland", "fr": "France", "nl": "Netherlands", "in": "India",
    "au": "Australia", "ca": "Canada", "sg": "Singapore", "za": "South Africa",
    "kr": "South Korea", "th": "Thailand", "tr": "Turkey", "br": "Brazil", "cn": "China",
    "ae": "United Arab Emirates",
}

ALL_REGION_ENTITIES = [e for ents in PACKS.values() for e in ents]


def active_regions(env=None) -> List[str]:
    """Country codes switched on by JNVOY_REGIONS (default: all)."""
    import os
    env = os.environ if env is None else env
    raw = str(env.get("JNVOY_REGIONS", "")).strip().lower()
    if not raw:
        raw = "all"
    chosen: List[str] = []
    unknown: List[str] = []
    for name in (n.strip() for n in raw.split(",") if n.strip()):
        if name in ALIASES:
            chosen += ALIASES[name]
        elif name in PACKS:
            chosen.append(name)
        else:
            unknown.append(name)
    if unknown:
        raise ValueError(
            "JNVOY_REGIONS has unknown region(s): " + ", ".join(unknown)
            + ". Valid: " + ", ".join(sorted(PACKS)) + ", eu, all, none."
        )
    return [c for c in PACKS if c in chosen]


def region_entities(env=None) -> List[str]:
    return [e for c in active_regions(env) for e in PACKS[c]]


# A valid identifier outranks Presidio's phone guess (0.9). When a telling word is nearby it
# outranks other identifiers of the same shape (a 3-3-3 number can be a TFN or a SIN).
SCORE_VALID = 0.92
SCORE_WITH_CONTEXT = 0.97


# ── helpers ───────────────────────────────────────────────────────────────────

def _digits(s: str) -> List[int]:
    return [int(c) for c in s if c.isdigit()]


def _luhn(s: str) -> bool:
    d = _digits(s)[::-1]
    total = 0
    for i, x in enumerate(d):
        if i % 2:
            x *= 2
            if x > 9:
                x -= 9
        total += x
    return total % 10 == 0


def _is_bare_digits(value: str) -> bool:
    return value.isdigit()


def _has_context(text: str, start: int, end: int, words, before: int = 60, after: int = 30) -> bool:
    window = text[max(0, start - before):start] + " " + text[end:end + after]
    window = window.lower()
    return any(re.search(r"(?<!\w)" + re.escape(w) + r"(?!\w)", window) for w in words)


# ── check-digit validators for identifiers Presidio does not cover ────────────

def _cpf_ok(value: str) -> bool:
    d = _digits(value)
    if len(d) != 11 or len(set(d)) == 1:
        return False
    for n in (9, 10):
        s = sum(d[i] * (n + 1 - i) for i in range(n))
        if (s * 10 % 11) % 10 != d[n]:
            return False
    return True


def _nir_ok(value: str) -> bool:
    compact = re.sub(r"\s", "", value).upper()
    base, key = compact[:13], compact[13:]
    base = base.replace("2A", "19").replace("2B", "18")
    if not (base.isdigit() and key.isdigit()):
        return False
    return 97 - (int(base) % 97) == int(key)


def _bsn_ok(value: str) -> bool:
    d = _digits(value)
    if len(d) != 9 or len(set(d)) == 1:
        return False
    total = sum(d[i] * (9 - i) for i in range(8)) - d[8]
    return total % 11 == 0


def _cn_id_ok(value: str) -> bool:
    v = value.upper()
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    total = sum(int(c) * w for c, w in zip(v[:17], weights))
    return "10X98765432"[total % 11] == v[17]


def _uae_id_ok(value: str) -> bool:
    return len(_digits(value)) == 15 and _luhn(value)


def _sin_ok(value: str) -> bool:
    d = _digits(value)
    return len(d) == 9 and len(set(d)) > 1 and _luhn(value)


def _nric_ok(value: str) -> bool:
    v = value.upper()
    weights = [2, 7, 6, 5, 4, 3, 2]
    total = sum(int(c) * w for c, w in zip(v[1:8], weights))
    if v[0] in "TG":
        total += 4
    table = "JZIHGFEDCBA" if v[0] in "ST" else "XWUTRQPNMLK"
    return table[total % 11] == v[8]


# ── recognisers ───────────────────────────────────────────────────────────────

class _RegexRecogniser(EntityRecognizer):
    """
    A regex whose match must pass a validator. Plain-digit matches also need a telling word
    nearby (context); formatted matches and matches with letters do not.
    """

    def __init__(self, entity: str, regex: str, name: str,
                 validate: Optional[Callable[[str], bool]] = None,
                 context: Optional[List[str]] = None,
                 always_context: bool = False,
                 group: Optional[str] = None,
                 flags: int = 0, score: float = SCORE_VALID):
        self._re = re.compile(regex, flags)
        self._validate = validate
        self._context = [c.lower() for c in (context or [])]
        self._always_context = always_context
        self._group = group
        self._score = score
        super().__init__(supported_entities=[entity], supported_language="en", name=name)

    def load(self) -> None:  # noqa: D102
        pass

    def analyze(self, text: str, entities: List[str], nlp_artifacts=None) -> List[RecognizerResult]:
        out = []
        for m in self._re.finditer(text):
            value = m.group(self._group) if self._group else m.group(0)
            start, end = (m.start(self._group), m.end(self._group)) if self._group else m.span()
            if self._validate and not self._validate(value):
                continue
            score = self._score
            if self._context:
                near = _has_context(text, start, end, self._context)
                if (self._always_context or _is_bare_digits(value)) and not near:
                    continue
                score = SCORE_WITH_CONTEXT if near else self._score
            out.append(RecognizerResult(self.supported_entities[0], start, end, score))
        return out


class _ValidatedPresidio(EntityRecognizer):
    """
    Wraps one of Presidio's country recognisers. Presidio gives a high score only when the
    check digit is valid, so anything below 0.9 is dropped. Plain-digit values also need a
    telling word nearby.
    """

    def __init__(self, entity: str, class_name: str, context: List[str]):
        import presidio_analyzer.predefined_recognizers as predefined
        self._inner = getattr(predefined, class_name)(supported_language="en")
        self._context = [c.lower() for c in context]
        super().__init__(supported_entities=[entity], supported_language="en",
                         name=f"Region{class_name}")

    def load(self) -> None:  # noqa: D102
        self._inner.load()

    def analyze(self, text: str, entities: List[str], nlp_artifacts=None) -> List[RecognizerResult]:
        entity = self.supported_entities[0]
        out = []
        for r in self._inner.analyze(text, [entity], nlp_artifacts) or []:
            if r.score < 0.9:
                continue
            value = text[r.start:r.end]
            near = _has_context(text, r.start, r.end, self._context)
            if _is_bare_digits(value) and not near:
                continue
            out.append(RecognizerResult(entity, r.start, r.end, SCORE_WITH_CONTEXT if near else SCORE_VALID))
        return out


_US_STATES = (
    "AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|"
    "NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC|PR"
)


def make_region_recognisers() -> list:
    """Every region recogniser. Which ones run is decided by the entity filter."""
    P = _ValidatedPresidio
    R = _RegexRecogniser
    return [
        # United States: ZIP code after a state, or after the word "zip".
        R("US_ZIP_CODE",
          rf"\b[A-Z][a-z]+\s*,?\s+(?:{_US_STATES})\s+(?P<v>\d{{5}}(?:-\d{{4}})?)\b",
          "UsZipAfterState", group="v"),
        R("US_ZIP_CODE",
          r"\b(?:zip|zipcode|postal)\s*(?:code)?\s*(?:is|:|=)?\s*(?P<v>\d{5}(?:-\d{4})?)\b",
          "UsZipLabelled", group="v", flags=re.IGNORECASE),

        # Europe
        P("DE_TAX_ID", "DeTaxIdRecognizer", ["steuer", "tax id", "tax identification", "idnr", "tin"]),
        P("DE_SOCIAL_SECURITY", "DeSocialSecurityRecognizer",
          ["rentenversicherung", "social security", "sozialversicherung"]),
        P("ES_NIF", "EsNifRecognizer", ["nif", "dni"]),
        P("ES_NIE", "EsNieRecognizer", ["nie"]),
        P("IT_FISCAL_CODE", "ItFiscalCodeRecognizer", ["codice fiscale", "fiscal code"]),
        P("PL_PESEL", "PlPeselRecognizer", ["pesel"]),
        P("SE_PERSONNUMMER", "SePersonnummerRecognizer", ["personnummer", "personal identity"]),
        P("FI_PERSONAL_IDENTITY_CODE", "FiPersonalIdentityCodeRecognizer",
          ["henkilötunnus", "personal identity code", "hetu"]),
        R("FR_NIR",
          r"\b[12]\s?\d{2}\s?(?:0[1-9]|1[0-2])\s?(?:\d{2}|2[AB])\s?\d{3}\s?\d{3}\s?\d{2}\b",
          "FrNir", validate=_nir_ok,
          context=["sécurité sociale", "securite sociale", "insee", "nir", "numéro de sécu",
                   "social security"]),
        R("NL_BSN", r"\b\d{9}\b", "NlBsn", validate=_bsn_ok, always_context=True,
          context=["bsn", "burgerservicenummer", "citizen service number"]),

        # Asia-Pacific
        P("IN_AADHAAR", "InAadhaarRecognizer", ["aadhaar", "aadhar", "uidai", "uid"]),
        R("IN_PAN", r"\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b", "InPan"),
        P("AU_TFN", "AuTfnRecognizer", ["tfn", "tax file number"]),
        P("AU_MEDICARE", "AuMedicareRecognizer", ["medicare"]),
        R("SG_NRIC_FIN", r"\b[STFG]\d{7}[A-Z]\b", "SgNricFin", validate=_nric_ok,
          flags=re.IGNORECASE),
        P("KR_RRN", "KrRrnRecognizer", ["rrn", "resident registration", "주민등록"]),
        P("TH_TNIN", "ThTninRecognizer", ["national id", "thai id", "tnin", "citizen id"]),
        R("CN_RESIDENT_ID",
          r"\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b",
          "CnResidentId", validate=_cn_id_ok),

        # Americas
        R("CA_SIN", r"\b\d{3}[ -]?\d{3}[ -]?\d{3}\b", "CaSin", validate=_sin_ok,
          context=["sin", "social insurance"]),
        R("BR_CPF", r"\b(?:\d{3}\.\d{3}\.\d{3}-\d{2}|\d{11})\b", "BrCpf", validate=_cpf_ok,
          context=["cpf"]),

        # Middle East and Africa
        R("AE_EMIRATES_ID", r"\b784[- ]?\d{4}[- ]?\d{7}[- ]?\d\b", "AeEmiratesId",
          validate=_uae_id_ok),
        P("ZA_ID_NUMBER", "ZaIdNumberRecognizer", ["id number", "south african id", "identity number"]),
        P("TR_NATIONAL_ID", "TrNationalIdRecognizer",
          ["tc kimlik", "kimlik", "national id", "turkish id", "tckn"]),
    ]
