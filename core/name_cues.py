"""
Finds people's names from the words around them, for the cases a language model misses.

The small language model that the hosted service uses is good at names in ordinary sentences and
weak when a name stands in a letter, a form or a list ("Dear Ms Jane Testington", "Name: Lucía
Fernández Ortega", "Attendees: A, B and C"). A name in those places is announced by a cue: a
title (Mr, Dr), a greeting (Dear, Hi), a label (Patient:, Name:), a sign-off (Regards,) or a
verb that introduces a person (call, written by, forward to). This recogniser looks for the cue
and treats the capitalised words after it as a name. It runs next to the language model, so it
only ever adds names, and the same value found twice is redacted once.

Care taken against redacting things that are not people:
  * the weaker cues (a verb or a preposition) need at least two capitalised words;
  * a name word may not be a day, a month, or a word such as Team, Support, Royal or New;
  * words such as Ltd, Hospital, Street or University anywhere in the match rule it out;
  * the language model's own tags for places (city, country, building) win over the weak cues.

Only the name is redacted, not the cue, so "Dear Ms [PERSON_1]," stays readable.
"""

import re
from typing import List

from presidio_analyzer import EntityRecognizer, RecognizerResult

# ── what a name looks like ────────────────────────────────────────────────────

_UP = "A-ZÀ-ÖØ-ÞĀ-ſ"
_LO = "a-zà-öø-ÿĀ-ſ"
_TOK = rf"[{_UP}][A-Za-zÀ-ÖØ-öø-ÿĀ-ſ'’\-]*[{_LO}]"
_PART = r"(?:van|von|der|den|de|del|della|di|da|dos|das|du|la|le|bin|ibn|ben|ter|ten|op|af|av)"
_ELEM = rf"(?:(?:{_PART}[ \t]+)*{_TOK}|(?:al|el|Al|El)-{_TOK})"


def _name(min_elems: int, max_elems: int = 3) -> str:
    rest = f"(?:[ \\t]+{_ELEM}){{{min_elems - 1},{max_elems - 1}}}"
    return f"{_ELEM}{rest}"


# A name written in capital letters ("LYNN STEPHENS"). Each word needs three or more letters, so
# initials and short acronyms (HR, IT, UK) are not names. Used only after a cue, and only when the
# cue itself is not in capitals (so a shouted sentence is not read as names).
_CAPS_ELEM = rf"[{_UP}][{_UP}'’\-]{{2,}}(?![{_UP}{_LO}])"   # not the start of "O'Neill"


def _caps_name(min_elems: int, max_elems: int = 3) -> str:
    return f"{_CAPS_ELEM}(?:[ \\t]+{_CAPS_ELEM}){{{min_elems - 1},{max_elems - 1}}}"


# "Surname, Given" ("Klotz, Katrin", "van Wickerode, Pien"): a surname of one or two parts, a comma,
# one given name.
_SURNAME_FIRST = rf"(?:{_ELEM}(?:[ \t]+{_ELEM})?[ \t]*,[ \t]+{_ELEM})"
# What may follow a "Surname, Given" that was announced only by a weak cue: the end of a clause,
# or a verb that says what the person did. "Hi Anna, Thanks for..." is not a name.
_SF_END = (r"(?=[ \t]*(?:[,.;:!?)\n]|$)|[ \t]+(?:joined|has|have|about|and|is|was|will|-|–|—)(?![A-Za-z]))")

_TITLE = r"(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof|Professor|Sir|Dame|Lord|Lady|Rev|Revd|Mister|Madam)"

_DAYS = {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"}
_MONTHS = {"January", "February", "March", "April", "May", "June", "July", "August", "September",
           "October", "November", "December"}
# Capitalised words that start a sentence or name a role, not a person.
_NOT_NAMES = _DAYS | _MONTHS | {
    "All", "Team", "Everyone", "Everybody", "There", "Sir", "Madam", "Sirs", "Customer", "Client",
    "Colleagues", "Friends", "Folks", "Guys", "World", "Again", "Mate", "Support", "Admin", "User",
    "Both", "Manager", "Applicant", "Parent", "Parents", "Anyone", "Please", "Thanks", "Thank",
    "Regards", "Kind", "Best", "Wishes", "You", "Yours", "The", "This", "That", "These", "Those",
    "Our", "Your", "My", "His", "Her", "Their", "Sales", "Finance", "Legal", "Helpdesk", "Service",
    "Services", "Department", "Office", "Group", "Royal", "National", "New", "Old", "Great", "North",
    "South", "East", "West", "Central", "Greater", "United", "Los", "Las", "San", "Santa", "Saint",
    "St", "Mount", "Lake", "Port", "Fort", "Cape", "Isle", "Upper", "Lower", "Little", "Big",
    "Hong", "Sri", "Costa", "Puerto", "Buenos", "Kuala", "Abu", "Tel", "Rio", "Hello", "Dear",
    "Hi", "Hey", "Cheers", "Sincerely", "Faithfully", "Today", "Tomorrow", "Yesterday", "Monday",
    # titles (the title rule handles these) and the words that label a field ("Bcc: ...")
    "Mr", "Mrs", "Ms", "Miss", "Mx", "Dr", "Prof", "Professor", "Dame", "Lord", "Lady", "Rev", "Revd",
    "Mister", "Cc", "Bcc", "To", "From", "Subject", "Date", "Sent", "Name", "Employer", "Address",
    "Phone", "Email", "Tel", "Mobile", "Position", "Title", "Company", "Role", "Dept",
}
# Words that mark an organisation, a building or a place. If any is in the match it is not a person.
_ORG_WORDS = {
    "Ltd", "Limited", "Inc", "Plc", "LLC", "LLP", "Corp", "Corporation", "Company", "Co", "Group",
    "Bank", "Hospital", "Clinic", "Surgery", "University", "College", "School", "Academy", "Council",
    "Station", "Street", "Road", "Avenue", "Lane", "Park", "Airport", "Hotel", "Church", "Museum",
    "Office", "Department", "Services", "Solutions", "Systems", "Square", "Bridge", "Cross", "Centre",
    "Center", "Association", "Society", "Club", "Trust", "Foundation", "Institute", "Agency",
    "Authority", "Police", "Ministry", "Court", "Cathedral", "Library", "Market", "Gardens", "Hill",
    "Valley", "Beach", "Island", "Islands", "Mountains", "River", "Lake", "Bay", "Harbour", "Port",
    "Palace", "Castle", "Tower", "Theatre", "Cinema", "Stadium", "Arena", "Restaurant", "Cafe", "Pub",
    "Insurance", "Holdings", "Partners", "Associates", "Consulting", "Technologies", "Labs", "Studios",
    "Mail", "Post", "Bus", "Rail", "Line", "Express", "Airlines", "Airways", "Motors", "Foods",
}

# Places only: the small model often calls an unfamiliar name an ORG or PRODUCT. The recogniser sees the
# labels Presidio gives the language model's tags (LOCATION), not spaCy's own (GPE, LOC, FAC), so both are listed.
_BAD_NER = {"GPE", "LOC", "FAC", "LOCATION"}
# A name in capital letters is also refused when the model calls it an organisation or a group, because
# "Call NASA ESA" is not a person. Names in capitals are often tagged ORGANIZATION by mistake, so this costs some recall.
_BAD_NER_CAPS = _BAD_NER | {"ORG", "ORGANIZATION", "NORP", "NRP"}

_LABEL_CUES = (
    r"full[ \t]+name|first[ \t]+name|last[ \t]+name|surname|forename|name|patient|client|"
    r"customer|applicant|employee|contact|witness|author|signed|signatory|account[ \t]+holder|"
    r"policy[ \t]*holder|candidate|claimant|defendant|next[ \t]+of[ \t]+kin|emergency[ \t]+contact|"
    r"referred[ \t]+by|prepared[ \t]+by|reviewed[ \t]+by|approved[ \t]+by|witness[ \t]+statement[ \t]+of"
)
_VERB_CUES = (
    r"written by|reviewed by|approved by|signed by|prepared by|submitted by|sent by|raised by|"
    r"spoke with|spoken to|speak to|speak with|talk to|talked to|call|phone|email|e-mail|contact|ring|"
    r"ask|asked|tell|told|meet|met|meeting with|forward to|send to|sent to|deliver to|delivered to|"
    r"belongs to|belonging to|invoice to|invoiced to|welcome|introduce|thanks to|attn|attention|"
    r"c/o|care of|new hire|new starter|statement of|for|with|from|to|by"
)
_GREETING_CUES = r"dear|hi|hello|hey|thanks|thank you|cheers"

# Titles are matched with their capital letter; everything else is cue words in any case.
def _rules(_name):
    return [
        # (name, regex with group v, score, minimum words in the name, uses the NER veto)
        ("title", rf"\b{_TITLE}\.?[ \t]+(?P<v>{_name(1)})", 0.85, 1, False),
        ("greeting",
         rf"\b(?i:dear|hi|hello|hey|thanks|thank you|cheers)[ \t]*,?[ \t]+(?P<v>{_name(1, 2)})"
         rf"(?=[ \t]*(?:[,.:;!?\n]|$))", 0.75, 1, False),
        ("signoff",
         rf"(?im:^[ \t]*(?:regards|kind regards|best regards|warm regards|best wishes|best|sincerely|"
         rf"yours sincerely|yours faithfully|yours|cheers|thanks|thank you|many thanks)[ \t]*,?[ \t]*\n[ \t]*)"
         rf"(?P<v>{_name(1)})[ \t]*$", 0.8, 1, False),
        ("label",
         rf"\b(?i:{_LABEL_CUES})"
         rf"[ \t]*[:\-–][ \t]*(?P<v>{_name(1)})", 0.8, 1, False),
        ("pair_label",
         rf"\b(?i:from|to|cc|bcc|owner|manager|host|guest|speaker|presenter|present|apologies|attendees?)"
         rf"[ \t]*:[ \t]*(?P<v>{_name(2)})", 0.8, 2, False),
        ("cue_verb",
         rf"\b(?i:{_VERB_CUES})"
         rf"[ \t]+(?P<v>{_name(2)})", 0.65, 2, True),
    ]


def _surname_first_rules():
    sf = _SURNAME_FIRST
    return [
        ("sf_greeting", rf"\b(?i:{_GREETING_CUES})[ \t]*,?[ \t]+(?P<v>{sf}){_SF_END}", 0.75, 2, False),
        ("sf_label", rf"\b(?i:{_LABEL_CUES})[ \t]*[:\-–][ \t]*(?P<v>{sf})", 0.8, 2, False),
        ("sf_verb", rf"\b(?i:{_VERB_CUES})[ \t]+(?P<v>{sf}){_SF_END}", 0.65, 2, True),
        ("sf_joined", rf"(?P<v>{sf})[ \t]+(?:joined|has[ \t]+joined|has[ \t]+passed|will[ \t]+join)\b", 0.7, 2, True),
    ]


# (kind, compiled regex, score, minimum words, uses the place veto, mode)
#   mode "": the normal capitalised name; "caps": a name in capital letters after a cue that is not
#   itself in capitals; "sf": "Surname, Given".
_CAPS_KINDS = {"title", "greeting", "signoff", "label", "cue_verb"}
_COMPILED = (
    [(n, re.compile(rx, re.MULTILINE), sc, m, veto, "") for n, rx, sc, m, veto in _rules(_name)]
    + [(n, re.compile(rx, re.MULTILINE), sc, m, veto, "caps")
       for n, rx, sc, m, veto in _rules(_caps_name) if n in _CAPS_KINDS]
    + [(n, re.compile(rx, re.MULTILINE), sc, m, veto, "sf") for n, rx, sc, m, veto in _surname_first_rules()]
)

# An attendee list: "Attendees: A B, C D and E F". The label starts it and each name is its own result.
_LIST = re.compile(
    rf"\b(?i:attendees?|present|apologies|cc|bcc|to|participants|invited)[ \t]*:[ \t]*"
    rf"(?P<v>{_name(1)}(?:(?:[ \t]*[,;&][ \t]*|[ \t]+and[ \t]+){_name(1)})+)")
_LIST_SPLIT = re.compile(r"[ \t]*[,;&][ \t]*|[ \t]+and[ \t]+")

_POSSESSIVE = re.compile(r"['’]s$")
_DR_AFTER_NUMBER = re.compile(r"\d[ \t]+[A-Z][\w']*(?:[ \t]+[A-Z][\w']*)?[ \t]+$")


def _words(value: str) -> list:
    return [w for w in re.split(r"[ \t]+", value) if w]


def _plausible(value: str, min_words: int) -> bool:
    words = _words(value)
    capitalised = [w for w in words if w[:1].isupper() or w[:3].lower() in ("al-", "el-")]
    if len(capitalised) < min_words:
        return False
    for w in capitalised:
        bare = w.strip(".,;:")
        if bare in _NOT_NAMES or bare in _ORG_WORDS or bare.capitalize() in _NOT_NAMES or bare.capitalize() in _ORG_WORDS:
            return False
    return True


class NameCueRecognizer(EntityRecognizer):
    """Adds PERSON results for names announced by a title, greeting, label, sign-off or verb."""

    def __init__(self):
        super().__init__(supported_entities=["PERSON"], supported_language="en", name="NameCueRecognizer")

    def load(self) -> None:  # noqa: D102
        pass

    @staticmethod
    def _vetoed(start: int, end: int, nlp_artifacts, labels=_BAD_NER) -> bool:
        """True if the language model says this span is a place (or, for a name in capitals, an organisation)."""
        entities = getattr(nlp_artifacts, "entities", None) or []
        for ent in entities:
            if ent.label_ in labels and ent.start_char < end and ent.end_char > start:
                return True
        return False

    def analyze(self, text: str, entities: List[str], nlp_artifacts=None) -> List[RecognizerResult]:
        out = []
        seen = set()

        def add(start: int, end: int, score: float) -> None:
            value = text[start:end]
            trimmed = _POSSESSIVE.sub("", value)
            end -= len(value) - len(trimmed)
            if end > start and (start, end) not in seen:
                seen.add((start, end))
                out.append(RecognizerResult(entity_type="PERSON", start=start, end=end, score=score))

        for kind, rx, score, min_words, veto, mode in _COMPILED:
            for m in rx.finditer(text):
                value = m.group("v")
                start, end = m.start("v"), m.end("v")
                if not _plausible(value, min_words):
                    continue
                if mode == "caps":
                    cue = re.sub(r"[^A-Za-z]", "", text[m.start():start])
                    if len(cue) >= 3 and cue.isupper():
                        continue  # a whole sentence in capitals is shouting, not a name after a cue
                if kind == "title" and m.group(0).startswith("Dr") and \
                        _DR_AFTER_NUMBER.search(text[:m.start()] + " "):
                    continue  # "14 Acacia Dr Hampton" is an address, not Doctor Hampton
                if (mode == "caps" or kind == "sf_verb") and self._vetoed(start, end, nlp_artifacts, _BAD_NER_CAPS):
                    continue
                if veto and self._vetoed(start, end, nlp_artifacts):
                    continue
                add(start, end, score)

        for m in _LIST.finditer(text):
            base = m.start("v")
            value = m.group("v")
            pos = 0
            for piece in _LIST_SPLIT.split(value):
                at = value.find(piece, pos)
                pos = at + len(piece)
                after = text[base + at + len(piece):base + at + len(piece) + 4].lstrip(" \t")
                if piece and _plausible(piece, 1) and not after.startswith(":"):
                    add(base + at, base + at + len(piece), 0.8)
        return out
