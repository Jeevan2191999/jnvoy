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

_BAD_NER = {"GPE", "LOC", "FAC"}   # places only: the small model often calls an unfamiliar name an ORG or PRODUCT

# Titles are matched with their capital letter; everything else is cue words in any case.
_RULES = [
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
     rf"\b(?i:full[ \t]+name|first[ \t]+name|last[ \t]+name|surname|forename|name|patient|client|"
     rf"customer|applicant|employee|contact|witness|author|signed|signatory|account[ \t]+holder|"
     rf"policy[ \t]*holder|candidate|claimant|defendant|next[ \t]+of[ \t]+kin|emergency[ \t]+contact|"
     rf"referred[ \t]+by|prepared[ \t]+by|reviewed[ \t]+by|approved[ \t]+by|witness[ \t]+statement[ \t]+of)"
     rf"[ \t]*[:\-–][ \t]*(?P<v>{_name(1)})", 0.8, 1, False),
    ("pair_label",
     rf"\b(?i:from|to|cc|bcc|owner|manager|host|guest|speaker|presenter|present|apologies|attendees?)"
     rf"[ \t]*:[ \t]*(?P<v>{_name(2)})", 0.8, 2, False),
    ("cue_verb",
     rf"\b(?i:written by|reviewed by|approved by|signed by|prepared by|submitted by|sent by|raised by|"
     rf"spoke with|spoken to|speak to|speak with|talk to|talked to|call|phone|email|e-mail|contact|ring|"
     rf"ask|asked|tell|told|meet|met|meeting with|forward to|send to|sent to|deliver to|delivered to|"
     rf"belongs to|belonging to|invoice to|invoiced to|welcome|introduce|thanks to|attn|attention|"
     rf"c/o|care of|new hire|new starter|statement of|for|with|from|to|by)"
     rf"[ \t]+(?P<v>{_name(2)})", 0.65, 2, True),
]
_COMPILED = [(n, re.compile(rx, re.MULTILINE), s, m, veto) for n, rx, s, m, veto in _RULES]

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
        if bare in _NOT_NAMES or bare in _ORG_WORDS:
            return False
    return True


class NameCueRecognizer(EntityRecognizer):
    """Adds PERSON results for names announced by a title, greeting, label, sign-off or verb."""

    def __init__(self):
        super().__init__(supported_entities=["PERSON"], supported_language="en", name="NameCueRecognizer")

    def load(self) -> None:  # noqa: D102
        pass

    @staticmethod
    def _vetoed(start: int, end: int, nlp_artifacts) -> bool:
        """True if the language model says this span is a place, organisation or product."""
        entities = getattr(nlp_artifacts, "entities", None) or []
        for ent in entities:
            if ent.label_ in _BAD_NER and ent.start_char < end and ent.end_char > start:
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

        for kind, rx, score, min_words, veto in _COMPILED:
            for m in rx.finditer(text):
                value = m.group("v")
                start, end = m.start("v"), m.end("v")
                if not _plausible(value, min_words):
                    continue
                if kind == "title" and m.group(0).startswith("Dr") and \
                        _DR_AFTER_NUMBER.search(text[:m.start()] + " "):
                    continue  # "14 Acacia Dr Hampton" is an address, not Doctor Hampton
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
