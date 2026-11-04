"""
Names found from the words around them (core/name_cues.py), and the two small steps that go with it.

These tests call the rule directly, so they do not depend on which language model is installed.

Run:  pytest tests/test_name_cues.py -q
"""

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from presidio_analyzer import RecognizerResult  # noqa: E402

from core.detector_v2 import PIIDetectorV2, _cut_names_at_line_end, _merge_person_spans  # noqa: E402
from core.name_cues import NameCueRecognizer  # noqa: E402

rule = NameCueRecognizer()


def names(text, artifacts=None):
    return sorted(text[r.start:r.end] for r in rule.analyze(text, ["PERSON"], artifacts))


@pytest.mark.parametrize("text,expected", [
    ("Dear Ms Jane Testington, your appointment", ["Jane Testington"]),
    ("Mr Achterberg called", ["Achterberg"]),
    ("Prof. Anil Kapoor will speak", ["Anil Kapoor"]),
    ("Dr Priya Ramanathan will see you", ["Priya Ramanathan"]),
    ("Mrs O'Neill's coat", ["O'Neill"]),
    ("Mr Sipho van der Merwe", ["Sipho van der Merwe"]),
    ("Mr Ibrahim al-Farsi", ["Ibrahim al-Farsi"]),
    ("Miss Aoife Brennan-Walsh attended", ["Aoife Brennan-Walsh"]),
    ("Ms Lucía Fernández Ortega", ["Lucía Fernández Ortega"]),
])
def test_a_title_announces_a_name(text, expected):
    assert names(text) == expected


def test_dr_in_an_address_is_not_a_doctor():
    assert names("14 Acacia Dr Hampton is the address") == []
    assert names("Dear Dr Hampton, thanks") == ["Hampton"]


@pytest.mark.parametrize("text,expected", [
    ("Hi Callum, thanks for the update", ["Callum"]),
    ("Hello Jane Testington, welcome", ["Jane Testington"]),
    ("Thanks, Joao", ["Joao"]),
    ("Dear Chioma!", ["Chioma"]),
])
def test_a_greeting_announces_a_name(text, expected):
    assert names(text) == expected


@pytest.mark.parametrize("text", [
    "Hello World, this is my first program.", "Hi All, quick update", "Dear Sir or Madam,",
    "Thanks, Friday works", "Best Buy and Best Western are hotels", "Hi there",
    "Dear Customer Service Team,", "Thanks, Support",
])
def test_greetings_to_nobody_in_particular_are_left_alone(text):
    assert names(text) == []


def test_a_signoff_announces_a_name_on_the_next_line():
    assert names("Many thanks\nRegards,\nTunde Bakare\nOperations Manager") == ["Tunde Bakare"]
    assert names("Best,\nSupport Team") == []
    assert names("Regards\nthe team") == []


def test_a_label_announces_a_name_but_not_the_next_line():
    text = "Name: Lucía Fernández Ortega\nEmployer: Microsoft"
    assert names(text) == ["Lucía Fernández Ortega"]
    assert names("Patient: Mrs Imogen Featherstone-Hale, seen") == ["Imogen Featherstone-Hale"]
    assert names("Witness statement of Eilidh MacAskill, taken in Inverness") == ["Eilidh MacAskill"]


def test_labels_that_are_often_places_need_two_words():
    assert names("From: London Office <ops@example.com>") == []     # Office is not a name
    assert names("From: Beatrix Holloway <b@example.org>") == ["Beatrix Holloway"]
    assert names("To: London") == []


def test_a_list_after_a_label_gives_each_name():
    text = "Attendees: Brigid O'Donnell, Hamza Rahman and Tomasz Wiśniewski."
    assert names(text) == ["Brigid O'Donnell", "Hamza Rahman", "Tomasz Wiśniewski"]
    assert names("Cc: Henrik Lindqvist; Bcc: Rosalind Appiah") == ["Henrik Lindqvist", "Rosalind Appiah"]


@pytest.mark.parametrize("text,expected", [
    ("Please forward to Yusuf Demir, who handles it", ["Yusuf Demir"]),
    ("Call Ravi Shankar on 07700 900456", ["Ravi Shankar"]),
    ("Ask Delphine Marchetti about the contract", ["Delphine Marchetti"]),
    ("The report was written by Aiko Tanaka", ["Aiko Tanaka"]),
    ("Our new hire Marguerite Thibault starts Monday", ["Marguerite Thibault"]),
])
def test_a_verb_that_introduces_a_person(text, expected):
    assert names(text) == expected


@pytest.mark.parametrize("text", [
    "Please send it to Heathrow Airport by Tuesday", "We shipped to New York and from Los Angeles",
    "Spoke with Royal Mail about the delivery", "Call Monday Morning meeting", "call Gillian",
    "Invoice to Hartwell Ltd", "Meet at Downing Street", "from North London", "for Marks Spencer Group",
])
def test_the_weaker_cues_do_not_fire_on_places_firms_days_or_one_word(text):
    assert names(text) == []


def test_the_language_models_place_tags_veto_the_weak_cues():
    text = "We moved to Milton Keynes last year"
    place = SimpleNamespace(label_="GPE", start_char=text.index("Milton"), end_char=text.index(" last"))
    assert names(text) == ["Milton Keynes"]
    assert names(text, SimpleNamespace(entities=[place])) == []
    org = SimpleNamespace(label_="ORG", start_char=text.index("Milton"), end_char=text.index(" last"))
    assert names(text, SimpleNamespace(entities=[org])) == ["Milton Keynes"]   # unfamiliar names are often called ORG


def test_the_place_veto_understands_the_labels_the_detector_really_passes():
    # Presidio hands the recogniser LOCATION, not spaCy's GPE. Before this was checked, a weak cue plus
    # an unfamiliar place ("Ann Arbor") was redacted as a person.
    text = "We drove to Ann Arbor yesterday"
    place = SimpleNamespace(label_="LOCATION", start_char=text.index("Ann"), end_char=text.index(" yesterday"))
    assert names(text) == ["Ann Arbor"]
    assert names(text, SimpleNamespace(entities=[place])) == []


# ── names in capital letters ──────────────────────────────────────────────────

@pytest.mark.parametrize("text,expected", [
    ("Dear LYNN STEPHENS,", ["LYNN STEPHENS"]),
    ("Patient: AMY GUINEVAN", ["AMY GUINEVAN"]),
    ("Signed: JEREMIAH RICHARDS\nthanks", ["JEREMIAH RICHARDS"]),
    ("Assigned to VICTOIRE MENARD.", ["VICTOIRE MENARD"]),
    ("Spoke to BRIAN AUSTIN about the renewal", ["BRIAN AUSTIN"]),
    ("Please forward this to HARSHIL KRISHNA.", ["HARSHIL KRISHNA"]),
    ("Dr SMITH will see you", ["SMITH"]),
    ("Name: MARÍA PETERSSON", ["MARÍA PETERSSON"]),
])
def test_a_name_in_capitals_is_found_after_a_cue(text, expected):
    assert names(text) == expected


@pytest.mark.parametrize("text", [
    "FOR MORE INFORMATION CONTACT SALES TEAM",       # a shouted sentence, cue in capitals
    "PLEASE SEND TO JOHN SMITH TOMORROW",            # likewise: a capitals sentence is not read as names
    "Send this to IT SUPPORT today",                 # SUPPORT is a role word
    "contact HR DEPARTMENT for details",
    "Meeting with ACME CORP",
    "Assigned to NEW YORK OFFICE",
    "from UNITED KINGDOM to GERMANY",
    "See ACCOUNTS PAYABLE for refunds",
    "Call Jo AB",                                     # two-letter words are not names
])
def test_capitals_that_are_not_names_are_left_alone(text):
    assert names(text) == []


def test_a_name_in_capitals_that_the_model_calls_an_organisation_is_refused():
    text = "Call NASA ESA for details"
    org = SimpleNamespace(label_="ORGANIZATION", start_char=text.index("NASA"), end_char=text.index(" for"))
    assert names(text, SimpleNamespace(entities=[org])) == []
    assert names(text) == ["NASA ESA"]   # without the model's opinion the rule alone cannot tell


# ── "Surname, Given" ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("text,expected", [
    ("Name: Klotz, Katrin", ["Klotz, Katrin"]),
    ("Patient: Graf, Emilia", ["Graf, Emilia"]),
    ("Dear Smith, Nathan,", ["Smith, Nathan"]),
    ("Spoke to Behl, Chandani about the renewal.", ["Behl, Chandani"]),
    ("Reference requested for Holmberg, Olle.", ["Holmberg, Olle"]),
    ("Dear van Wickerode, Pien,", ["van Wickerode, Pien"]),
    ("Gour, Vrinda joined the team in March", ["Gour, Vrinda"]),
    ("Signed: Étienne, Édith Login from", ["Étienne, Édith"]),
])
def test_surname_first_names_are_found_after_a_cue(text, expected):
    assert [n for n in names(text) if "," in n] == expected


@pytest.mark.parametrize("text", [
    "Hi Anna, Thanks for the update.",
    "Hi Anna, Meeting notes attached.",
    "Tuesday, March 3rd",
    "Hello, World",
    "Dear Sir, Madam,",
    "Thanks, Bob",
    "Reference: the Smith, Jones agreement is ready",
])
def test_a_comma_between_two_capitalised_words_is_not_always_a_name(text):
    for n in names(text):
        assert "," not in n, n


def test_cities_with_their_country_are_not_surname_first_names():
    text = "Please forward to Paris, France."
    ents = [SimpleNamespace(label_="LOCATION", start_char=text.index("Paris"), end_char=text.index("."))]
    assert names(text, SimpleNamespace(entities=ents)) == []


@pytest.mark.parametrize("text,expected", [
    ("Could Anna Berg please confirm the booking?", ["Anna Berg"]),
    ("Could JENNIFER LEWIS please confirm", ["JENNIFER LEWIS"]),
    ("Cc'd Ladli Tata on the thread.", ["Ladli Tata"]),
    ("Minutes taken by Alfio Rismondo.", ["Alfio Rismondo"]),
    ("CV attached for Maria Lopez.", ["Maria Lopez"]),
    ("Lunch with Johann, Giesela on Thursday", ["Johann, Giesela"]),
    ("Please welcome Devery, Niall to the team.", ["Devery, Niall"]),
    ("Spoke to Brian Austin The deadline is Friday", ["Brian Austin"]),   # the next sentence's first word is not part of the name
])
def test_everyday_phrasings_announce_a_name(text, expected):
    assert [n for n in names(text) if n] == expected


@pytest.mark.parametrize("text", [
    "Could you please confirm", "Could New York please confirm?", "Cc'd the team", "Lunch with the team",
    "Can Support please look at it", "Would Finance please approve",
])
def test_those_phrasings_do_not_fire_on_pronouns_places_or_departments(text):
    assert names(text) == []


def test_only_the_name_is_marked_not_the_cue():
    r = rule.analyze("Dear Ms Jane Testington,", ["PERSON"], None)[0]
    assert "Dear Ms Jane Testington,"[r.start:r.end] == "Jane Testington"
    assert r.score >= 0.6


# ── the two steps in the detector ─────────────────────────────────────────────

def person(start, end, score=0.8):
    return RecognizerResult(entity_type="PERSON", start=start, end=end, score=score)


def test_overlapping_person_results_become_one_name():
    other = RecognizerResult(entity_type="EMAIL_ADDRESS", start=50, end=60, score=1.0)
    merged = _merge_person_spans([person(0, 5, 0.7), person(3, 12, 0.9), person(20, 25), other])
    spans = sorted((r.start, r.end) for r in merged if r.entity_type == "PERSON")
    assert spans == [(0, 12), (20, 25)]
    assert [r.score for r in merged if r.start == 0] == [0.9]
    assert other in merged


def test_a_name_is_cut_at_the_line_break():
    text = "Name: Lucía Fernández Ortega\nEmployer: Microsoft"
    cut = _cut_names_at_line_end(text, [person(6, text.index("Employer") + 8)])
    assert [text[r.start:r.end] for r in cut] == ["Lucía Fernández Ortega"]
    assert _cut_names_at_line_end("\nabc", [person(0, 4)]) == []
    assert _cut_names_at_line_end("abc", [person(0, 3)])[0].end == 3


def test_the_detector_uses_the_rule_whatever_model_is_installed():
    det = PIIDetectorV2(confidence_threshold=0.6)
    out = det.detect("Test letter\nDear Ms Jane Testington,\nYour appointment is booked.").redacted_text
    assert "Testington" not in out and "Jane" not in out
    out = det.detect("Name: Lucía Fernández Ortega\nEmployer: Microsoft").redacted_text
    assert "Fernández" not in out and "Employer: Microsoft" in out


def test_health_says_which_language_model_is_in_use():
    from fastapi.testclient import TestClient
    from api.proxy_v2 import app
    body = TestClient(app).get("/health").json()
    assert body["detector"]["spacy_model"] in ("en_core_web_lg", "en_core_web_sm")
