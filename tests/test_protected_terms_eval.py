"""
The protected-terms measurement (evaluation/protected_terms_eval.py): the data file is what the generator
makes, the numbers on the accuracy page are the stored numbers, and the supported forms still come out of
the code. The rest is re-measured only with the large model, as in CI, because what the ordinary name
detector happens to catch depends on the model.
"""
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "evaluation"))

import protected_terms_eval as pte  # noqa: E402

RESULTS = json.loads((ROOT / "evaluation" / "results_protected_terms.json").read_text(encoding="utf-8"))
PAGE = (ROOT / "static" / "accuracy.html").read_text(encoding="utf-8")


def _section():
    return PAGE.split('<section id="protected-terms">')[1].split("</section>")[0]


def test_the_data_file_is_what_the_generator_makes():
    stored = [json.loads(x) for x in (ROOT / "evaluation" / "protected_terms.jsonl").read_text(encoding="utf-8").splitlines()]
    assert stored == pte.build_rows()
    assert len(stored) == RESULTS["documents"]


def test_the_set_holds_supported_unsupported_and_unlisted_names():
    forms = {r["sensitive"][0]["type"] for r in pte.build_rows()}
    assert forms == set(pte.SUPPORTED) | set(pte.UNSUPPORTED) | {"not_listed"}
    assert not set(pte.NOT_LISTED) & set(pte.LISTED)


def test_a_template_does_not_hold_a_word_from_a_listed_name():
    words = {w.lower() for t in pte.LISTED for w in t.split()}
    for tpl, keep in pte.TEMPLATES:
        for k in keep:
            assert not words & {w.lower().strip(".,") for w in k.split()}, (tpl, k)


def test_the_page_numbers_are_the_stored_numbers():
    sec = _section()
    w, wo = RESULTS["systems"]["with_list"], RESULTS["systems"]["without_list"]
    assert f"hid {w['supported']['caught']} of {w['supported']['n']}" in sec
    assert f"hid {wo['supported']['caught']} of {wo['supported']['n']}" in sec
    assert f"{w['unsupported']['caught']} of {w['unsupported']['n']}" in sec
    assert f"{w['not_listed']['caught']} of {w['not_listed']['n']}" in sec
    assert f"{w['keep_kept']} of {w['keep_total']}" in sec


def test_the_page_says_what_the_setting_does_not_find():
    sec = _section()
    for phrase in ("initials", "plurals", "misspelling", "never listed", "A name you forget to list is not protected"):
        assert phrase in sec


def test_the_unsupported_forms_gain_nothing_from_the_list():
    s = RESULTS["systems"]
    assert s["with_list"]["unsupported"] == s["without_list"]["unsupported"]
    assert s["with_list"]["not_listed"] == s["without_list"]["not_listed"]


def test_the_list_does_not_hide_harmless_words():
    s = RESULTS["systems"]
    assert s["with_list"]["keep_kept"] == s["without_list"]["keep_kept"] == s["with_list"]["keep_total"]


def test_the_supported_forms_are_all_hidden_by_the_code():
    # independent of the spaCy model: protected spans are chosen before anything else
    measured = pte.measure()["systems"]["with_list"]
    assert measured["supported"]["caught"] == measured["supported"]["n"] == RESULTS["systems"]["with_list"]["supported"]["n"]
    assert measured["keep_kept"] == measured["keep_total"]


def _pinned_spacy():
    import re
    m = re.search(r"^spacy==(\S+)", (ROOT / "constraints.txt").read_text(encoding="utf-8"), re.M)
    return m.group(1) if m else None


def _lg_available():
    try:
        import spacy
        spacy.load("en_core_web_lg")
        return spacy.__version__ == _pinned_spacy()
    except Exception:
        return False


@pytest.mark.skipif(not _lg_available(), reason="measured with the pinned spaCy and en_core_web_lg; not available here")
def test_every_stored_number_still_comes_out_of_the_code():
    assert pte.measure()["systems"] == RESULTS["systems"]
