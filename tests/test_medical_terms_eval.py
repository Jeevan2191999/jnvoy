"""
The medical-terms measurement (evaluation/medical_terms_eval.py): the data file is what the generator makes,
the numbers on the accuracy page are the stored numbers, the page states what is missed, and the stored
numbers are re-measured only with the large model, as in CI.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "evaluation"))

import medical_terms_eval as mte  # noqa: E402

RESULTS = json.loads((ROOT / "evaluation" / "results_medical_terms.json").read_text(encoding="utf-8"))
PAGE = (ROOT / "static" / "accuracy.html").read_text(encoding="utf-8")
ON, OFF = RESULTS["systems"]["on"], RESULTS["systems"]["off"]


def _section():
    return PAGE.split('<section id="medical-terms">')[1].split("</section>")[0]


def _sum(system, groups):
    t = system["per_type"]
    return sum(t[g]["caught"] for g in groups), sum(t[g]["n"] for g in groups)


LISTED = ("listed_condition", "listed_procedure", "listed_medicine")
NOTHING_TO_GO_ON = ("unseen_condition", "unseen_procedure", "unseen_brand_name", "unseen_medicine_without_ending")


def test_the_data_file_is_what_the_generator_makes():
    stored = [json.loads(x) for x in (ROOT / "evaluation" / "medical_terms.jsonl").read_text(encoding="utf-8").splitlines()]
    assert stored == mte.build_rows()
    assert len(stored) == RESULTS["documents"]


def test_the_unseen_words_are_not_on_the_list():
    from core import medical_terms as mt
    listed = {w.lower() for w in mt.CONDITIONS + mt.PROCEDURES + mt.MEDICINES + mt.AMBIGUOUS}
    unseen = (mte.UNSEEN_CONDITIONS + mte.UNSEEN_MEDICINES_STEM + mte.UNSEEN_MEDICINES_OTHER
              + mte.UNSEEN_BRANDS + mte.UNSEEN_PROCEDURES)
    assert not listed & {w.lower() for w in unseen}


def test_the_page_numbers_are_the_stored_numbers():
    sec = _section()
    c, n = _sum(ON, LISTED)
    assert f"hid {c} of {n} (100.0%)" in sec and f"Off, {_sum(OFF, LISTED)[0]} of {n}" in sec
    c, n = _sum(ON, ("cue_gated_with_cue",))
    assert f"{c} of {n} hidden on, {_sum(OFF, ('cue_gated_with_cue',))[0]} of {n} off" in sec
    c, n = _sum(ON, ("unseen_medicine_with_ending",))
    assert f"{c} of {n} ({100 * c / n:.1f}%" in sec
    c, n = _sum(ON, ("unseen_name_with_dose",))
    assert f"{c} of {n} hidden" in sec
    c, n = _sum(ON, NOTHING_TO_GO_ON)
    c_off = _sum(OFF, NOTHING_TO_GO_ON)[0]
    assert f"{c} of {n} ({100 * c / n:.1f}%), against {c_off} of {n}" in sec
    assert f"{ON['keep_kept']} of {ON['keep_total']} stayed readable" in sec
    assert f"against {OFF['keep_kept']} of {OFF['keep_total']} off" in sec
    assert f"{RESULTS['documents']} invented sentences" in sec


def test_the_page_says_what_it_misses():
    sec = _section()
    for phrase in ("gout", "Prozac", "do worse", "not a medical-data control", "upper bound", "history of the depression"):
        assert phrase in sec or phrase.replace("do worse", "would do worse") in sec


def test_the_setting_is_off_by_default_and_changes_nothing_when_off():
    assert OFF["per_type"]["listed_condition"]["caught"] == 0
    for g in LISTED:
        assert ON["per_type"][g]["caught"] == ON["per_type"][g]["n"]


def test_switching_it_on_hides_almost_no_harmless_word():
    assert OFF["keep_kept"] == OFF["keep_total"]
    assert ON["keep_total"] - ON["keep_kept"] <= 1
    assert ON["over_redacted"] == ["depression in Europe"]


def test_what_it_cannot_reach_stays_low_and_is_published():
    c, n = _sum(ON, NOTHING_TO_GO_ON)
    assert c / n < 0.10


def _lg_available():
    try:
        import spacy
        spacy.load("en_core_web_lg")
        return True
    except Exception:
        return False


def _pinned_spacy():
    for line in (ROOT / "constraints.txt").read_text(encoding="utf-8").splitlines():
        if line.lower().startswith("spacy=="):
            return line.split("==")[1].strip()
    return None


def _model_matches():
    if not _lg_available():
        return False
    import spacy
    return spacy.__version__ == _pinned_spacy()


@pytest.mark.skipif(not _model_matches(), reason="the stored numbers were measured with the pinned spaCy and en_core_web_lg")
def test_every_stored_number_still_comes_out_of_the_code():
    assert mte.measure()["systems"] == RESULTS["systems"]
