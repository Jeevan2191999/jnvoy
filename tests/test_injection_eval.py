"""
The prompt-injection measurement (evaluation/injection_eval.py). The hand-written cases are re-measured on every
run, because the detector is plain regular expressions and needs no model. The public sets are not stored, so
their numbers are re-measured only when they have been fetched (`python evaluation/injection_eval.py --fetch`).
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "evaluation"))

import injection_eval as ie  # noqa: E402
from core.injection import INJECTION_PATTERNS  # noqa: E402

RESULTS = json.loads((ROOT / "evaluation" / "results_injection.json").read_text(encoding="utf-8"))
PAGE = (ROOT / "static" / "accuracy.html").read_text(encoding="utf-8")
HOME = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
HW, PUB = RESULTS["handwritten"], RESULTS["public"]


def _section():
    return PAGE.split('<section id="injection">')[1].split("</section>")[0]


def _n(k, n):
    return f"{k:,} of {n:,}"


def test_the_data_file_is_what_the_generator_makes():
    stored = [json.loads(x) for x in (ROOT / "evaluation" / "injection_handwritten.jsonl").read_text(encoding="utf-8").splitlines()]
    assert stored == ie.build_rows()
    assert len(stored) == RESULTS["handwritten_rows"]


def test_the_hand_written_results_still_come_out_of_the_code():
    assert ie.measure_handwritten() == HW


def test_the_page_numbers_are_the_stored_numbers():
    sec = _section()
    assert f"{len(INJECTION_PATTERNS)} fixed phrase patterns" in sec
    j, t = PUB["jailbreak_all"], PUB["jailbreak_test"]
    assert f"{j['blocked']} blocked ({100 * j['blocked'] / j['n']:.1f}%" in sec
    assert _n(t["blocked"], t["n"]) in sec and f"({100 * t['blocked'] / t['n']:.1f}%" in sec
    f = HW["by_form"]
    for form in ("canonical", "canonical_in_document", "paraphrase", "paraphrase_in_document", "other_language",
                 "obfuscated", "split_across_messages"):
        assert _n(f[form]["blocked"], f[form]["n"]).replace(",", "") in sec.replace(",", ""), form
    a, r = PUB["alpaca"], PUB["regular_all"]
    assert _n(a["blocked"], a["n"]) in sec
    assert _n(r["blocked"], r["n"]) in sec and f"{r['blocked_only_by_instruction_override']} of them only" in sec
    s = RESULTS["hand_read_sample"]
    assert f"{s['jailbreaks']} were DAN-style" in sec and f"{s['ordinary']} were ordinary" in sec and s["n"] == 40
    h = HW["harmless"]
    assert f"{h['blocked']} of {h['n']} were blocked" in sec
    m = PUB["mcp_descriptions"]
    assert f"0 of {m['real_benign']['n']} descriptions" in sec and m["real_benign"]["blocked"] == 0
    assert f"{m['poisoned']['canonical']['blocked']} of {m['poisoned']['canonical']['n']} blocked" in sec
    assert f"{m['poisoned']['paraphrase']['blocked']} of {m['poisoned']['paraphrase']['n']} reworded" in sec


def test_the_page_says_what_it_is_and_is_not():
    sec = _section()
    for phrase in ("tripwire", "do not rely on it for an agent", "The check is off by default", "A customer can turn the check on in their settings", "About four in five real jailbreak prompts get through",
                   "We have not compared Jnvoy with any"):
        assert phrase in sec, phrase


def test_the_stated_misses_are_misses():
    f = HW["by_form"]
    assert f["paraphrase"]["blocked"] == f["other_language"]["blocked"] == f["obfuscated"]["blocked"] == 0
    assert f["split_across_messages"]["blocked"] == 0
    assert HW["by_category"]["obfuscation"]["blocked"] == 0         # noticed, never blocked: those rules are "medium"


def test_the_public_claim_is_narrow():
    assert "blocks prompt injection." not in HOME                # the old, unmeasured wording
    assert "31 well-known injection and jailbreak phrases" in HOME
    assert "Off by default." in HOME
    assert "tripwire, not a defence" in HOME


def _fetched():
    return ie.have_public()


@pytest.mark.skipif(not _fetched(), reason="the public sets are fetched on request: python evaluation/injection_eval.py --fetch")
def test_the_public_numbers_still_come_out_of_the_data():
    assert ie.measure_public() == PUB
