#!/usr/bin/env python3
"""
Measures the opt-in medical-term detection (entity MEDICAL_TERM, policy redact_extra "medical_term").

    python evaluation/medical_terms_eval.py            print the result
    python evaluation/medical_terms_eval.py --write    also write medical_terms.jsonl and results_medical_terms.json

The question this answers is not "does it find the words on its list". It will, and that proves little. The
questions are:
  1. How much of medical vocabulary that is NOT on its list does it find? (held-out conditions, medicines,
     brand names and procedures, written separately from the list, plus medicines with a dose beside them)
  2. Does it hide everyday words used in their ordinary sense? ("a cold call", "the depression of 1929")
  3. Do the cue-gated words (cancer, depression, stroke ...) stay readable without a clinical cue?

The held-out words were written by the same person, in the same sitting, as the list, and the medicine-name
endings were chosen knowing common medicines. So the held-out result is better than a stranger's vocabulary
would get. Treat it as an upper bound.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

UNSEEN_CONDITIONS = [
    "gout", "lupus", "fibromyalgia", "sciatica", "tinnitus", "vertigo", "rosacea", "shingles", "glandular fever",
    "appendicitis", "cirrhosis", "pancreatitis", "scoliosis", "carpal tunnel syndrome", "restless legs syndrome",
    "narcolepsy", "hypoglycaemia", "thrombosis", "sepsis", "meningitis", "measles", "malaria", "endocarditis",
    "gallstones", "diverticulitis", "hepatitis c", "cholesterol", "tonsillitis", "pleurisy", "urticaria",
    "osteoarthritis", "emphysema", "hyperlipidaemia", "dyslexia", "autism",
]
# Medicines whose names end like a medicine (the endings rule can reach them).
UNSEEN_MEDICINES_STEM = [
    "ramipril", "bisoprolol", "rosuvastatin", "pravastatin", "losartan", "candesartan", "atenolol", "metoprolol",
    "esomeprazole", "pantoprazole", "clarithromycin", "azithromycin", "flucloxacillin", "doxycycline",
    "fluconazole", "aciclovir", "levetiracetam", "olanzapine", "mirtazapine", "escitalopram", "lorazepam",
    "sumatriptan", "montelukast", "ranitidine", "rivaroxaban", "enoxaparin", "sitagliptin", "empagliflozin",
    "semaglutide", "anastrozole", "imatinib", "cisplatin", "venlafaxine",
]
# Medicines the endings rule cannot reach.
UNSEEN_MEDICINES_OTHER = [
    "clopidogrel", "lamotrigine", "carbamazepine", "quetiapine", "risperidone", "zopiclone", "naproxen",
    "diclofenac", "hydroxychloroquine", "tamoxifen", "methylphenidate", "fexofenadine", "domperidone",
    "furosemide", "spironolactone", "digoxin", "amiodarone", "oxycodone", "fentanyl", "buprenorphine",
    "naloxone", "gliclazide", "bumetanide", "tacrolimus",
]
UNSEEN_BRANDS = ["Prozac", "Ventolin", "Lipitor", "Zoloft", "Nurofen", "Calpol", "Xanax", "Ozempic", "Viagra", "Panadol"]
UNSEEN_PROCEDURES = ["appendectomy", "tonsillectomy", "endoscopy", "hysterectomy", "laparoscopy", "cystoscopy",
                     "angiogram", "skin graft"]

CUE_PHRASES = [
    "She was diagnosed with {t}.", "He has a history of {t}.", "Treated for {t} last spring.",
    "Her mother died of {t}.", "He is living with {t}.",
]
EVERYDAY = [   # (sentence, words that must stay readable)
    ("A cold call about a stroke of luck.", ["cold call", "stroke of luck"]),
    ("The depression of 1929 changed the economy.", ["depression of 1929"]),
    ("My cancer horoscope says to rest.", ["cancer horoscope"]),
    ("Anxiety about the deadline grew all week.", ["Anxiety about the deadline"]),
    ("The pregnancy of the project was long.", ["pregnancy of the project"]),
    ("Take 2 tablets 500 mg after food.", ["tablets"]),
    ("Heart disease charities raised money this year.", ["Heart disease charities"]),
    ("The flu season story ran on page two.", ["flu season story"]),
    ("An injury report was filed by the venue.", ["injury report"]),
    ("A fracture in the plan became obvious.", ["fracture in the plan"]),
    ("Addiction to caffeine is a common joke.", ["Addiction to caffeine"]),
    ("An infection of the build server stopped the release.", ["infection of the build server"]),
    ("Insomnia Cookies opened a shop nearby.", ["Insomnia Cookies"]),
    ("Meet in April at the Alpine lodge in Capri.", ["April", "Alpine", "Capri"]),
    ("The Platinum plan includes the program review.", ["Platinum", "program review"]),
    ("The cancer of corruption spread through the firm.", ["corruption spread"]),
    ("The stroke of midnight ended the party.", ["stroke of midnight"]),
    ("The injury time goal came in the 92nd minute.", ["injury time goal"]),
    ("The flu jab queue was short at the shop.", ["flu jab queue"]),
    ("The bypass road opened to traffic last week.", ["bypass road"]),
    # A clinical cue followed by an everyday use. This is a known false positive (a cue is all the rule has):
    ("She wrote a history of the depression in Europe.", ["depression in Europe"]),
]


def build_rows() -> list:
    from core import medical_terms as mt
    rows, n = [], 0

    def add(text, sensitive, keep=()):
        nonlocal n
        rows.append({"id": f"mt{n:04d}", "text": text, "sensitive": sensitive, "keep": list(keep)})
        n += 1

    plain = ["Her notes say she has {t}.", "He told the team about his {t}.", "Notes: patient reports {t} since June.",
             "The file mentions {t} and a follow-up in March.", "Please summarise the {t} case before Friday."]
    plain_med = ["He was prescribed {t} last month.", "She takes {t} every morning.", "Notes: started {t} in May.",
                 "The chart lists {t} and a review in March.", "Please check the {t} supply before Friday."]
    for group, words, templates in (
        ("listed_condition", mt.CONDITIONS, plain), ("listed_procedure", mt.PROCEDURES, plain),
        ("listed_medicine", mt.MEDICINES, plain_med),
        ("unseen_condition", UNSEEN_CONDITIONS, plain), ("unseen_procedure", UNSEEN_PROCEDURES, plain),
        ("unseen_medicine_with_ending", UNSEEN_MEDICINES_STEM, plain_med),
        ("unseen_medicine_without_ending", UNSEEN_MEDICINES_OTHER, plain_med),
        ("unseen_brand_name", UNSEEN_BRANDS, plain_med),
    ):
        for i, w in enumerate(words):
            add(templates[i % len(templates)].format(t=w), [{"value": w, "type": group}], ["Friday"] if "Friday" in templates[i % len(templates)] else [])
    for i, w in enumerate(mt.AMBIGUOUS):
        add(CUE_PHRASES[i % len(CUE_PHRASES)].format(t=w), [{"value": w, "type": "cue_gated_with_cue"}])
    for i, w in enumerate(UNSEEN_MEDICINES_OTHER[:12] + UNSEEN_BRANDS[:6]):
        add(f"He takes {w} {[5, 10, 20, 40, 100][i % 5]} mg daily.", [{"value": w, "type": "unseen_name_with_dose"}], ["daily"])
    for text, keep in EVERYDAY:
        add(text, [], keep)
    return rows


def _systems():
    from core.detector_v2 import resolve_entities
    from core.judged_detector import JudgedPIIDetector
    off = JudgedPIIDetector(judge=None, from_env=False)
    on = JudgedPIIDetector(judge=None, from_env=False,
                           entities=resolve_entities(env={"JNVOY_REDACT_EXTRA": "MEDICAL_TERM"}))
    return {"off": lambda t: off.detect(t).redacted_text, "on": lambda t: on.detect(t).redacted_text}


def measure() -> dict:
    import compare
    rows = build_rows()
    out = {}
    for name, redact in _systems().items():
        s = compare.score_system(rows, redact)
        out[name] = {"n": s["n"], "caught": s["caught"], "keep_total": s["keep_total"], "keep_kept": s["keep_kept"],
                     "per_type": {k: v for k, v in sorted(s["per_type"].items())},
                     "over_redacted": sorted({o["value"] for o in s["over"]})}
    return {"documents": len(rows), "systems": out}


def main():
    import compare
    result = measure()
    result["model"] = compare.which_model(False)
    print(f"{result['documents']} documents, spaCy model {result['model']}\n")
    for name, s in result["systems"].items():
        print(name)
        for k, v in s["per_type"].items():
            lo, hi = compare.wilson(v["caught"], v["n"])
            print(f"   {k:<34}{v['caught']:>3}/{v['n']:<3} {100 * v['caught'] / v['n']:5.1f}%  ({100 * lo:.0f}-{100 * hi:.0f})")
        print(f"   harmless words kept {s['keep_kept']}/{s['keep_total']}  over-redacted: {s['over_redacted']}\n")
    if "--write" in sys.argv:
        (HERE / "medical_terms.jsonl").write_text(
            "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in build_rows()), encoding="utf-8")
        (HERE / "results_medical_terms.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print("written")


if __name__ == "__main__":
    main()
