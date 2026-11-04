#!/usr/bin/env python3
"""
Measures the protected-terms setting (policy.protected_terms): names a customer lists, such as client and
project names, are always redacted.

    python evaluation/protected_terms_eval.py            print the result
    python evaluation/protected_terms_eval.py --write    also write evaluation/results_protected_terms.json
                                                         and evaluation/protected_terms.jsonl

What this is, and is not. The setting matches the names a customer lists. So the number that matters is
how many ways a listed name can show up, and which of them it finds. Each document here contains one
name in one form. Forms the setting is built to find ("supported") and forms it is not ("unsupported") are
scored separately and neither is hidden. Names that were never listed are in the set too, because that is
the honest answer to "does it find confidential names by itself?": it does not.

The names are invented. The sentences were written by us, with the matcher in mind, so the supported
forms are a check that the matcher does what it says, not evidence about real documents.
"""
import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

SEED = 20261104

CLIENTS = ["Brightwater Capital", "Northgate Logistics", "Kestrel Dynamics", "Halcyon Foods",
           "Ironbridge Partners", "Quillon Energy", "Tamsin Biotech", "Redfern Holdings",
           "Oakhaven Bank", "Veridian Labs", "Sablewood Insurance", "Cragmoor Shipping"]
PROJECTS = ["Project Falcon", "Project Lantern", "Operation Bluebird", "Atlas Migration",
            "Codename Heron", "Project Nightingale", "Initiative Ember", "Project Cobalt"]
LISTED = CLIENTS + PROJECTS
NOT_LISTED = ["Pelham Retail", "Dunmore Systems", "Project Willow", "Greywell Group"]

# Each template: text with {s} where the name goes, and the harmless words it holds (must stay readable).
TEMPLATES = [
    ("Can you summarise the {s} contract renewal before Friday's call?", ["Friday", "contract renewal"]),
    ("Subject: {s} budget overrun. We are over on the second phase.", ["budget overrun", "second phase"]),
    ("// TODO: remove the hard-coded {s} credentials from the staging config", ["staging config", "TODO"]),
    ("Has anyone heard back from {s} about the rollout timeline?", ["rollout timeline"]),
    ("Meeting notes: {s} wants the report by Monday; legal is still reviewing.", ["Monday", "legal"]),
    ('git commit -m "fix invoice export for {s}"', ["invoice export"]),
    ("TICKET-4821: {s} onboarding is blocked on data room access.", ["TICKET-4821", "data room"]),
    ("Please draft a polite reply to {s} explaining the delay.", ["polite reply", "delay"]),
]

SUPPORTED = ["exact", "lowercase", "uppercase", "hyphenated", "underscored", "joined", "possessive", "in_identifier"]
UNSUPPORTED = ["abbreviation", "plural", "misspelt", "one_word_of_two"]


def _form(term: str, form: str, rng: random.Random) -> str:
    words = term.split()
    if form == "exact":
        return term
    if form == "lowercase":
        return term.lower()
    if form == "uppercase":
        return term.upper()
    if form == "hyphenated":
        return "-".join(words)
    if form == "underscored":
        return "_".join(w.lower() for w in words)
    if form == "joined":
        return "".join(words)
    if form == "possessive":
        return term + "'s"
    if form == "in_identifier":
        return "_".join(w.lower() for w in words)          # used inside get_<name>_report() below
    if form == "abbreviation":
        return "".join(w[0] for w in words).upper()
    if form == "plural":
        return term + "s"
    if form == "misspelt":
        last = list(words[-1])
        i = rng.randrange(1, len(last) - 2)
        last[i], last[i + 1] = last[i + 1], last[i]
        return " ".join(words[:-1] + ["".join(last)])
    if form == "one_word_of_two":
        return words[-1]
    raise ValueError(form)


def build_rows() -> list:
    rng = random.Random(SEED)
    rows, n = [], 0
    for term in LISTED:
        for form in SUPPORTED + UNSUPPORTED:
            tpl, keep = TEMPLATES[n % len(TEMPLATES)]
            surface = _form(term, form, rng)
            text = tpl.format(s=surface)
            if form == "in_identifier":
                text = f"def get_{surface}_report(client_id):  # {keep[0]}"
                keep = [keep[0]]
            rows.append({"id": f"pt{n:04d}", "text": text, "listed": True,
                         "sensitive": [{"value": surface, "type": form}], "keep": keep})
            n += 1
    for term in NOT_LISTED:
        for tpl, keep in TEMPLATES:
            rows.append({"id": f"pt{n:04d}", "text": tpl.format(s=term), "listed": False,
                         "sensitive": [{"value": term, "type": "not_listed"}], "keep": keep})
            n += 1
    return rows


def _systems(model_small: bool = False):
    from core.custom_detector import CustomisedDetector
    from core.custom_rules import validate_protected_terms
    from core.judged_detector import JudgedPIIDetector
    plain = JudgedPIIDetector(judge=None, from_env=False)
    listed = CustomisedDetector(protected_terms=validate_protected_terms(LISTED), judge=None, from_env=False)
    return {"without_list": lambda t: plain.detect(t).redacted_text,
            "with_list": lambda t: listed.detect(t).redacted_text}


def measure() -> dict:
    import compare
    rows = build_rows()
    out = {}
    for name, redact in _systems().items():
        s = compare.score_system(rows, redact)
        out[name] = {"n": s["n"], "caught": s["caught"], "keep_total": s["keep_total"], "keep_kept": s["keep_kept"],
                     "per_form": {k: v for k, v in sorted(s["per_type"].items())}}
        sup = [s["per_type"][f] for f in SUPPORTED]
        uns = [s["per_type"][f] for f in UNSUPPORTED]
        nl = s["per_type"]["not_listed"]
        out[name]["supported"] = {"n": sum(x["n"] for x in sup), "caught": sum(x["caught"] for x in sup)}
        out[name]["unsupported"] = {"n": sum(x["n"] for x in uns), "caught": sum(x["caught"] for x in uns)}
        out[name]["not_listed"] = {"n": nl["n"], "caught": nl["caught"]}
    return {"documents": len(rows), "listed_terms": len(LISTED), "systems": out}


def main():
    import compare
    result = measure()
    model = compare.which_model(False)
    result["model"] = model
    print(f"{result['documents']} documents, {result['listed_terms']} listed terms, spaCy model {model}\n")
    for name, s in result["systems"].items():
        print(f"{name}")
        for group in ("supported", "unsupported", "not_listed"):
            g = s[group]
            lo, hi = compare.wilson(g["caught"], g["n"])
            print(f"  {group:<12}{g['caught']:>4}/{g['n']:<4} {100 * g['caught'] / g['n']:5.1f}%  ({100 * lo:.1f}-{100 * hi:.1f})")
        for form, v in s["per_form"].items():
            print(f"      {form:<16}{v['caught']:>3}/{v['n']}")
        print(f"  harmless words kept {s['keep_kept']}/{s['keep_total']}\n")
    if "--write" in sys.argv:
        (HERE / "protected_terms.jsonl").write_text(
            "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in build_rows()), encoding="utf-8")
        (HERE / "results_protected_terms.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print("written")


if __name__ == "__main__":
    main()
