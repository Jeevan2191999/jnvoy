#!/usr/bin/env python3
"""
Re-measures every labelled set and rewrites evaluation/results_large.json, which the accuracy page is
rendered from (scripts/render_independent_accuracy.py). Takes a few minutes: it runs Presidio too.

    python evaluation/refresh_results.py

The "before_fixes" block (what the same sets scored before the rules were changed) is kept from the
existing file. It is history, not something this script can reproduce.
"""
import hashlib
import json
import sys
import time
from importlib.metadata import version
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

import breakdown  # noqa: E402
import compare  # noqa: E402
from run_eval import load_rows  # noqa: E402

SETS = {
    "large": ("large.jsonl", 20261103, "original",
              "The development set. Rule fixes were made by looking at its misses, so its score is optimistic."),
    "large_heldout": ("large_heldout.jsonl", 4242, "original",
                      "Never looked at while fixing rules, but it uses the same sentence wordings as the development set, "
                      "so fixes that match those wordings help it too."),
    "large_fresh": ("large_fresh.jsonl", 9090, "fresh",
                    "Sentence wordings written after the rules were fixed, never used to fix a rule. The figure to trust."),
}


def main():
    path = HERE / "results_large.json"
    old = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    res = {
        "measured": time.strftime("%Y-%m-%d"),
        "versions": {"spacy": version("spacy"), "presidio": version("presidio-analyzer"), "faker": version("faker")
                     if _has("faker") else old.get("versions", {}).get("faker", "")},
        "note": ("Numbers in the larger-test section of the public accuracy page come from this file; "
                 "tests/test_larger_accuracy.py re-measures them and fails if they differ."),
        "sets": {},
    }
    try:
        import spacy
        res["versions"]["spacy_models"] = spacy.load("en_core_web_lg").meta["version"]
    except Exception:
        res["versions"]["spacy_models"] = old.get("versions", {}).get("spacy_models", "")
    for key, (fname, seed, phrasing, role) in SETS.items():
        f = HERE / fname
        rows = load_rows(f)
        entry = {"file": f"evaluation/{fname}", "seed": seed, "phrasing": phrasing, "md5": hashlib.md5(f.read_bytes()).hexdigest(),
                 "role": role}
        entry["en_core_web_lg"] = compare.run(rows, small=False, presidio=True, out=lambda *_: None)
        if key == "large":
            entry["breakdown_en_core_web_lg"] = breakdown.compute(rows, compare.jnvoy_system())
        if key == "large_fresh":
            entry["breakdown_en_core_web_lg"] = breakdown.compute(rows, compare.jnvoy_system())
        res["sets"][key] = entry
        print("measured", key)
    # The small model, which the hosted service runs. Each run is its own process: the detector keeps the
    # language model it first loaded, so switching models inside one process would measure the large one twice.
    import subprocess
    import tempfile
    for key in ("large", "large_fresh"):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "sm.json"
            subprocess.run([sys.executable, str(HERE / "compare.py"), "--dataset", str(HERE / SETS[key][0]),
                            "--small-model", "--no-presidio", "--json", str(out)],
                           check=True, capture_output=True, timeout=1800)
            res["sets"][key]["en_core_web_sm"] = json.loads(out.read_text(encoding="utf-8"))
        print("measured", key, "with the small model")
    if "before_fixes" in old:
        res["before_fixes"] = old["before_fixes"]
    path.write_text(json.dumps(res, indent=1, ensure_ascii=False), encoding="utf-8")
    print("wrote", path)


def _has(mod):
    try:
        version(mod)
        return True
    except Exception:
        return False


if __name__ == "__main__":
    main()
