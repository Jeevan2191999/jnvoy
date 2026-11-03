#!/usr/bin/env python3
"""
Scores Jnvoy against plain Presidio on the same labelled text, with confidence intervals.

    python evaluation/compare.py                              the 1,000-document set (large.jsonl)
    python evaluation/compare.py --small-model                with en_core_web_sm, which the hosted service runs
    python evaluation/compare.py --dataset my.jsonl           any file in the same format (see check_my_data.py)
    python evaluation/compare.py --no-presidio                Jnvoy only
    python evaluation/compare.py --misses                     list what each system leaked
    python evaluation/compare.py --json out.json              full results as JSON

What is measured
  CAUGHT  share of sensitive values that no longer appear in the redacted text. A value counts as
          leaked if the whole value, or any recognisable part of it (a surname, the last digits of
          a number), is still visible. This is the same rule as run_eval.py.
  KEPT    share of harmless words (companies, places, amounts, ticket numbers) left readable.
  Every share comes with a 95% Wilson interval. With few values the interval is wide: believe it.

Two Presidio baselines, both Microsoft Presidio's analyzer with its built-in recognisers and the
same spaCy model as Jnvoy for that run, with every detected span replaced:
  presidio    default settings: it looks for every entity type it knows, including dates and places.
              This is what a team gets by adding Presidio themselves, and it hides a lot of harmless text.
  presidio_tuned  the same with dates, places and nationalities switched off (the noisy types Jnvoy
              also leaves readable), which is what a careful team would do. It then cannot see a birth
              date at all, because Presidio's only date type is DATE_TIME.
Neither is any particular product's configuration, and neither has recognisers written for this data.

Limits. The large set is synthetic: values come from the Faker library, the sentences around them
were written by us. Treat the result as a regression gauge, not a certified accuracy figure. The
number that matters is the one you get on your own text: see check_my_data.py.
"""

import argparse
import json
import math
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from run_eval import leaked, load_rows  # noqa: E402  (same leak rule as the older script)

LARGE = Path(__file__).resolve().parent / "large.jsonl"


# ---- statistics ---------------------------------------------------------------------------

def wilson(k: int, n: int, z: float = 1.96):
    """95% Wilson score interval for k successes in n trials, as (low, high) fractions."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def mcnemar_exact(only_a: int, only_b: int) -> float:
    """Two-sided exact p-value that two systems differ, from the values only one of them caught."""
    n = only_a + only_b
    if n == 0:
        return 1.0
    k = min(only_a, only_b)
    tail = sum(math.comb(n, i) for i in range(0, k + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def fmt(k: int, n: int) -> str:
    if n == 0:
        return "n/a"
    lo, hi = wilson(k, n)
    return f"{100 * k / n:5.1f}% ({100 * lo:.1f}-{100 * hi:.1f})"


# ---- systems ------------------------------------------------------------------------------

def use_small_model():
    import spacy
    real = spacy.load

    def load(name, *a, **k):
        if name == "en_core_web_lg":
            raise OSError("large model switched off by --small-model")
        return real(name, *a, **k)
    spacy.load = load


def jnvoy_system():
    from core.judged_detector import JudgedPIIDetector
    det = JudgedPIIDetector(judge=None, from_env=False)
    return lambda text: det.detect(text).redacted_text


NOISY = {"DATE_TIME", "LOCATION", "NRP"}   # entity types Jnvoy leaves readable by default


def presidio_system(model_name: str, tuned: bool = False):
    """tuned=False: Presidio's defaults (every entity it knows). tuned=True: the same, with the noisy
    types Jnvoy also leaves off (dates, places, nationalities) switched off, which is what a careful
    team would do. Note that Presidio has no birth-date recogniser: its only date type is DATE_TIME."""
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    from presidio_anonymizer import AnonymizerEngine
    nlp = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy", "models": [{"lang_code": "en", "model_name": model_name}],
    }).create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp, supported_languages=["en"])
    anonymizer = AnonymizerEngine()
    entities = None
    if tuned:
        entities = [e for e in analyzer.get_supported_entities("en") if e not in NOISY]

    def run(text):
        found = analyzer.analyze(text=text, language="en", entities=entities)
        return anonymizer.anonymize(text=text, analyzer_results=found).text
    return run


def which_model(small: bool) -> str:
    if small:
        return "en_core_web_sm"
    try:
        import spacy
        spacy.load("en_core_web_lg")
        return "en_core_web_lg"
    except Exception:
        return "en_core_web_sm"


# ---- scoring ------------------------------------------------------------------------------

def score_system(rows, redact):
    t0 = time.perf_counter()
    out = {r["id"]: redact(r["text"]) for r in rows}
    ms = (time.perf_counter() - t0) * 1000 / max(1, len(rows))
    per = defaultdict(lambda: {"n": 0, "caught": 0})
    caught_flags, misses, over = {}, [], []
    keep_total = keep_kept = 0
    for r in rows:
        red = out[r["id"]]
        for i, s in enumerate(r["sensitive"]):
            per[s["type"]]["n"] += 1
            leak = leaked(s["value"], red)
            caught_flags[(r["id"], i)] = not leak
            if leak:
                misses.append({"id": r["id"], "type": s["type"], "value": s["value"], "redacted": red})
            else:
                per[s["type"]]["caught"] += 1
        for k in r["keep"]:
            keep_total += 1
            if k in red:
                keep_kept += 1
            else:
                over.append({"id": r["id"], "value": k, "redacted": red})
    n = sum(v["n"] for v in per.values())
    caught = sum(v["caught"] for v in per.values())
    return {"per_type": dict(per), "n": n, "caught": caught, "keep_total": keep_total,
            "keep_kept": keep_kept, "misses": misses, "over": over, "ms_per_doc": ms,
            "_flags": caught_flags}


def report(rows, systems, show_misses=False, model="", out=print):
    names = list(systems)
    types = sorted({t for s in systems.values() for t in s["per_type"]})
    out(f"\n{len(rows)} documents, {systems[names[0]]['n']} sensitive values, "
        f"{systems[names[0]]['keep_total']} harmless words. spaCy model: {model}")
    out("CAUGHT = share of sensitive values no longer visible (95% interval in brackets)\n")
    w = 26
    out(f"{'type':<12}{'n':>5}  " + "".join(f"{nm:<{w}}" for nm in names))
    out("-" * (19 + w * len(names)))
    for t in types:
        n = systems[names[0]]["per_type"].get(t, {"n": 0})["n"]
        out(f"{t:<12}{n:>5}  " + "".join(
            f"{fmt(systems[nm]['per_type'].get(t, {'caught': 0})['caught'], n):<{w}}" for nm in names))
    out("-" * (19 + w * len(names)))
    out(f"{'ALL':<12}{systems[names[0]]['n']:>5}  " + "".join(
        f"{fmt(systems[nm]['caught'], systems[nm]['n']):<{w}}" for nm in names))
    out("\nHARMLESS WORDS KEPT READABLE (higher is better)")
    for nm in names:
        s = systems[nm]
        out(f"  {nm:<10} {fmt(s['keep_kept'], s['keep_total'])}   over-redacted: {len(s['over'])}")
    out("\nSPEED (first pass, per document)")
    for nm in names:
        out(f"  {nm:<10} {systems[nm]['ms_per_doc']:.0f} ms")
    result = {"documents": len(rows), "model": model, "systems": {}}
    for nm in names:
        s = systems[nm]
        lo, hi = wilson(s["caught"], s["n"])
        klo, khi = wilson(s["keep_kept"], s["keep_total"])
        result["systems"][nm] = {
            "caught": s["caught"], "n": s["n"], "caught_ci95": [round(lo, 4), round(hi, 4)],
            "keep_kept": s["keep_kept"], "keep_total": s["keep_total"], "keep_ci95": [round(klo, 4), round(khi, 4)],
            "ms_per_doc": round(s["ms_per_doc"], 1),
            "per_type": {t: v for t, v in s["per_type"].items()},
        }
    result["head_to_head"] = {}
    for other in names[1:]:
        a, b = names[0], other
        fa, fb = systems[a]["_flags"], systems[b]["_flags"]
        both = sum(1 for k in fa if fa[k] and fb[k])
        only_a = sum(1 for k in fa if fa[k] and not fb[k])
        only_b = sum(1 for k in fa if fb[k] and not fa[k])
        neither = sum(1 for k in fa if not fa[k] and not fb[k])
        p = mcnemar_exact(only_a, only_b)
        out(f"\nHEAD TO HEAD {a} vs {b} on the same {len(fa)} values")
        out(f"  both caught {both}   only {a} {only_a}   only {b} {only_b}   neither {neither}   exact McNemar p = {p:.4f}")
        result["head_to_head"][b] = {"both": both, f"only_{a}": only_a, f"only_{b}": only_b, "neither": neither, "mcnemar_p": round(p, 6)}
    if show_misses:
        for nm in names:
            out(f"\nLEAKED by {nm}:")
            for m in systems[nm]["misses"]:
                out(f"  {m['id']} {m['type']:<9}{m['value']!r}  ->  {m['redacted'][:140]!r}")
    return result


def run(rows, small=False, presidio=True, show_misses=False, out=print):
    if small:
        use_small_model()
    model = which_model(small)
    systems = {"jnvoy": score_system(rows, jnvoy_system())}
    if presidio:
        systems["presidio"] = score_system(rows, presidio_system(model))
        systems["presidio_tuned"] = score_system(rows, presidio_system(model, tuned=True))
    return report(rows, systems, show_misses, model, out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default=str(LARGE))
    ap.add_argument("--small-model", action="store_true")
    ap.add_argument("--no-presidio", action="store_true")
    ap.add_argument("--misses", action="store_true")
    ap.add_argument("--json", metavar="FILE")
    a = ap.parse_args()
    rows = load_rows(Path(a.dataset))
    result = run(rows, small=a.small_model, presidio=not a.no_presidio, show_misses=a.misses)
    if a.json:
        Path(a.json).write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nwrote {a.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
