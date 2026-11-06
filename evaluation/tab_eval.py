#!/usr/bin/env python3
"""
Names in real court judgments: Jnvoy and Presidio on the Text Anonymization Benchmark (TAB).

    python evaluation/tab_eval.py --fetch          download TAB at a fixed commit into evaluation/_public/tab
    python evaluation/tab_eval.py                  measure and print (needs the fetch first)
    python evaluation/tab_eval.py --write          also rewrite evaluation/results_tab.json and the page section
    python evaluation/tab_eval.py --page           rewrite the page section from the stored results only
    python evaluation/tab_eval.py --misses         also list the names Jnvoy left visible

TAB (Pilan, Lison, Ovrelid, Papadopoulou, Sanchez, Batet, 2022, MIT licence) is 1,268 English judgments of
the European Court of Human Rights, annotated by hand by an outside team. It is the only test here whose
text and labels were not written by Jnvoy's author. It is used as follows:

  sets       "test" and "dev" (127 judgments each). Only the "train" split may be read when fixing rules,
             so that these two stay unseen. Nothing was changed in Jnvoy after looking at them.
  annotator  the first annotator listed for each judgment ("first"), and, as a stricter check, a name counts
             as one to hide if any annotator marked it so ("union").
  must hide  each distinct PERSON text per judgment that the annotator marked DIRECT or QUASI (to be masked).
             A name counts as hidden only if neither it nor any part of it of 4+ letters is visible anywhere
             in the redacted judgment: the same rule (run_eval.leaked) as the larger test.
  keep       each distinct ORG, LOC or DEM text per judgment marked NO_MASK ("the Court", "Turkey",
             "the Government"), kept if the exact text is still in the redacted judgment.

What it does not test: TAB has no emails, phone numbers, card numbers, keys or postal addresses, so it says
nothing about those. Most of its names are applicants, lawyers, judges and witnesses, written in legal style
("Mr Galip Yalman", "Mance LJ", "B.O."). It is one kind of text, carefully written, not chat or email.
"""
import argparse
import hashlib
import json
import subprocess
import sys
import time
from importlib.metadata import version
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

import compare  # noqa: E402
from run_eval import leaked  # noqa: E402

TAB = HERE / "_public" / "tab"
URL = "https://github.com/NorskRegnesentral/text-anonymization-benchmark"
COMMIT = "558e09e26d6b36f5f78440074e6a233946d98bd9"
FILES = {
    "test": ("echr_test.json", "cd0f0f15f84a8739654c7cf30c6be8ce27b051ef73974d39d792a0cb8c846379"),
    "dev": ("echr_dev.json", "8c3c7306f46b8d54debeb38ae11d8b0b8bcf4bdccbc3b6f13c12ad7be16893ec"),
}
RESULTS_FILE = HERE / "results_tab.json"
KEEP_TYPES = ("ORG", "LOC", "DEM")
RUNS = (("test", "first"), ("dev", "first"), ("test", "union"))


def fetch():
    if TAB.exists():
        return
    TAB.mkdir(parents=True)
    for cmd in (["git", "init", "-q"], ["git", "remote", "add", "origin", URL],
                ["git", "fetch", "-q", "--depth", "1", "origin", COMMIT], ["git", "checkout", "-q", "FETCH_HEAD"]):
        subprocess.run(cmd, cwd=TAB, check=True)
    print("fetched TAB", COMMIT[:10])


def have_tab() -> bool:
    return all((TAB / name).exists() for name, _ in FILES.values())


def load(split: str) -> list:
    name, sha = FILES[split]
    raw = (TAB / name).read_bytes()
    if hashlib.sha256(raw).hexdigest() != sha:
        raise SystemExit(f"{name} is not the pinned file; delete evaluation/_public/tab and fetch again")
    return json.loads(raw)


def build_rows(docs: list, annotators: str = "first") -> list:
    rows = []
    for d in docs:
        names = sorted(d["annotations"])
        if annotators == "first":
            names = names[:1]
        hide, keep = {}, set()
        for a in names:
            for m in d["annotations"][a]["entity_mentions"]:
                kind, text = m["identifier_type"], m["span_text"].strip()
                if not text:
                    continue
                if m["entity_type"] == "PERSON" and kind in ("DIRECT", "QUASI"):
                    hide[text] = "DIRECT" if "DIRECT" in (hide.get(text), kind) else kind
                elif m["entity_type"] in KEEP_TYPES and kind == "NO_MASK":
                    keep.add(text)
        rows.append({"id": d["doc_id"], "text": d["text"], "hide": sorted(hide.items()),
                     "keep": sorted(keep - set(hide))})
    return rows


def score(rows: list, redact) -> dict:
    hidden = {"DIRECT": 0, "QUASI": 0}
    total = {"DIRECT": 0, "QUASI": 0}
    kept = keep_n = 0
    flags, misses = {}, []
    for r in rows:
        red = redact(r["text"])
        for text, kind in r["hide"]:
            ok = not leaked(text, red)
            total[kind] += 1
            hidden[kind] += ok
            flags[(r["id"], text)] = ok
            if not ok:
                misses.append([r["id"], text])
        for k in r["keep"]:
            keep_n += 1
            kept += k in red
    return {"hidden": hidden, "total": total, "kept": kept, "keep_n": keep_n, "_flags": flags, "_misses": misses}


def systems(model: str = "en_core_web_lg") -> dict:
    return {"jnvoy": compare.jnvoy_system(),
            "presidio": compare.presidio_system(model),
            "presidio_tuned": compare.presidio_system(model, tuned=True)}


def measure(model: str = "en_core_web_lg") -> dict:
    found = systems(model)
    out = {"source": {"url": URL, "commit": COMMIT, "licence": "MIT"},
           "measured": time.strftime("%Y-%m-%d"),
           "versions": {p: version(p) for p in ("spacy", "presidio-analyzer")},
           "model": model, "runs": {}}
    for split, annotators in RUNS:
        rows = build_rows(load(split), annotators)
        run = {"documents": len(rows),
               "avg_characters": round(sum(len(r["text"]) for r in rows) / len(rows)),
               "systems": {}}
        scored = {name: score(rows, fn) for name, fn in found.items()}
        j = scored["jnvoy"]["_flags"]
        for name, s in scored.items():
            entry = {k: v for k, v in s.items() if not k.startswith("_")}
            if name != "jnvoy":
                o = s["_flags"]
                entry["only_jnvoy_hid"] = sum(1 for k in j if j[k] and not o[k])
                entry["only_this_hid"] = sum(1 for k in j if o[k] and not j[k])
            else:
                entry["misses"] = s["_misses"]
            run["systems"][name] = entry
        out["runs"][f"{split}_{annotators}"] = run
    return out


def summary(res: dict) -> str:
    lines = []
    for key, run in res["runs"].items():
        lines.append(f"{key}: {run['documents']} judgments, about {run['avg_characters']:,} characters each")
        for name, s in run["systems"].items():
            h, n = sum(s["hidden"].values()), sum(s["total"].values())
            extra = ""
            if "only_jnvoy_hid" in s:
                extra = f"   only Jnvoy hid {s['only_jnvoy_hid']}, only this hid {s['only_this_hid']}"
            lines.append(f"  {name:15} names hidden {h}/{n} ({100 * h / n:.1f}%)   "
                         f"harmless kept {s['kept']}/{s['keep_n']} ({100 * s['kept'] / s['keep_n']:.1f}%){extra}")
    return "\n".join(lines)


PAGE = HERE.parent / "static" / "accuracy.html"
START, END = "<!-- court-judgments:start -->", "<!-- court-judgments:end -->"
# Patterns among Jnvoy's misses on test_first, read by hand on 5 November 2026. Kept here, not computed,
# because they are a reading of the misses; a test checks each example really is among the stored misses.
MISS_PATTERNS = (
    ("names with no title in front, especially Turkish ones", ("Erdal Güler", "Resul Sadak")),
    ("British judges' styles", ("Mance LJ", "Lord Slynn")),
    ("initials", ("C.Ç.", "W.K.")),
)


def _p(k, n):
    lo, hi = compare.wilson(k, n)
    return f"{100 * k / n:.1f}% ({100 * lo:.1f} to {100 * hi:.1f})"


def render(res: dict) -> str:
    def cells(run):
        s = res["runs"][run]["systems"]
        out = {}
        for name, v in s.items():
            h, n = sum(v["hidden"].values()), sum(v["total"].values())
            out[name] = (h, n, v["kept"], v["keep_n"], v.get("only_jnvoy_hid"), v.get("only_this_hid"))
        return out

    main = cells("test_first")
    run = res["runs"]["test_first"]
    jh, jn, jk, jkn, _, _ = main["jnvoy"]
    ph, pn, pk, pkn, _, _ = main["presidio"]
    th, tn, tk, tkn, t_only_j, t_only_t = main["presidio_tuned"]
    rows = []
    for label, name in (("Jnvoy", "jnvoy"), ("Presidio, default settings", "presidio"),
                        ("Presidio, set up like Jnvoy", "presidio_tuned")):
        h, n, k, kn, _, _ = main[name]
        rows.append(f'          <div class="row"><div class="k">{label}</div><div class="v">Names hidden: {h} of {n}, '
                    f'{_p(h, n)}. Harmless names of courts, countries and offices kept: {k:,} of {kn:,}, {_p(k, kn)}.</div>'
                    f'<div class="s mid">{100 * h / n:.1f}%</div></div>')
    checks = []
    for key, label in (("dev_first", "On the second set of 127 judgments"),
                       ("test_union", "Counting a name as one to hide if any annotator marked it")):
        c = cells(key)
        jh2, jn2 = c["jnvoy"][:2]
        th2, tn2, _, _, oj, ot = c["presidio_tuned"]
        checks.append(f"<li><strong>{label}:</strong> Jnvoy hid {100 * jh2 / jn2:.1f}% of names and Presidio set up "
                      f"like Jnvoy {100 * th2 / tn2:.1f}%. Of the names only one of the two hid, Jnvoy hid {oj} and Presidio {ot}.</li>")
    p_value = compare.mcnemar_exact(t_only_j, t_only_t)
    if t_only_t == 0:
        versus = (f"Jnvoy hid every name that Presidio set up this way hid, and {t_only_j} more, mostly names "
                  f'written after a title such as "Mr", "Mrs" or "Judge".')
    else:
        versus = f"Jnvoy hid {t_only_j} names that Presidio set up this way missed, and missed {t_only_t} that it hid."
    versus += (" That difference is small but very unlikely to be chance." if p_value < 0.05 else
               " That difference is small enough to be chance.")
    patterns = "; ".join(f"{what} (for example {', '.join(ex)})" for what, ex in MISS_PATTERNS)
    src = res["source"]
    return f"""{START}
      <section id="court-judgments">
        <h2>Real court judgments: an outside team's text and labels</h2>
        <p>Every other test on this page uses text we wrote. This one does not. The <a href="https://arxiv.org/abs/2202.00443">Text Anonymization Benchmark</a> (TAB) is a set of English judgments of the European Court of Human Rights in which a research team marked by hand every name that should be hidden. We used its test set of {run["documents"]} judgments, about {run["avg_characters"]:,} characters each, which is around fifty times longer than the documents in the larger test. Nothing in Jnvoy was changed after looking at it. It mainly tests <strong>names</strong>: the judgments contain no emails, card numbers, keys or postal addresses, so this test says nothing about those.</p>
        <div class="ledger">
          <div class="row head"><div>System</div><div>Result, with the 95% range in brackets</div><div>Names hidden</div></div>
{chr(10).join(rows)}
        </div>
        <p><strong>What it shows.</strong> Jnvoy and Presidio find names about equally well when both use their default settings ({100 * jh / jn:.1f}% against {100 * ph / pn:.1f}%), but Presidio's defaults also hide most of the harmless text: they kept only {100 * pk / pkn:.1f}% of the court, country and office names, against {100 * jk / jkn:.1f}% for Jnvoy. Set up the way Jnvoy is, Presidio keeps about as much harmless text ({100 * tk / tkn:.1f}%) and hides fewer names ({100 * th / tn:.1f}%). {versus}</p>
        <ul class="plain">
{chr(10).join("          " + c for c in checks)}
        </ul>
        <p><strong>What Jnvoy still misses here.</strong> {jn - jh} of {jn} names stayed visible: {patterns}, and surnames on their own. It also hid some foreign-language court names that should have stayed readable.</p>
        <p><strong>Limits.</strong> This is one kind of text, carefully written legal English. We chose this benchmark and ran it ourselves, so it is not an independent evaluation. The data is not stored in the repository: <code>python evaluation/tab_eval.py --fetch</code> downloads it at a fixed commit ({src["commit"][:10]}) under its MIT licence and reproduces every number here. Its training set is the only part we will read when improving name detection, so these two sets stay unseen.</p>
      </section>
{END}"""


def write_page(res: dict) -> None:
    page = PAGE.read_text(encoding="utf-8")
    block = render(res)
    if START in page:
        before, rest = page.split(START, 1)
        page = before + block + rest.split(END, 1)[1]
    else:
        anchor = "<!-- larger-test:end -->\n"
        assert page.count(anchor) == 1
        page = page.replace(anchor, anchor + block + "\n")
    PAGE.write_text(page, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--fetch", action="store_true")
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--misses", action="store_true")
    ap.add_argument("--page", action="store_true", help="rewrite the accuracy page section from results_tab.json and stop")
    a = ap.parse_args()
    if a.page:
        write_page(json.loads(RESULTS_FILE.read_text(encoding="utf-8")))
        print("updated", PAGE.relative_to(HERE.parent))
        return 0
    if a.fetch:
        fetch()
    if not have_tab():
        print("TAB is not here yet: run  python evaluation/tab_eval.py --fetch")
        return 1
    res = measure()
    print(summary(res))
    if a.misses:
        for doc, name in res["runs"]["test_first"]["systems"]["jnvoy"]["misses"]:
            print("  missed", doc, name)
    if a.write:
        RESULTS_FILE.write_text(json.dumps(res, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        print("wrote", RESULTS_FILE.relative_to(HERE.parent))
        write_page(res)
        print("updated", PAGE.relative_to(HERE.parent))
    return 0


if __name__ == "__main__":
    sys.exit(main())
