#!/usr/bin/env python3
"""
Measures how well Jnvoy hides personal data, and how often it hides things it should not.

All examples are synthetic (documented example numbers, fictional people). Nothing real.

    python evaluation/run_eval.py                 first pass only (Presidio and the UK rules)
    python evaluation/run_eval.py --judge         also runs the LLM judge and shows what it adds
    python evaluation/run_eval.py --misses        list every value that leaked
    python evaluation/run_eval.py --json out.json write the full results to a file

The judge uses the same settings as the live app, for example:
    JNVOY_JUDGE_BACKEND=anthropic ANTHROPIC_API_KEY=... python evaluation/run_eval.py --judge
    JNVOY_JUDGE_BACKEND=ollama python evaluation/run_eval.py --judge

Two numbers matter:
  CAUGHT   share of sensitive values that no longer appear in the redacted text.
           A value counts as leaked if the whole value OR any recognisable part of it
           (a surname, the last digits of a number) is still visible.
  KEPT     share of harmless words (companies, places, dates) that stayed readable.
           Low means over-redaction: the model gets a worse prompt for no privacy gain.

The dataset is small and written by us, so treat the numbers as a regression gauge and a
starting point, not as a certified accuracy figure.
"""

import argparse
import asyncio
import json
import re
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DATASET = Path(__file__).resolve().parent / "dataset.jsonl"
_PART = re.compile(r"[A-Za-z0-9]+")


def fragments(value: str) -> list:
    """Recognisable pieces of a value: alphabetic parts of 4+ letters, numeric parts of 3+ digits."""
    out = []
    for part in _PART.findall(value):
        if part.isdigit():
            if len(part) >= 3:
                out.append(part)
        elif len(part) >= 4:
            out.append(part)
    return out


def leaked(value: str, redacted: str) -> bool:
    """True if the value, or any recognisable part of it, is still visible."""
    if value in redacted:
        return True
    squeezed_value = re.sub(r"[\s\-]", "", value)
    squeezed_text = re.sub(r"[\s\-]", "", redacted)
    if len(squeezed_value) >= 6 and squeezed_value in squeezed_text:
        return True
    return any(f in redacted for f in fragments(value))


def _refang(x):
    """The data files store secret-looking test values with a '<>' break after their first character,
    so scanners (and GitHub push protection) do not mistake synthetic keys for real ones."""
    return x.replace("<>", "")


def load_rows(path: Path = DATASET) -> list:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    for r in rows:
        r["text"] = _refang(r["text"])
        r["keep"] = [_refang(k) for k in r["keep"]]
        for s in r["sensitive"]:
            s["value"] = _refang(s["value"])
    return rows


def score(rows: list, redacted_by_id: dict) -> dict:
    """Pure scoring: returns per-type counts, misses and false redactions."""
    per_type = defaultdict(lambda: {"n": 0, "caught": 0})
    misses, over = [], []
    keep_total = keep_kept = 0
    for row in rows:
        red = redacted_by_id[row["id"]]
        for s in row["sensitive"]:
            per_type[s["type"]]["n"] += 1
            if leaked(s["value"], red):
                misses.append({"id": row["id"], "type": s["type"], "value": s["value"], "redacted": red})
            else:
                per_type[s["type"]]["caught"] += 1
        for k in row["keep"]:
            keep_total += 1
            if k in red:
                keep_kept += 1
            else:
                over.append({"id": row["id"], "value": k, "redacted": red})
    n = sum(v["n"] for v in per_type.values())
    caught = sum(v["caught"] for v in per_type.values())
    return {
        "per_type": dict(per_type), "n": n, "caught": caught,
        "keep_total": keep_total, "keep_kept": keep_kept,
        "misses": misses, "over": over,
    }


def pct(a: int, b: int) -> str:
    return "  n/a" if b == 0 else f"{100 * a / b:5.1f}"


async def run(rows: list, use_judge: bool):
    from core.judged_detector import JudgedPIIDetector

    first = JudgedPIIDetector(judge=None, from_env=False)
    t0 = time.perf_counter()
    primary = {r["id"]: first.detect(r["text"]).redacted_text for r in rows}
    primary_ms = (time.perf_counter() - t0) * 1000 / max(1, len(rows))

    judged, judge_info = None, None
    if use_judge:
        det = JudgedPIIDetector(from_env=True)
        if det.judge is None:
            sys.exit("No judge configured. Set JNVOY_JUDGE_BACKEND=anthropic (with ANTHROPIC_API_KEY) or ollama.")
        judged, ran, errors, added, lat = {}, 0, 0, 0, []
        for r in rows:
            t = time.perf_counter()
            try:
                res = await det.detect_async(r["text"])
            except Exception as exc:  # fail-closed judge errors count as errors, not crashes
                errors += 1
                judged[r["id"]] = primary[r["id"]]
                print(f"  judge error on {r['id']}: {type(exc).__name__}", file=sys.stderr)
                continue
            lat.append((time.perf_counter() - t) * 1000)
            judged[r["id"]] = res.redacted_text
            ran += int(res.judge_ran)
            errors += int(bool(res.judge_error))
            added += res.judge_added
        await det.aclose()
        lat.sort()
        judge_info = {
            "documents": len(rows), "judge_ran": ran, "errors": errors, "spans_added": added,
            "median_ms": round(lat[len(lat) // 2], 1) if lat else None,
            "p95_ms": round(lat[int(len(lat) * 0.95) - 1], 1) if lat else None,
        }
    return primary, judged, primary_ms, judge_info


def report(rows, primary, judged, primary_ms, judge_info, show_misses):
    a = score(rows, primary)
    b = score(rows, judged) if judged else None
    types = sorted(a["per_type"])
    head = f"{'type':<13}{'n':>4}{'first pass':>12}" + (f"{'+ judge':>10}{'added':>8}" if b else "")
    print("\n" + head)
    print("-" * len(head))
    for t in types:
        pa = a["per_type"][t]
        line = f"{t:<13}{pa['n']:>4}{pct(pa['caught'], pa['n']):>11}%"
        if b:
            pb = b["per_type"][t]
            line += f"{pct(pb['caught'], pb['n']):>9}%{pb['caught'] - pa['caught']:>+8}"
        print(line)
    print("-" * len(head))
    line = f"{'ALL':<13}{a['n']:>4}{pct(a['caught'], a['n']):>11}%"
    if b:
        line += f"{pct(b['caught'], b['n']):>9}%{b['caught'] - a['caught']:>+8}"
    print(line)
    print(f"\nharmless words kept readable: first pass {pct(a['keep_kept'], a['keep_total'])}% "
          f"({a['keep_kept']}/{a['keep_total']})"
          + (f", with judge {pct(b['keep_kept'], b['keep_total'])}% ({b['keep_kept']}/{b['keep_total']})" if b else ""))
    print(f"first pass speed: {primary_ms:.0f} ms per document")
    if judge_info:
        print(f"judge: ran on {judge_info['judge_ran']}/{judge_info['documents']} documents, "
              f"{judge_info['errors']} errors, {judge_info['spans_added']} spans added, "
              f"median {judge_info['median_ms']} ms, p95 {judge_info['p95_ms']} ms (includes first pass)")

    final = b or a
    label = "after judge" if b else "first pass"
    if a["over"] or (b and b["over"]):
        print(f"\nOVER-REDACTED ({label}): harmless text that was hidden")
        for o in final["over"]:
            print(f"  {o['id']}  {o['value']!r}  ->  {o['redacted']!r}")
    if show_misses:
        print(f"\nLEAKED ({label}):")
        for m in final["misses"]:
            print(f"  {m['id']}  {m['type']:<12}{m['value']!r}  ->  {m['redacted']!r}")
    elif final["misses"]:
        print(f"\n{len(final['misses'])} values leaked ({label}). Run with --misses to see them.")
    return {"first_pass": a, "with_judge": b, "judge": judge_info, "ms_per_doc": primary_ms}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--judge", action="store_true", help="also run the LLM judge (needs JNVOY_JUDGE_* settings)")
    ap.add_argument("--misses", action="store_true", help="list every leaked value")
    ap.add_argument("--json", metavar="FILE", help="write full results to FILE")
    ap.add_argument("--dataset", default=str(DATASET))
    args = ap.parse_args()

    rows = load_rows(Path(args.dataset))
    print(f"{len(rows)} documents, {sum(len(r['sensitive']) for r in rows)} sensitive values, "
          f"{sum(len(r['keep']) for r in rows)} harmless words to keep")
    primary, judged, ms, info = asyncio.run(run(rows, args.judge))
    result = report(rows, primary, judged, ms, info, args.misses)
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
