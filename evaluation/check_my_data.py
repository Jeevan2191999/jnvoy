#!/usr/bin/env python3
"""
Check Jnvoy on YOUR text. This is the number that matters, more than any figure we publish.

    python evaluation/check_my_data.py my_texts.csv
    python evaluation/check_my_data.py my_texts.jsonl --compare-presidio
    python evaluation/check_my_data.py my_texts.csv --small-model     (what the hosted service runs)

Everything runs on this machine. Nothing is sent anywhere. The report prints the values that
leaked, so run it in a terminal you control and do not paste its output into a public place.

You label your own text. For each document you give:
  text        the document as it would be sent to a model
  sensitive   the values that must not survive (names, numbers, keys, addresses...)
  keep        optional: words that should stay readable (so over-redaction shows up)

CSV: three columns named text, sensitive, keep. Separate several values in one cell with " || ".
     A value may be written TYPE::value to get a per-type table, for example  PERSON::Jane Smith
     (without a type it is counted as VALUE).
JSONL: one object per line, the same format as large.jsonl:
     {"id": "1", "text": "...", "sensitive": [{"value": "...", "type": "PERSON"}], "keep": ["..."]}

A value counts as leaked if the whole value, or any recognisable part of it (a surname, the last
digits of a number), is still visible after redaction. Include enough documents: with 20 values the
95% interval is about +/-20 points. With 300 it is about +/-5. The report shows the interval.
"""

import argparse
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import compare  # noqa: E402


def _split(cell):
    return [p.strip() for p in (cell or "").split("||") if p.strip()]


def load_user_rows(path: Path) -> list:
    if path.suffix.lower() == ".jsonl":
        rows = []
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            r = json.loads(line)
            if "text" not in r:
                raise ValueError(f"line {n}: every document needs a text field")
            rows.append({"id": str(r.get("id", n)), "text": r["text"],
                         "sensitive": [{"value": s["value"], "type": s.get("type", "VALUE")} for s in r.get("sensitive", [])],
                         "keep": list(r.get("keep", []))})
        return _checked(rows)
    rows = []
    with path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or "text" not in reader.fieldnames:
            raise ValueError("the CSV needs a header row with a column called text (and optionally sensitive, keep)")
        for n, rec in enumerate(reader, 1):
            sens = []
            for item in _split(rec.get("sensitive")):
                typ, sep, val = item.partition("::")
                sens.append({"value": val.strip(), "type": typ.strip().upper()} if sep else {"value": item, "type": "VALUE"})
            rows.append({"id": str(n), "text": rec["text"], "sensitive": sens, "keep": _split(rec.get("keep"))})
    return _checked(rows)


def _checked(rows: list) -> list:
    if not rows:
        raise ValueError("no documents found")
    for r in rows:
        for s in r["sensitive"]:
            if s["value"] not in r["text"]:
                raise ValueError(f"document {r['id']}: the value {s['value']!r} is not in its text, so it cannot be scored")
        for k in r["keep"]:
            if k not in r["text"]:
                raise ValueError(f"document {r['id']}: the keep word {k!r} is not in its text")
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", help="a .csv or .jsonl file of your labelled text")
    ap.add_argument("--compare-presidio", action="store_true", help="also score plain Presidio on the same text")
    ap.add_argument("--small-model", action="store_true", help="use en_core_web_sm, as the hosted service does")
    ap.add_argument("--quiet", action="store_true", help="do not list the leaked values")
    a = ap.parse_args()
    try:
        rows = load_user_rows(Path(a.file))
    except (ValueError, OSError) as exc:
        print(f"Cannot read {a.file}: {exc}", file=sys.stderr)
        return 2
    n_values = sum(len(r["sensitive"]) for r in rows)
    if n_values < 50:
        print(f"Note: only {n_values} labelled values. Read the interval: it is wide. 300 or more gives a firm answer.\n")
    compare.run(rows, small=a.small_model, presidio=a.compare_presidio, show_misses=not a.quiet)
    return 0


if __name__ == "__main__":
    sys.exit(main())
