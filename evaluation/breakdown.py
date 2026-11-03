#!/usr/bin/env python3
"""
Splits the biggest misses on large.jsonl into the formats that cause them, so the accuracy page
can say exactly where Jnvoy fails instead of giving one blended number.

    python evaluation/breakdown.py            prints the split for the first-pass detector
"""
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from run_eval import leaked, load_rows  # noqa: E402


def compute(rows, redact):
    out = {k: {"n": 0, "caught": 0} for k in (
        "person_plain", "person_all_capitals", "person_surname_first",
        "password_after_the_word_password", "password_after_pwd", "password_other")}
    cards = defaultdict(lambda: {"n": 0, "caught": 0})
    for r in rows:
        red = redact(r["text"])
        for s in r["sensitive"]:
            ok = not leaked(s["value"], red)
            v, t = s["value"], s["type"]
            if t == "PERSON":
                key = "person_all_capitals" if v.isupper() else ("person_surname_first" if ", " in v else "person_plain")
            elif t == "PASSWORD":
                if re.search(r"\bpwd\s+" + re.escape(v), r["text"]):
                    key = "password_after_pwd"
                elif re.search(r"password\s*[:=]?\s*(is\s+)?" + re.escape(v), r["text"], re.I):
                    key = "password_after_the_word_password"
                else:
                    key = "password_other"
            elif t == "CARD":
                n = str(len(re.sub(r"\D", "", v)))
                cards[n]["n"] += 1
                cards[n]["caught"] += int(ok)
                continue
            else:
                continue
            out[key]["n"] += 1
            out[key]["caught"] += int(ok)
    out["card_by_digit_count"] = dict(sorted(cards.items(), key=lambda kv: int(kv[0])))
    return out


def main():
    import compare
    rows = load_rows(compare.LARGE)
    res = compute(rows, compare.jnvoy_system())
    for k, v in res.items():
        print(k, v)


if __name__ == "__main__":
    main()
