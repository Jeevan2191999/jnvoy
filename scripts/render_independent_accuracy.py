#!/usr/bin/env python3
"""
Writes the "larger test" section of static/accuracy.html from evaluation/results_large.json,
so the page can only say what was measured.

    python scripts/render_independent_accuracy.py --write     update the page
    python scripts/render_independent_accuracy.py             print the section

A test (tests/test_larger_accuracy.py) re-measures the numbers and checks the page matches.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "evaluation"))
sys.path.insert(0, str(ROOT))

from compare import wilson  # noqa: E402

PAGE = ROOT / "static" / "accuracy.html"
RESULTS = ROOT / "evaluation" / "results_large.json"
START, END = "<!-- larger-test:start -->", "<!-- larger-test:end -->"


def pc(k, n):
    return f"{100 * k / n:.1f}%"


def rng(k, n):
    lo, hi = wilson(k, n)
    return f"{100 * lo:.1f} to {100 * hi:.1f}"


def full(k, n):
    return f"{pc(k, n)} ({rng(k, n)})"


def cls(k, n):
    p = k / n
    return "no" if p >= 0.9 else ("mid" if p >= 0.75 else "yes")


def _sys(res, key, model="en_core_web_lg", name="jnvoy"):
    return res["sets"][key][model]["systems"][name]


def _t(sysd, typ):
    v = sysd["per_type"][typ]
    return v["caught"], v["n"]


def render(res=None):
    res = res or json.loads(RESULTS.read_text(encoding="utf-8"))
    B, R1 = res["before_fixes"], res["round1"]
    keys = ("large", "large_heldout", "large_fresh", "large_fresh2")
    dev, ho, fr1, fr = (_sys(res, k) for k in keys)       # fr = the unseen set, fr1 = the set round two was made against
    fr_sm = _sys(res, "large_fresh2", "en_core_web_sm")
    P, T = _sys(res, "large_fresh2", name="presidio"), _sys(res, "large_fresh2", name="presidio_tuned")
    h2h = res["sets"]["large_fresh2"]["en_core_web_lg"]["head_to_head"]["presidio"]
    docs = {k: res["sets"][k]["en_core_web_lg"]["documents"] for k in keys}
    bd_b, bd_a = B["large"]["breakdown"], res["sets"]["large"]["breakdown_en_core_web_lg"]

    def hist(src, key):
        return src[key]["caught"], src[key]["n"]

    def setrow(name, text, key, sysd):
        k, n = sysd["caught"], sysd["n"]
        bk, bn = hist(B, key)
        r1k, r1n = hist(R1, key)
        return (f'          <div class="row"><div class="k">{name}</div><div class="v">{text} '
                f'Before any fixes: {bk:,} of {bn:,} ({pc(bk, bn)}). After round one: {pc(r1k, r1n)}. '
                f'Now: {k:,} of {n:,} ({pc(k, n)}, range {rng(k, n)}). '
                f'Harmless words kept: {pc(sysd["keep_kept"], sysd["keep_total"])}.</div>'
                f'<div class="s {cls(k, n)}">{pc(k, n)}</div></div>')

    sets_rows = "\n".join([
        setrow("Development set", f'{docs["large"]:,} documents, {dev["n"]:,} sensitive values. We fixed the rules by looking at '
               "its misses, so this score is optimistic.", "large", dev),
        setrow("Second set, same wording", f'{docs["large_heldout"]} documents. Used only to check totals, its misses were never read, '
               "but its sentences use the same wordings as the development set, so a fix written for those wordings helps it too.",
               "large_heldout", ho),
        setrow("Third set, new wording", f'{docs["large_fresh"]} documents. It was unseen after round one; its misses were then read and '
               "round two of the fixes was written against them, so it is optimistic now.", "large_fresh", fr1),
        setrow("Fourth set, another new wording", f'{docs["large_fresh2"]} documents, {fr["n"]:,} sensitive values. Sentences written '
               "before round two and never used to change a rule. <strong>This is the figure to trust.</strong>", "large_fresh2", fr),
    ])

    rows = []
    for t, v in sorted(fr["per_type"].items(), key=lambda kv: kv[1]["caught"] / kv[1]["n"]):
        pv = P["per_type"][t]
        rows.append(
            f'          <div class="row"><div class="k">{t}</div><div class="v">{v["n"]} values. '
            f'Jnvoy hid {full(v["caught"], v["n"])}. Presidio with its default settings hid {full(pv["caught"], pv["n"])}.</div>'
            f'<div class="s {cls(v["caught"], v["n"])}">{pc(v["caught"], v["n"])}</div></div>')

    ahead, behind, level = [], [], []
    for t, v in fr["per_type"].items():
        pv = P["per_type"][t]
        if v["caught"] / v["n"] >= 0.999 and pv["caught"] / pv["n"] >= 0.999:
            continue
        jlo, jhi = wilson(v["caught"], v["n"])
        plo, phi = wilson(pv["caught"], pv["n"])
        text = f'{t} ({pc(v["caught"], v["n"])} against {pc(pv["caught"], pv["n"])})'
        (ahead if jlo > phi else behind if jhi < plo else level).append(text)

    def pt(typ, sysd):
        k, n = _t(sysd, typ)
        return f"{k} of {n}"

    def bpart(key, which):
        v = which[key]
        return f'{v["caught"]} of {v["n"]}'

    cards_b, cards_a = bd_b["card_by_digit_count"], bd_a["card_by_digit_count"]
    odd = [d for d in cards_b if d not in ("13", "14", "16")]
    card_bits = ", ".join(f'{d}-digit {cards_b[d]["caught"]} of {cards_b[d]["n"]} to {cards_a[d]["caught"]} of {cards_a[d]["n"]}'
                          for d in odd)
    dev_b = B["large"]["per_type"]

    def dv(typ):
        return (f'{dev_b[typ]["caught"]} of {dev_b[typ]["n"]} to {dev["per_type"][typ]["caught"]} of {dev["per_type"][typ]["n"]}')

    def r2(typ):
        a1, a2 = _t(R1["large_fresh"], typ), _t(fr1, typ)
        u1, u2 = _t(R1["large_fresh2"], typ), _t(fr, typ)
        return (f'<li><strong>{typ}:</strong> on the set the fixes were written against, {a1[0]} of {a1[1]} to {a2[0]} of {a2[1]}; '
                f'on the unseen set, {u1[0]} of {u1[1]} to {u2[0]} of {u2[1]}.</li>')

    gap = 100 * (ho["caught"] / ho["n"] - fr["caught"] / fr["n"])
    r1u, r2u = hist(R1, "large_fresh2"), (fr["caught"], fr["n"])
    r1f, r2f = hist(R1, "large_fresh"), (fr1["caught"], fr1["n"])
    round2 = "\n          ".join(r2(t) for t in ("PASSWORD", "DOB", "US_SSN", "ADDRESS", "POSTCODE", "PERSON"))

    return f'''{START}
      <section id="larger-test">
        <h2>A larger test: 1,000 documents with generated values</h2>
        <p>The sets above were written by the person who wrote the detector, so they flatter it. To see how much, we built larger sets where the values (names, emails, phone numbers, addresses, card numbers, bank numbers, dates of birth, IP addresses, keys and passwords) are generated by Faker, a public library, in formats from several countries. We still wrote the sentences around them, so this is not an independent evaluation, only a harder and larger one. The sets are made from fixed seeds, so anyone can regenerate them.</p>
        <p><strong>Result.</strong> On sentence wordings the rules were not tuned on, Jnvoy hid {fr["caught"]:,} of {fr["n"]:,} sensitive values ({pc(fr["caught"], fr["n"])}; the likely range is {rng(fr["caught"], fr["n"])}). With the small language model that the hosted service runs it hid {pc(fr_sm["caught"], fr_sm["n"])} (range {rng(fr_sm["caught"], fr_sm["n"])}). <strong>Roughly one sensitive value in six was still visible afterwards.</strong> The first two sets score about {gap:.0f} points higher because the fixes were written against their wordings; that gap is how much of the improvement is familiarity and not general ability.</p>
        <div class="ledger">
          <div class="row head"><div>Set</div><div>What it is, and the score before and after the fixes</div><div>Hidden now</div></div>
{sets_rows}
        </div>
        <h3>By type of data, on the unseen set</h3>
        <div class="ledger">
          <div class="row head"><div>Type</div><div>Result, with the 95% range in brackets</div><div>Jnvoy hid</div></div>
{chr(10).join(rows)}
        </div>
        <p><strong>Harmless words kept readable.</strong> Jnvoy kept {full(fr["keep_kept"], fr["keep_total"])}. Presidio with its default settings kept {full(P["keep_kept"], P["keep_total"])}, because it hides dates and places by default. With those switched off it kept {full(T["keep_kept"], T["keep_total"])} and hid {pc(T["caught"], T["n"])} of the sensitive values; without a date type it cannot see a birth date at all.</p>
        <h3>Where Jnvoy is ahead, behind, or too close to call</h3>
        <ul class="plain">
          <li><strong>Clearly ahead of Presidio's defaults</strong> (the ranges do not overlap): {", ".join(ahead) or "none"}.</li>
          <li><strong>Clearly behind:</strong> {", ".join(behind) or "none"}.</li>
          <li><strong>Too close to call at this sample size</strong> (the ranges overlap, so a difference in either direction could be chance): {", ".join(level) or "none"}.</li>
        </ul>
        <p>The comparison is with Presidio on its own, using the same language model, and is not any product's configuration. Overall, Jnvoy hid {pc(fr["caught"], fr["n"])} against {pc(P["caught"], P["n"])} for Presidio's defaults on this set; of the values only one of them hid, Jnvoy hid {h2h["only_jnvoy"]} and Presidio {h2h["only_presidio"]}.</p>
        <h3>What round one of the fixes changed, measured on the development set</h3>
        <ul class="plain">
          <li><strong>Names in capital letters</strong> (after a cue such as "Dear" or "Patient:"): {bpart("person_all_capitals", bd_b)} hidden before, {bpart("person_all_capitals", bd_a)} now. <strong>"Surname, First" names:</strong> {bpart("person_surname_first", bd_b)} before, {bpart("person_surname_first", bd_a)} now.</li>
          <li><strong>Passwords written "pwd secret":</strong> {bpart("password_after_pwd", bd_b)} before, {bpart("password_after_pwd", bd_a)} now.</li>
          <li><strong>Card numbers of 12, 15 and 19 digits and the newer 2-series Mastercards</strong>, when a word such as "card" or "visa" is next to them: cards overall {dv("CARD")}; by length, {card_bits}.</li>
          <li><strong>Phone numbers and street addresses after a label</strong> such as "phone", "WhatsApp", "ship to" or "lives at", in any layout: phones {dv("PHONE")}, street addresses {dv("ADDRESS")}, postcodes {dv("POSTCODE")}.</li>
          <li><strong>A bug in an older rule:</strong> a weak name cue ("to", "from", "with") followed by an unfamiliar place, such as "Ann Arbor", was being redacted as a person, because the check that should have stopped it looked for the wrong labels. It now works, and a test covers it.</li>
        </ul>
        <h3>Round two, and why the unseen set moved so little</h3>
        <p>Round two added more wordings found in the third set: "pass:", "pw" and "Wi-Fi key" for passwords, "DOB was" and "birth date is", social security numbers written 123-45-6789 without a label, more ways of introducing an address, and everyday phrasings that introduce a name. It lifted the third set from {pc(*r1f)} to {pc(*r2f)}, which is the set it was written against. On the unseen fourth set it moved from {pc(*r1u)} to {pc(*r2u)}.</p>
        <ul class="plain">
          {round2}
        </ul>
        <p>What generalised were rules that are not tied to a wording: the dashed social security number and the date-of-birth labels. What did not were rules that list the words people use before a value. Adding words to such lists fixes the wording that was seen and little else, so further rounds of this kind give small gains. A different approach is needed for the rest, and we do not claim to have one yet.</p>
        <h3>What it still misses</h3>
        <p>Measured on the unseen set (and read afterwards to describe it, so it is spent):</p>
        <ul class="plain">
          <li><strong>Passwords</strong> hidden {pt("PASSWORD", fr)}: "The password was ...", "login pass ..." and "Wi-Fi password ..." with no "is", colon or equals sign are missed.</li>
          <li><strong>Street addresses</strong> hidden {pt("ADDRESS", fr)} and <strong>postcodes</strong> {pt("POSTCODE", fr)}: addresses introduced by wordings the rules do not list, for example "Delivery goes to ...", "Return parcel to ...", "Their office: ..." and "Site visit at ...".</li>
          <li><strong>Names</strong> hidden {pt("PERSON", fr)}: names after wordings such as "Attn:", "Referred by" and "Could you loop in ...", names at the start of a sentence ("... is the account owner"), and names in capitals after those wordings.</li>
          <li><strong>Phone numbers</strong> hidden {pt("PHONE", fr)}: "Landline:", "Dial", "Hotline" and "Best number:" are not recognised as phone words.</li>
          <li><strong>Card numbers</strong> hidden {pt("CARD", fr)}: "Charge it to ..." and "Payment made with ..." are not recognised as card words.</li>
        </ul>
        <p>These are measured gaps, not fixed ones. When rules change, this section is measured again and replaced.</p>
        <h3>How to read it</h3>
        <ul class="plain">
          <li>The values are synthetic and were not chosen by us, but the sentences around them were. Real documents are messier, so expect real accuracy to differ, probably downwards.</li>
          <li>A value counts as hidden only if neither the whole value nor any recognisable part of it is still visible. This is strict: a street name left behind a hidden house number counts as a leak.</li>
          <li>Only the development set and, for round two, the third set were used to decide what to fix. The others were used to check totals. A set stops being unseen the moment its misses are read, so each round of fixes needs a new one.</li>
          <li>The best figure is the one you get on your own text. <code>python evaluation/check_my_data.py your_file.csv</code> measures it on your machine without sending anything anywhere.</li>
        </ul>
      </section>
{END}'''


def main():
    section = render()
    if "--write" not in sys.argv:
        print(section)
        return 0
    page = PAGE.read_text(encoding="utf-8")
    if START in page:
        page = re.sub(re.escape(START) + r".*?" + re.escape(END), lambda m: section, page, flags=re.S)
    else:
        anchor = '      <section id="types">'
        assert page.count(anchor) == 1
        page = page.replace(anchor, section + "\n\n" + anchor)
        toc = '        <li><a href="#types">By type of data</a></li>\n'
        assert page.count(toc) == 1
        page = page.replace(toc, '        <li><a href="#larger-test">Larger test</a></li>\n' + toc)
    PAGE.write_text(page, encoding="utf-8")
    print("updated", PAGE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
