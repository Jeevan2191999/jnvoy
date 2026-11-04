#!/usr/bin/env python3
"""
Builds evaluation/large.jsonl: a larger labelled set made with the Faker library.

Why this exists. The older sets in this folder were written by hand, by the person who wrote
the detector, so they are small and likely to be kind to it. Here the *values* (names, emails,
phone numbers, addresses, card numbers, IBANs, social security numbers, dates of birth, IP
addresses) come from Faker's locale generators, not from us, and are many times more varied.
The sentences around them are still written by us, so this is still synthetic and still
optimistic about real documents. Run `check_my_data.py` on your own text for the real answer.

Everything is made up. Card numbers pass the Luhn check but are random; people and addresses
are invented by Faker. Secret-looking keys are random strings with a '<>' break after the first
character, as in the other data files, so secret scanners do not mistake them for real keys.

Needs:   pip install faker        (only to regenerate; the committed file is what the tests read)
Run:     python evaluation/generate_large.py            (always writes the same file: fixed seed)
         python evaluation/generate_large.py --seed 4242 --docs 600 --out evaluation/large_heldout.jsonl
         python evaluation/generate_large.py --seed 9090 --docs 600 --phrasing fresh --out evaluation/large_fresh.jsonl
"""

import json
import random
import string
import sys
from pathlib import Path

try:
    from faker import Faker
except ImportError:  # pragma: no cover
    sys.exit("This script needs Faker: pip install faker")

OUT = Path(__file__).resolve().parent / "large.jsonl"
SEED = 20261103
N_DOCS = 1000

# Names come from these locales. About 55% English-speaking, 45% other European and Indian
# names, because real customer text is not all English names.
ENGLISH = ["en_GB", "en_US", "en_IE", "en_AU", "en_CA"]
OTHER = ["de_DE", "fr_FR", "es_ES", "it_IT", "pl_PL", "nl_NL", "sv_SE", "en_IN"]
PHONE_LOCALES = ["en_GB", "en_US", "en_IE", "en_AU", "de_DE", "fr_FR", "es_ES", "en_IN"]
ADDRESS_LOCALES = ["en_GB", "en_US", "en_IE", "en_AU", "en_CA", "de_DE", "fr_FR"]

COMPANIES = ["Acme Logistics", "Contoso", "Fabrikam", "Northwind Traders", "Globex", "Initech",
             "Hooli", "Wayne Enterprises", "Stark Industries", "Umbrella Health", "Soylent Foods"]
PRODUCTS = ["Salesforce", "Slack", "Excel", "Azure", "Kubernetes", "PostgreSQL", "Zoom", "Jira"]
COUNTRIES = ["France", "Germany", "Spain", "Ireland", "Canada", "Australia", "India", "Poland"]
AMOUNTS = ["£1,250.00", "$4,300", "€899", "£75", "$12.50", "€2,010.40"]
WHEN = ["14 March", "Q3 2026", "next Tuesday", "end of April", "the second week of June", "Monday"]
ROLES = ["Head of Finance", "Support Engineer", "Account Manager", "Data Analyst", "Nurse Practitioner"]

# A second wording for every kind of value, used by --phrasing fresh. The sentences in `snippet` below
# were the ones the detector was tuned on. These were written afterwards, as a person would phrase it
# in a message, so a set made with them shows how much of the score comes from familiar wording.
FRESH = {
    "PERSON": ["Could {n} please confirm the booking?", "Minutes taken by {n}.", "CV attached for {n}.",
               "{n} (Operations) has asked for access.", "Spoke with {n} yesterday.", "Re: invoice query from {n}",
               "Cc'd {n} on the thread.", "Please welcome {n} to the team.", "Lunch with {n} on Thursday."],
    "EMAIL": ["You can reach me at {e}.", "email: {e}", "Her work address is {e}.", "Send invoices to {e}",
              "Mailing list: {e}", "(contact {e})"],
    "PHONE": ["Reachable on {p}.", "My number is {p}.", "Mobile: {p}", "You can ring me - {p}",
              "Call back on {p} please", "tel. {p}", "Phone number {p}", "Text me on {p}"],
    "ADDRESS": ["Please post it to {a}.", "Parcel for {a}.", "Her flat is at {a}.", "New address: {a}",
                "Collection point: {a}.", "Invoice address - {a}", "Sent to {a} yesterday"],
    "CARD": ["Use my Mastercard {c} for this.", "The number on the card is {c}.", "CC: {c}", "Payment card: {c}",
             "Amex {c}", "Card details: {c}"],
    "IBAN": ["Bank details: {i}", "Pay into {i}", "IBAN: {i}", "Account number {i} for the refund."],
    "SSN": ["SSN: {s}", "Social: {s}", "Her social security number is {s}.", "Tax ID {s}"],
    "DOB": ["Birthday: {d}", "Date of birth - {d}", "Born {d}.", "DOB was {d}", "Her birth date is {d}."],
    "IP": ["Seen from {i}", "Source IP: {i}", "host {i}", "Requests from {i} were throttled."],
    "API_KEY": ["token {k}", "Set OPENAI_API_KEY={k}", "secret = '{k}'", "curl -H 'Authorization: Bearer {k}'",
                "Here is the key: {k}"],
    "PASSWORD": ["My password for the VPN is {p}", "pass: {p}", "pw {p}", "credentials: admin / {p}", "password {p}",
                 "The Wi-Fi key is {p}", "passcode: {p}"],
}


def _tok(rng, n, alphabet=string.ascii_letters + string.digits):
    return "".join(rng.choice(alphabet) for _ in range(n))


def _break(secret):
    """'sk-abc' -> 's<>k-abc' so scanners do not flag the synthetic key."""
    return secret[0] + "<>" + secret[1:]


class Maker:
    def __init__(self, seed, fresh=False):
        self.fresh = fresh
        self.rng = random.Random(seed)
        Faker.seed(seed)
        self.fk = {}
        for i, loc in enumerate(sorted(set(ENGLISH + OTHER + PHONE_LOCALES + ADDRESS_LOCALES))):  # sorted: same order every run
            self.fk[loc] = Faker(loc)
            self.fk[loc].seed_instance(seed + i)
        self.counts = {}

    def _count(self, key):
        self.counts[key] = self.counts.get(key, 0) + 1

    # ----- values -------------------------------------------------------------------------
    def person(self):
        loc = self.rng.choice(ENGLISH if self.rng.random() < 0.55 else OTHER)
        f = self.fk[loc]
        first, last = f.first_name(), f.last_name()
        self._count("name:" + loc)
        return first, last

    def full_name(self):
        first, last = self.person()
        style = self.rng.choice(["plain", "plain", "plain", "reversed", "upper"])
        if style == "reversed":
            return f"{last}, {first}", [f"{last}, {first}"]
        if style == "upper":
            return f"{first.upper()} {last.upper()}", [f"{first.upper()} {last.upper()}"]
        return f"{first} {last}", [f"{first} {last}"]

    def email(self):
        loc = self.rng.choice(ENGLISH)
        f = self.fk[loc]
        first, last = f.first_name().lower(), f.last_name().lower()
        first = "".join(c for c in first if c.isascii() and c.isalpha()) or "user"
        last = "".join(c for c in last if c.isascii() and c.isalpha()) or "name"
        dom = self.rng.choice(["gmail.com", "outlook.com", "yahoo.co.uk", "proton.me",
                               "northwind-traders.ie", "acme-logistics.com", "hooli.io"])
        form = self.rng.choice([f"{first}.{last}", f"{first}{last}", f"{first[0]}{last}", f"{first}_{last}{self.rng.randint(1, 99)}"])
        return f"{form}@{dom}"

    def phone(self):
        loc = self.rng.choice(PHONE_LOCALES)
        v = self.fk[loc].phone_number().strip()
        self._count("phone:" + loc)
        return v

    def address(self):
        loc = self.rng.choice(ADDRESS_LOCALES)
        f = self.fk[loc]
        street = f.street_address().replace("\n", ", ")
        city, pc = f.city(), f.postcode()
        self._count("addr:" + loc)
        return street, city, pc

    def card(self):
        f = self.fk["en_US"]
        v = f.credit_card_number()
        if self.rng.random() < 0.5 and len(v) == 16:
            v = " ".join(v[i:i + 4] for i in range(0, 16, 4))
        return v

    def iban(self):
        loc = self.rng.choice(["en_GB", "de_DE", "fr_FR", "es_ES", "en_IE"])
        return self.fk[loc].iban()

    def ssn(self):
        return self.fk["en_US"].ssn()

    def dob(self):
        d = self.fk["en_GB"].date_of_birth(minimum_age=18, maximum_age=90)
        fmt = self.rng.choice(["%d/%m/%Y", "%d %B %Y", "%Y-%m-%d", "%d-%m-%Y", "%B %d, %Y"])
        return d.strftime(fmt)

    def ip(self):
        return self.fk["en_GB"].ipv4_private() if self.rng.random() < 0.5 else self.fk["en_GB"].ipv4_public()

    def api_key(self):
        r = self.rng
        kind = r.choice(["anthropic", "openai", "openai2", "github", "aws", "slack", "google"])
        if kind == "anthropic":
            return _break("sk-ant-api03-" + _tok(r, 90, string.ascii_letters + string.digits + "-_"))
        if kind == "openai":
            return _break("sk-proj-" + _tok(r, 48))
        if kind == "openai2":
            return _break("sk-" + _tok(r, 48))
        if kind == "github":
            return _break("ghp_" + _tok(r, 36))
        if kind == "aws":
            return _break("AKIA" + _tok(r, 16, string.ascii_uppercase + string.digits))
        if kind == "slack":
            return _break(f"xoxb-{r.randint(10**11, 10**12 - 1)}-{r.randint(10**11, 10**12 - 1)}-" + _tok(r, 24))
        return _break("AIza" + _tok(r, 35, string.ascii_letters + string.digits + "-_"))

    def password(self):
        return self.fk["en_GB"].password(length=self.rng.randint(10, 16), special_chars=self.rng.random() < 0.6)

    # ----- harmless context ---------------------------------------------------------------
    def harmless(self):
        r = self.rng
        kind = r.choice(["company", "product", "city", "country", "amount", "when", "order", "version", "role"])
        if kind == "company":
            c = r.choice(COMPANIES)
            return r.choice([f"The contract with {c} is up for renewal.", f"{c} sent the revised quote."]), [c]
        if kind == "product":
            p = r.choice(PRODUCTS)
            return f"We moved the reporting from {p} last quarter.", [p]
        if kind == "city":
            c = self.fk[r.choice(ADDRESS_LOCALES)].city()
            return f"The team meets in {c} for the review.", [c]
        if kind == "country":
            c = r.choice(COUNTRIES)
            return f"Shipping to {c} takes about a week.", [c]
        if kind == "amount":
            a = r.choice(AMOUNTS)
            return f"The invoice total was {a} including delivery.", [a]
        if kind == "when":
            w = r.choice(WHEN)
            return f"Let's talk again {w}." if w[0].islower() else f"The deadline is {w}.", [w]
        if kind == "order":
            n = r.choice([f"order {r.randint(10000, 99999)}", f"ticket INC-{r.randint(10000, 99999)}",
                          f"invoice 2026-{r.randint(1000, 9999)}", f"v{r.randint(1, 9)}.{r.randint(0, 9)}.{r.randint(0, 9)}"])
            return f"Please check {n} before Friday.", [n]
        role = r.choice(ROLES)
        return f"The {role} will pick this up.", [role]

    # ----- snippets: (text, sensitive[(value,type)], keep[]) --------------------------------
    def snippet(self, kind):
        r = self.rng
        if kind == "PERSON":
            v, parts = self.full_name()
            first = v.split()[0].strip(",")
            t = r.choice([
                "Dear {n},", "Patient: {n}", "Spoke to {n} about the renewal.", "{n} joined the team in March.",
                "Name: {n}", "Please forward this to {n}.", "Meeting notes from the call with {n}.",
                "Applicant {n} has passed the first screen.", "Reference requested for {n}.",
                "Hi {n}, thanks for getting back to us.", "Signed: {n}", "Assigned to {n}.",
            ])
            if self.fresh:
                t = r.choice(FRESH["PERSON"])
            return t.format(n=v), [(v, "PERSON")]
        if kind == "EMAIL":
            e = self.email()
            t = r.choice(["Reply to {e} when ready.", "cc: {e}", "My email is {e}.", "Send the file to {e} please.",
                          "Contact: {e}", "From: {e}", "forward to {e} and copy finance"])
            if self.fresh:
                t = r.choice(FRESH["EMAIL"])
            return t.format(e=e), [(e, "EMAIL")]
        if kind == "PHONE":
            p = self.phone()
            t = r.choice(["Call me on {p}.", "Tel: {p}", "His mobile is {p}.", "Ring {p} after 5pm.", "phone {p}", "WhatsApp {p}"])
            if self.fresh:
                t = r.choice(FRESH["PHONE"])
            return t.format(p=p), [(p, "PHONE")]
        if kind == "ADDRESS":
            street, city, pc = self.address()
            full = f"{street}, {city} {pc}"
            t = r.choice(["Ship to {a}.", "Home address: {a}", "Registered office at {a}.", "Deliver to {a} before noon.",
                          "She lives at {a}.", "Billing address {a}"])
            if self.fresh:
                t = r.choice(FRESH["ADDRESS"])
            return t.format(a=full), [(street, "ADDRESS"), (pc, "POSTCODE")]
        if kind == "CARD":
            c = self.card()
            t = r.choice(["Card number {c}.", "Paid with card {c}", "Please charge {c}.", "visa: {c}", "card on file {c}"])
            if self.fresh:
                t = r.choice(FRESH["CARD"])
            return t.format(c=c), [(c, "CARD")]
        if kind == "IBAN":
            i = self.iban()
            t = r.choice(["IBAN {i}", "Transfer to {i}.", "Account (IBAN): {i}", "Refund to {i} please."])
            if self.fresh:
                t = r.choice(FRESH["IBAN"])
            return t.format(i=i), [(i, "IBAN")]
        if kind == "SSN":
            s = self.ssn()
            t = r.choice(["SSN {s}", "Social security number: {s}", "Her SSN is {s}.", "Tax record for SSN {s}."])
            if self.fresh:
                t = r.choice(FRESH["SSN"])
            return t.format(s=s), [(s, "US_SSN")]
        if kind == "DOB":
            d = self.dob()
            t = r.choice(["DOB {d}", "Date of birth: {d}", "Born on {d}.", "She was born {d}.", "dob: {d}"])
            if self.fresh:
                t = r.choice(FRESH["DOB"])
            return t.format(d=d), [(d, "DOB")]
        if kind == "IP":
            i = self.ip()
            t = r.choice(["Login from {i} at 09:14.", "Server {i} is down.", "IP address {i}", "Blocked {i} after repeated failures."])
            if self.fresh:
                t = r.choice(FRESH["IP"])
            return t.format(i=i), [(i, "IP")]
        if kind == "API_KEY":
            k = self.api_key()
            t = r.choice(["key = {k}", "Authorization: Bearer {k}", "export API_KEY={k}", "Use this token: {k}", "api_key: \"{k}\""])
            if self.fresh:
                t = r.choice(FRESH["API_KEY"])
            return t.format(k=k), [(k, "API_KEY")]
        if kind == "PASSWORD":
            p = self.password()
            t = r.choice(["password: {p}", "The password is {p}", "login with password={p}", "pwd {p}"])
            if self.fresh:
                t = r.choice(FRESH["PASSWORD"])
            return t.format(p=p), [(p, "PASSWORD")]
        raise ValueError(kind)

    def doc(self, i):
        r = self.rng
        # about 12% of documents hold no sensitive value at all, to measure false redactions
        if r.random() < 0.12:
            parts, keep = [], []
            for _ in range(r.randint(2, 4)):
                t, k = self.harmless()
                parts.append(t)
                keep += k
            return {"id": f"L{i:04d}", "text": " ".join(parts), "sensitive": [], "keep": keep}
        weights = {"PERSON": 22, "EMAIL": 11, "PHONE": 11, "ADDRESS": 10, "CARD": 6, "IBAN": 5,
                   "SSN": 5, "DOB": 8, "IP": 5, "API_KEY": 9, "PASSWORD": 4}
        kinds = r.choices(list(weights), weights=list(weights.values()), k=r.choice([1, 1, 2, 2, 3]))
        parts, sens, keep = [], [], []
        for kd in kinds:
            t, s = self.snippet(kd)
            parts.append(t)
            sens += [{"value": v, "type": ty} for v, ty in s]
        if r.random() < 0.6:
            t, k = self.harmless()
            parts.insert(r.randint(0, len(parts)), t)
            keep += k
        sep = r.choice([" ", ". ", "\n", " - "])
        text = sep.join(p.rstrip(".") if sep.startswith(".") else p for p in parts)
        # every value must really be in the text, in the exact form that is labelled
        for s in sens:
            assert s["value"] in text, (s, text)
        for k in keep:
            assert k in text, (k, text)
        return {"id": f"L{i:04d}", "text": text, "sensitive": sens, "keep": keep}


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Regenerate the labelled sets (same seed, same file).")
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--docs", type=int, default=N_DOCS)
    ap.add_argument("--out", default=str(OUT))
    ap.add_argument("--phrasing", choices=["original", "fresh"], default="original",
                    help="fresh: the second set of sentence wordings, written after the detector was tuned")
    a = ap.parse_args()
    out = Path(a.out)
    m = Maker(a.seed, fresh=a.phrasing == "fresh")
    rows = [m.doc(i + 1) for i in range(a.docs)]
    with out.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    n = sum(len(r["sensitive"]) for r in rows)
    print(f"wrote {out.name}: {len(rows)} documents, {n} sensitive values, {sum(len(r['keep']) for r in rows)} harmless words")
    by = {}
    for r in rows:
        for s in r["sensitive"]:
            by[s["type"]] = by.get(s["type"], 0) + 1
    print("by type:", dict(sorted(by.items())))


if __name__ == "__main__":
    main()
