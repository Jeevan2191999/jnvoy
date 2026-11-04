#!/usr/bin/env python3
"""
Measures Jnvoy's prompt-injection blocking, as it runs in the proxy: every message is scanned, and a request
is blocked when a rule of severity critical or high matches (core/injection.py, action "block").

    python evaluation/injection_eval.py                 hand-written cases only (needs nothing, runs anywhere)
    python evaluation/injection_eval.py --fetch         download the public sets listed below (needs GitHub)
    python evaluation/injection_eval.py --public        also measure the public sets
    python evaluation/injection_eval.py --public --write   write evaluation/results_injection.json

Three kinds of evidence, kept apart because they answer different questions.
  1. Public attacks. The 1,405 jailbreak prompts of the JailbreakHub dataset (Shen et al., MIT licence), real
     prompts collected from Reddit, Discord and prompt sites in 2022-2023. Nobody here wrote them, and no rule
     was changed after looking at them. Split by a hash of the text into a "dev" half (we may read it) and a
     "test" half (we do not read it), so that fixing rules later does not spend the whole set.
  2. Public ordinary text. 52,002 instructions from Stanford Alpaca (Apache 2.0). Short, polite, mostly one
     sentence, so a false-positive count on it flatters any detector. JailbreakHub's own "regular" prompts are
     measured too, but they are NOT clean: the dataset's labeller missed many jailbreaks in it, and many are
     ordinary prompt-library templates that begin "Please ignore all previous instructions". They are reported as
     what they are, with a hand-read sample.
  3. Hand-written cases (injection_cases.py): attacks in the wordings the rules were written for, in
     paraphrase, in other languages, obfuscated, buried in a document and split across messages; plus harmless
     text that shares words with attacks. Written by the person who wrote the rules, so the canonical rows are a
     check that the rules do what they say and the rest is the honest part.

The public sets are not committed (licence, size). `--fetch` downloads fixed commits into evaluation/_public/.
"""
import csv
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

PUBLIC = HERE / "_public"
SOURCES = {
    "jailbreak_llms": ("https://github.com/verazuo/jailbreak_llms", "4f4031bf8be187f4478c7f94f42b08714722c12e"),
    "stanford_alpaca": ("https://github.com/tatsu-lab/stanford_alpaca", "761dc5bfbdeeffa89b8bff5d038781a4055f796a"),
    "mcp_servers": ("https://github.com/modelcontextprotocol/servers", "194cc86e3ae6400958555bd4116849d822d69263"),
}
RESULTS_FILE = HERE / "results_injection.json"


# ── the system under test ────────────────────────────────────────────────────────────────────────────────────

def detector():
    from core.injection import InjectionDetector
    return InjectionDetector(action="block", confidence_threshold=0.6)   # exactly as api/proxy_v2.py builds it


def mcp_scanner():
    from core.mcp_security import MCPSecurityScanner
    return MCPSecurityScanner(action="block", confidence_threshold=0.6)


# ── hand-written cases ───────────────────────────────────────────────────────────────────────────────────────

def build_rows() -> list:
    from injection_cases import ATTACKS, CATEGORIES, DOCUMENT_WRAPS, HARMLESS, SPLIT
    rows = []

    def add(kind, category, form, messages):
        rows.append({"id": f"inj{len(rows):04d}", "kind": kind, "category": category, "form": form,
                     "messages": messages})

    for cat in CATEGORIES:
        for form, texts in ATTACKS[cat].items():
            for t in texts:
                add("attack", cat, form, [t])
    for cat in CATEGORIES:                       # the same instructions, buried in a longer document
        for form in ("canonical", "paraphrase"):
            for i, t in enumerate(ATTACKS[cat][form][:3]):
                add("attack", cat, f"{form}_in_document", [DOCUMENT_WRAPS[i % len(DOCUMENT_WRAPS)].format(x=t)])
    for parts in SPLIT:
        add("attack", "split", "split_across_messages", list(parts))
    for group, texts in HARMLESS.items():
        for t in texts:
            add("harmless", group, group, [t])
    return rows


def _blocked(det, messages) -> bool:
    return det.scan_messages([{"role": "user", "content": m} for m in messages]).blocked


def measure_handwritten() -> dict:
    det = detector()
    by_form, by_cat = defaultdict(lambda: [0, 0]), defaultdict(lambda: [0, 0])
    harmless = defaultdict(lambda: [0, 0])
    blocked_harmless = []
    for r in build_rows():
        hit = _blocked(det, r["messages"])
        if r["kind"] == "attack":
            by_form[r["form"]][0] += hit
            by_form[r["form"]][1] += 1
            by_cat[r["category"]][0] += hit
            by_cat[r["category"]][1] += 1
        else:
            harmless[r["category"]][0] += hit
            harmless[r["category"]][1] += 1
            if hit:
                blocked_harmless.append(r["messages"][0][:90])
    a_hit = sum(v[0] for v in by_form.values())
    a_n = sum(v[1] for v in by_form.values())
    h_hit = sum(v[0] for v in harmless.values())
    h_n = sum(v[1] for v in harmless.values())
    return {"attacks": {"blocked": a_hit, "n": a_n},
            "by_form": {k: {"blocked": v[0], "n": v[1]} for k, v in sorted(by_form.items())},
            "by_category": {k: {"blocked": v[0], "n": v[1]} for k, v in sorted(by_cat.items())},
            "harmless": {"blocked": h_hit, "n": h_n},
            "harmless_by_group": {k: {"blocked": v[0], "n": v[1]} for k, v in sorted(harmless.items())},
            "harmless_blocked_examples": blocked_harmless}


# ── public sets ──────────────────────────────────────────────────────────────────────────────────────────────

def fetch():
    PUBLIC.mkdir(exist_ok=True)
    for name, (url, sha) in SOURCES.items():
        d = PUBLIC / name
        if d.exists():
            continue
        d.mkdir()
        for cmd in (["git", "init", "-q"], ["git", "remote", "add", "origin", url],
                    ["git", "fetch", "-q", "--depth", "1", "origin", sha], ["git", "checkout", "-q", "FETCH_HEAD"]):
            subprocess.run(cmd, cwd=d, check=True)
        print("fetched", name, sha[:10])


def have_public() -> bool:
    return all((PUBLIC / n).exists() for n in SOURCES)


def _is_dev(text: str) -> bool:
    return hashlib.sha256(text.encode()).digest()[0] % 2 == 0


def _csv_prompts(path: Path) -> list:
    csv.field_size_limit(10 ** 9)
    with open(path, encoding="utf-8") as f:
        return [r["prompt"] for r in csv.DictReader(f)]


def load_public() -> dict:
    jb = PUBLIC / "jailbreak_llms" / "data" / "prompts"
    alpaca = json.loads((PUBLIC / "stanford_alpaca" / "alpaca_data.json").read_text(encoding="utf-8"))
    return {
        "jailbreak": _csv_prompts(jb / "jailbreak_prompts_2023_12_25.csv"),
        "regular": _csv_prompts(jb / "regular_prompts_2023_12_25.csv"),
        "alpaca": [(a["instruction"] + "\n" + a["input"]).strip() for a in alpaca],
        "mcp": mcp_descriptions(),
    }


def mcp_descriptions() -> list:
    """Tool and parameter descriptions written into the reference MCP servers (src/**/*.ts and *.py)."""
    out = []
    root = PUBLIC / "mcp_servers" / "src"
    for p in sorted(root.rglob("*")):
        if p.suffix in (".ts", ".py") and "node_modules" not in p.parts and "test" not in p.name.lower():
            s = p.read_text(errors="ignore")
            for m in re.finditer(r"description:\s*(?:\n\s*)?(`[^`]{40,}`|\"[^\"]{40,}\"|'[^']{40,}')", s):
                out.append(m.group(1)[1:-1])
            for m in re.finditer(r'"""([^"]{60,}?)"""', s):
                out.append(m.group(1))
    return out


def _count(det, texts) -> dict:
    blocked = detected = 0
    types = Counter()
    only_override = 0
    for t in texts:
        r = det.scan(t)
        blocked += r.blocked
        detected += r.injection_detected
        if r.blocked:
            kinds = {m.attack_type for m in r.matches if m.severity in ("critical", "high")}
            types.update(kinds)
            only_override += kinds == {"DIRECT_INJECTION"}
    return {"n": len(texts), "blocked": blocked, "detected": detected,
            "blocked_by_type": dict(sorted(types.items())), "blocked_only_by_instruction_override": only_override}


def measure_public() -> dict:
    from injection_cases import MCP_POISONED
    det, data = detector(), load_public()
    jb = data["jailbreak"]
    out = {
        "jailbreak_all": _count(det, jb),
        "jailbreak_dev": _count(det, [x for x in jb if _is_dev(x)]),
        "jailbreak_test": _count(det, [x for x in jb if not _is_dev(x)]),
        "regular_all": _count(det, data["regular"]),
        "alpaca": _count(det, data["alpaca"]),
    }
    sc = mcp_scanner()
    benign = [sc.scan_tool_description("t", d).blocked for d in data["mcp"]]
    poisoned = {f: [sc.scan_tool_description("t", d).blocked for d in ds] for f, ds in MCP_POISONED.items()}
    out["mcp_descriptions"] = {"real_benign": {"n": len(benign), "blocked": sum(benign)},
                               "poisoned": {f: {"n": len(v), "blocked": sum(v)} for f, v in poisoned.items()}}
    return out


# ── output ───────────────────────────────────────────────────────────────────────────────────────────────────

def measure(public: bool = False) -> dict:
    result = {"handwritten_rows": len(build_rows()), "handwritten": measure_handwritten()}
    if public:
        result["sources"] = {k: {"url": u, "commit": c} for k, (u, c) in SOURCES.items()}
        result["public"] = measure_public()
    return result


def _pct(k, n):
    from compare import wilson
    lo, hi = wilson(k, n)
    return f"{k:>6}/{n:<6} {100 * k / n:5.1f}%  ({100 * lo:.1f}-{100 * hi:.1f})"


def main():
    if "--fetch" in sys.argv:
        fetch()
    use_public = "--public" in sys.argv
    if use_public and not have_public():
        sys.exit("public sets missing: run with --fetch first")
    res = measure(use_public)
    hw = res["handwritten"]
    print(f"hand-written: {res['handwritten_rows']} cases")
    print("  attacks blocked      ", _pct(hw["attacks"]["blocked"], hw["attacks"]["n"]))
    for k, v in hw["by_form"].items():
        print(f"     {k:<34}", _pct(v["blocked"], v["n"]))
    for k, v in hw["by_category"].items():
        print(f"     [{k}]".ljust(40), _pct(v["blocked"], v["n"]))
    print("  harmless blocked     ", _pct(hw["harmless"]["blocked"], hw["harmless"]["n"]))
    for k, v in hw["harmless_by_group"].items():
        print(f"     {k:<34}", _pct(v["blocked"], v["n"]))
    for e in hw["harmless_blocked_examples"]:
        print("       blocked:", e)
    if use_public:
        pub = res["public"]
        for k in ("jailbreak_all", "jailbreak_dev", "jailbreak_test", "regular_all", "alpaca"):
            v = pub[k]
            print(f"  {k:<16}", _pct(v["blocked"], v["n"]), f"  detected {v['detected']}  only-by-override {v['blocked_only_by_instruction_override']}")
        m = pub["mcp_descriptions"]
        print("  mcp real benign  ", _pct(m["real_benign"]["blocked"], m["real_benign"]["n"]))
        for f, v in m["poisoned"].items():
            print(f"  mcp poisoned {f:<10}", _pct(v["blocked"], v["n"]))
    if "--write" in sys.argv:
        if not use_public:
            sys.exit("--write needs --public, so the stored file has every number")
        RESULTS_FILE.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
        (HERE / "injection_handwritten.jsonl").write_text(
            "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in build_rows()), encoding="utf-8")
        print("written")


if __name__ == "__main__":
    main()
