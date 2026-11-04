"""The evaluation tools themselves: statistics, the datasets, and the bring-your-own-data checker.

If these were wrong, every accuracy figure we publish would be wrong, so they are tested like code.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
EVAL = ROOT / "evaluation"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(EVAL))

import check_my_data  # noqa: E402
import compare  # noqa: E402
from run_eval import leaked, load_rows  # noqa: E402

RESULTS = json.loads((EVAL / "results_large.json").read_text(encoding="utf-8"))


# ---- statistics ----------------------------------------------------------------------------

def test_wilson_interval_matches_known_values():
    lo, hi = compare.wilson(50, 100)
    assert (round(lo, 3), round(hi, 3)) == (0.404, 0.596)
    lo, hi = compare.wilson(0, 10)
    assert lo == 0.0 and round(hi, 3) == 0.278
    lo, hi = compare.wilson(10, 10)
    assert hi == 1.0 and round(lo, 3) == 0.722
    assert compare.wilson(0, 0) == (0.0, 1.0)


def test_interval_narrows_as_the_sample_grows():
    small = compare.wilson(15, 20)
    large = compare.wilson(750, 1000)
    assert (large[1] - large[0]) < (small[1] - small[0]) / 4


def test_mcnemar_exact_known_values():
    assert compare.mcnemar_exact(0, 0) == 1.0
    assert compare.mcnemar_exact(5, 5) == 1.0
    assert round(compare.mcnemar_exact(0, 10), 6) == round(2 / 1024, 6)
    assert compare.mcnemar_exact(10, 0) == compare.mcnemar_exact(0, 10)
    assert compare.mcnemar_exact(228, 114) < 0.001


# ---- the datasets --------------------------------------------------------------------------

@pytest.mark.parametrize("name, docs", [("large.jsonl", 1000), ("large_heldout.jsonl", 600), ("large_fresh.jsonl", 600), ("large_fresh2.jsonl", 600)])
def test_dataset_is_well_formed(name, docs):
    rows = load_rows(EVAL / name)
    assert len(rows) == docs
    assert len({r["id"] for r in rows}) == docs, "ids must be unique"
    for r in rows:
        for s in r["sensitive"]:
            assert s["value"] in r["text"], (r["id"], s)
            assert s["type"], (r["id"], s)
        for k in r["keep"]:
            assert k in r["text"], (r["id"], k)
    assert any(not r["sensitive"] for r in rows), "the set must include documents with nothing sensitive"


def test_the_sets_share_no_document_that_contains_a_sensitive_value():
    # A harmless-only sentence can coincide (a handful of fixed templates), which cannot inflate a score.
    # A shared document with a sensitive value could, so none may be shared.
    sets = [{r["text"] for r in load_rows(EVAL / n) if r["sensitive"]}
            for n in ("large.jsonl", "large_heldout.jsonl", "large_fresh.jsonl", "large_fresh2.jsonl")]
    assert all(not (a & b) for i, a in enumerate(sets) for b in sets[i + 1:])


def test_secret_looking_values_cannot_trip_a_secret_scanner():
    # Keys and passwords carry a "<>" break so the repository holds no unbroken secret-shaped string.
    for name in ("large.jsonl", "large_heldout.jsonl", "large_fresh.jsonl", "large_fresh2.jsonl"):
        text = (EVAL / name).read_text(encoding="utf-8")
        assert not re.search(r"\bsk-[A-Za-z0-9]{20,}", text)
        assert not re.search(r"\bAKIA[0-9A-Z]{16}\b", text)
        assert not re.search(r"\bghp_[A-Za-z0-9]{30,}", text)


@pytest.mark.parametrize("key, name", [("large", "large.jsonl"), ("large_heldout", "large_heldout.jsonl"),
                                       ("large_fresh", "large_fresh.jsonl"), ("large_fresh2", "large_fresh2.jsonl")])
def test_results_file_describes_the_committed_datasets(key, name):
    md5 = hashlib.md5((EVAL / name).read_bytes()).hexdigest()
    assert RESULTS["sets"][key]["md5"] == md5, (
        f"{name} changed but results_large.json was not re-measured. Run compare.py and "
        "scripts/render_independent_accuracy.py --write")


def test_the_same_seed_regenerates_the_same_file(tmp_path):
    pytest.importorskip("faker")
    from importlib.metadata import version
    have = version("faker")
    if have != RESULTS["versions"]["faker"]:
        pytest.skip(f"the files were generated with Faker {RESULTS['versions']['faker']}, this is {have}")
    import subprocess
    out = tmp_path / "again.jsonl"
    subprocess.run([sys.executable, str(EVAL / "generate_large.py"), "--out", str(out)], check=True,
                   capture_output=True, timeout=300)
    assert hashlib.md5(out.read_bytes()).hexdigest() == RESULTS["sets"]["large"]["md5"]
    fresh = tmp_path / "fresh.jsonl"
    subprocess.run([sys.executable, str(EVAL / "generate_large.py"), "--seed", "9090", "--docs", "600",
                    "--phrasing", "fresh", "--out", str(fresh)], check=True, capture_output=True, timeout=300)
    assert hashlib.md5(fresh.read_bytes()).hexdigest() == RESULTS["sets"]["large_fresh"]["md5"]
    fresh2 = tmp_path / "fresh2.jsonl"
    subprocess.run([sys.executable, str(EVAL / "generate_large.py"), "--seed", "31337", "--docs", "600",
                    "--phrasing", "fresh2", "--out", str(fresh2)], check=True, capture_output=True, timeout=300)
    assert hashlib.md5(fresh2.read_bytes()).hexdigest() == RESULTS["sets"]["large_fresh2"]["md5"]


def test_the_generator_does_not_depend_on_todays_date():
    # Faker's date_of_birth counts back from today, which made the same seed give a different file each day.
    source = (EVAL / "generate_large.py").read_text(encoding="utf-8")
    assert ".date_of_birth(" not in source
    assert "REFERENCE_DAY" in source and "date.today" not in source and "datetime.now" not in source


def test_the_fresh_set_really_uses_different_wording():
    pytest.importorskip("faker")
    import generate_large
    original = {r["text"] for r in load_rows(EVAL / "large.jsonl")}
    fresh = [r["text"] for r in load_rows(EVAL / "large_fresh.jsonl")]
    # none of the sentence templates of the fresh set appear in the development set
    assert not any("Parcel for" in t or "Cc'd" in t or "Wi-Fi key" in t for t in original)
    assert any("Parcel for" in t or "Cc'd" in t or "Wi-Fi key" in t for t in fresh)
    assert generate_large.FRESH2.keys() >= {"PERSON", "PHONE", "ADDRESS", "CARD", "PASSWORD", "DOB", "SSN"}
    assert generate_large.FRESH.keys() >= {"PERSON", "EMAIL", "PHONE", "ADDRESS", "CARD", "PASSWORD", "DOB", "API_KEY"}


# ---- the scoring rule ----------------------------------------------------------------------

def test_a_visible_fragment_counts_as_a_leak():
    assert leaked("Jane Smith", "Dear [PERSON], thanks") is False
    assert leaked("Jane Smith", "Dear Smith, thanks") is True
    assert leaked("4111 1111 1111 1111", "card 4111 1111 1111 [CARD]") is True
    assert leaked("4111 1111 1111 1111", "card [CARD]") is False


# ---- check_my_data -------------------------------------------------------------------------

def test_the_example_csv_loads():
    rows = check_my_data.load_user_rows(EVAL / "example_my_data.csv")
    assert rows and all(r["text"] for r in rows)
    assert any(s["type"] == "PERSON" for r in rows for s in r["sensitive"])


def test_csv_values_and_types_are_parsed(tmp_path):
    f = tmp_path / "d.csv"
    f.write_text('text,sensitive,keep\n"Hi Jane Smith, card 4111 1111 1111 1111 at Acme",PERSON::Jane Smith || CARD::4111 1111 1111 1111,Acme\n'
                 '"plain value 12345",12345,\n', encoding="utf-8")
    rows = check_my_data.load_user_rows(f)
    assert rows[0]["sensitive"] == [{"value": "Jane Smith", "type": "PERSON"}, {"value": "4111 1111 1111 1111", "type": "CARD"}]
    assert rows[0]["keep"] == ["Acme"]
    assert rows[1]["sensitive"] == [{"value": "12345", "type": "VALUE"}]


def test_jsonl_input_is_accepted(tmp_path):
    f = tmp_path / "d.jsonl"
    f.write_text(json.dumps({"id": "a", "text": "mail bob@example.org", "sensitive": [{"value": "bob@example.org", "type": "EMAIL"}]}) + "\n",
                 encoding="utf-8")
    rows = check_my_data.load_user_rows(f)
    assert rows[0]["id"] == "a" and rows[0]["keep"] == []


def test_a_label_that_is_not_in_the_text_is_refused_not_silently_scored(tmp_path):
    f = tmp_path / "bad.csv"
    f.write_text('text,sensitive,keep\n"hello world",secret-not-here,\n', encoding="utf-8")
    with pytest.raises(ValueError, match="not in its text"):
        check_my_data.load_user_rows(f)


def test_missing_text_column_and_empty_files_are_refused(tmp_path):
    f = tmp_path / "bad.csv"
    f.write_text("body,sensitive\nhello,x\n", encoding="utf-8")
    with pytest.raises(ValueError, match="text"):
        check_my_data.load_user_rows(f)
    e = tmp_path / "empty.jsonl"
    e.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="no documents"):
        check_my_data.load_user_rows(e)


def test_the_command_reports_a_bad_file_with_exit_code_2(tmp_path, monkeypatch, capsys):
    f = tmp_path / "bad.csv"
    f.write_text('text,sensitive,keep\n"hello",nope,\n', encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["check_my_data.py", str(f)])
    assert check_my_data.main() == 2
    assert "Cannot read" in capsys.readouterr().err


def test_compare_runs_end_to_end_on_a_small_slice_without_presidio():
    rows = load_rows(EVAL / "large.jsonl")[:25]
    lines = []
    result = compare.run(rows, presidio=False, out=lines.append)
    j = result["systems"]["jnvoy"]
    assert j["n"] == sum(len(r["sensitive"]) for r in rows)
    assert 0 <= j["caught"] <= j["n"]
    lo, hi = j["caught_ci95"]
    assert lo <= j["caught"] / j["n"] <= hi
    assert any("CAUGHT" in line for line in lines)
