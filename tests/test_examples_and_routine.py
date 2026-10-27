"""The quickstart, the example scripts and the monthly dependency routine."""

import importlib.util
import os
import re
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _load(path):
    spec = importlib.util.spec_from_file_location(Path(path).stem, ROOT / path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── the example scripts ───────────────────────────────────────────────────────

def test_the_scan_example_works_against_the_real_app(monkeypatch):
    key = "ex-quick-key-" + "2" * 27
    monkeypatch.setenv("JNVOY_API_KEYS", key)
    monkeypatch.setenv("JNVOY_RATE_LIMIT_PER_MIN", "0")
    import api.proxy_v2 as app_module
    from fastapi.testclient import TestClient

    demo = _load("examples/see_redaction.py")
    client = TestClient(app_module.app)
    client.headers.update({"x-forwarded-for": "203.0.113.99"})
    report = demo.scan(demo.SAMPLE, key, "http://testserver", client=client)
    out = demo.show(demo.SAMPLE, report)
    assert "anna.lee@example.com" in out.split("What the model would receive:")[0]
    assert "anna.lee@example.com" not in out.split("What the model would receive:")[1]
    assert "EMAIL_ADDRESS" in out


def test_the_scan_example_explains_a_missing_key(monkeypatch, capsys):
    monkeypatch.delenv("JNVOY_API_KEY", raising=False)
    demo = _load("examples/see_redaction.py")
    assert demo.main(["x"]) == 2
    assert "JNVOY_API_KEY" in capsys.readouterr().err


def test_the_chat_example_explains_missing_keys_and_builds_a_client(monkeypatch, capsys):
    monkeypatch.delenv("JNVOY_API_KEY", raising=False)
    monkeypatch.delenv("PROVIDER_KEY", raising=False)
    demo = _load("examples/chat_demo.py")
    assert demo.main(["x"]) == 2
    assert "PROVIDER_KEY" in capsys.readouterr().err
    pytest.importorskip("openai")
    c = demo.make_client("jnvoy-key", "provider-key", "https://example.test")
    assert str(c.base_url).rstrip("/") == "https://example.test/v1"


def test_the_prompt_in_the_chat_example_contains_values_jnvoy_should_hide():
    from core.detector_v2 import PIIDetectorV2
    demo = _load("examples/chat_demo.py")
    found = PIIDetectorV2().detect(demo.PROMPT).summary
    assert "EMAIL_ADDRESS" in found and "PHONE_NUMBER" in found


# ── the quickstart ────────────────────────────────────────────────────────────

QUICK = (ROOT / "QUICKSTART.md").read_text(encoding="utf-8")


def test_quickstart_points_at_things_that_exist():
    for rel in re.findall(r"\]\((examples/[^)]+)\)", QUICK):
        assert (ROOT / rel).exists(), rel
    for path in re.findall(r"https://www\.jnvoy\.com(/[a-z0-9/]+)", QUICK):
        assert path in {"/v1", "/v1/scan", "/privacy", "/security", "/accuracy"}, path


def test_quickstart_claims_match_the_code():
    from core.tenants import TIER_LIMITS
    assert TIER_LIMITS["free"] == 10_000 and "10,000 calls a month" in QUICK
    import api.openai_compat as oc
    assert oc.provider_for("claude-haiku-4-5") == "anthropic" and oc.provider_for("gpt-4o") == "openai"
    assert not re.search(r"sk-[A-Za-z0-9_-]{20,}", QUICK)


def test_homepage_and_readme_no_longer_say_streaming_is_missing():
    for name in ("static/index.html", "README.md"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "not streamed" not in text.lower(), name
        assert "QUICKSTART.md" in text, name


# ── the monthly dependency routine ────────────────────────────────────────────

SCRIPT = _load("scripts/refresh_constraints.py")


def test_refreshing_from_the_current_environment_changes_nothing():
    existing = (ROOT / "constraints.txt").read_text()
    pins = [l for l in existing.splitlines() if l and not l.startswith("#")]
    noisy = pins + ["en_core_web_lg @ https://example.test/x.whl", "en-core-web-sm==3.7.1",
                    "setuptools==80.0.0", "pip==25.0", "-e git+https://example.test/x#egg=x"]
    assert SCRIPT.refresh("\n".join(reversed(noisy)), existing) == existing


def test_a_new_version_shows_up_and_the_header_is_kept():
    existing = "# header one\n# header two\nfoo==1.0\nbar==2.0\n"
    out = SCRIPT.refresh("bar==2.1\nfoo==1.0\nBaz==0.3\n", existing)
    assert out == "# header one\n# header two\nbar==2.1\nBaz==0.3\nfoo==1.0\n"


def test_an_unexpected_line_stops_the_refresh_instead_of_being_written():
    with pytest.raises(SystemExit):
        SCRIPT.refresh("foo>=1.0\n", "")


def test_the_monthly_workflow_runs_the_tests_before_it_writes_anything():
    wf = yaml.safe_load((ROOT / ".github/workflows/refresh-pins.yml").read_text())
    triggers = wf.get(True) or wf.get("on")
    assert triggers["schedule"][0]["cron"].split()[2] == "1" and "workflow_dispatch" in triggers
    steps = wf["jobs"]["refresh"]["steps"]
    names = [s.get("name", "") for s in steps]
    run_tests = next(i for i, n in enumerate(names) if n.startswith("Run the full tests"))
    write = next(i for i, n in enumerate(names) if n.startswith("Write the new constraints"))
    assert run_tests < write
    assert "pytest -q" in steps[run_tests]["run"]
    assert wf["permissions"] == {"contents": "write", "pull-requests": "write"}
    assert "services" in wf["jobs"]["refresh"] and "DATABASE_URL" in wf["jobs"]["refresh"]["env"]


def test_dependabot_no_longer_sends_one_package_pull_requests_that_cannot_pass():
    cfg = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text())
    pip = next(u for u in cfg["updates"] if u["package-ecosystem"] == "pip")
    assert pip["open-pull-requests-limit"] == 0


def test_the_runbook_explains_the_routine():
    text = (ROOT / "RUNBOOK.md").read_text()
    assert "refresh-pins" in text and "scripts/refresh_constraints.py" in text
