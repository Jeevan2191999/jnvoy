"""
Model routing is opt-in and stays inside one provider. Reports make no claim the code
cannot back up. Run:  pytest tests/test_routing_and_claims.py -q
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ADMIN_KEY = "test-admin-key-" + "0" * 24
os.environ["JNVOY_ADMIN_KEYS"] = ADMIN_KEY

from fastapi.testclient import TestClient  # noqa: E402

import api.proxy_v2 as app_module  # noqa: E402
from core.intelligence import QueryComplexity, classify_query  # noqa: E402

client = TestClient(app_module.app)
HEADERS = {"x-api-key": ADMIN_KEY}


def test_routing_is_off_unless_asked_for():
    assert app_module.ProxyRequest(model="gpt-4o", messages=[]).use_routing is False


def test_ordinary_words_do_not_trigger_the_expensive_tier():
    assert classify_query("Summarise the second section") != QueryComplexity.CRITICAL
    assert classify_query("A brisk walk with Jordan and the secretary") != QueryComplexity.CRITICAL
    assert classify_query("Is this contract a legal risk?") == QueryComplexity.CRITICAL


def _body(provider, model, **extra):
    return {"messages": [{"role": "user", "content": "Summarise the second section"}],
            "provider": provider, "model": model, "use_cache": False, **extra}


def test_openai_request_is_never_sent_as_a_claude_model(monkeypatch):
    seen = {}

    async def fake_openai(messages, model, max_tokens, temperature, api_key=None):
        seen["model"] = model
        return "ok"

    monkeypatch.setattr(app_module, "call_openai", fake_openai)
    for extra in ({}, {"use_routing": True}):
        seen.clear()
        r = client.post("/v1/proxy", json=_body("openai", "gpt-4o", **extra), headers=HEADERS)
        assert r.status_code == 200, r.text
        assert seen["model"].startswith("gpt"), (extra, seen)
    # without routing, the caller's model is used exactly
    seen.clear()
    client.post("/v1/proxy", json=_body("openai", "gpt-4o"), headers=HEADERS)
    assert seen["model"] == "gpt-4o"


def test_the_callers_model_is_kept_when_routing_is_off(monkeypatch):
    seen = {}

    async def fake_anthropic(messages, model, max_tokens, api_key=None):
        seen["model"] = model
        return "ok"

    monkeypatch.setattr(app_module, "call_anthropic", fake_anthropic)
    r = client.post("/v1/proxy", json=_body("anthropic", "claude-haiku-4-5"), headers=HEADERS)
    assert r.status_code == 200, r.text
    assert seen["model"] == "claude-haiku-4-5"


def test_reports_do_not_assert_compliance_or_zero_transmission():
    src = Path(app_module.__file__).resolve().parent.parent.joinpath("core", "report.py").read_text()
    for banned in ('"ZERO"', '"Compliant"', "Confirmed by audit log", "open source software",
                   "full compliance", "generate_eu_ai_act_report"):
        assert banned not in src, banned
    assert not any(getattr(r, "path", "").endswith("eu-ai-act") for r in app_module.app.routes)


def test_homepage_makes_no_unbuilt_or_unverifiable_claims():
    page = client.get("/").text
    for banned in ("Series A fintech", "unsolicited", "Slack connector", "every major LLM",
                   "Change one URL", "Acme Financial", "20+ "):
        assert banned not in page, banned
    # the quickstart must show the header a hosted customer needs
    assert "x-provider-key" in page
    # the footer sample report is a real, public file, not an admin route that answers 401
    assert "/v1/report/compliance" not in page
    assert client.get("/static/sample-report.pdf").status_code == 200


def test_readme_matches_what_is_built():
    readme = Path(app_module.__file__).resolve().parent.parent.joinpath("README.md").read_text()
    for banned in ("Google Gemini, Mistral", "fail over", "Slack connector", "eu-ai-act"):
        assert banned not in readme, banned
    assert "source-available, not open source" in readme
    assert "x-provider-key" in readme
