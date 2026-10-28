"""Using Jnvoy from LiteLLM: the page, the example files, and the exact requests LiteLLM sends.

LiteLLM itself is not installed in CI. The request bodies below were captured from LiteLLM 1.106.5
(litellm.completion pointed at an OpenAI-compatible server, with extra_headers set), then replayed here.
"""

import html
import importlib.util
import json
import re
import sys
import uuid
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import api.proxy_v2 as app_module  # noqa: E402

PATH = "/guides/litellm"
OPERATOR = "ll-operator-key-" + "7" * 24
ADMIN = "ll-admin-key-" + "8" * 28
PROVIDER_KEY = "sk-litellm-test-provider-key"


def _load(rel):
    spec = importlib.util.spec_from_file_location(Path(rel).stem, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── the page ──────────────────────────────────────────────────────────────────

def test_the_page_is_served_with_search_metadata():
    r = TestClient(app_module.app).get(PATH)
    assert r.status_code == 200
    h = r.text
    assert f'rel="canonical" href="https://www.jnvoy.com{PATH}"' in h
    assert "<title>Use Jnvoy with LiteLLM</title>" in h
    assert h.count("<h1>") == 1 and 'name="description"' in h
    assert 'property="og:title"' in h and 'name="twitter:card"' in h
    assert "remove-personal-data-from-prompts" not in re.search(r"<head>.*?</head>", h, re.S).group(0)


def test_the_page_is_in_the_sitemap_and_linked_from_every_page():
    c = TestClient(app_module.app)
    assert f"https://www.jnvoy.com{PATH}" in c.get("/sitemap.xml").text
    for path in ("/", "/privacy", "/security", "/accuracy", "/guides/remove-personal-data-from-prompts", PATH):
        assert f'href="{PATH}"' in c.get(path).text, path


def test_the_config_files_are_shown_on_the_page_exactly_as_shipped():
    page = TestClient(app_module.app).get(PATH).text
    for name in ("litellm_config.yaml", "litellm_config_per_user.yaml"):
        text = (ROOT / "examples" / name).read_text(encoding="utf-8").rstrip("\n")
        assert html.escape(text, quote=True) in page, name


def test_the_page_makes_no_overclaim_and_states_the_limits():
    text = TestClient(app_module.app).get(PATH).text.lower()
    for banned in ("100% accurate", "guaranteed", "gdpr compliant", "certified", "zero risk"):
        assert banned not in text, banned
    assert "no tool catches everything" in text
    assert "token counts show as zero" in text
    assert "litellm itself" in text and "still sees the original text" in text


def test_the_sdk_snippet_is_the_same_on_the_page_and_in_the_readme():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    page = html.unescape(TestClient(app_module.app).get(PATH).text)
    for line in ('model="openai/gpt-4o-mini"', 'api_base="https://www.jnvoy.com/v1"',
                 'extra_headers={"x-provider-key"'):
        assert line in readme and line in page, line
    assert "/guides/litellm" in readme


# ── the example files ─────────────────────────────────────────────────────────

def _models(name):
    return yaml.safe_load((ROOT / "examples" / name).read_text(encoding="utf-8"))


def test_the_proxy_config_points_every_model_at_jnvoy_with_keys_from_the_environment():
    cfg = _models("litellm_config.yaml")
    assert len(cfg["model_list"]) >= 2
    for entry in cfg["model_list"]:
        p = entry["litellm_params"]
        assert p["model"].startswith("openai/")
        assert p["api_base"] == "https://www.jnvoy.com/v1"
        assert p["api_key"] == "os.environ/JNVOY_API_KEY"
        assert p["extra_headers"]["x-provider-key"].startswith("os.environ/")
    from api import openai_compat as oc
    names = {e["litellm_params"]["model"].split("/", 1)[1] for e in cfg["model_list"]}
    assert {oc.provider_for(n) for n in names} == {"openai", "anthropic"}     # one model for each provider


def test_the_per_user_config_forwards_the_callers_header_and_holds_no_provider_key():
    cfg = _models("litellm_config_per_user.yaml")
    assert cfg["general_settings"]["forward_client_headers_to_llm_api"] is True
    for entry in cfg["model_list"]:
        p = entry["litellm_params"]
        assert p["api_base"].endswith("/v1") and p["api_key"].startswith("os.environ/")
        assert "extra_headers" not in p
    assert not re.search(r"sk-[A-Za-z0-9_-]{20,}", (ROOT / "examples" / "litellm_config_per_user.yaml").read_text())


def test_no_example_file_contains_a_real_looking_key():
    for name in ("litellm_demo.py", "litellm_config.yaml", "litellm_config_per_user.yaml"):
        assert not re.search(r"sk-[A-Za-z0-9_-]{20,}", (ROOT / "examples" / name).read_text()), name


def test_the_demo_script_builds_the_arguments_litellm_needs():
    demo = _load("examples/litellm_demo.py")
    args = demo.call_args("jk", "pk", "gpt-4o-mini", base_url="https://example.test/")
    assert args == {"model": "openai/gpt-4o-mini", "api_base": "https://example.test/v1", "api_key": "jk",
                    "extra_headers": {"x-provider-key": "pk"}}
    assert demo.call_args("jk", "pk")["api_base"] == demo.BASE_URL.rstrip("/") + "/v1"


def test_the_demo_prompt_contains_values_jnvoy_should_hide():
    from core.detector_v2 import PIIDetectorV2
    found = PIIDetectorV2().detect(_load("examples/litellm_demo.py").PROMPT).summary
    assert "EMAIL_ADDRESS" in found and "PHONE_NUMBER" in found


def test_the_demo_script_asks_for_keys_instead_of_crashing(monkeypatch, capsys):
    monkeypatch.delenv("JNVOY_API_KEY", raising=False)
    monkeypatch.delenv("PROVIDER_KEY", raising=False)
    assert _load("examples/litellm_demo.py").main(["litellm_demo.py"]) == 2
    assert "JNVOY_API_KEY" in capsys.readouterr().err


# ── what LiteLLM really sends, replayed against the app ───────────────────────

SYSTEM = {"role": "system", "content": "Be brief."}
USER = {"role": "user", "content": "Write to anna.lee@example.com about invoice 5521."}
TOOL = {"type": "function", "function": {"name": "get_weather", "description": "w",
                                         "parameters": {"type": "object", "properties": {"city": {"type": "string"}}}}}

CAPTURED = {                                    # bodies LiteLLM 1.106.5 sent, with the user text swapped
    "plain": {"messages": [SYSTEM, USER], "model": "gpt-4o-mini"},
    "stream": {"messages": [SYSTEM, USER], "model": "gpt-4o-mini", "stream": True},
    "stream_usage": {"messages": [SYSTEM, USER], "model": "gpt-4o-mini", "stream": True,
                     "stream_options": {"include_usage": True}},
    "tools": {"messages": [SYSTEM, USER], "model": "gpt-4o-mini", "tool_choice": "auto", "tools": [TOOL]},
    "params": {"messages": [SYSTEM, USER], "model": "gpt-4o-mini", "max_tokens": 50, "stop": ["x"],
               "temperature": 0.2, "top_p": 0.9, "user": "u1"},
}
LITELLM_HEADERS = {"authorization": f"Bearer {OPERATOR}", "content-type": "application/json",
                   "x-provider-key": PROVIDER_KEY}


@pytest.fixture()
def jnvoy(monkeypatch):
    for k, v in {"JNVOY_API_KEYS": OPERATOR, "JNVOY_ADMIN_KEYS": ADMIN, "JNVOY_RATE_LIMIT_PER_MIN": "0"}.items():
        monkeypatch.setenv(k, v)
    seen = {}

    async def text_model(messages, model, max_tokens, temperature, api_key=None):
        seen.update(path="text", messages=messages, model=model, key=api_key)
        return "Hello from the fake model."

    async def tool_model(messages, model, max_tokens, temperature, tools, tool_choice, parallel, api_key=None):
        seen.update(path="tools", messages=messages, model=model, key=api_key, tools=tools)
        return {"content": None, "finish_reason": "tool_calls",
                "tool_calls": [{"id": "call_1", "name": "get_weather", "arguments": '{"city": "Paris"}'}]}

    class Upstream:
        async def pieces(self):
            for piece in ("Hello from ", "the fake model."):
                yield piece

        async def aclose(self):
            pass

    async def open_stream(provider, messages, model, max_tokens, temperature, api_key=None):
        seen.update(path="stream", messages=messages, model=model, key=api_key)
        return Upstream()

    monkeypatch.setattr(app_module, "call_openai", text_model)
    monkeypatch.setattr(app_module, "open_upstream_stream", open_stream)
    monkeypatch.setattr(app_module, "call_openai_tools", tool_model)
    c = TestClient(app_module.app)
    c.headers.update({"x-forwarded-for": "203.0.113.77"})
    return c, seen


def _post(c, name):
    body = json.loads(json.dumps(CAPTURED[name]))
    body["messages"][1]["content"] += " Reference " + uuid.uuid4().hex   # a fresh prompt, so Jnvoy's cache is not used
    return c.post("/v1/chat/completions", headers=LITELLM_HEADERS, json=body)


def test_a_plain_litellm_call_is_redacted_and_the_provider_key_reaches_the_model_call(jnvoy):
    c, seen = jnvoy
    r = _post(c, "plain")
    assert r.status_code == 200 and r.json()["choices"][0]["message"]["content"] == "Hello from the fake model."
    sent = json.dumps(seen["messages"])
    assert "anna.lee@example.com" not in sent and "[EMAIL_ADDRESS_1]" in sent
    assert seen["key"] == PROVIDER_KEY and seen["model"] == "gpt-4o-mini"


@pytest.mark.parametrize("name", ["stream", "stream_usage"])
def test_a_streamed_litellm_call_arrives_as_server_sent_events(jnvoy, name):
    c, seen = jnvoy
    r = _post(c, name)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
    chunks = [json.loads(line[6:]) for line in r.text.splitlines() if line.startswith("data: ") and "[DONE]" not in line]
    assert "".join(ch["choices"][0]["delta"].get("content") or "" for ch in chunks if ch["choices"]) \
        == "Hello from the fake model."
    assert r.text.rstrip().endswith("data: [DONE]")
    assert "anna.lee@example.com" not in json.dumps(seen["messages"]) and seen["key"] == PROVIDER_KEY


def test_a_litellm_tool_call_comes_back_as_tool_calls(jnvoy):
    c, seen = jnvoy
    r = _post(c, "tools")
    assert r.status_code == 200
    choice = r.json()["choices"][0]
    assert choice["finish_reason"] == "tool_calls"
    call = choice["message"]["tool_calls"][0]
    assert call["function"]["name"] == "get_weather" and json.loads(call["function"]["arguments"]) == {"city": "Paris"}
    assert seen["path"] == "tools" and "anna.lee@example.com" not in json.dumps(seen["messages"])


def test_ordinary_litellm_parameters_are_accepted(jnvoy):
    c, _ = jnvoy
    r = _post(c, "params")
    assert r.status_code == 200, r.text


def test_the_reply_has_the_fields_litellm_reads(jnvoy):
    c, _ = jnvoy
    body = _post(c, "plain").json()
    assert body["object"] == "chat.completion" and body["choices"][0]["message"]["role"] == "assistant"
    assert body["choices"][0]["finish_reason"] == "stop" and "id" in body and "created" in body
    assert "jnvoy" in body                                   # extra field, which LiteLLM passes through


def test_a_wrong_key_is_a_401_that_names_both_ways_to_send_a_key(jnvoy):
    c, _ = jnvoy
    r = c.post("/v1/chat/completions", json=CAPTURED["plain"],
               headers={**LITELLM_HEADERS, "authorization": "Bearer " + "z" * 30})
    assert r.status_code == 401 and r.json()["error"] == "invalid_api_key"
    assert "x-api-key" in r.json()["message"] and "Bearer" in r.json()["message"]
