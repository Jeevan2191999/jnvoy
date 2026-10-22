#!/usr/bin/env python3
"""
Rewrites the README so the first screen says what Jnvoy does, who it is for and how to try it,
and fixes the Python / LangChain client, which no longer worked against the server.

Client bug (core/langchain_integration.py):
  * it sent the key as "X-Jnvoy-API-Key", but the server reads "x-api-key", so every call was a 401
  * its scan methods used GET, which now answers 410 (text in a web address gets logged)
  Both are fixed, and tests/test_langchain_integration.py is updated to match, with a new test that
  the text goes in the request body.

Run from the repo root:   python apply_readme_client.py
Safe: every edit must match exactly once, or nothing is written. Re-running is a no-op.
Undo with:  git checkout README.md core/langchain_integration.py tests/test_langchain_integration.py
"""
import sys
from pathlib import Path

README = Path("README.md")
CLIENT = Path("core") / "langchain_integration.py"
TESTS = Path("tests") / "test_langchain_integration.py"

README_TEXT = r'''# Jnvoy

**A privacy and security gateway for LLM traffic.**

Jnvoy sits between your application and any LLM. It finds personal data in prompts, replaces each value with a token before the prompt leaves, puts the real values back into the reply, blocks prompt injection, scans MCP tool traffic, and keeps an audit log of what was found, never the original text.

[Website](https://www.jnvoy.com) | [API docs](https://www.jnvoy.com/docs) | [Privacy and data handling](https://www.jnvoy.com/privacy)

## See it work

What your application sends:

```
Patient NHS number 943 476 5919, DOB 12/03/1984, lives at 14 Elm Road, London SW1A 1AA.
```

What the model receives:

```
Patient NHS number [UK_NHS_1], DOB [DATE_OF_BIRTH_1], lives at [STREET_ADDRESS_1], London [UK_POSTCODE_1].
```

The model answers using the tokens, and Jnvoy swaps the real values back in before the reply reaches you. Cities, organisations and dates stay readable by default so answers stay useful. One setting widens the scope (see Configuration).

## Try it

API keys come from whoever runs the deployment. For the hosted service, get in touch through [jnvoy.com](https://www.jnvoy.com).

```bash
curl -X POST https://www.jnvoy.com/v1/scan \
  -H "x-api-key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '{"text": "My name is John Smith and my NI number is AB123456C"}'
```

Send a protected request to a model:

```bash
curl -X POST https://www.jnvoy.com/v1/proxy \
  -H "x-api-key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '{"model": "claude-haiku-4-5-20251001", "provider": "anthropic",
       "messages": [{"role": "user", "content": "My email is john@example.com. Say hello."}]}'
```

Always send text in the request body. A web address is commonly written to logs.

## Run it yourself

```bash
git clone https://github.com/Jeevan2191999/jnvoy.git
cd jnvoy
cp .env.example .env     # then open .env and set your keys
docker-compose up
```

Generate a key with `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`. Without at least one key in `JNVOY_API_KEYS`, every `/v1` route answers 503 on purpose.

Without Docker: `pip install -r requirements.txt`, then `uvicorn api.proxy_v2:app --port 8000`.

## What it detects

**Personal data** (redacted by default): names, email addresses, phone numbers, payment cards, IBANs, bank account numbers and sort codes, National Insurance and NHS numbers, passport numbers, postcodes and street addresses, dates of birth, reference numbers such as customer or case IDs, IP and MAC addresses, URLs, and credentials such as API keys, tokens, passwords and connection strings.

**Off by default:** organisations, locations, dates and nationalities. Switch them on with `JNVOY_REDACT_EXTRA`.

**Attacks:** direct injection, jailbreaks, system prompt extraction, role confusion, indirect injection, data exfiltration and obfuscation in prompts, and tool poisoning, secret leakage and injection in MCP traffic.

## How well does it work

Detection combines pattern rules, a trained model for names and places, and an optional second check by a language model. It is strong, and it is not guaranteed to catch everything. It can also hide harmless words.

There is a small labelled test set in [`evaluation/`](evaluation/) written by the author. Run it yourself:

```bash
python evaluation/run_eval.py --misses
```

On the hold-out set, the optional second check raised recall from 93% to 100% of sensitive values. That set is small and was used while tuning the rules, so treat the number as indicative. The second check adds about a second per request and sends the already-redacted text to Anthropic. It is off by default.

## API

All `/v1` routes need an `x-api-key` header. Routes marked admin need an admin key.

| Route | What it does | Key |
|---|---|---|
| `GET /health` | Service status | none |
| `POST /v1/proxy` | Send a prompt to a model with personal data removed | client |
| `POST /v1/scan` | Scan text for personal data | client |
| `POST /v1/scan/injection` | Scan text for prompt injection | client |
| `POST /v1/mcp/scan` | Scan an MCP message for threats | client |
| `POST /v1/mcp/scan/tool-response` | Scan an MCP tool response | client |
| `POST /v1/mcp/scan/tool-description` | Scan an MCP tool description for poisoning | client |
| `GET /v1/audit`, `GET /v1/audit/summary` | Read the audit log | admin |
| `GET /v1/report/compliance` | Compliance report (PDF) | admin |
| `GET /v1/report/eu-ai-act` | EU AI Act report (PDF) | admin |
| `GET /v1/cache/stats`, `DELETE /v1/cache` | Response cache statistics and reset | admin |
| `GET /v1/providers/health` | Model provider health | admin |

Full request and response details, with an Authorize button for trying calls, are at [/docs](https://www.jnvoy.com/docs).

## Configuration

| Variable | Purpose |
|---|---|
| `JNVOY_API_KEYS` | Client keys, comma separated, at least 24 characters each |
| `JNVOY_ADMIN_KEYS` | Admin keys, comma separated |
| `JNVOY_RATE_LIMIT_PER_MIN` | Requests per key per minute. Default 60, `0` for no limit |
| `JNVOY_AUTH=off` | Switches authentication off. Local development only |
| `JNVOY_REDACT_EXTRA` | `ORGANIZATION`, `LOCATION`, `DATE_TIME`, `NRP`, or `all` |
| `JNVOY_JUDGE_BACKEND` | Second check: `none` (default), `ollama` or `anthropic` |
| `JNVOY_JUDGE_FAIL_MODE` | If the second check fails: `open` (default) keeps first-pass redaction, `closed` rejects the request |
| `DATABASE_URL` | PostgreSQL for the audit log. Without it, an in-memory log is used |
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`, `MISTRAL_API_KEY` | Provider keys for the models you use |

## Python and LangChain

```bash
pip install langchain-core httpx
```

```python
from core.langchain_integration import JnvoyChat
from langchain_core.messages import HumanMessage

chat = JnvoyChat(
    jnvoy_url="https://www.jnvoy.com",
    api_key="YOUR_KEY",          # or set JNVOY_API_KEY
    provider="anthropic",
    model="claude-haiku-4-5-20251001",
)
print(chat.invoke([HumanMessage(content="My email is john@example.com. Say hello.")]).content)
```

## Providers

Anthropic Claude, OpenAI, Google Gemini, Mistral, Azure OpenAI, and local models through Ollama. If a provider is down, requests can fail over to another.

## Other pieces

A Slack connector in [`connectors/`](connectors/) protects messages to AI bots in a Slack workspace. A Docker stack starts the API and PostgreSQL together.

## Tests

```bash
pytest -q
```

## Security

To report a vulnerability, email j.nagaraj2109@gmail.com. Please do not open a public issue for it.

## About

Built by Jeevan Nagaraj. Operated by JNVOY LIMITED, registered in England and Wales, company number 17536574.

Licensed under the Business Source License 1.1. See [LICENSE](LICENSE). It converts to Apache 2.0 after four years.
'''

SCAN_OLD = (
    "        response = httpx.get(\n"
    '            f"{self.jnvoy_url}/v1/scan",\n'
    '            params={"text": text},\n'
)
SCAN_NEW = (
    "        response = httpx.post(\n"
    '            f"{self.jnvoy_url}/v1/scan",\n'
    '            json={"text": text},\n'
)
INJ_OLD = (
    "        response = httpx.get(\n"
    '            f"{self.jnvoy_url}/v1/scan/injection",\n'
    '            params={"text": text},\n'
)
INJ_NEW = (
    "        response = httpx.post(\n"
    '            f"{self.jnvoy_url}/v1/scan/injection",\n'
    '            json={"text": text},\n'
)

NEW_TEST = '''

def test_scans_send_text_in_the_body_not_the_url():
    from core.langchain_integration import JnvoyClient

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {}
    with patch("httpx.post", return_value=mock_response) as post:
        client = JnvoyClient(api_key="k" * 24)
        client.scan_pii("secret text")
        client.scan_injection("secret text")
    assert post.call_count == 2
    for call in post.call_args_list:
        assert call.kwargs["json"] == {"text": "secret text"}
        assert "params" not in call.kwargs
        assert call.kwargs["headers"]["x-api-key"] == "k" * 24
'''

CLIENT_EDITS = [
    ('            headers["X-Jnvoy-API-Key"] = self.api_key\n', '            headers["x-api-key"] = self.api_key\n', 1),
    (SCAN_OLD, SCAN_NEW, 1),
    (INJ_OLD, INJ_NEW, 1),
]
TEST_EDITS = [
    ('    assert "X-Jnvoy-API-Key" not in headers\n', '    assert "x-api-key" not in headers\n', 1),
    ('    assert headers["X-Jnvoy-API-Key"] == "test-key-123"\n', '    assert headers["x-api-key"] == "test-key-123"\n', 1),
    ('    with patch("httpx.get", return_value=mock_response):\n', '    with patch("httpx.post", return_value=mock_response):\n', 2),
]


def plan(path, edits):
    src = path.read_bytes().decode("utf-8")
    for number, (old, _new, expected) in enumerate(edits, start=1):
        found = src.count(old)
        if found != expected:
            print(f"{path} edit {number}: expected {expected} match(es), found {found}. NOTHING WAS CHANGED.")
            print(f"Send me:  grep -n 'X-Jnvoy\\|httpx.get' {path}")
            return None
    for old, new, _ in edits:
        src = src.replace(old, new)
    return src


def main() -> int:
    for p in (README, CLIENT, TESTS):
        if not p.exists():
            print(f"Cannot find {p}. Run this from the repo root.")
            return 1
    if "x-api-key" in CLIENT.read_bytes().decode("utf-8"):
        print("Already applied. Nothing to do.")
        return 0
    if not README.read_bytes().decode("utf-8").startswith("# Jnvoy: privacy and security gateway"):
        print("README.md is not the version I expected (it may have been edited). NOTHING WAS CHANGED.")
        print("Send me:  head -5 README.md")
        return 1
    client_src = plan(CLIENT, CLIENT_EDITS)
    tests_src = plan(TESTS, TEST_EDITS)
    if client_src is None or tests_src is None:
        return 1
    README.write_bytes(README_TEXT.encode("utf-8"))
    CLIENT.write_bytes(client_src.encode("utf-8"))
    TESTS.write_bytes((tests_src.rstrip() + "\n" + NEW_TEST).encode("utf-8"))
    print("Applied: README rewritten, Python/LangChain client fixed (x-api-key, POST scans), tests updated.")
    print("Next:  pytest -q")
    return 0


if __name__ == "__main__":
    sys.exit(main())
