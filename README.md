# Jnvoy

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

**National identifiers, by region.** Beyond the UK and US rules, Jnvoy recognises these. Each is accepted only when its own check digit is valid, and plain-digit numbers are only reported next to a telling word (for example "Aadhaar" or "TFN"), so ordinary numbers are left alone.

| Region | Identifiers |
|---|---|
| United Kingdom | National Insurance, NHS number, postcode, sort code and account number, passport |
| United States | Social Security number, ITIN, passport, driver's licence, bank account, ZIP code |
| European Union | Germany tax ID and pension number, Spain NIF and NIE, Italy codice fiscale, Poland PESEL, Sweden personnummer, Finland henkilötunnus, France NIR, Netherlands BSN |
| India | Aadhaar, PAN |
| Australia | Tax file number, Medicare number |
| Canada | Social Insurance Number |
| Singapore | NRIC and FIN |
| China | Resident identity card number |
| South Korea | Resident registration number |
| Thailand, Turkey | National ID numbers |
| Brazil | CPF |
| United Arab Emirates | Emirates ID |
| South Africa | ID number |

All regions are on by default. Restrict them with `JNVOY_REGIONS` (for example `in,au,sg`, `eu`, or `none`). They are tested against published sample numbers (`evaluation/regions.jsonl`); accuracy on real data has not been measured. Names are detected best in English and street addresses in UK and US formats. If your country is missing, open an issue with the identifier.

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
| `GET /v1/me` | Your plan, this month's usage and your settings | client |
| `GET /v1/me/audit` (`?format=csv` to export), `GET /v1/me/audit/summary` | Your own audit log | client |
| `GET /v1/me/report/compliance` | Your own compliance report (PDF) | client |
| `POST/GET /v1/admin/tenants`, `GET/PATCH/DELETE /v1/admin/tenants/{id}`, `POST /v1/admin/tenants/{id}/rotate-key` | Create and manage customers and their keys | admin |
| `GET /v1/audit`, `GET /v1/audit/summary` | Read any customer's audit log (`?tenant_id=`) | admin |
| `GET /v1/report/compliance` | Compliance report (PDF) | admin |
| `GET /v1/report/eu-ai-act` | EU AI Act report (PDF) | admin |
| `GET /v1/cache/stats`, `DELETE /v1/cache` | Response cache statistics and reset | admin |
| `GET /v1/providers/health` | Model provider health | admin |

### Scanning the model's reply

Jnvoy also checks what the model sends back, before your values are put back in. It looks for credentials, payment cards, bank identifiers and national ID numbers (the same checksum rules as the request side), and for injection-style instructions aimed at whatever reads the reply next. Names, URLs, emails and phone numbers are not checked in replies, because models write them legitimately. With `output_scan: flag` (the default) the reply is left alone and the response carries an `output_scan` object listing what was found. With `redact`, secrets and identifiers are replaced by `[REDACTED_TYPE]`. Injection-style text is only ever reported, never removed. The audit log keeps counts by type, never the text.

### Customers

Each customer gets its own key, plan, monthly allowance, settings, audit log and report. Create one with an admin key:

```
curl -X POST https://your-host/v1/admin/tenants -H "x-api-key: $ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"company_name":"Acme Ltd","email":"security@acme.example","tier":"free","policy":{"regions":"eu","judge":"off"}}'
```

The response holds the customer's key once. Plans are `free` (10,000 calls a month), `production` (100,000), `business` and `enterprise`; set `monthly_limit` to agree a custom allowance. A customer who reaches the allowance gets `429 monthly_limit_reached`, and every metered response carries `X-Jnvoy-Monthly-Limit` and `X-Jnvoy-Monthly-Remaining`. Usage is counted per calendar month, so nothing needs resetting.

Settings (`policy`) per customer: `regions`, `redact_extra`, `judge` (`default`, `on`, `off`), `judge_fail_mode` and `output_scan` (`flag` by default, `redact`, or `off`). `judge: off` means no text, not even redacted text, goes to a second provider. Keys from `JNVOY_API_KEYS` and `JNVOY_ADMIN_KEYS` are the operator's own and are not metered. Customers need the database (`DATABASE_URL`).

#### Model provider keys

Customers pay their model provider directly. Jnvoy does not supply model access and never uses its own provider keys for a customer. A customer calls `/v1/proxy` with their own provider key in the `x-provider-key` header:

```
curl -X POST https://your-host/v1/proxy -H "x-api-key: $JNVOY_KEY" -H "x-provider-key: $ANTHROPIC_KEY" \
  -H "Content-Type: application/json" \
  -d '{"provider":"anthropic","model":"claude-haiku-4-5","messages":[{"role":"user","content":"Hello"}]}'
```

The provider key is used for that one request. It is never stored, logged, cached or written to the audit log, and a rejected key is reported as `400 provider_key_rejected` without repeating any part of it. Without the header a customer gets `400 provider_key_required`. `/v1/scan` and the MCP routes call no provider, so they need no provider key.

Full request and response details, with an Authorize button for trying calls, are at [/docs](https://www.jnvoy.com/docs).

## Configuration

| Variable | Purpose |
|---|---|
| `JNVOY_API_KEYS` | Client keys, comma separated, at least 24 characters each |
| `JNVOY_ADMIN_KEYS` | Admin keys, comma separated |
| `JNVOY_RATE_LIMIT_PER_MIN` | Requests per key per minute. Default 60, `0` for no limit |
| `JNVOY_AUTH=off` | Switches authentication off. Local development only |
| `JNVOY_REGIONS` | National identifier packs: `all` (default), `none`, `eu`, or country codes such as `in,au,sg` |
| `JNVOY_REDACT_EXTRA` | `ORGANIZATION`, `LOCATION`, `DATE_TIME`, `NRP`, or `all` |
| `JNVOY_JUDGE_BACKEND` | Second check: `none` (default), `ollama` or `anthropic` |
| `JNVOY_JUDGE_FAIL_MODE` | If the second check fails: `open` (default) keeps first-pass redaction, `closed` rejects the request |
| `DATABASE_URL` | PostgreSQL for the audit log. Without it, an in-memory log is used |
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`, `MISTRAL_API_KEY` | Provider keys for the models you use. These belong to whoever runs Jnvoy and are used only for the operator's own keys. A hosted customer sends their own, see below |

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

A Slack connector in [`connectors/`](connectors/) protects messages to AI bots in a Slack workspace. A Docker stack starts the API and PostgreSQL together. [`RUNBOOK.md`](RUNBOOK.md) covers day-to-day operation: customers, keys, backups, deploys and what to do when something is wrong.

## Tests

```bash
pytest -q
```

## Security

To report a vulnerability, email j.nagaraj2109@gmail.com. Please do not open a public issue for it.

## About

Built by Jeevan Nagaraj. Operated by JNVOY LIMITED, registered in England and Wales, company number 17536574.

Licensed under the Business Source License 1.1. See [LICENSE](LICENSE). It converts to Apache 2.0 after four years.
