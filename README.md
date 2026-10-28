# Jnvoy

**A privacy and security gateway for LLM traffic.**

Jnvoy sits between your application and a model provider (Anthropic or OpenAI). It finds personal data in prompts, replaces each value with a token before the prompt leaves, puts the real values back into the reply, blocks prompt injection, scans MCP tool traffic, and keeps an audit log of what was found, never the original text.

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

Hosted keys are issued on request: email j.nagaraj2109@gmail.com or use the "Request a free key" link on [jnvoy.com](https://www.jnvoy.com). If you run Jnvoy yourself, you create your own keys (see below).

```bash
curl -X POST https://www.jnvoy.com/v1/scan \
  -H "x-api-key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '{"text": "My name is John Smith and my NI number is AB123456C"}'
```

Send a protected request to a model. The hosted service needs two headers: your Jnvoy key, and your own key from the model provider. Jnvoy uses the provider key for that one request and never stores or logs it. `/v1/proxy` uses Jnvoy's own request format. If your app already uses the OpenAI client library, use `/v1/chat/completions` instead (see below), which also streams. A 5-minute walkthrough is in [QUICKSTART.md](QUICKSTART.md), and runnable examples are in [`examples/`](examples).

```bash
curl -X POST https://www.jnvoy.com/v1/proxy \
  -H "x-api-key: YOUR_JNVOY_KEY" -H "x-provider-key: YOUR_ANTHROPIC_KEY" \
  -H "Content-Type: application/json" \
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

The first build downloads the language models Jnvoy uses for names and places, so it takes several minutes.

Without Docker: `pip install -r requirements.txt`, then `uvicorn api.proxy_v2:app --port 8000`.

Try your own copy at `http://localhost:8000`, with the key you put in `JNVOY_API_KEYS`:

```bash
curl -X POST http://localhost:8000/v1/scan \
  -H "x-api-key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '{"text": "My name is John Smith and my NI number is AB123456C"}'
```

Keys in `JNVOY_API_KEYS` are operator keys: the model calls use the provider keys in your `.env` and are not metered.

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
| `POST /v1/chat/completions` | The same, in OpenAI's request and response format (see below) | client |
| `POST /v1/scan` | Scan text for personal data | client |
| `POST /v1/scan/injection` | Scan text for prompt injection | client |
| `POST /v1/mcp/scan` | Scan an MCP message for threats | client |
| `POST /v1/mcp/scan/tool-response` | Scan an MCP tool response | client |
| `POST /v1/mcp/scan/tool-description` | Scan an MCP tool description for poisoning | client |
| `GET /v1/me` | Your plan, this month's usage and your settings | client |
| `GET /v1/me/audit` (`?format=json\|csv\|ndjson`, `&from=` and `&to=` dates), `GET /v1/me/audit/summary` | Your own audit log | client |
| `GET /v1/me/report/compliance` | Your own compliance report (PDF) | client |
| `POST/GET /v1/admin/tenants`, `GET/PATCH/DELETE /v1/admin/tenants/{id}`, `POST /v1/admin/tenants/{id}/rotate-key` | Create and manage customers and their keys | admin |
| `GET /v1/audit`, `GET /v1/audit/summary` | Read or export any customer's audit log (`?tenant_id=`, same options as above) | admin |
| `GET /v1/report/compliance` | Compliance report (PDF) | admin |
| `GET /v1/cache/stats`, `DELETE /v1/cache` | Response cache statistics and reset | admin |
| `GET /v1/providers/health` | Model provider health | admin |

### Scanning the model's reply

### Exporting the audit log

The audit log holds counts and types only, never text. To hand it to a compliance team or a log system:

```bash
# one month, one JSON event per line (for Splunk, Elastic, Datadog and similar)
curl "https://www.jnvoy.com/v1/me/audit?format=ndjson&from=2026-10-01&to=2026-10-31" -H "x-api-key: $JNVOY_KEY" -o october.ndjson
# the same as a spreadsheet
curl "https://www.jnvoy.com/v1/me/audit?format=csv&from=2026-10-01&to=2026-10-31" -H "x-api-key: $JNVOY_KEY" -o october.csv
```

Dates are UTC; `to` includes the whole of that day. A page holds up to 5,000 entries for CSV and NDJSON (1,000 for JSON). The response header `X-Total-Count` gives the number of matching entries, and `X-Next-Offset` (absent on the last page) is the `offset` to pass for the next page. `provider=openai` filters by provider. Text that a spreadsheet could run as a formula (for example a model name starting with `=`) is prefixed with an apostrophe in the CSV.

Jnvoy also checks what the model sends back, before your values are put back in. It looks for credentials, payment cards, bank identifiers and national ID numbers (the same checksum rules as the request side), and for injection-style instructions aimed at whatever reads the reply next. Names, URLs, emails and phone numbers are not checked in replies, because models write them legitimately. With `output_scan: flag` (the default) the reply is left alone and the response carries an `output_scan` object listing what was found. With `redact`, secrets and identifiers are replaced by `[REDACTED_TYPE]`. Injection-style text is only ever reported, never removed. The audit log keeps counts by type, never the text.

### Customers

Each customer gets its own key, plan, monthly allowance, settings, audit log and report. Create one with an admin key:

```
curl -X POST https://your-host/v1/admin/tenants -H "x-api-key: $ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"company_name":"Acme Ltd","email":"security@acme.example","tier":"free","policy":{"regions":"eu","judge":"off"}}'
```

The response holds the customer's key once. Plans are `free` (10,000 calls a month), `production` (100,000), `business` and `enterprise`; set `monthly_limit` to agree a custom allowance. A customer who reaches the allowance gets `429 monthly_limit_reached`, and every metered response carries `X-Jnvoy-Monthly-Limit` and `X-Jnvoy-Monthly-Remaining`. Usage is counted per calendar month, so nothing needs resetting.

Settings (`policy`) per customer: `regions`, `redact_extra`, `judge` (`default`, `on`, `off`), `judge_fail_mode` and `output_scan` (`flag` by default, `redact`, or `off`). `judge: off` means no text, not even redacted text, goes to a second provider. Two more settings are lists. `custom_patterns` redacts things only that customer has, for example `[{"name": "employee_id", "pattern": "\\bEMP-\\d{6}\\b"}]` turns `EMP-123456` into `[CUSTOM_EMPLOYEE_ID_1]` (up to 20 patterns of at most 300 characters; a pattern that can match nothing, or that can run away on hostile input, is refused when you save it, and a pattern that runs out of time on a request refuses that request instead of letting text through). `allowlist` is whole words or phrases that must never be redacted, for example `["Acme Ltd", "support@acme.com"]`, matched ignoring case; it wins over both custom patterns and built-in detection. Customers can change all of these themselves with their own key (see below). Keys from `JNVOY_API_KEYS` and `JNVOY_ADMIN_KEYS` are the operator's own and are not metered. Customers need the database (`DATABASE_URL`).

#### Customers changing their own settings

A customer can read and change their own settings with their own key, with no need to ask you:

```bash
# see the current settings and what each one does
curl https://www.jnvoy.com/v1/me/policy -H "x-api-key: $JNVOY_KEY"
# turn on reply redaction and add one pattern and two allowlist entries; other settings stay as they are
curl -X PATCH https://www.jnvoy.com/v1/me/policy -H "x-api-key: $JNVOY_KEY" -H "Content-Type: application/json" \
  -d '{"policy":{"output_scan":"redact","custom_patterns":[{"name":"employee_id","pattern":"\\bEMP-\\d{6}\\b"}],"allowlist":["Acme Ltd","support@acme.com"]}}'
```

Send only the fields to change. A field sent as `null` (or an empty list) goes back to the server default. Changes take effect on the customer's next request. The checks are the same as for you, plus two more because the patterns now come from customers: a pattern that is small to write but huge to build (for example nested counted repeats such as `(?:a{500}){500}`) is refused before it is compiled, and a whole list has a time budget for checking. A customer may make 20 changes in 10 minutes, counting failed ones, then gets `429 too_many_policy_changes` with `Retry-After`. Operator keys have no stored settings and get `403 policy_not_editable`. A customer can weaken their own protection (for example `regions: none`); that is their choice for their own data, and the change is logged by field name, never by value.

#### Model provider keys

Customers pay their model provider directly. Jnvoy does not supply model access and never uses its own provider keys for a customer. A customer calls `/v1/proxy` with their own provider key in the `x-provider-key` header:

```
curl -X POST https://your-host/v1/proxy -H "x-api-key: $JNVOY_KEY" -H "x-provider-key: $ANTHROPIC_KEY" \
  -H "Content-Type: application/json" \
  -d '{"provider":"anthropic","model":"claude-haiku-4-5","messages":[{"role":"user","content":"Hello"}]}'
```

The provider key is used for that one request. It is never stored, logged, cached or written to the audit log, and a rejected key is reported as `400 provider_key_rejected` without repeating any part of it. Without the header a customer gets `400 provider_key_required`. `/v1/scan` and the MCP routes call no provider, so they need no provider key.

#### Using an OpenAI client library

`/v1/chat/completions` speaks OpenAI's chat format, so an existing app only changes where it points:

```python
from openai import OpenAI

client = OpenAI(
    base_url="https://www.jnvoy.com/v1",
    api_key="<your Jnvoy key>",                       # sent as Authorization: Bearer
    default_headers={"x-provider-key": "<your OpenAI or Anthropic key>"},
)
reply = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "..."}])
```

Models starting with `claude` go to Anthropic, everything else to OpenAI (override with the `x-jnvoy-provider` header). It handles text, files and tools (see Tool calls below): images, audio, the older `functions`, JSON mode and `n` above 1 are refused with a `400`, because they cannot be scanned for personal data or are not supported yet. A file can be sent as a `file` part (see Files below). Other optional fields (`top_p`, `stop`, `seed`...) are ignored, and the `x-jnvoy-ignored-params` response header lists any that were. `usage` is not returned. With `stream: true` the reply arrives word by word, with your values restored as it goes. The reply is scanned after it has been sent, so if your account's reply scanning is set to `redact` the reply is checked in full first and then streamed. The Jnvoy key goes in `Authorization: Bearer` on this route only; every other route needs `x-api-key`.

#### Using LiteLLM

LiteLLM can use Jnvoy as an OpenAI-compatible server, so a LiteLLM app or proxy gets the same protection without other changes. In the Python SDK:

```python
import litellm

reply = litellm.completion(
    model="openai/gpt-4o-mini",              # "openai/" means "an OpenAI-compatible server"
    api_base="https://www.jnvoy.com/v1",     # must end in /v1
    api_key="<your Jnvoy key>",              # sent as Authorization: Bearer
    extra_headers={"x-provider-key": "<your OpenAI or Anthropic key>"},
    messages=[{"role": "user", "content": "..."}],
)
```

For the LiteLLM proxy, [`examples/litellm_config.yaml`](examples/litellm_config.yaml) keeps one provider key on the LiteLLM server and [`examples/litellm_config_per_user.yaml`](examples/litellm_config_per_user.yaml) lets each caller bring their own. Streaming and tool calls work. LiteLLM itself, and its logs and callbacks, still see the original text; Jnvoy protects what reaches the model provider. Jnvoy returns no token usage, so LiteLLM reports 0 tokens for these calls. Tested with LiteLLM 1.106.5. The setup page is at [/guides/litellm](https://www.jnvoy.com/guides/litellm).

## Files

Jnvoy reads PDFs (with a text layer), Word (`.docx`) and plain text files (`txt`, `md`, `csv`, `tsv`, `json`, `jsonl`, `log`, `xml`, `html`, `yaml`), checks the text for personal data, and never sends the file itself anywhere.

Scan a file without calling a model:

```bash
curl https://www.jnvoy.com/v1/scan/file -H "x-api-key: $JNVOY_KEY" -H "content-type: application/json" \
  -d "{\"filename\": \"letter.pdf\", \"content_base64\": \"$(base64 -w0 letter.pdf)\"}"
```

The reply has the redacted text, what was found, and for a PDF the pages the findings are on (`findings_by_page`). Send a file to a model with the personal data removed, using the OpenAI library:

```python
import base64
data = base64.b64encode(open("letter.pdf", "rb").read()).decode()
client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": [
    {"type": "text", "text": "Summarise this letter."},
    {"type": "file", "file": {"filename": "letter.pdf", "file_data": "data:application/pdf;base64," + data}},
]}])
```

The model receives the text of the file, redacted like any other message, between `[Attached file: ...]` markers, and your values are restored in the reply. The response's `jnvoy.files` lists each file read (name, format, pages, characters, never content).

What is refused rather than skipped, so nothing is passed along unchecked: scanned PDFs and images (the text in them cannot be read yet), password-protected PDFs, old `.doc` and Excel/PowerPoint files, and anything over the limits (5 MB, 100 PDF pages, 200,000 characters per file, 3 files per chat request). Pictures inside a readable PDF or Word file are not read and are reported as `images_skipped`; pages with no text are reported as `pages_without_text`. Only the extracted text is ever used.

Each file is read in a separate, locked-down process that has no access to keys or the database, has a memory and time limit, and cannot write files. Nothing is stored. Very long documents take longer to check: expect roughly 8 seconds for 100,000 characters of dense text.

Full request and response details, with an Authorize button for trying calls, are at [/docs](https://www.jnvoy.com/docs).

## Tool calls

Function calling works through `/v1/chat/completions` with OpenAI models. Send `tools`, `tool_choice` and `parallel_tool_calls` as usual; Jnvoy sits between your agent loop and the model:

- **Tool results** (messages with `role: "tool"`) are redacted before the model reads them. This is where agents leak most: a database row, a search hit or an email body that a tool fetched.
- **Earlier tool-call arguments** in the conversation are redacted too: every string, every object key and every long number. The JSON stays valid.
- **The model's tool calls** come back with your real values restored, so your code can run the tool. Each value is restored on its own and re-encoded as JSON, so a quote inside a real value cannot break the arguments. They go through the same reply scan as text (`flag`, or `redact` replaces secrets and identifiers).
- **A tool the model invents** (one not in your `tools`) is never passed on: the request fails with `502 undeclared_tool`.
- **Injection hidden in a tool result** is blocked like any other injection (`400 prompt_injection_detected`).

Limits: tool definitions (names, descriptions, parameter schemas) are sent to the model as you wrote them, so keep personal data out of them; at most 64 tools and 100,000 characters of definitions; at most 1,000 values in the tool-call arguments of one request. With tools, `stream: true` does not deliver the reply word by word: it arrives as one complete set of chunks, because arguments cannot be restored while they are half written. Responses are never cached on this path. Claude models are not supported with tools yet and get `400 tools_not_supported_for_provider`. The older `functions` and `function_call` fields are refused; use `tools`.

## Configuration

| Variable | Purpose |
|---|---|
| `JNVOY_API_KEYS` | Client keys, comma separated, at least 24 characters each |
| `JNVOY_ADMIN_KEYS` | Admin keys, comma separated |
| `JNVOY_RATE_LIMIT_PER_MIN` | Requests per key per minute. Default 60, `0` for no limit |
| `JNVOY_MAX_BODY_BYTES` | Largest request body accepted, in bytes. Default 262144 (about 256 KB) |
| `JNVOY_MAX_FILE_BYTES` | Largest file accepted. Default 5,000,000. File routes accept a body a third bigger (base64) |
| `JNVOY_MAX_FILE_CHARS`, `JNVOY_MAX_FILE_PAGES` | Most text read from one file (default 200,000) and most PDF pages (default 100) |
| `JNVOY_MAX_FILES_PER_REQUEST` | Files in one chat request. Default 3 |
| `JNVOY_FILE_TIMEOUT_S`, `JNVOY_FILE_MEMORY_MB`, `JNVOY_FILE_WORKERS` | Time limit (20), memory limit (768) and number of files read at once (2) for the file reader |
| `JNVOY_AUTH=off` | Switches authentication off. Local development only |
| `JNVOY_REGIONS` | National identifier packs: `all` (default), `none`, `eu`, or country codes such as `in,au,sg` |
| `JNVOY_REDACT_EXTRA` | `ORGANIZATION`, `LOCATION`, `DATE_TIME`, `NRP`, or `all` |
| `JNVOY_JUDGE_BACKEND` | Second check: `none` (default), `ollama` or `anthropic` |
| `JNVOY_JUDGE_FAIL_MODE` | If the second check fails: `open` (default) keeps first-pass redaction, `closed` rejects the request |
| `DATABASE_URL` | PostgreSQL for the audit log. Without it, an in-memory log is used |
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` | Provider keys for the models you use. These belong to whoever runs Jnvoy and are used only for the operator's own keys. A hosted customer sends their own, see below |

## Python and LangChain

```bash
pip install langchain-core httpx
```

```python
from core.langchain_integration import JnvoyChat
from langchain_core.messages import HumanMessage

chat = JnvoyChat(
    jnvoy_url="https://www.jnvoy.com",
    api_key="YOUR_JNVOY_KEY",     # or set JNVOY_API_KEY
    provider_key="YOUR_PROVIDER_KEY",  # or set ANTHROPIC_API_KEY / OPENAI_API_KEY
    provider="anthropic",
    model="claude-haiku-4-5-20251001",
)
print(chat.invoke([HumanMessage(content="My email is john@example.com. Say hello.")]).content)
```

## Providers

`/v1/proxy` supports Anthropic and OpenAI. Optional model routing (`use_routing: true`, off by default) can switch between models of the provider you chose. The scan, reply-scan and MCP routes call no provider.

## Other pieces

A Docker stack starts the API and PostgreSQL together. [`RUNBOOK.md`](RUNBOOK.md) covers day-to-day operation: customers, keys, backups, deploys and what to do when something is wrong.

## Tests

```bash
pytest -q
```

## Security

To report a vulnerability, email j.nagaraj2109@gmail.com. Please do not open a public issue for it.

Every pinned dependency is checked against public vulnerability databases each week by the `audit` workflow, and the whole API is attacked with malformed and hostile requests in the test suite (`tests/test_security_hardening.py`). Files are read in a locked-down child process, and customers' own regular expressions are size-checked, time-limited and refused if they could exhaust memory.

## About

Built by Jeevan Nagaraj. Operated by JNVOY LIMITED, registered in England and Wales, company number 17536574.

Jnvoy is source-available, not open source. It is licensed under the Business Source License 1.1 (see [LICENSE](LICENSE)). In plain terms: you may read, modify and self-host it, including in production inside your own business, at no charge. You may not sell it as a hosted service that competes with Jnvoy's own. Each version converts to Apache 2.0 after four years.
