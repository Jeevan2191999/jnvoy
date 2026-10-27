# Jnvoy quickstart (about 5 minutes)

Jnvoy sits between your app and a model provider. It replaces personal data in each prompt with placeholders before the prompt leaves, and puts the real values back into the reply. If your app already uses the OpenAI client library, you change two lines.

You need two keys:

- a **Jnvoy key**, which we issue (ask for one at j.nagaraj2109@gmail.com, free pilots get 10,000 calls a month), and
- **your own key from the model provider** (OpenAI or Anthropic). You pay the provider directly. Jnvoy uses your provider key for that one request and does not store or log it.

## 1. See what it would hide (1 minute, no provider key needed)

```bash
curl -X POST https://www.jnvoy.com/v1/scan \
  -H "x-api-key: YOUR_JNVOY_KEY" -H "Content-Type: application/json" \
  -d '{"text": "Email anna.lee@example.com or call 020 7946 0123 about NHS number 943 476 5919."}'
```

The `redacted_text` in the reply is exactly what a model would receive. Try a few of your own examples.

## 2. Point your OpenAI client at Jnvoy (2 minutes)

Python:

```python
from openai import OpenAI

client = OpenAI(
    base_url="https://www.jnvoy.com/v1",
    api_key="YOUR_JNVOY_KEY",
    default_headers={"x-provider-key": "YOUR_OPENAI_OR_ANTHROPIC_KEY"},
)

reply = client.chat.completions.create(
    model="gpt-4o",   # or a Claude model, for example "claude-haiku-4-5"
    messages=[{"role": "user", "content": "Draft a reply to anna.lee@example.com about her invoice."}],
)
print(reply.choices[0].message.content)   # the real address is back in the reply
print(reply.model_extra["jnvoy"]["pii_summary"])   # what was found, never the values
```

JavaScript:

```js
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "https://www.jnvoy.com/v1",
  apiKey: "YOUR_JNVOY_KEY",
  defaultHeaders: { "x-provider-key": "YOUR_OPENAI_OR_ANTHROPIC_KEY" },
});
```

LangChain:

```python
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    model="gpt-4o",
    base_url="https://www.jnvoy.com/v1",
    api_key="YOUR_JNVOY_KEY",
    default_headers={"x-provider-key": "YOUR_OPENAI_OR_ANTHROPIC_KEY"},
)
```

Models whose name starts with `claude` go to Anthropic, everything else to OpenAI. Streaming (`stream=True`) works.

## 3. Check it is working

- The model never sees the real values. In the reply, `jnvoy.pii_summary` lists the types that were replaced (for example `EMAIL_ADDRESS: 1`).
- Every response shows your allowance in the `X-Jnvoy-Monthly-Remaining` header.
- A runnable version of step 2 is in [`examples/chat_demo.py`](examples/chat_demo.py), and of step 1 in [`examples/see_redaction.py`](examples/see_redaction.py).

## What to tell us (this is the useful part)

Jnvoy is set up per customer. Tell us and we change your account in minutes:

- **Countries.** National ID formats are on for many countries by default. If you only need some (for example `uk` or `eu`), we can narrow them.
- **Your own identifiers.** Things like `EMP-123456` or `CASE-2024-0099` can be added as custom patterns.
- **Words that must stay.** Your company name, support email or product names can go on an allowlist so they are never replaced.
- **Reply scanning.** Replies are checked for secrets and card or ID numbers. We can report only (the default), remove them, or switch it off.

## Good to know

- **Text only.** Images, audio, tools or function calling, and JSON mode are refused with a clear error for now.
- **Not a guarantee.** Detection is strong but not perfect: names and addresses are where it misses most. The measured results and the misses are public at https://www.jnvoy.com/accuracy. Do not use it as your only control.
- **What we store.** An audit log of counts by type, never the original text or the replies. Details: https://www.jnvoy.com/privacy and https://www.jnvoy.com/security.
- **Errors.** `401` bad Jnvoy key, `400 provider_key_required` or `provider_key_rejected` for the provider key, `429` for the rate limit or monthly allowance.

Questions, or something it should have caught: j.nagaraj2109@gmail.com. Reports of misses are the most useful feedback we can get.
