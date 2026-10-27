#!/usr/bin/env python3
"""
A protected chat call, end to end, using the standard OpenAI client library.

    pip install openai
    export JNVOY_API_KEY=...        # your Jnvoy key
    export PROVIDER_KEY=...         # your own OpenAI or Anthropic key
    python examples/chat_demo.py                         # OpenAI model
    python examples/chat_demo.py claude-haiku-4-5        # Claude model

The model only ever sees placeholders such as [EMAIL_ADDRESS_1]. The reply you print has the real
values put back. Set JNVOY_BASE_URL to use a server you run yourself.
"""

import os
import sys

BASE_URL = os.environ.get("JNVOY_BASE_URL", "https://www.jnvoy.com")
PROMPT = ("Write a two-sentence reply to anna.lee@example.com, whose invoice 5521 is overdue. "
          "Mention her phone number 020 7946 0123 so she knows we have it on file.")


def make_client(jnvoy_key: str, provider_key: str, base_url: str = BASE_URL):
    from openai import OpenAI          # imported here so the error below can be friendly
    return OpenAI(base_url=base_url.rstrip("/") + "/v1", api_key=jnvoy_key,
                  default_headers={"x-provider-key": provider_key})


def main(argv) -> int:
    jnvoy_key, provider_key = os.environ.get("JNVOY_API_KEY"), os.environ.get("PROVIDER_KEY")
    if not jnvoy_key or not provider_key:
        print("Set JNVOY_API_KEY (your Jnvoy key) and PROVIDER_KEY (your OpenAI or Anthropic key).",
              file=sys.stderr)
        return 2
    try:
        client = make_client(jnvoy_key, provider_key)
    except ImportError:
        print("Install the OpenAI library first: pip install openai", file=sys.stderr)
        return 2
    model = argv[1] if len(argv) > 1 else "gpt-4o-mini"

    print("Prompt sent by the app:\n  " + PROMPT + "\n")
    reply = client.chat.completions.create(model=model, messages=[{"role": "user", "content": PROMPT}])
    print("Reply, with the real values restored:\n  " + (reply.choices[0].message.content or ""))
    info = (reply.model_extra or {}).get("jnvoy", {})
    print("\nWhat Jnvoy replaced before the model saw the prompt:", info.get("pii_summary", {}).get("types_detected"))

    print("\nSame call, streamed:\n  ", end="")
    for chunk in client.chat.completions.create(model=model, stream=True,
                                                messages=[{"role": "user", "content": PROMPT}]):
        print(chunk.choices[0].delta.content or "", end="", flush=True)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
