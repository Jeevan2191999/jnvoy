#!/usr/bin/env python3
"""
A protected chat call through LiteLLM's Python SDK.

    pip install litellm
    export JNVOY_API_KEY=...        # your Jnvoy key
    export PROVIDER_KEY=...         # your own OpenAI or Anthropic key
    python examples/litellm_demo.py                      # OpenAI model
    python examples/litellm_demo.py claude-haiku-4-5     # Claude model

LiteLLM treats Jnvoy as an OpenAI-compatible server, so the model name gets the "openai/" prefix and
api_base ends in /v1. The model only ever sees placeholders such as [EMAIL_ADDRESS_1]; the reply you
print has the real values put back. Set JNVOY_BASE_URL to use a server you run yourself.
"""

import os
import sys

BASE_URL = os.environ.get("JNVOY_BASE_URL", "https://www.jnvoy.com")
PROMPT = ("Write a two-sentence reply to anna.lee@example.com, whose invoice 5521 is overdue. "
          "Mention her phone number 020 7946 0123 so she knows we have it on file.")


def call_args(jnvoy_key: str, provider_key: str, model: str = "gpt-4o-mini", base_url: str = BASE_URL) -> dict:
    """The arguments that point litellm.completion at Jnvoy."""
    return {
        "model": "openai/" + model,                       # "openai/" means "an OpenAI-compatible server"
        "api_base": base_url.rstrip("/") + "/v1",
        "api_key": jnvoy_key,                             # sent as Authorization: Bearer
        "extra_headers": {"x-provider-key": provider_key},  # your own OpenAI or Anthropic key
    }


def main(argv) -> int:
    jnvoy_key, provider_key = os.environ.get("JNVOY_API_KEY"), os.environ.get("PROVIDER_KEY")
    if not jnvoy_key or not provider_key:
        print("Set JNVOY_API_KEY (your Jnvoy key) and PROVIDER_KEY (your OpenAI or Anthropic key).",
              file=sys.stderr)
        return 2
    try:
        import litellm
    except ImportError:
        print("Install LiteLLM first: pip install litellm", file=sys.stderr)
        return 2
    args = call_args(jnvoy_key, provider_key, argv[1] if len(argv) > 1 else "gpt-4o-mini")
    messages = [{"role": "user", "content": PROMPT}]

    print("Prompt sent by the app:\n  " + PROMPT + "\n")
    reply = litellm.completion(messages=messages, **args)
    print("Reply, with the real values restored:\n  " + (reply.choices[0].message.content or ""))

    print("\nSame call, streamed:\n  ", end="")
    for chunk in litellm.completion(messages=messages, stream=True, **args):
        print(chunk.choices[0].delta.content or "", end="", flush=True)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
