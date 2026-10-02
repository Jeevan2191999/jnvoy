# Jnvoy - AI Privacy Firewall

Protect sensitive data before it reaches any LLM API.

Jnvoy sits between your application and any LLM and automatically detects and redacts PII before forwarding requests. Original values are restored in the response. Every transaction is logged for compliance.

## What It Does

- Detects 14 types of PII locally with zero external API calls
- Works with Claude, GPT-4o, Gemini, Mistral, and local models via Ollama
- Generates FCA and GDPR-grade compliance audit reports
- Reduces LLM costs 30-50% through semantic caching and intelligent routing
- Zero downtime during provider outages via automatic failover

## Quick Start

git clone https://github.com/Jeevan2191999/jnvoy.git
cd jnvoy
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 -m spacy download en_core_web_sm
export ANTHROPIC_API_KEY=your_key_here
uvicorn api.proxy:app --reload --port 8000

## PII Types Detected

Emails, UK phone numbers, credit cards, National Insurance numbers, NHS numbers, UK postcodes, sort codes, account numbers, passport numbers, API keys, secret tokens, IP addresses, dates of birth, person names, organisations, locations.

## Supported LLM Providers

- Anthropic: Claude Sonnet, Haiku, Opus
- OpenAI: GPT-4o, GPT-4o-mini
- Google: Gemini 1.5 Pro, Flash
- Mistral: Mistral Large, Small
- Ollama: Llama3, Mistral, Phi-3 (local, free)
- Azure OpenAI: Enterprise deployments

## Test Results

64 tests passing across PII detection, LLM gateway, semantic cache, intelligent router, and outage detector.

## Built By

Jeevan Nagaraj
github.com/Jeevan2191999
zenodo.org/records/22770661

## Licence

MIT
