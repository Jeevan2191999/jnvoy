# Jnvoy — AI Privacy Firewall

**Live API:** https://jnvoy.onrender.com
**API Docs:** https://jnvoy.onrender.com/docs

Protect sensitive data before it reaches any LLM API.

Jnvoy sits between your application and any LLM and automatically detects and redacts PII before forwarding requests. Original values are restored in the response. Every transaction is logged for compliance.

## Version 2.0 — What is new

- Microsoft Presidio PII detection with 20 plus types and confidence scoring
- Semantic caching saves 20 to 40 percent of LLM costs automatically
- Intelligent routing assigns the cheapest capable model to each query
- Automatic failover when a provider goes down
- Docker stack: API plus PostgreSQL plus Redis in one command
- 90 automated tests passing

## Quick Start

git clone https://github.com/Jeevan2191999/jnvoy.git
cd jnvoy
docker-compose up

Or run locally:

pip install -r requirements.txt
python -m spacy download en_core_web_lg
export ANTHROPIC_API_KEY=your_key_here
uvicorn api.proxy_v2:app --reload --port 8000

## Test PII Detection

curl "https://jnvoy.onrender.com/v1/scan?text=My%20name%20is%20John%20Smith%20and%20email%20is%20john@example.com"

## Send a Protected Request

curl -X POST "https://jnvoy.onrender.com/v1/proxy" \
  -H "Content-Type: application/json" \
  -d '{"model": "claude-haiku-4-5-20251001", "provider": "anthropic", "messages": [{"role": "user", "content": "My email is john@example.com. Say hello."}]}'

## Get Compliance Report

curl "https://jnvoy.onrender.com/v1/audit/summary"

## PII Types Detected

Emails, phone numbers, credit cards, National Insurance numbers, NHS numbers, UK postcodes, sort codes, account numbers, passport numbers, API keys, secret tokens, IP addresses, dates of birth, person names, organisations, locations.

## Supported LLM Providers

Anthropic Claude, OpenAI GPT-4o, Google Gemini, Mistral, Ollama local models, Azure OpenAI.

## Docker Stack

docker-compose up starts API plus PostgreSQL plus Redis in one command.

## Test Results

90 tests passing across PII detection, LLM gateway, semantic cache, intelligent router, outage detector, and proxy v2.

## Built By

Jeevan Nagaraj
github.com/Jeevan2191999
zenodo.org/records/22770661

## Licence

MIT