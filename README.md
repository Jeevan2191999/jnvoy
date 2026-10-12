# Jnvoy — AI Trust Layer

**Live API:** https://jnvoy.onrender.com
**API Docs:** https://jnvoy.onrender.com/docs
**Website:** https://jnvoy.com

Protect sensitive data and block attacks before they reach any LLM.

Jnvoy sits between your application and any LLM. It detects and redacts PII locally, blocks prompt injection attacks, and generates compliance audit reports. Zero code changes. Change one URL.

## Version 2.2 — What is new

- Prompt injection detection: 7 attack types, 30 plus patterns, blocks attacks before they reach the LLM
- Microsoft Presidio PII detection with 20 plus entity types and confidence scoring
- Semantic caching saves 20 to 40 percent of LLM costs automatically
- Intelligent routing assigns the cheapest capable model to each query
- Automatic failover when a provider goes down
- PostgreSQL audit logs that survive forever for FCA and GDPR compliance
- Multi-tenant API keys so multiple companies can use it with complete data isolation
- PDF compliance report generator, FCA and GDPR ready
- Slack connector protecting AI bot messages in enterprise workspaces
- Docker stack: API plus PostgreSQL plus Redis in one command
- 141 automated tests passing
- Support for Claude, GPT-4o, Gemini, Mistral, and local models via Ollama

## Quick Start

git clone https://github.com/Jeevan2191999/jnvoy.git
cd jnvoy
docker-compose up

## Test PII Detection

curl "https://jnvoy.onrender.com/v1/scan?text=My%20name%20is%20John%20Smith%20and%20NI%20is%20AB123456C"

## Test Injection Detection

curl "https://jnvoy.onrender.com/v1/scan/injection?text=Ignore%20all%20previous%20instructions"

## Send a Protected Request

curl -X POST "https://jnvoy.onrender.com/v1/proxy" \
  -H "Content-Type: application/json" \
  -d '{"model": "claude-haiku-4-5-20251001", "provider": "anthropic", "messages": [{"role": "user", "content": "My email is john@example.com. Say hello."}]}'

## Get Compliance Report PDF

curl "https://jnvoy.onrender.com/v1/report/compliance?company_name=Acme+Ltd" --output report.pdf

## Attack Types Detected

Direct injection, jailbreaks, system prompt extraction, role confusion, indirect injection, data exfiltration, obfuscation.

## PII Types Detected

Emails, phone numbers, credit cards, National Insurance numbers, NHS numbers, UK postcodes, sort codes, account numbers, passport numbers, API keys, secret tokens, IP addresses, dates of birth, person names, organisations, locations.

## Supported LLM Providers

Anthropic Claude, OpenAI GPT-4o, Google Gemini, Mistral, Ollama local models, Azure OpenAI.

## Test Results

141 tests passing across PII detection, prompt injection detection, LLM gateway, semantic cache, intelligent router, outage detector, database, multi-tenant keys, PDF report, and proxy v2.

## Built By

Jeevan Nagaraj
github.com/Jeevan2191999
jnvoy.com

## Licence

MIT