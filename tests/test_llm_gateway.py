"""
Tests for the Jnvoy LLM Gateway.
Tests provider routing, cost calculation, model registry, and fallback logic.
All tests run without real API keys using mocks.
Fixed for Python 3.14 asyncio compatibility.
"""

import sys
sys.path.insert(0, "/home/claude/privacyfire")

import pytest
from unittest.mock import AsyncMock, patch
from core.llm_gateway import (
    LLMGateway, LLMMessage, LLMResponse, LLMUsage,
    Provider, calculate_cost, AnthropicProvider,
    OpenAIProvider, GoogleProvider, MistralProvider, OllamaProvider
)


# ─── Cost Calculation Tests ───────────────────────────────────────────────────

def test_cost_calculation_claude():
    cost = calculate_cost("claude-sonnet-4-6", 1000, 500)
    assert cost > 0
    assert round(cost, 8) == round((1000/1_000_000)*3.0 + (500/1_000_000)*15.0, 8)

def test_cost_calculation_gpt4o():
    cost = calculate_cost("gpt-4o", 2000, 1000)
    assert cost > 0

def test_cost_calculation_ollama_is_free():
    cost = calculate_cost("llama3", 10000, 5000)
    assert cost == 0.0

def test_cost_calculation_unknown_model():
    cost = calculate_cost("unknown-model-xyz", 1000, 500)
    assert cost == 0.0


# ─── Gateway Model Registry Tests ─────────────────────────────────────────────

def test_gateway_lists_all_providers():
    gw = LLMGateway()
    models = gw.list_models()
    assert "anthropic" in models
    assert "openai" in models
    assert "google" in models
    assert "mistral" in models
    assert "ollama" in models
    assert "azure_openai" in models

def test_gateway_routes_claude_to_anthropic():
    gw = LLMGateway()
    provider = gw.get_provider_for_model("claude-sonnet-4-6")
    assert provider is not None
    assert provider.provider_name == Provider.ANTHROPIC

def test_gateway_routes_gpt4o_to_openai():
    gw = LLMGateway()
    provider = gw.get_provider_for_model("gpt-4o")
    assert provider is not None
    assert provider.provider_name == Provider.OPENAI

def test_gateway_routes_gemini_to_google():
    gw = LLMGateway()
    provider = gw.get_provider_for_model("gemini-1.5-pro")
    assert provider is not None
    assert provider.provider_name == Provider.GOOGLE

def test_gateway_routes_mistral_to_mistral():
    gw = LLMGateway()
    provider = gw.get_provider_for_model("mistral-large-latest")
    assert provider is not None
    assert provider.provider_name == Provider.MISTRAL

def test_gateway_routes_llama_to_ollama():
    gw = LLMGateway()
    provider = gw.get_provider_for_model("llama3")
    assert provider is not None
    assert provider.provider_name == Provider.OLLAMA

def test_gateway_returns_none_for_unknown_model():
    gw = LLMGateway()
    provider = gw.get_provider_for_model("completely-unknown-model-xyz")
    assert provider is None

@pytest.mark.asyncio
async def test_gateway_raises_for_unknown_model_on_complete():
    gw = LLMGateway()
    with pytest.raises(ValueError, match="No provider registered"):
        await gw.complete(
            messages=[LLMMessage(role="user", content="hello")],
            model="unknown-model-xyz"
        )


# ─── Provider Completion Tests (mocked) ───────────────────────────────────────

def make_mock_response(provider: Provider, model: str) -> LLMResponse:
    return LLMResponse(
        content=f"Response from {provider.value}",
        model=model,
        provider=provider,
        usage=LLMUsage(input_tokens=100, output_tokens=50, total_tokens=150),
        latency_ms=120.0,
    )

@pytest.mark.asyncio
async def test_gateway_calls_anthropic():
    gw = LLMGateway()
    mock_response = make_mock_response(Provider.ANTHROPIC, "claude-sonnet-4-6")

    with patch.object(gw._providers[Provider.ANTHROPIC], "complete",
                      new_callable=AsyncMock, return_value=mock_response):
        response = await gw.complete(
            messages=[LLMMessage(role="user", content="Hello Claude")],
            model="claude-sonnet-4-6"
        )
        assert response.provider == Provider.ANTHROPIC
        assert response.content == "Response from anthropic"

@pytest.mark.asyncio
async def test_gateway_calls_openai():
    gw = LLMGateway()
    mock_response = make_mock_response(Provider.OPENAI, "gpt-4o")

    with patch.object(gw._providers[Provider.OPENAI], "complete",
                      new_callable=AsyncMock, return_value=mock_response):
        response = await gw.complete(
            messages=[LLMMessage(role="user", content="Hello GPT")],
            model="gpt-4o"
        )
        assert response.provider == Provider.OPENAI

@pytest.mark.asyncio
async def test_gateway_calls_mistral():
    gw = LLMGateway()
    mock_response = make_mock_response(Provider.MISTRAL, "mistral-large-latest")

    with patch.object(gw._providers[Provider.MISTRAL], "complete",
                      new_callable=AsyncMock, return_value=mock_response):
        response = await gw.complete(
            messages=[LLMMessage(role="user", content="Hello Mistral")],
            model="mistral-large-latest"
        )
        assert response.provider == Provider.MISTRAL

@pytest.mark.asyncio
async def test_gateway_fallback_on_failure():
    gw = LLMGateway()
    fallback_response = make_mock_response(Provider.OPENAI, "gpt-4o-mini")

    with patch.object(gw._providers[Provider.ANTHROPIC], "complete",
                      new_callable=AsyncMock, side_effect=Exception("API down")):
        with patch.object(gw._providers[Provider.OPENAI], "complete",
                          new_callable=AsyncMock, return_value=fallback_response):
            response = await gw.complete(
                messages=[LLMMessage(role="user", content="Hello")],
                model="claude-sonnet-4-6",
                fallback_model="gpt-4o-mini",
                max_retries=0
            )
            assert response.provider == Provider.OPENAI

@pytest.mark.asyncio
async def test_gateway_health_check_all():
    gw = LLMGateway()
    results = await gw.health_check_all()
    assert isinstance(results, dict)
    assert "anthropic" in results
    assert "openai" in results
    assert "google" in results
    assert "mistral" in results
    assert "ollama" in results


# ─── Cost Estimation Tests ────────────────────────────────────────────────────

def test_gateway_estimate_cost():
    gw = LLMGateway()
    cost = gw.estimate_cost("gpt-4o", 5000, 2000)
    assert cost > 0
    assert isinstance(cost, float)

def test_gateway_estimate_cost_free_for_ollama():
    gw = LLMGateway()
    cost = gw.estimate_cost("llama3", 10000, 5000)
    assert cost == 0.0
