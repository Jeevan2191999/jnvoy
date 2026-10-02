"""
Jnvoy LLM Gateway
Enterprise-grade multi-provider LLM abstraction layer.

Built following the adapter pattern used by real organisations.
No application code changes when switching providers.
Every provider logs cost, latency, and token usage for audit.

Supported providers:
- Anthropic (Claude Sonnet, Claude Haiku, Claude Opus)
- OpenAI (GPT-4o, GPT-4o-mini, GPT-3.5-turbo)
- Google (Gemini 1.5 Pro, Gemini 1.5 Flash)
- Mistral (Mistral Large, Mistral Small, Mixtral)
- Ollama (Local models: Llama3, Mistral, Phi-3, Gemma)
- Azure OpenAI (Enterprise deployments)
"""

import asyncio
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import httpx


# ─── Data Models ──────────────────────────────────────────────────────────────

class Provider(str, Enum):
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    GOOGLE = "google"
    MISTRAL = "mistral"
    OLLAMA = "ollama"
    AZURE_OPENAI = "azure_openai"


@dataclass
class LLMMessage:
    role: str  # system | user | assistant
    content: str


@dataclass
class LLMRequest:
    messages: list[LLMMessage]
    model: str
    provider: Provider
    max_tokens: int = 1000
    temperature: float = 0.7
    system_prompt: Optional[str] = None


@dataclass
class LLMUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0


@dataclass
class LLMResponse:
    content: str
    model: str
    provider: Provider
    usage: LLMUsage
    latency_ms: float
    raw_response: dict = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return bool(self.content)


# ─── Cost Calculator ──────────────────────────────────────────────────────────

# Prices per 1M tokens as of 2026
PRICING: dict[str, dict[str, float]] = {
    # Anthropic
    "claude-sonnet-4-6":        {"input": 3.0,   "output": 15.0},
    "claude-haiku-4-5":         {"input": 0.25,  "output": 1.25},
    "claude-opus-4":            {"input": 15.0,  "output": 75.0},
    # OpenAI
    "gpt-4o":                   {"input": 2.5,   "output": 10.0},
    "gpt-4o-mini":              {"input": 0.15,  "output": 0.6},
    "gpt-3.5-turbo":            {"input": 0.5,   "output": 1.5},
    # Google
    "gemini-1.5-pro":           {"input": 1.25,  "output": 5.0},
    "gemini-1.5-flash":         {"input": 0.075, "output": 0.3},
    # Mistral
    "mistral-large-latest":     {"input": 2.0,   "output": 6.0},
    "mistral-small-latest":     {"input": 0.1,   "output": 0.3},
    "open-mixtral-8x7b":        {"input": 0.7,   "output": 0.7},
    # Local models via Ollama
    "llama3":                   {"input": 0.0,   "output": 0.0},
    "mistral":                  {"input": 0.0,   "output": 0.0},
    "phi3":                     {"input": 0.0,   "output": 0.0},
    "gemma":                    {"input": 0.0,   "output": 0.0},
}


def calculate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Calculate estimated cost in USD for a completion."""
    pricing = PRICING.get(model, {"input": 0.0, "output": 0.0})
    input_cost = (input_tokens / 1_000_000) * pricing["input"]
    output_cost = (output_tokens / 1_000_000) * pricing["output"]
    return round(input_cost + output_cost, 8)


# ─── Base Provider Interface ──────────────────────────────────────────────────

class BaseLLMProvider(ABC):
    """
    Abstract base class for all LLM providers.
    Every provider must implement complete() and health_check().
    This enforces the contract that all providers return the same LLMResponse format.
    """

    @abstractmethod
    async def complete(self, request: LLMRequest) -> LLMResponse:
        """Send a completion request and return a unified LLMResponse."""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if this provider is reachable and configured correctly."""
        pass

    @property
    @abstractmethod
    def provider_name(self) -> Provider:
        pass

    @property
    @abstractmethod
    def available_models(self) -> list[str]:
        pass


# ─── Anthropic Provider ───────────────────────────────────────────────────────

class AnthropicProvider(BaseLLMProvider):
    """
    Anthropic Claude provider.
    Supports: claude-sonnet-4-6, claude-haiku-4-5, claude-opus-4
    """

    BASE_URL = "https://api.anthropic.com/v1"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")

    @property
    def provider_name(self) -> Provider:
        return Provider.ANTHROPIC

    @property
    def available_models(self) -> list[str]:
        return ["claude-sonnet-4-6", "claude-haiku-4-5", "claude-opus-4"]

    async def complete(self, request: LLMRequest) -> LLMResponse:
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY not configured")

        start = time.time()

        # Build Anthropic message format
        messages = [{"role": m.role, "content": m.content}
                    for m in request.messages if m.role != "system"]

        payload: dict = {
            "model": request.model,
            "max_tokens": request.max_tokens,
            "messages": messages,
        }

        # Anthropic uses a top-level system parameter
        system = request.system_prompt or next(
            (m.content for m in request.messages if m.role == "system"), None
        )
        if system:
            payload["system"] = system

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{self.BASE_URL}/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json=payload,
            )
            response.raise_for_status()
            data = response.json()

        latency_ms = (time.time() - start) * 1000
        input_tokens = data.get("usage", {}).get("input_tokens", 0)
        output_tokens = data.get("usage", {}).get("output_tokens", 0)

        return LLMResponse(
            content=data["content"][0]["text"],
            model=request.model,
            provider=Provider.ANTHROPIC,
            usage=LLMUsage(
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                total_tokens=input_tokens + output_tokens,
                estimated_cost_usd=calculate_cost(request.model, input_tokens, output_tokens),
            ),
            latency_ms=round(latency_ms, 2),
            raw_response=data,
        )

    async def health_check(self) -> bool:
        if not self.api_key:
            return False
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(
                    f"{self.BASE_URL}/models",
                    headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
                )
                return response.status_code == 200
        except Exception:
            return False


# ─── OpenAI Provider ──────────────────────────────────────────────────────────

class OpenAIProvider(BaseLLMProvider):
    """
    OpenAI provider.
    Supports: gpt-4o, gpt-4o-mini, gpt-3.5-turbo
    Also used as base for Azure OpenAI.
    """

    BASE_URL = "https://api.openai.com/v1"

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.base_url = base_url or self.BASE_URL

    @property
    def provider_name(self) -> Provider:
        return Provider.OPENAI

    @property
    def available_models(self) -> list[str]:
        return ["gpt-4o", "gpt-4o-mini", "gpt-3.5-turbo"]

    async def complete(self, request: LLMRequest) -> LLMResponse:
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY not configured")

        start = time.time()

        messages = []
        if request.system_prompt:
            messages.append({"role": "system", "content": request.system_prompt})
        messages.extend([{"role": m.role, "content": m.content} for m in request.messages])

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "content-type": "application/json",
                },
                json={
                    "model": request.model,
                    "messages": messages,
                    "max_tokens": request.max_tokens,
                    "temperature": request.temperature,
                },
            )
            response.raise_for_status()
            data = response.json()

        latency_ms = (time.time() - start) * 1000
        input_tokens = data.get("usage", {}).get("prompt_tokens", 0)
        output_tokens = data.get("usage", {}).get("completion_tokens", 0)

        return LLMResponse(
            content=data["choices"][0]["message"]["content"],
            model=request.model,
            provider=Provider.OPENAI,
            usage=LLMUsage(
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                total_tokens=input_tokens + output_tokens,
                estimated_cost_usd=calculate_cost(request.model, input_tokens, output_tokens),
            ),
            latency_ms=round(latency_ms, 2),
            raw_response=data,
        )

    async def health_check(self) -> bool:
        if not self.api_key:
            return False
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(
                    f"{self.base_url}/models",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
                return response.status_code == 200
        except Exception:
            return False


# ─── Google Gemini Provider ───────────────────────────────────────────────────

class GoogleProvider(BaseLLMProvider):
    """
    Google Gemini provider.
    Supports: gemini-1.5-pro, gemini-1.5-flash
    """

    BASE_URL = "https://generativelanguage.googleapis.com/v1beta"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")

    @property
    def provider_name(self) -> Provider:
        return Provider.GOOGLE

    @property
    def available_models(self) -> list[str]:
        return ["gemini-1.5-pro", "gemini-1.5-flash"]

    async def complete(self, request: LLMRequest) -> LLMResponse:
        if not self.api_key:
            raise ValueError("GOOGLE_API_KEY not configured")

        start = time.time()

        # Google uses a different message format
        contents = []
        for m in request.messages:
            if m.role == "system":
                continue  # Handle separately
            role = "user" if m.role == "user" else "model"
            contents.append({"role": role, "parts": [{"text": m.content}]})

        payload: dict = {"contents": contents}
        if request.system_prompt:
            payload["systemInstruction"] = {"parts": [{"text": request.system_prompt}]}

        payload["generationConfig"] = {
            "maxOutputTokens": request.max_tokens,
            "temperature": request.temperature,
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{self.BASE_URL}/models/{request.model}:generateContent",
                params={"key": self.api_key},
                json=payload,
            )
            response.raise_for_status()
            data = response.json()

        latency_ms = (time.time() - start) * 1000

        # Extract token counts from Google response
        usage_meta = data.get("usageMetadata", {})
        input_tokens = usage_meta.get("promptTokenCount", 0)
        output_tokens = usage_meta.get("candidatesTokenCount", 0)
        content = data["candidates"][0]["content"]["parts"][0]["text"]

        return LLMResponse(
            content=content,
            model=request.model,
            provider=Provider.GOOGLE,
            usage=LLMUsage(
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                total_tokens=input_tokens + output_tokens,
                estimated_cost_usd=calculate_cost(request.model, input_tokens, output_tokens),
            ),
            latency_ms=round(latency_ms, 2),
            raw_response=data,
        )

    async def health_check(self) -> bool:
        if not self.api_key:
            return False
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(
                    f"{self.BASE_URL}/models",
                    params={"key": self.api_key},
                )
                return response.status_code == 200
        except Exception:
            return False


# ─── Mistral Provider ─────────────────────────────────────────────────────────

class MistralProvider(BaseLLMProvider):
    """
    Mistral AI provider.
    Supports: mistral-large-latest, mistral-small-latest, open-mixtral-8x7b
    """

    BASE_URL = "https://api.mistral.ai/v1"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("MISTRAL_API_KEY")

    @property
    def provider_name(self) -> Provider:
        return Provider.MISTRAL

    @property
    def available_models(self) -> list[str]:
        return ["mistral-large-latest", "mistral-small-latest", "open-mixtral-8x7b"]

    async def complete(self, request: LLMRequest) -> LLMResponse:
        if not self.api_key:
            raise ValueError("MISTRAL_API_KEY not configured")

        start = time.time()

        messages = []
        if request.system_prompt:
            messages.append({"role": "system", "content": request.system_prompt})
        messages.extend([{"role": m.role, "content": m.content} for m in request.messages])

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{self.BASE_URL}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "content-type": "application/json",
                },
                json={
                    "model": request.model,
                    "messages": messages,
                    "max_tokens": request.max_tokens,
                    "temperature": request.temperature,
                },
            )
            response.raise_for_status()
            data = response.json()

        latency_ms = (time.time() - start) * 1000
        input_tokens = data.get("usage", {}).get("prompt_tokens", 0)
        output_tokens = data.get("usage", {}).get("completion_tokens", 0)

        return LLMResponse(
            content=data["choices"][0]["message"]["content"],
            model=request.model,
            provider=Provider.MISTRAL,
            usage=LLMUsage(
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                total_tokens=input_tokens + output_tokens,
                estimated_cost_usd=calculate_cost(request.model, input_tokens, output_tokens),
            ),
            latency_ms=round(latency_ms, 2),
            raw_response=data,
        )

    async def health_check(self) -> bool:
        if not self.api_key:
            return False
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(
                    f"{self.BASE_URL}/models",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
                return response.status_code == 200
        except Exception:
            return False


# ─── Ollama Provider (Local Models) ──────────────────────────────────────────

class OllamaProvider(BaseLLMProvider):
    """
    Ollama local model provider.
    Runs models completely locally: Llama3, Mistral, Phi-3, Gemma.
    Zero cost. Zero data leaving the machine. Perfect for air-gapped environments.
    Requires Ollama installed locally: ollama.ai
    """

    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url

    @property
    def provider_name(self) -> Provider:
        return Provider.OLLAMA

    @property
    def available_models(self) -> list[str]:
        return ["llama3", "mistral", "phi3", "gemma", "codellama", "llama3.1"]

    async def complete(self, request: LLMRequest) -> LLMResponse:
        start = time.time()

        messages = []
        if request.system_prompt:
            messages.append({"role": "system", "content": request.system_prompt})
        messages.extend([{"role": m.role, "content": m.content} for m in request.messages])

        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": request.model,
                    "messages": messages,
                    "stream": False,
                    "options": {
                        "num_predict": request.max_tokens,
                        "temperature": request.temperature,
                    },
                },
            )
            response.raise_for_status()
            data = response.json()

        latency_ms = (time.time() - start) * 1000

        return LLMResponse(
            content=data["message"]["content"],
            model=request.model,
            provider=Provider.OLLAMA,
            usage=LLMUsage(
                input_tokens=data.get("prompt_eval_count", 0),
                output_tokens=data.get("eval_count", 0),
                total_tokens=data.get("prompt_eval_count", 0) + data.get("eval_count", 0),
                estimated_cost_usd=0.0,  # Local models are free
            ),
            latency_ms=round(latency_ms, 2),
            raw_response=data,
        )

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                response = await client.get(f"{self.base_url}/api/tags")
                return response.status_code == 200
        except Exception:
            return False


# ─── Azure OpenAI Provider ────────────────────────────────────────────────────

class AzureOpenAIProvider(OpenAIProvider):
    """
    Azure OpenAI provider for enterprise deployments.
    Uses the same interface as OpenAI but with Azure endpoints.
    Required for companies using Microsoft 365 and Azure infrastructure.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        api_version: str = "2024-02-01",
    ):
        azure_key = api_key or os.getenv("AZURE_OPENAI_API_KEY")
        azure_endpoint = endpoint or os.getenv("AZURE_OPENAI_ENDPOINT")
        base_url = f"{azure_endpoint}/openai" if azure_endpoint else None
        super().__init__(api_key=azure_key, base_url=base_url)
        self.api_version = api_version

    @property
    def provider_name(self) -> Provider:
        return Provider.AZURE_OPENAI

    @property
    def available_models(self) -> list[str]:
        return ["gpt-4o", "gpt-4o-mini", "gpt-35-turbo"]


# ─── LLM Gateway ─────────────────────────────────────────────────────────────

class LLMGateway:
    """
    Enterprise LLM Gateway.
    Single entry point for all LLM calls across the Jnvoy platform.

    Features:
    - Automatic provider selection by model name
    - Fallback to secondary provider on failure
    - Cost tracking across all providers
    - Health monitoring of all providers
    - Retry logic with exponential backoff

    Usage:
        gateway = LLMGateway()
        response = await gateway.complete(
            messages=[LLMMessage(role="user", content="Hello")],
            model="claude-sonnet-4-6"
        )
    """

    def __init__(self):
        self._providers: dict[Provider, BaseLLMProvider] = {}
        self._model_registry: dict[str, Provider] = {}
        self._register_defaults()

    def _register_defaults(self):
        """
        Register all available providers.
        Order matters: register Azure before OpenAI so OpenAI wins the
        shared model names (gpt-4o etc.) in the model registry.
        Azure customers override by calling register_provider() explicitly.
        """
        providers = [
            AzureOpenAIProvider(),   # Register first so OpenAI overwrites shared models
            AnthropicProvider(),
            OpenAIProvider(),
            GoogleProvider(),
            MistralProvider(),
            OllamaProvider(),
        ]
        for provider in providers:
            self._providers[provider.provider_name] = provider
            for model in provider.available_models:
                self._model_registry[model] = provider.provider_name

    def register_provider(self, provider: BaseLLMProvider):
        """Register a custom provider. Allows extension without modifying core code."""
        self._providers[provider.provider_name] = provider
        for model in provider.available_models:
            self._model_registry[model] = provider.provider_name

    def get_provider_for_model(self, model: str) -> Optional[BaseLLMProvider]:
        """Look up which provider handles a given model."""
        provider_name = self._model_registry.get(model)
        if not provider_name:
            return None
        return self._providers.get(provider_name)

    async def complete(
        self,
        messages: list[LLMMessage],
        model: str,
        max_tokens: int = 1000,
        temperature: float = 0.7,
        system_prompt: Optional[str] = None,
        fallback_model: Optional[str] = None,
        max_retries: int = 2,
    ) -> LLMResponse:
        """
        Send a completion request through the gateway.
        Automatically routes to the correct provider.
        Retries on failure. Falls back to secondary model if configured.
        """
        provider = self.get_provider_for_model(model)
        if not provider:
            raise ValueError(
                f"No provider registered for model '{model}'. "
                f"Available models: {list(self._model_registry.keys())}"
            )

        request = LLMRequest(
            messages=messages,
            model=model,
            provider=provider.provider_name,
            max_tokens=max_tokens,
            temperature=temperature,
            system_prompt=system_prompt,
        )

        last_error = None
        for attempt in range(max_retries + 1):
            try:
                return await provider.complete(request)
            except Exception as e:
                last_error = e
                if attempt < max_retries:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff

        # Try fallback model if primary fails after all retries
        if fallback_model and fallback_model != model:
            fallback_provider = self.get_provider_for_model(fallback_model)
            if fallback_provider:
                request.model = fallback_model
                request.provider = fallback_provider.provider_name
                return await fallback_provider.complete(request)

        raise RuntimeError(
            f"All {max_retries + 1} attempts failed for model '{model}'. "
            f"Last error: {last_error}"
        )

    async def health_check_all(self) -> dict[str, bool]:
        """Check health of all registered providers in parallel."""
        results = await asyncio.gather(
            *[p.health_check() for p in self._providers.values()],
            return_exceptions=True
        )
        return {
            provider.value: bool(result) and not isinstance(result, Exception)
            for provider, result in zip(self._providers.keys(), results)
        }

    def list_models(self) -> dict[str, list[str]]:
        """List all available models grouped by provider."""
        return {
            provider.value: p.available_models
            for provider, p in self._providers.items()
        }

    def estimate_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        """Estimate cost for a completion before making the call."""
        return calculate_cost(model, input_tokens, output_tokens)


# ─── Singleton Gateway Instance ───────────────────────────────────────────────

# Single gateway instance shared across the entire application
# This is the standard pattern in large organisations
gateway = LLMGateway()
