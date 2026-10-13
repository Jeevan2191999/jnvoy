"""
Jnvoy LangChain Integration

Drop-in LangChain LLM wrapper that automatically protects every call.

Usage:
    from core.langchain_integration import JnvoyLLM, JnvoyChat

    # As a simple LLM
    llm = JnvoyLLM(
        jnvoy_url="https://jnvoy.onrender.com",
        provider="anthropic",
        model="claude-haiku-4-5-20251001"
    )
    result = llm.invoke("My email is john@example.com. Summarise this.")

    # As a ChatModel (recommended)
    chat = JnvoyChat(
        jnvoy_url="https://jnvoy.onrender.com",
        provider="anthropic",
        model="claude-haiku-4-5-20251001"
    )
    result = chat.invoke([HumanMessage(content="My NI is AB123456C. Help me.")])

What happens automatically:
    - PII detected and redacted before reaching the LLM
    - Prompt injection attacks blocked
    - MCP tool responses scanned if tools are used
    - Every call logged to PostgreSQL audit trail
    - Compliance report available at /v1/report/compliance

Works with all LangChain chains, agents, and tools.
LangGraph compatible.
"""

import os
from typing import Any, Iterator, List, Mapping, Optional

import httpx

# LangChain imports with graceful fallback
try:
    from langchain_core.language_models.llms import LLM
    from langchain_core.language_models.chat_models import BaseChatModel
    from langchain_core.messages import (
        AIMessage, BaseMessage, HumanMessage, SystemMessage
    )
    from langchain_core.outputs import ChatGeneration, ChatResult, LLMResult, Generation
    from langchain_core.callbacks.manager import (
        CallbackManagerForLLMRun,
        AsyncCallbackManagerForLLMRun
    )
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False


# ── Base Jnvoy Client ─────────────────────────────────────────────────────────

class JnvoyClient:
    """
    HTTP client for the Jnvoy API.
    Used by both JnvoyLLM and JnvoyChat.
    """

    def __init__(
        self,
        jnvoy_url: str = "https://jnvoy.onrender.com",
        api_key: Optional[str] = None,
        provider: str = "anthropic",
        model: str = "claude-haiku-4-5-20251001",
        max_tokens: int = 1000,
        temperature: float = 0.7,
        use_cache: bool = True,
        use_routing: bool = True,
        timeout: float = 60.0,
    ):
        self.jnvoy_url = jnvoy_url.rstrip("/")
        self.api_key = api_key or os.getenv("JNVOY_API_KEY")
        self.provider = provider
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.use_cache = use_cache
        self.use_routing = use_routing
        self.timeout = timeout

    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-Jnvoy-API-Key"] = self.api_key
        return headers

    def call(self, messages: list[dict]) -> dict:
        """Make a synchronous call to the Jnvoy proxy."""
        payload = {
            "model": self.model,
            "provider": self.provider,
            "messages": messages,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "use_cache": self.use_cache,
            "use_routing": self.use_routing,
        }
        response = httpx.post(
            f"{self.jnvoy_url}/v1/proxy",
            json=payload,
            headers=self._headers(),
            timeout=self.timeout
        )
        if response.status_code == 400:
            data = response.json()
            if isinstance(data.get("detail"), dict):
                error = data["detail"].get("error", "")
                if error == "prompt_injection_detected":
                    raise ValueError(
                        f"Jnvoy blocked this request: prompt injection detected. "
                        f"Attack types: {data['detail'].get('attack_types', [])}. "
                        f"Severity: {data['detail'].get('severity', 'unknown')}."
                    )
        response.raise_for_status()
        return response.json()

    async def acall(self, messages: list[dict]) -> dict:
        """Make an async call to the Jnvoy proxy."""
        payload = {
            "model": self.model,
            "provider": self.provider,
            "messages": messages,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "use_cache": self.use_cache,
            "use_routing": self.use_routing,
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.jnvoy_url}/v1/proxy",
                json=payload,
                headers=self._headers()
            )
            response.raise_for_status()
            return response.json()

    def scan_pii(self, text: str) -> dict:
        """Scan text for PII without calling the LLM."""
        response = httpx.get(
            f"{self.jnvoy_url}/v1/scan",
            params={"text": text},
            headers=self._headers(),
            timeout=30.0
        )
        response.raise_for_status()
        return response.json()

    def scan_injection(self, text: str) -> dict:
        """Scan text for prompt injection attempts."""
        response = httpx.get(
            f"{self.jnvoy_url}/v1/scan/injection",
            params={"text": text},
            headers=self._headers(),
            timeout=30.0
        )
        response.raise_for_status()
        return response.json()

    def get_audit_summary(self) -> dict:
        """Get the compliance audit summary."""
        response = httpx.get(
            f"{self.jnvoy_url}/v1/audit/summary",
            headers=self._headers(),
            timeout=30.0
        )
        response.raise_for_status()
        return response.json()


# ── LangChain LLM ─────────────────────────────────────────────────────────────

if LANGCHAIN_AVAILABLE:

    class JnvoyLLM(LLM):
        """
        LangChain LLM wrapper for Jnvoy.

        Automatically protects every LLM call with:
        - PII detection and redaction
        - Prompt injection blocking
        - Compliance audit logging

        Example:
            from core.langchain_integration import JnvoyLLM

            llm = JnvoyLLM(provider="anthropic", model="claude-haiku-4-5-20251001")
            result = llm.invoke("My email is john@example.com. Summarise this.")
        """

        jnvoy_url: str = "https://jnvoy.onrender.com"
        jnvoy_api_key: Optional[str] = None
        provider: str = "anthropic"
        model: str = "claude-haiku-4-5-20251001"
        max_tokens: int = 1000
        temperature: float = 0.7
        use_cache: bool = True
        use_routing: bool = True
        timeout: float = 60.0

        @property
        def _llm_type(self) -> str:
            return "jnvoy"

        @property
        def _client(self) -> JnvoyClient:
            return JnvoyClient(
                jnvoy_url=self.jnvoy_url,
                api_key=self.jnvoy_api_key,
                provider=self.provider,
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                use_cache=self.use_cache,
                use_routing=self.use_routing,
                timeout=self.timeout,
            )

        def _call(
            self,
            prompt: str,
            stop: Optional[List[str]] = None,
            run_manager: Optional[CallbackManagerForLLMRun] = None,
            **kwargs: Any,
        ) -> str:
            messages = [{"role": "user", "content": prompt}]
            result = self._client.call(messages)
            return result["content"]

        @property
        def _identifying_params(self) -> Mapping[str, Any]:
            return {
                "jnvoy_url": self.jnvoy_url,
                "provider": self.provider,
                "model": self.model,
            }


    class JnvoyChat(BaseChatModel):
        """
        LangChain ChatModel wrapper for Jnvoy.

        Recommended over JnvoyLLM for most use cases.
        Works with ChatPromptTemplate, ConversationChain, and agents.

        Example:
            from core.langchain_integration import JnvoyChat
            from langchain_core.messages import HumanMessage

            chat = JnvoyChat(provider="anthropic", model="claude-haiku-4-5-20251001")
            result = chat.invoke([HumanMessage(content="My NI is AB123456C. Help.")])
            print(result.content)
        """

        jnvoy_url: str = "https://jnvoy.onrender.com"
        jnvoy_api_key: Optional[str] = None
        provider: str = "anthropic"
        model: str = "claude-haiku-4-5-20251001"
        max_tokens: int = 1000
        temperature: float = 0.7
        use_cache: bool = True
        use_routing: bool = True
        timeout: float = 60.0

        @property
        def _llm_type(self) -> str:
            return "jnvoy-chat"

        @property
        def _client(self) -> JnvoyClient:
            return JnvoyClient(
                jnvoy_url=self.jnvoy_url,
                api_key=self.jnvoy_api_key,
                provider=self.provider,
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                use_cache=self.use_cache,
                use_routing=self.use_routing,
                timeout=self.timeout,
            )

        def _convert_messages(self, messages: List[BaseMessage]) -> List[dict]:
            """Convert LangChain messages to Jnvoy format."""
            converted = []
            for msg in messages:
                if isinstance(msg, HumanMessage):
                    converted.append({"role": "user", "content": msg.content})
                elif isinstance(msg, AIMessage):
                    converted.append({"role": "assistant", "content": msg.content})
                elif isinstance(msg, SystemMessage):
                    converted.append({"role": "user", "content": f"[System: {msg.content}]"})
                else:
                    converted.append({"role": "user", "content": str(msg.content)})
            return converted

        def _generate(
            self,
            messages: List[BaseMessage],
            stop: Optional[List[str]] = None,
            run_manager: Optional[CallbackManagerForLLMRun] = None,
            **kwargs: Any,
        ) -> ChatResult:
            converted = self._convert_messages(messages)
            result = self._client.call(converted)
            message = AIMessage(content=result["content"])
            generation = ChatGeneration(message=message)
            return ChatResult(generations=[generation])

        async def _agenerate(
            self,
            messages: List[BaseMessage],
            stop: Optional[List[str]] = None,
            run_manager: Optional[AsyncCallbackManagerForLLMRun] = None,
            **kwargs: Any,
        ) -> ChatResult:
            converted = self._convert_messages(messages)
            result = await self._client.acall(converted)
            message = AIMessage(content=result["content"])
            generation = ChatGeneration(message=message)
            return ChatResult(generations=[generation])

        @property
        def _identifying_params(self) -> Mapping[str, Any]:
            return {
                "jnvoy_url": self.jnvoy_url,
                "provider": self.provider,
                "model": self.model,
            }

else:
    # Graceful fallback when LangChain is not installed
    class JnvoyLLM:
        def __init__(self, *args, **kwargs):
            raise ImportError(
                "LangChain is not installed. "
                "Install it with: pip install langchain-core"
            )

    class JnvoyChat:
        def __init__(self, *args, **kwargs):
            raise ImportError(
                "LangChain is not installed. "
                "Install it with: pip install langchain-core"
            )
