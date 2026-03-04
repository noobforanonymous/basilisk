"""
Basilisk LiteLLM Adapter — universal provider adapter via litellm.

Supports OpenAI, Anthropic, Google, Azure, AWS Bedrock, Ollama, vLLM,
and any other litellm-supported provider through a single interface.
"""

from __future__ import annotations

import time
from typing import Any, AsyncIterator

import litellm

from basilisk.providers.base import ProviderAdapter, ProviderMessage, ProviderResponse

# Suppress litellm's verbose logging
litellm.suppress_debug_info = True


class LiteLLMAdapter(ProviderAdapter):
    """
    Universal LLM adapter using litellm for multi-provider support.

    litellm translates calls to OpenAI, Anthropic, Google, Azure,
    Bedrock, Ollama, vLLM, and 100+ other providers automatically.
    """

    def __init__(
        self,
        api_key: str = "",
        api_base: str | None = None,
        provider: str = "openai",
        default_model: str = "",
        timeout: float = 30.0,
        max_retries: int = 3,
        custom_headers: dict[str, str] | None = None,
    ) -> None:
        self._provider = provider

        # GitHub Models: free AI API via github.com/marketplace/models
        if provider == "github":
            import os
            self._api_key = api_key or os.environ.get("GH_MODELS_TOKEN", "")
            self._api_base = api_base or "https://models.inference.ai.azure.com"
            self._custom_headers = custom_headers or {}
        else:
            self._api_key = api_key
            self._api_base = api_base
            self._custom_headers = custom_headers or {}

        self._default_model = default_model or self._infer_default_model(provider)
        self._timeout = timeout
        self._max_retries = max_retries

    @property
    def name(self) -> str:
        return f"litellm:{self._provider}"

    @property
    def provider(self) -> str:
        """Expose provider for testing/logging."""
        return self._provider

    @property
    def default_model(self) -> str:
        """Expose default_model for testing/logging."""
        return self._default_model

    def _infer_default_model(self, provider: str) -> str:
        defaults = {
            "openai": "gpt-4",
            "anthropic": "claude-3-5-sonnet-20241022",
            "google": "gemini/gemini-2.0-flash",
            "azure": "azure/gpt-4",
            "ollama": "ollama/llama3.1",
            "bedrock": "bedrock/anthropic.claude-3-sonnet",
            "github": "gpt-4o-mini",
        }
        return defaults.get(provider, "gpt-4")

    def _build_messages(self, messages: list[ProviderMessage]) -> list[dict[str, Any]]:
        formatted = []
        for msg in messages:
            m: dict[str, Any] = {"role": msg.role, "content": msg.content}
            if msg.name:
                m["name"] = msg.name
            if msg.tool_call_id:
                m["tool_call_id"] = msg.tool_call_id
            if msg.tool_calls:
                m["tool_calls"] = msg.tool_calls
            formatted.append(m)
        return formatted

    async def send(
        self,
        messages: list[ProviderMessage],
        model: str = "",
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> ProviderResponse:
        model = model or self._default_model
        formatted = self._build_messages(messages)

        call_kwargs: dict[str, Any] = {
            "model": model,
            "messages": formatted,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "timeout": self._timeout,
            "num_retries": self._max_retries,
        }

        if self._api_key:
            call_kwargs["api_key"] = self._api_key
        if self._api_base:
            call_kwargs["api_base"] = self._api_base
        if self._custom_headers:
            call_kwargs["extra_headers"] = self._custom_headers
        if "tools" in kwargs:
            call_kwargs["tools"] = kwargs["tools"]
        if "response_format" in kwargs:
            call_kwargs["response_format"] = kwargs["response_format"]

        start = time.monotonic()
        try:
            response = await litellm.acompletion(**call_kwargs)
            latency = (time.monotonic() - start) * 1000

            choice = response.choices[0]
            content = choice.message.content or ""
            tool_calls = []
            if hasattr(choice.message, "tool_calls") and choice.message.tool_calls:
                tool_calls = [
                    {
                        "id": tc.id,
                        "type": tc.type,
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in choice.message.tool_calls
                ]

            usage = response.usage
            return ProviderResponse(
                content=content,
                role="assistant",
                finish_reason=choice.finish_reason or "",
                model=response.model or model,
                input_tokens=usage.prompt_tokens if usage else 0,
                output_tokens=usage.completion_tokens if usage else 0,
                total_tokens=usage.total_tokens if usage else 0,
                latency_ms=latency,
                raw_response=response.model_dump() if hasattr(response, "model_dump") else {},
                tool_calls=tool_calls,
            )
        except Exception as e:
            latency = (time.monotonic() - start) * 1000
            return ProviderResponse(
                content="",
                latency_ms=latency,
                error=str(e),
            )

    async def send_streaming(
        self,
        messages: list[ProviderMessage],
        model: str = "",
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        model = model or self._default_model
        formatted = self._build_messages(messages)

        call_kwargs: dict[str, Any] = {
            "model": model,
            "messages": formatted,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True,
            "timeout": self._timeout,
        }

        if self._api_key:
            call_kwargs["api_key"] = self._api_key
        if self._api_base:
            call_kwargs["api_base"] = self._api_base

        try:
            response = await litellm.acompletion(**call_kwargs)
            async for chunk in response:
                delta = chunk.choices[0].delta
                if delta and delta.content:
                    yield delta.content
        except Exception as e:
            yield f"[ERROR] {e}"

    async def send_with_tools(
        self,
        messages: list[ProviderMessage],
        tools: list[dict[str, Any]],
        model: str = "",
        **kwargs: Any,
    ) -> ProviderResponse:
        return await self.send(messages, model=model, tools=tools, **kwargs)

    def estimate_tokens(self, text: str) -> int:
        """Use tiktoken for accurate OpenAI token estimation, fallback to heuristic."""
        try:
            import tiktoken
            enc = tiktoken.encoding_for_model(self._default_model)
            return len(enc.encode(text))
        except Exception:
            return max(1, len(text) // 4)
