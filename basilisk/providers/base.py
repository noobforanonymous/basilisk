"""
Basilisk Provider Base — abstract interface for all LLM providers.

Every provider adapter (OpenAI, Anthropic, custom HTTP, WebSocket)
implements this interface for uniform access from the scanner engine.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, AsyncIterator


@dataclass
class ProviderResponse:
    """Standardized response from any LLM provider."""
    content: str = ""
    role: str = "assistant"
    finish_reason: str = ""
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    latency_ms: float = 0.0
    raw_response: dict[str, Any] = field(default_factory=dict)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    def __init__(self, **kwargs: Any) -> None:
        """Flexible constructor to handle legacy 'usage' and current fields."""
        # Handle 'usage' if passed from older tests
        if "usage" in kwargs:
            usage = kwargs.pop("usage")
            kwargs["input_tokens"] = usage.get("prompt_tokens", 0)
            kwargs["output_tokens"] = usage.get("completion_tokens", 0)
            kwargs["total_tokens"] = usage.get("total_tokens", usage.get("prompt_tokens", 0) + usage.get("completion_tokens", 0))
        
        # Set fields manually because dataclass __init__ is overridden
        for k, v in kwargs.items():
            setattr(self, k, v)
        
        # Ensure defaults for missing fields
        for field_name in ["content", "role", "finish_reason", "model", "error"]:
            if not hasattr(self, field_name):
                setattr(self, field_name, "" if field_name != "error" else None)
        for field_name in ["input_tokens", "output_tokens", "total_tokens", "latency_ms"]:
            if not hasattr(self, field_name):
                setattr(self, field_name, 0 if field_name != "latency_ms" else 0.0)
        if not hasattr(self, "raw_response"):
            self.raw_response = {}
        if not hasattr(self, "tool_calls"):
            self.tool_calls = []

    @property
    def is_refusal(self) -> bool:
        """Detect if the response is a safety refusal."""
        from basilisk.core.refusal import is_refusal
        return is_refusal(self.content or "")

    @property
    def refusal_confidence(self) -> float:
        """Score 0.0-1.0 how confidently this is a refusal."""
        from basilisk.core.refusal import refusal_confidence
        return refusal_confidence(self.content or "")

    def to_dict(self) -> dict[str, Any]:
        """Convert response to a serializable dictionary."""
        return {
            "content": self.content,
            "role": self.role,
            "finish_reason": self.finish_reason,
            "model": self.model,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "latency_ms": self.latency_ms,
            "tool_calls": self.tool_calls,
            "is_refusal": self.is_refusal,
            "refusal_confidence": self.refusal_confidence,
            "error": self.error,
        }


@dataclass
class ProviderMessage:
    """Standard message format for sending to providers."""
    role: str
    content: str
    name: str | None = None
    tool_call_id: str | None = None
    tool_calls: list[dict[str, Any]] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert message to a dictionary for API requests."""
        data = {"role": self.role, "content": self.content}
        if self.name:
            data["name"] = self.name
        if self.tool_call_id:
            data["tool_call_id"] = self.tool_call_id
        if self.tool_calls:
            data["tool_calls"] = self.tool_calls
        return data


class ProviderAdapter(ABC):
    """
    Abstract base for all LLM provider adapters.

    Implementations handle authentication, request formatting,
    response parsing, and streaming for their specific provider API.

    Supports the async context manager protocol for resource cleanup:

        async with MyAdapter(...) as provider:
            response = await provider.send(messages)
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider identifier string."""
        ...

    @abstractmethod
    async def send(
        self,
        messages: list[ProviderMessage],
        model: str = "",
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> ProviderResponse:
        """Send messages and return a single response."""
        ...

    @abstractmethod
    async def send_streaming(
        self,
        messages: list[ProviderMessage],
        model: str = "",
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Send messages and yield response chunks as they stream."""
        ...

    async def send_with_tools(
        self,
        messages: list[ProviderMessage],
        tools: list[dict[str, Any]],
        model: str = "",
        **kwargs: Any,
    ) -> ProviderResponse:
        """Send messages with tool/function definitions."""
        return await self.send(messages, model=model, tools=tools, **kwargs)

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count for a text string."""
        # Rough estimate: ~4 chars per token for English
        return max(1, len(text) // 4)

    async def health_check(self) -> bool:
        """Check if the provider is reachable and authenticated."""
        try:
            resp = await self.send(
                [ProviderMessage(role="user", content="Say 'ok'")],
                max_tokens=5,
            )
            return resp.error is None
        except Exception:
            return False

    async def close(self) -> None:
        """Release any resources held by the adapter. Override in subclasses."""
        pass

    async def __aenter__(self) -> "ProviderAdapter":
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()
