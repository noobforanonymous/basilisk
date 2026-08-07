"""NVIDIA API Catalog adapter using its documented OpenAI-compatible endpoint."""

from __future__ import annotations

import json
import time
from typing import Any, AsyncIterator

import httpx

from basilisk.providers.base import ProviderAdapter, ProviderMessage, ProviderResponse
from basilisk.providers.limits import (
    ProviderResponseLimitError,
    iter_sse_data_limited,
    read_http_response_limited,
)


NVIDIA_API_BASE = "https://integrate.api.nvidia.com/v1"
NVIDIA_DEFAULT_MODEL = "openai/gpt-oss-20b"


class NVIDIAAdapter(ProviderAdapter):
    """Direct adapter for NVIDIA's hosted prototype endpoints."""

    def __init__(
        self,
        api_key: str,
        default_model: str = NVIDIA_DEFAULT_MODEL,
        timeout: float = 30.0,
        max_response_bytes: int = 1_000_000,
    ) -> None:
        self._api_key = api_key
        self._default_model = default_model or NVIDIA_DEFAULT_MODEL
        self._timeout = timeout
        self._max_response_bytes = max_response_bytes
        self._client: httpx.AsyncClient | None = None

    @property
    def name(self) -> str:
        return "nvidia"

    @property
    def default_model(self) -> str:
        return self._default_model

    @property
    def api_base(self) -> str:
        return NVIDIA_API_BASE

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=NVIDIA_API_BASE,
                timeout=self._timeout,
                follow_redirects=False,
            )
        return self._client

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

    @staticmethod
    def _messages(messages: list[ProviderMessage]) -> list[dict[str, Any]]:
        return [message.to_dict() for message in messages]

    async def send(
        self,
        messages: list[ProviderMessage],
        model: str = "",
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> ProviderResponse:
        client = await self._get_client()
        selected_model = model or self._default_model
        body: dict[str, Any] = {
            "model": selected_model,
            "messages": self._messages(messages),
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }
        for key in ("top_p", "tools", "tool_choice", "response_format", "seed"):
            if key in kwargs:
                body[key] = kwargs[key]
        started = time.monotonic()
        try:
            async with client.stream(
                "POST", "/chat/completions", headers=self._headers(), json=body
            ) as response:
                response.raise_for_status()
                raw_response = await read_http_response_limited(
                    response, self._max_response_bytes
                )
                payload = json.loads(raw_response)
            choice = payload.get("choices", [{}])[0]
            message = choice.get("message", {})
            usage = payload.get("usage", {})
            return ProviderResponse(
                content=message.get("content") or "",
                role=message.get("role") or "assistant",
                finish_reason=choice.get("finish_reason") or "",
                model=payload.get("model") or selected_model,
                input_tokens=int(usage.get("prompt_tokens") or 0),
                output_tokens=int(usage.get("completion_tokens") or 0),
                total_tokens=int(usage.get("total_tokens") or 0),
                latency_ms=(time.monotonic() - started) * 1000,
                raw_response={
                    "id": payload.get("id", ""),
                    "system_fingerprint": payload.get("system_fingerprint", ""),
                },
                tool_calls=message.get("tool_calls") or [],
            )
        except httpx.TimeoutException:
            error = "nvidia_timeout"
        except httpx.HTTPStatusError as exc:
            error = f"nvidia_http_{exc.response.status_code}"
        except httpx.RequestError:
            error = "nvidia_transport_error"
        except ProviderResponseLimitError:
            error = "nvidia_response_limit_exceeded"
        except (json.JSONDecodeError, KeyError, IndexError, TypeError, ValueError):
            error = "nvidia_invalid_response"
        return ProviderResponse(error=error, latency_ms=(time.monotonic() - started) * 1000)

    async def send_streaming(
        self,
        messages: list[ProviderMessage],
        model: str = "",
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        client = await self._get_client()
        body = {
            "model": model or self._default_model,
            "messages": self._messages(messages),
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True,
        }
        async with client.stream(
            "POST", "/chat/completions", headers=self._headers(), json=body
        ) as response:
            response.raise_for_status()
            async for raw in iter_sse_data_limited(response, self._max_response_bytes):
                raw = raw.strip()
                if raw == "[DONE]":
                    break
                try:
                    payload = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                content = payload.get("choices", [{}])[0].get("delta", {}).get("content")
                if content:
                    yield str(content)

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
