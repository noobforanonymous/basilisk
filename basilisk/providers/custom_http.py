"""
Basilisk Custom HTTP Adapter — for arbitrary REST API AI endpoints.

Supports any HTTP-based AI service with configurable request/response mapping.
"""

from __future__ import annotations

import json
import time
from typing import Any, AsyncIterator

import httpx

from basilisk.providers.base import ProviderAdapter, ProviderMessage, ProviderResponse


class CustomHTTPAdapter(ProviderAdapter):
    """
    Provider adapter for custom HTTP REST API endpoints.

    Handles arbitrary AI services that don't fit standard provider APIs.
    Configurable request body template and response content extraction.
    """

    def __init__(
        self,
        base_url: str,
        auth_header: str = "",
        custom_headers: dict[str, str] | None = None,
        request_template: dict[str, Any] | None = None,
        response_content_path: str = "choices.0.message.content",
        timeout: float = 30.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth_header = auth_header
        self._custom_headers = custom_headers or {}
        self._request_template = request_template or {}
        self._response_content_path = response_content_path
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    @property
    def name(self) -> str:
        return "custom_http"

    @property
    def base_url(self) -> str:
        """Expose base_url for testing/logging."""
        return self._base_url

    def _build_headers(self) -> dict[str, str]:
        """Build headers for testing/internal use."""
        headers = {"Content-Type": "application/json", **self._custom_headers}
        if self._auth_header:
            headers["Authorization"] = self._auth_header
        return headers

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            headers: dict[str, str] = {
                "Content-Type": "application/json",
                **self._custom_headers,
            }
            if self._auth_header:
                headers["Authorization"] = self._auth_header
            self._client = httpx.AsyncClient(
                headers=headers,
                timeout=self._timeout,
                follow_redirects=True,
            )
        return self._client

    def _build_request_body(
        self,
        messages: list[ProviderMessage],
        temperature: float,
        max_tokens: int,
        **kwargs: Any,
    ) -> dict[str, Any]:
        body = {
            **self._request_template,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
            **kwargs,
        }
        return body

    def _extract_content(self, data: dict[str, Any]) -> str:
        """Extract content from response using dot-notation path."""
        parts = self._response_content_path.split(".")
        current: Any = data
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, list):
                try:
                    current = current[int(part)]
                except (ValueError, IndexError):
                    return ""
            else:
                return ""
            if current is None:
                return ""
        return str(current)

    async def send(
        self,
        messages: list[ProviderMessage],
        model: str = "",
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> ProviderResponse:
        client = await self._get_client()
        body = self._build_request_body(messages, temperature, max_tokens, **kwargs)
        if model:
            body["model"] = model

        start = time.monotonic()
        try:
            resp = await client.post(self._base_url, json=body)
            latency = (time.monotonic() - start) * 1000
            resp.raise_for_status()
            data = resp.json()
            content = self._extract_content(data)

            return ProviderResponse(
                content=content,
                role="assistant",
                model=model,
                latency_ms=latency,
                raw_response=data,
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
        client = await self._get_client()
        body = self._build_request_body(messages, temperature, max_tokens, stream=True, **kwargs)
        if model:
            body["model"] = model

        try:
            async with client.stream("POST", self._base_url, json=body) as resp:
                async for line in resp.aiter_lines():
                    if line.startswith("data: "):
                        chunk = line[6:]
                        if chunk.strip() == "[DONE]":
                            break
                        try:
                            data = json.loads(chunk)
                            content = self._extract_content(data)
                            if content:
                                yield content
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            yield f"[ERROR] {e}"

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
