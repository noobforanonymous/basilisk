"""
Basilisk Custom HTTP Adapter — for arbitrary REST API AI endpoints.

Supports any HTTP-based AI service with configurable request/response mapping.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, AsyncIterator
from urllib.parse import urljoin

import httpx

from basilisk.core.redaction import sanitize_error_text
from basilisk.providers.base import ProviderAdapter, ProviderMessage, ProviderResponse
from basilisk.providers.limits import iter_sse_data_limited, read_http_response_limited
from basilisk.runtime.destination_policy import DestinationPolicy

logger = logging.getLogger("basilisk.providers.http")


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
        destination_policy: DestinationPolicy | None = None,
        max_response_bytes: int = 1_000_000,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth_header = auth_header
        self._custom_headers = custom_headers or {}
        self._request_template = request_template or {}
        self._response_content_path = response_content_path
        self._timeout = timeout
        self._destination_policy = destination_policy or DestinationPolicy()
        self._max_response_bytes = max_response_bytes
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
            self._client = httpx.AsyncClient(
                headers=self._build_headers(),
                timeout=self._timeout,
                follow_redirects=False,
                trust_env=False,
                limits=httpx.Limits(max_keepalive_connections=0),
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
            current_url = self._base_url
            for redirect_count in range(self._destination_policy.max_redirects + 1):
                approved = await self._destination_policy.approve(current_url)
                async with client.stream(
                    "POST",
                    approved.connect_url,
                    json=body,
                    headers={"Host": approved.host_header},
                    extensions={"sni_hostname": approved.server_hostname},
                ) as resp:
                    if resp.status_code in {301, 302, 303, 307, 308}:
                        location = resp.headers.get("location", "")
                        if not location or redirect_count >= self._destination_policy.max_redirects:
                            raise ValueError("redirect limit reached or redirect location missing")
                        current_url = urljoin(current_url, location)
                        continue
                    resp.raise_for_status()
                    raw_response = await read_http_response_limited(
                        resp, self._max_response_bytes
                    )
                    data = json.loads(raw_response)
                    break
            else:
                raise ValueError("redirect limit reached")
            latency = (time.monotonic() - start) * 1000
            content = self._extract_content(data)
            usage = data.get("usage", {}) if isinstance(data, dict) else {}
            choices = data.get("choices", []) if isinstance(data, dict) else []
            first_choice = choices[0] if choices and isinstance(choices[0], dict) else {}
            message = first_choice.get("message", {}) if isinstance(first_choice, dict) else {}

            return ProviderResponse(
                content=content,
                role="assistant",
                model=str(data.get("model", model)) if isinstance(data, dict) else model,
                latency_ms=latency,
                input_tokens=int(usage.get("prompt_tokens", 0) or 0),
                output_tokens=int(usage.get("completion_tokens", 0) or 0),
                total_tokens=int(usage.get("total_tokens", 0) or 0),
                finish_reason=str(first_choice.get("finish_reason", "")),
                tool_calls=list(message.get("tool_calls", []) or []) if isinstance(message, dict) else [],
                raw_response={
                    key: data[key]
                    for key in ("id", "system_fingerprint", "provider", "model_version")
                    if isinstance(data, dict) and key in data
                },
            )
        except Exception as e:
            latency = (time.monotonic() - start) * 1000
            return ProviderResponse(
                content="",
                latency_ms=latency,
                error=sanitize_error_text(
                    e,
                    secrets=(self._auth_header, *self._custom_headers.values()),
                ),
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
            approved = await self._destination_policy.approve(self._base_url)
            async with client.stream(
                "POST",
                approved.connect_url,
                json=body,
                headers={"Host": approved.host_header},
                extensions={"sni_hostname": approved.server_hostname},
            ) as resp:
                if resp.is_redirect:
                    raise ValueError("streaming redirects are not allowed")
                resp.raise_for_status()
                async for chunk in iter_sse_data_limited(resp, self._max_response_bytes):
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
            safe_error = sanitize_error_text(
                e,
                secrets=(self._auth_header, *self._custom_headers.values()),
            )
            logger.warning("Streaming error: %s", safe_error)
            raise RuntimeError(safe_error) from None

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
