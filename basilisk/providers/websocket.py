"""
Basilisk WebSocket Adapter — for WebSocket-based AI endpoints.

Pairs naturally with WSHawk for WebSocket AI application red teaming.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
from typing import Any, AsyncIterator

import websockets
from websockets.protocol import State

from basilisk.core.redaction import sanitize_error_text
from basilisk.providers.base import ProviderAdapter, ProviderMessage, ProviderResponse
from basilisk.runtime.destination_policy import DestinationPolicy

logger = logging.getLogger("basilisk.providers.websocket")


class WebSocketAdapter(ProviderAdapter):
    """
    Provider adapter for WebSocket-based AI services.

    Many real-time AI applications (chatbots, voice assistants, game AI)
    communicate over WebSocket rather than REST. This adapter handles
    the stateful, bidirectional connection.
    """

    def __init__(
        self,
        ws_url: str,
        auth_header: str = "",
        custom_headers: dict[str, str] | None = None,
        message_format: str = "json",  # json, plain, or binary
        response_content_path: str = "content",
        send_format_template: dict[str, Any] | None = None,
        timeout: float = 30.0,
        destination_policy: DestinationPolicy | None = None,
        max_response_bytes: int = 1_000_000,
    ) -> None:
        self._ws_url = ws_url
        self._auth_header = auth_header
        self._custom_headers = custom_headers or {}
        self._message_format = message_format
        self._response_content_path = response_content_path
        self._send_template = send_format_template or {}
        self._timeout = timeout
        self._destination_policy = destination_policy or DestinationPolicy()
        self._max_response_bytes = max_response_bytes
        self._ws: Any = None

    @property
    def name(self) -> str:
        return "websocket"

    async def _connect(self) -> Any:
        if not self._connection_is_open():
            approved = await self._destination_policy.approve(self._ws_url)
            headers = {**self._custom_headers}
            if self._auth_header:
                headers["Authorization"] = self._auth_header
            self._ws = await websockets.connect(
                self._ws_url,
                additional_headers=headers,
                open_timeout=self._timeout,
                close_timeout=self._timeout,
                max_size=self._max_response_bytes,
                host=approved.selected_address,
                port=approved.port,
                proxy=None,
            )
        return self._ws

    def _connection_is_open(self) -> bool:
        """Support both legacy websockets clients and websockets 16+."""
        if self._ws is None:
            return False
        state = getattr(self._ws, "state", None)
        if state is not None:
            return state is State.OPEN
        closed = getattr(self._ws, "closed", True)
        return not bool(closed)

    def _format_outgoing(self, messages: list[ProviderMessage], **kwargs: Any) -> str | bytes:
        if self._message_format == "binary":
            return (messages[-1].content if messages else "").encode("utf-8")
        if self._message_format == "plain":
            return messages[-1].content if messages else ""
        payload = {
            **self._send_template,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            **kwargs,
        }
        return json.dumps(payload)

    def _extract_content(self, raw: str) -> str:
        if self._message_format == "plain":
            return raw
        try:
            data = json.loads(raw)
            parts = self._response_content_path.split(".")
            current: Any = data
            for part in parts:
                if isinstance(current, dict):
                    current = current.get(part)
                elif isinstance(current, list):
                    try:
                        current = current[int(part)]
                    except (ValueError, IndexError):
                        return raw
                else:
                    return raw
                if current is None:
                    return raw
            return str(current)
        except json.JSONDecodeError:
            return raw

    def _normalize_incoming(self, raw: str | bytes) -> tuple[str, dict[str, Any]]:
        if isinstance(raw, bytes):
            encoded = base64.b64encode(raw).decode("ascii")
            return encoded, {
                "binary": True,
                "encoding": "base64",
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        content = self._extract_content(raw)
        try:
            payload = json.loads(raw)
            raw_dict = payload if isinstance(payload, dict) else {"json_type": type(payload).__name__}
        except (json.JSONDecodeError, TypeError):
            raw_dict = {
                "text": True,
                "bytes": len(raw.encode("utf-8", errors="replace")),
                "sha256": hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest(),
            }
        return content, raw_dict

    async def send(
        self,
        messages: list[ProviderMessage],
        model: str = "",
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> ProviderResponse:
        ws = await self._connect()
        outgoing = self._format_outgoing(messages, model=model, temperature=temperature, max_tokens=max_tokens, **kwargs)

        start = time.monotonic()
        try:
            await ws.send(outgoing)
            raw_response = await ws.recv()
            latency = (time.monotonic() - start) * 1000
            wire_size = len(raw_response) if isinstance(raw_response, bytes) else len(
                raw_response.encode("utf-8", errors="replace")
            )
            if wire_size > self._max_response_bytes:
                raise ValueError(f"provider response exceeded {self._max_response_bytes} bytes")
            content, raw_dict = self._normalize_incoming(raw_response)

            return ProviderResponse(
                content=content,
                role="assistant",
                model=model,
                latency_ms=latency,
                raw_response=raw_dict,
            )
        except Exception as e:
            failed_ws, self._ws = self._ws, None
            if failed_ws is not None:
                try:
                    await failed_ws.close()
                except Exception:
                    logger.debug("Failed to close broken WebSocket connection", exc_info=True)
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
        ws = await self._connect()
        outgoing = self._format_outgoing(messages, model=model, temperature=temperature, max_tokens=max_tokens, stream=True, **kwargs)

        try:
            await ws.send(outgoing)
            async for raw in ws:
                wire_size = len(raw) if isinstance(raw, bytes) else len(
                    raw.encode("utf-8", errors="replace")
                )
                if wire_size > self._max_response_bytes:
                    raise ValueError(f"provider response exceeded {self._max_response_bytes} bytes")
                content, _ = self._normalize_incoming(raw)
                if content:
                    yield content
                # Check for stream end signals
                if isinstance(raw, bytes):
                    continue
                try:
                    data = json.loads(raw)
                    if data.get("done") or data.get("finish_reason"):
                        break
                except (json.JSONDecodeError, TypeError):
                    pass
        except Exception as e:
            safe_error = sanitize_error_text(
                e,
                secrets=(self._auth_header, *self._custom_headers.values()),
            )
            logger.warning("Streaming error: %s", safe_error)
            failed_ws, self._ws = self._ws, None
            if failed_ws is not None:
                try:
                    await failed_ws.close()
                except Exception:
                    logger.debug("Failed to close broken WebSocket stream", exc_info=True)
            raise RuntimeError(safe_error) from None

    async def close(self) -> None:
        """Close the WebSocket connection."""
        ws, self._ws = self._ws, None
        if ws is not None:
            await ws.close()
