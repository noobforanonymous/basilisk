"""Bounded response readers used by network provider adapters."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx


class ProviderResponseLimitError(ValueError):
    """The provider exceeded the configured wire-response ceiling."""


async def read_http_response_limited(response: httpx.Response, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > limit:
            raise ProviderResponseLimitError(f"provider response exceeded {limit} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


async def iter_sse_data_limited(response: httpx.Response, limit: int) -> AsyncIterator[str]:
    """Yield SSE data fields while bounding protocol bytes before line decoding."""
    buffer = bytearray()
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > limit:
            raise ProviderResponseLimitError(f"provider stream exceeded {limit} bytes")
        buffer.extend(chunk)
        while b"\n" in buffer:
            line, _, remainder = buffer.partition(b"\n")
            buffer = bytearray(remainder)
            line = line.rstrip(b"\r")
            if line.startswith(b"data:"):
                yield line[5:].lstrip().decode("utf-8", errors="replace")
    if buffer.startswith(b"data:"):
        yield bytes(buffer[5:]).lstrip().decode("utf-8", errors="replace")
