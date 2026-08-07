"""
Basilisk Context Window Sizing — determine max context length.

Uses binary search with progressively longer inputs to find the
exact context window boundary.
"""

from __future__ import annotations

import asyncio
import logging

from basilisk.core.profile import BasiliskProfile
from basilisk.providers.base import ProviderAdapter, ProviderMessage

logger = logging.getLogger("basilisk.recon.context")


FILLER_WORD = "test "  # ~1 token per word
KNOWN_CONTEXT_WINDOWS = {
    "gpt-4": 128_000,
    "gpt-4-turbo": 128_000,
    "gpt-3.5-turbo": 16_385,
    "claude-3": 200_000,
    "claude-3-5-sonnet": 200_000,
    "gemini": 1_000_000,
    "llama": 8_192,
    "mistral": 32_768,
}


async def measure_context_window(
    provider: ProviderAdapter,
    profile: BasiliskProfile,
) -> int:
    """
    Determine the target model's context window size.

    First checks if the model was already fingerprinted and uses known values.
    Otherwise, performs a binary search by increasing input lengths.
    """
    # Check known values first
    for model_pattern, window_size in KNOWN_CONTEXT_WINDOWS.items():
        if model_pattern in profile.detected_model.lower():
            profile.context_window = window_size
            profile.notes.append(f"Context window from known database: {window_size:,} tokens")
            return window_size

    # Binary search for unknown models
    low = 1_000
    high = 200_000
    last_success = low

    while low <= high:
        mid = (low + high) // 2
        test_text = FILLER_WORD * (mid // 2)  # Rough 2 chars per token

        try:
            resp = await provider.send(
                [ProviderMessage(role="user", content=f"{test_text}\n\nSay 'ok'.")],
                temperature=0.0,
                max_tokens=5,
            )

            if resp.error and ("context" in str(resp.error).lower() or "token" in str(resp.error).lower()):
                high = mid - 1
            elif resp.error:
                high = mid - 1
            else:
                last_success = mid
                low = mid + 1

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("Context-window probe failed at %s tokens: %s", mid, type(exc).__name__)
            high = mid - 1

    profile.context_window = last_success
    profile.notes.append(f"Context window measured via binary search: ~{last_success:,} tokens")
    return last_success
