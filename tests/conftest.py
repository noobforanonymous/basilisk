"""
Basilisk test configuration and shared fixtures.
"""

import pytest
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

# Ensure basilisk package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from basilisk.providers.base import ProviderResponse, ProviderMessage, ProviderAdapter
from basilisk.core.profile import BasiliskProfile
from basilisk.core.finding import Finding, Severity, AttackCategory


# Unit tests exercise scan functions in-process; dedicated isolation tests cover
# the real child-worker boundary separately.
os.environ.setdefault("BASILISK_DISABLE_PROCESS_ISOLATION", "1")


# ============================================================
# Mock Provider
# ============================================================

class MockProvider(ProviderAdapter):
    """
    A controllable mock LLM provider for testing attack module execution.

    Usage:
        prov = MockProvider(responses=["Sure, here's how to...", "I can't help with that."])
        # First call to send() returns responses[0], second returns responses[1], etc.
    """

    def __init__(self, responses: list[str] | None = None, is_refusal: bool = False):
        self._responses = responses or ["This is a test response."]
        self._call_index = 0
        self._is_refusal = is_refusal
        self.call_history: list[list[ProviderMessage]] = []

    @property
    def name(self) -> str:
        return "mock"

    async def send(
        self,
        messages: list[ProviderMessage],
        model: str = "",
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs,
    ) -> ProviderResponse:
        self.call_history.append(messages)
        content = self._responses[min(self._call_index, len(self._responses) - 1)]
        self._call_index += 1
        return ProviderResponse(
            content=content,
            role="assistant",
            model=model or "mock-model",
            input_tokens=len(str(messages)) // 4,
            output_tokens=len(content) // 4,
            total_tokens=(len(str(messages)) + len(content)) // 4,
            latency_ms=10.0,
        )

    async def send_streaming(self, messages, model="", temperature=0.7, max_tokens=4096, **kwargs):
        resp = await self.send(messages, model, temperature, max_tokens, **kwargs)
        for word in resp.content.split():
            yield word + " "


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def mock_provider():
    """A basic mock provider that returns compliant responses."""
    return MockProvider(responses=[
        "Sure, I'd be happy to help with that request.",
        "Here is the information you asked for.",
        "I can provide that for you.",
    ])


@pytest.fixture
def refusing_provider():
    """A mock provider that always refuses."""
    return MockProvider(responses=[
        "I'm sorry, but I can't help with that. As an AI language model, my guidelines prevent me from assisting with this request.",
    ])


@pytest.fixture
def test_profile():
    """A basic BasiliskProfile for testing."""
    return BasiliskProfile(
        target_url="http://test-target.local",
        detected_model="gpt-4-test",
    )


@pytest.fixture
def test_session(test_profile):
    """A lightweight mock session for testing attack execution."""
    session = MagicMock()
    session.id = "test-session-001"
    session.profile = test_profile
    session.findings = []
    session.add_finding = AsyncMock()
    session.add_error = AsyncMock()
    return session
