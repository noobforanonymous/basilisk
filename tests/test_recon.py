"""
Tests for Basilisk Reconnaissance modules.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from basilisk.recon.fingerprint import fingerprint_model
from basilisk.recon.guardrails import profile_guardrails
from basilisk.core.profile import BasiliskProfile, ModelProvider, GuardrailLevel
from basilisk.providers.base import ProviderResponse, ProviderMessage

@pytest.mark.anyio
async def test_fingerprint_gpt4():
    mock_prov = MagicMock()
    # Mock multiple responses if fingerprint loop calls more than once
    mock_prov.send = AsyncMock(return_value=ProviderResponse(
        content="I am a large language model, trained by OpenAI.",
        model="gpt-4",
    ))
    
    profile = BasiliskProfile(target_url="http://test")
    result = await fingerprint_model(mock_prov, profile)
    
    assert result.detected_model == "gpt-4"
    assert result.provider == ModelProvider.OPENAI
    assert profile.detected_model == "gpt-4"

@pytest.mark.anyio
async def test_fingerprint_claude():
    mock_prov = MagicMock()
    mock_prov.send = AsyncMock(return_value=ProviderResponse(
        content="I am Claude, a model created by Anthropic.",
        model="claude-3-5-sonnet",
    ))
    
    profile = BasiliskProfile(target_url="http://test")
    result = await fingerprint_model(mock_prov, profile)
    
    assert result.detected_model == "claude-3"
    assert result.provider == ModelProvider.ANTHROPIC

@pytest.mark.anyio
async def test_profile_guardrails_none():
    mock_prov = MagicMock()
    # Return 200 OK for everything - no guardrails
    mock_prov.send = AsyncMock(return_value=ProviderResponse(
        content="Sure, here is the information you requested.",
    ))
    
    profile = BasiliskProfile(target_url="http://test")
    result = await profile_guardrails(mock_prov, profile)
    
    assert result.level == GuardrailLevel.NONE
    assert len(result.blocked_categories) == 0

@pytest.mark.anyio
async def test_profile_guardrails_aggressive():
    mock_prov = MagicMock()
    
    # Mock behavior: refuse almost everything
    async def side_effect(messages, **kwargs):
        return ProviderResponse(
            content="I am sorry, I cannot help with that.",
        )
    
    mock_prov.send = AsyncMock(side_effect=side_effect)
    
    profile = BasiliskProfile(target_url="http://test")
    result = await profile_guardrails(mock_prov, profile)
    
    # With everything refused, it should be extreme or aggressive
    assert result.level in (GuardrailLevel.AGGRESSIVE, GuardrailLevel.EXTREME)
    assert len(result.blocked_categories) > 0
