"""
Tests for Basilisk Provider Adapters.
"""

from __future__ import annotations

import pytest
from basilisk.providers.base import ProviderAdapter, ProviderMessage, ProviderResponse
from basilisk.providers.custom_http import CustomHTTPAdapter


class TestProviderMessage:
    def test_message_creation(self):
        msg = ProviderMessage(role="user", content="Hello")
        assert msg.role == "user"
        assert msg.content == "Hello"

    def test_message_to_dict(self):
        msg = ProviderMessage(role="assistant", content="Hi there")
        d = msg.to_dict()
        assert d["role"] == "assistant"
        assert d["content"] == "Hi there"


class TestProviderResponse:
    def test_response_creation(self):
        resp = ProviderResponse(
            content="Test response",
            model="gpt-4",
            usage={"prompt_tokens": 10, "completion_tokens": 20},
        )
        assert resp.content == "Test response"
        assert resp.model == "gpt-4"


class TestCustomHTTPAdapter:
    def test_adapter_creation(self):
        adapter = CustomHTTPAdapter(
            base_url="https://api.test.com/chat",
            auth_header="Bearer sk-test",
            timeout=30.0,
        )
        assert adapter.base_url == "https://api.test.com/chat"

    def test_adapter_headers(self):
        adapter = CustomHTTPAdapter(
            base_url="https://api.test.com",
            auth_header="Bearer sk-test",
            custom_headers={"X-Custom": "value"},
        )
        headers = adapter._build_headers()
        assert "Authorization" in headers or "X-Custom" in headers


class TestLiteLLMAdapter:
    def test_adapter_creation(self):
        from basilisk.providers.litellm_adapter import LiteLLMAdapter
        adapter = LiteLLMAdapter(
            api_key="sk-test",
            provider="openai",
            default_model="gpt-4",
        )
        assert adapter.provider == "openai"
        assert adapter.default_model == "gpt-4"
