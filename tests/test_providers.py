"""
Tests for Basilisk Provider Adapters.
"""

from __future__ import annotations

import json

import httpx

from basilisk.providers.base import ProviderMessage, ProviderResponse
from basilisk.providers.custom_http import CustomHTTPAdapter
from basilisk.providers.websocket import WebSocketAdapter
from basilisk.providers.nvidia import NVIDIAAdapter, NVIDIA_API_BASE
from basilisk.runtime import destination_policy as policy_module
from basilisk.runtime.destination_policy import DestinationPolicy
from websockets.protocol import State


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

    async def test_request_connects_to_approved_ip_with_original_host_and_sni(
        self,
        monkeypatch,
    ):
        monkeypatch.setattr(
            policy_module,
            "_resolve_addresses",
            lambda host, port: ["93.184.216.34"],
        )

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url == "https://93.184.216.34/chat"
            assert request.headers["Host"] == "api.example.test"
            assert request.extensions["sni_hostname"] == "api.example.test"
            return httpx.Response(200, json={
                "choices": [{"message": {"content": "pinned"}}],
            })

        adapter = CustomHTTPAdapter(
            "https://api.example.test/chat",
            destination_policy=DestinationPolicy(allowed_hosts=("api.example.test",)),
        )
        adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            response = await adapter.send([ProviderMessage(role="user", content="hello")])
            assert response.content == "pinned"
            assert not response.error
        finally:
            await adapter.close()


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


class TestNVIDIAAdapter:
    def test_documented_defaults(self):
        adapter = NVIDIAAdapter(api_key="test-only")
        assert adapter.api_base == "https://integrate.api.nvidia.com/v1"
        assert adapter.default_model == "openai/gpt-oss-20b"

    async def test_openai_compatible_chat_response(self):
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url == f"{NVIDIA_API_BASE}/chat/completions"
            assert request.headers["Authorization"] == "Bearer test-only"
            body = json.loads(request.content)
            assert body["model"] == "openai/gpt-oss-20b"
            return httpx.Response(200, json={
                "id": "chatcmpl-test",
                "model": body["model"],
                "choices": [{
                    "message": {"role": "assistant", "content": "ok"},
                    "finish_reason": "stop",
                }],
                "usage": {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3},
            })

        adapter = NVIDIAAdapter(api_key="test-only")
        adapter._client = httpx.AsyncClient(
            base_url=NVIDIA_API_BASE,
            transport=httpx.MockTransport(handler),
        )
        try:
            response = await adapter.send([ProviderMessage(role="user", content="hello")])
            assert response.content == "ok"
            assert response.total_tokens == 3
        finally:
            await adapter.close()

    async def test_http_failure_does_not_expose_response_or_credentials(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                401,
                request=request,
                text="credential nvapi-private-value rejected",
            )

        adapter = NVIDIAAdapter(api_key="nvapi-private-value")
        adapter._client = httpx.AsyncClient(
            base_url=NVIDIA_API_BASE,
            transport=httpx.MockTransport(handler),
        )
        try:
            response = await adapter.send([ProviderMessage(role="user", content="hello")])
            assert response.error == "nvidia_http_401"
            assert "nvapi-private-value" not in response.error
        finally:
            await adapter.close()

    async def test_openai_compatible_streaming_response(self):
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url == f"{NVIDIA_API_BASE}/chat/completions"
            assert request.headers["Authorization"] == "Bearer test-only"
            body = json.loads(request.content)
            assert body["stream"] is True
            return httpx.Response(
                200,
                request=request,
                headers={"Content-Type": "text/event-stream"},
                content=(
                    b'data: {"choices":[{"delta":{"content":"hello"}}]}\n\n'
                    b'data: {"choices":[{"delta":{"content":" world"}}]}\n\n'
                    b"data: [DONE]\n\n"
                ),
            )

        adapter = NVIDIAAdapter(api_key="test-only")
        adapter._client = httpx.AsyncClient(
            base_url=NVIDIA_API_BASE,
            transport=httpx.MockTransport(handler),
        )
        try:
            chunks = [
                chunk
                async for chunk in adapter.send_streaming(
                    [ProviderMessage(role="user", content="hello")]
                )
            ]
            assert chunks == ["hello", " world"]
        finally:
            await adapter.close()


class TestWebSocketAdapter:
    def test_websockets_16_open_state(self):
        class Connection:
            state = State.OPEN

        adapter = WebSocketAdapter("ws://127.0.0.1:9000")
        adapter._ws = Connection()
        assert adapter._connection_is_open()

    def test_websockets_16_closed_state(self):
        class Connection:
            state = State.CLOSED

        adapter = WebSocketAdapter("ws://127.0.0.1:9000")
        adapter._ws = Connection()
        assert not adapter._connection_is_open()

    async def test_connect_uses_approved_socket_ip_and_disables_proxy(
        self,
        monkeypatch,
    ):
        monkeypatch.setattr(
            policy_module,
            "_resolve_addresses",
            lambda host, port: ["93.184.216.34"],
        )
        captured = {}

        class Connection:
            state = State.OPEN

        async def fake_connect(uri, **kwargs):
            captured["uri"] = uri
            captured["kwargs"] = kwargs
            return Connection()

        monkeypatch.setattr("basilisk.providers.websocket.websockets.connect", fake_connect)
        adapter = WebSocketAdapter(
            "wss://socket.example.test:9443/chat",
            destination_policy=DestinationPolicy(allowed_hosts=("socket.example.test",)),
        )
        connection = await adapter._connect()
        assert isinstance(connection, Connection)
        assert captured["uri"] == "wss://socket.example.test:9443/chat"
        assert captured["kwargs"]["host"] == "93.184.216.34"
        assert captured["kwargs"]["port"] == 9443
        assert captured["kwargs"]["proxy"] is None
