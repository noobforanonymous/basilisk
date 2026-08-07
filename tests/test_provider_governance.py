from __future__ import annotations

import ast
from pathlib import Path

import httpx

import basilisk.runtime as runtime
from basilisk.providers.base import ImageContent, ProviderAdapter, ProviderMessage, ProviderResponse
from basilisk.providers.custom_http import CustomHTTPAdapter
from basilisk.providers.nvidia import NVIDIAAdapter, NVIDIA_API_BASE
from basilisk.runtime.destination_policy import DestinationPolicy
from basilisk.runtime.request_engine import RequestExecutor, RequestPolicy


ROOT = Path(__file__).resolve().parents[1]
NETWORK_MODULES = {"aiohttp", "httpx", "litellm", "requests", "urllib3", "websockets"}
CONCRETE_ADAPTERS = {
    "CustomHTTPAdapter",
    "LiteLLMAdapter",
    "NVIDIAAdapter",
    "WebSocketAdapter",
}


def _policy(**overrides) -> RequestPolicy:
    values = {
        "max_requests": 3,
        "max_input_tokens": 1_000,
        "max_output_tokens": 1_000,
        "max_response_bytes": 1_000,
        "timeout_seconds": 1.0,
        "max_concurrency": 1,
        "minimum_delay_seconds": 0.0,
    }
    values.update(overrides)
    return RequestPolicy(**values)


def test_runtime_public_api_does_not_expose_ungoverned_provider_factory():
    assert "create_raw_provider" not in runtime.__all__
    assert not hasattr(runtime, "create_raw_provider")


def test_transports_and_concrete_provider_construction_are_confined():
    violations: list[str] = []
    for path in (ROOT / "basilisk").rglob("*.py"):
        relative = path.relative_to(ROOT).as_posix()
        tree = ast.parse(path.read_text("utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported = {alias.name.split(".", 1)[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported = {(node.module or "").split(".", 1)[0]}
            else:
                imported = set()
            if imported & NETWORK_MODULES and not relative.startswith("basilisk/providers/"):
                violations.append(f"{relative}:{node.lineno}: network transport import")
            if isinstance(node, ast.Call):
                name = ""
                if isinstance(node.func, ast.Name):
                    name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    name = node.func.attr
                if name in CONCRETE_ADAPTERS and relative != "basilisk/runtime/orchestrator.py":
                    violations.append(f"{relative}:{node.lineno}: concrete adapter construction")
    assert violations == []


async def test_executor_counts_serialized_multimodal_input_before_transport():
    class NeverCalled(ProviderAdapter):
        calls = 0

        @property
        def name(self):
            return "never"

        async def send(self, *args, **kwargs):
            self.calls += 1
            return ProviderResponse(content="unexpected")

        async def send_streaming(self, *args, **kwargs):
            self.calls += 1
            yield "unexpected"

    raw = NeverCalled()
    executor = RequestExecutor(raw, _policy(max_input_tokens=10))
    response = await executor.send([
        ProviderMessage(
            role="user",
            content="x",
            images=[ImageContent(data="A" * 200)],
        )
    ])
    assert "input token budget exhausted" in response.error
    assert raw.calls == 0


async def test_executor_estimates_unreported_output_tokens():
    class Unmetered(ProviderAdapter):
        @property
        def name(self):
            return "unmetered"

        async def send(self, *args, **kwargs):
            return ProviderResponse(content="x" * 40, output_tokens=0)

        async def send_streaming(self, *args, **kwargs):
            yield "x" * 40

    response = await RequestExecutor(Unmetered(), _policy(max_output_tokens=5)).send([
        ProviderMessage(role="user", content="hello")
    ])
    assert "output token budget exhausted" in response.error


async def test_executor_sanitizes_unexpected_provider_exceptions():
    class Broken(ProviderAdapter):
        @property
        def name(self):
            return "broken"

        async def send(self, *args, **kwargs):
            raise RuntimeError("Authorization: Bearer nvapi-secret-value")

        async def send_streaming(self, *args, **kwargs):
            raise RuntimeError("Authorization: Bearer nvapi-secret-value")
            yield ""

    response = await RequestExecutor(Broken(), _policy()).send([
        ProviderMessage(role="user", content="hello")
    ])
    assert response.error
    assert "nvapi-secret-value" not in response.error


async def test_custom_http_caps_wire_response_before_json_parsing():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": "x" * 100}}]})

    adapter = CustomHTTPAdapter(
        "https://127.0.0.1/chat",
        destination_policy=DestinationPolicy(allow_private=True),
        max_response_bytes=32,
    )
    adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        response = await adapter.send([ProviderMessage(role="user", content="hello")])
        assert "provider response exceeded 32 bytes" in response.error
    finally:
        await adapter.close()


async def test_nvidia_caps_wire_response_before_json_parsing():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": "x" * 100}}]})

    adapter = NVIDIAAdapter(api_key="test-only", max_response_bytes=32)
    adapter._client = httpx.AsyncClient(
        base_url=NVIDIA_API_BASE,
        transport=httpx.MockTransport(handler),
    )
    try:
        response = await adapter.send([ProviderMessage(role="user", content="hello")])
        assert response.error == "nvidia_response_limit_exceeded"
    finally:
        await adapter.close()
