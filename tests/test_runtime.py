"""
Tests for the shared runtime/orchestration foundation.
"""

from __future__ import annotations

import asyncio

import pytest

from basilisk.campaign import build_attack_graph, should_use_attack_graph
from basilisk.attacks.base import describe_attack_module, resolve_attack_modules
from basilisk.attacks.injection.direct import DirectInjection
from basilisk.core.config import BasiliskConfig
from basilisk.core.session import ScanSession
from basilisk.providers.websocket import WebSocketAdapter
from basilisk.providers.base import ProviderMessage
from basilisk.runtime.orchestrator import create_provider
from basilisk.runtime.request_engine import (
    RequestBudgetExceeded,
    RequestExecutor,
    RequestLedger,
    RequestPolicy,
)


class TestAttackCatalog:
    def test_resolve_attack_modules_excludes_research_by_default(self):
        modules = resolve_attack_modules()
        assert modules
        assert all(module.trust_tier != "research" for module in modules)

    def test_resolve_attack_modules_allows_explicit_research_selection(self):
        modules = resolve_attack_modules(selected=["multimodal"])
        assert any(module.name.startswith("multimodal") for module in modules)

    def test_descriptor_exposes_success_criteria(self):
        descriptor = describe_attack_module(DirectInjection())
        assert descriptor.trust_tier in {"production", "beta", "research"}
        assert descriptor.success_criteria
        assert descriptor.evidence_requirements


class TestAttackGraph:
    def test_build_attack_graph_for_exploit_chain(self):
        cfg = BasiliskConfig.from_dict({
            "target": {"url": "https://example.test", "provider": "custom"},
            "policy": {"execution_mode": "exploit_chain"},
            "campaign": {"objective": {"name": "tool_chain_validation"}},
        })
        session = ScanSession(cfg)
        modules = resolve_attack_modules(
            selected=["injection.direct", "toolabuse.ssrf", "exfil.tool_schema"],
            include_research=False,
        )
        graph = build_attack_graph(session, modules)
        assert graph.execution_mode == "exploit_chain"
        assert graph.stages
        assert any(stage.name == "initial_access" for stage in graph.stages)
        assert any(stage.name == "exploitation" for stage in graph.stages)

    def test_should_use_attack_graph_for_research(self):
        cfg = BasiliskConfig.from_dict({
            "target": {"url": "https://example.test", "provider": "custom"},
            "policy": {"execution_mode": "research"},
        })
        session = ScanSession(cfg)
        assert should_use_attack_graph(session) is True


class TestWebSocketProviderSelection:
    def test_websocket_url_uses_websocket_adapter_without_api_key(self):
        cfg = BasiliskConfig.from_dict({
            "target": {"url": "wss://example.test/chat", "provider": "custom"},
        })
        assert cfg.validate() == []
        provider = create_provider(cfg)
        assert isinstance(provider, RequestExecutor)
        assert isinstance(provider.provider, WebSocketAdapter)

    def test_explicit_websocket_provider_is_keyless(self):
        cfg = BasiliskConfig.from_dict({
            "target": {"url": "ws://127.0.0.1:9000", "provider": "websocket"},
        })
        assert cfg.validate() == []
        provider = create_provider(cfg)
        assert isinstance(provider, RequestExecutor)
        assert isinstance(provider.provider, WebSocketAdapter)


class TestProviderCredentials:
    def test_runtime_credential_override_does_not_enter_config(self):
        cfg = BasiliskConfig.from_dict({
            "target": {
                "url": "direct",
                "provider": "nvidia",
                "model": "test-model",
            },
        })
        provider = create_provider(cfg, credential_override="runtime-only-secret")
        assert cfg.target.api_key == ""
        assert provider.provider._api_key == "runtime-only-secret"
        assert "runtime-only-secret" not in str(cfg.to_safe_dict())

    def test_runtime_auth_and_header_overrides_do_not_enter_config(self):
        cfg = BasiliskConfig.from_dict({
            "target": {
                "url": "https://example.test/chat",
                "provider": "custom",
            },
        })
        provider = create_provider(
            cfg,
            auth_header_override="Bearer runtime-persona-token",
            custom_headers_override={"X-Resource-Tenant": "tenant-a"},
        )
        raw = provider.provider
        assert raw._build_headers()["Authorization"] == "Bearer runtime-persona-token"
        assert raw._build_headers()["X-Resource-Tenant"] == "tenant-a"
        assert cfg.target.auth_header == ""
        assert cfg.target.custom_headers == {}
        assert "runtime-persona-token" not in str(cfg.to_safe_dict())

class TestRequestExecutor:
    @staticmethod
    def policy(**overrides):
        values = {
            "max_requests": 2,
            "max_input_tokens": 1_000,
            "max_output_tokens": 1_000,
            "max_response_bytes": 1_000,
            "timeout_seconds": 1.0,
            "max_concurrency": 2,
            "minimum_delay_seconds": 0.0,
            "retry_attempts": 0,
        }
        values.update(overrides)
        return RequestPolicy(**values)

    async def test_budget_counts_actual_provider_calls(self, mock_provider):
        executor = RequestExecutor(mock_provider, self.policy(), namespace="budget")
        message = [ProviderMessage(role="user", content="hello")]
        assert not (await executor.send(message)).error
        assert not (await executor.send(message)).error
        rejected = await executor.send(message)
        assert "request budget exhausted" in rejected.error
        assert len(mock_provider.call_history) == 2
        assert executor.stats.reserved_requests == 2

    async def test_response_limit_rejects_oversized_content(self, mock_provider):
        executor = RequestExecutor(
            mock_provider,
            self.policy(max_response_bytes=4),
            namespace="response-limit",
        )
        response = await executor.send([ProviderMessage(role="user", content="hello")])
        assert "response exceeded 4 bytes" in response.error
        assert response.content == ""

    async def test_request_ids_are_deterministic_for_same_namespace(self, mock_provider):
        left = RequestExecutor(type(mock_provider)(), self.policy(), namespace="stable")
        right = RequestExecutor(type(mock_provider)(), self.policy(), namespace="stable")
        message = [ProviderMessage(role="user", content="hello")]
        left_response = await left.send(message)
        right_response = await right.send(message)
        assert (
            left_response.raw_response["basilisk_request_id"]
            == right_response.raw_response["basilisk_request_id"]
        )

    async def test_request_ids_include_request_content(self, mock_provider):
        left = RequestExecutor(type(mock_provider)(), self.policy(), namespace="stable")
        right = RequestExecutor(type(mock_provider)(), self.policy(), namespace="stable")
        left_response = await left.send([ProviderMessage(role="user", content="first")])
        right_response = await right.send([ProviderMessage(role="user", content="second")])
        assert (
            left_response.raw_response["basilisk_request_id"]
            != right_response.raw_response["basilisk_request_id"]
        )

    async def test_cancellation_prevents_network_call(self, mock_provider):
        executor = RequestExecutor(mock_provider, self.policy())
        executor.cancel()
        with pytest.raises(asyncio.CancelledError):
            await executor.send([ProviderMessage(role="user", content="hello")])
        assert mock_provider.call_history == []

    async def test_shared_ledger_caps_target_and_attacker_calls_together(self, mock_provider):
        policy = self.policy(max_requests=2)
        ledger = RequestLedger(policy)
        target = RequestExecutor(
            type(mock_provider)(), policy, namespace="target", ledger=ledger
        )
        attacker = RequestExecutor(
            type(mock_provider)(), policy, namespace="attacker", ledger=ledger
        )
        message = [ProviderMessage(role="user", content="hello")]

        assert not (await target.send(message)).error
        assert not (await attacker.send(message)).error
        rejected = await target.send(message)

        assert "request budget exhausted" in rejected.error
        assert target.stats.reserved_requests == 1
        assert attacker.stats.reserved_requests == 1
        assert ledger.stats.reserved_requests == 2

    async def test_shared_ledger_atomically_caps_concurrent_stream_output(self, mock_provider):
        barrier = asyncio.Barrier(2)

        class BarrierStreamingProvider(type(mock_provider)):
            async def send_streaming(self, *args, **kwargs):
                await barrier.wait()
                yield "x" * 12  # three estimated tokens

        policy = self.policy(max_output_tokens=5)
        ledger = RequestLedger(policy)
        left = RequestExecutor(
            BarrierStreamingProvider(), policy, namespace="left", ledger=ledger
        )
        right = RequestExecutor(
            BarrierStreamingProvider(), policy, namespace="right", ledger=ledger
        )
        message = [ProviderMessage(role="user", content="hello")]

        async def consume(executor):
            return [chunk async for chunk in executor.send_streaming(message)]

        results = await asyncio.gather(consume(left), consume(right), return_exceptions=True)

        assert sum(isinstance(result, RequestBudgetExceeded) for result in results) == 1
        assert sum(isinstance(result, list) for result in results) == 1
        assert ledger.stats.output_tokens == 3
        assert ledger.stats.output_tokens <= policy.max_output_tokens
        assert ledger.stats.completed_requests == 1
        assert ledger.stats.failed_requests == 1


class TestModeProfiles:
    def test_mode_profile_limits_are_immutable(self):
        cfg = BasiliskConfig.from_dict({
            "target": {"url": "https://example.test", "provider": "custom"},
            "mode": "quick",
            "policy": {"request_budget": 99_999, "max_concurrency": 99},
        })
        policy = cfg.request_policy()
        assert policy.max_requests == 60
        assert policy.max_concurrency == 2

    def test_chaos_requires_explicit_isolated_environment(self):
        cfg = BasiliskConfig.from_dict({
            "target": {"url": "https://example.test", "provider": "custom"},
            "mode": "chaos",
        })
        assert "Chaos mode requires policy.isolated_environment=true" in cfg.validate()

    def test_only_isolated_chaos_enables_research_without_explicit_opt_in(self):
        deep = BasiliskConfig.from_dict({
            "target": {"url": "https://example.test", "provider": "custom"},
            "mode": "deep",
        })
        chaos = BasiliskConfig.from_dict({
            "target": {"url": "http://127.0.0.1:8765", "provider": "custom"},
            "mode": "chaos",
            "policy": {"isolated_environment": True},
        })
        assert deep.research_modules_enabled is False
        assert chaos.research_modules_enabled is True

    def test_cost_preview_is_deterministic_and_bounded_by_mode(self):
        cfg = BasiliskConfig.from_dict({
            "target": {"url": "https://example.test", "provider": "custom"},
            "mode": "quick",
            "modules": ["injection.direct"],
            "probe_ids": ["INJ-001"],
            "skip_recon": True,
            "evolution": {"enabled": False},
            "policy": {"request_budget": 99_999, "max_concurrency": 99},
        })

        left = cfg.cost_preview(input_usd_per_million=1.0, output_usd_per_million=2.0)
        right = cfg.cost_preview(input_usd_per_million=1.0, output_usd_per_million=2.0)

        assert left == right
        assert left.module_count == 1
        assert left.probe_executions == 1
        assert left.attack_requests == 1
        assert left.verification_reserve == 3
        assert left.evolution_requests == 0
        assert left.estimated_requests == 4
        assert left.request_maximum == 60
        assert left.estimated_cost_usd is not None
        assert left.estimated_requests <= left.request_maximum
