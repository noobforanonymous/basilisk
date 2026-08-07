"""Deterministic preflight request and provider-cost estimates."""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from basilisk.core.config import BasiliskConfig


@dataclass(frozen=True)
class ScanCostPreview:
    """A bounded plan shown before a scan transmits any target request."""

    mode: str
    module_count: int
    probe_executions: int
    recon_requests: int
    attack_requests: int
    verification_reserve: int
    evolution_requests: int
    uncapped_request_estimate: int
    estimated_requests: int
    request_maximum: int
    estimated_input_tokens: int
    estimated_output_tokens: int
    input_token_maximum: int
    output_token_maximum: int
    response_byte_maximum: int
    minimum_duration_seconds: float
    timeout_duration_maximum_seconds: float
    estimated_cost_usd: float | None
    cost_basis: str
    bounded_by_mode_ceiling: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _recon_request_estimate(config: BasiliskConfig) -> int:
    if config.skip_recon or not config.mode_profile.run_recon:
        return 0

    from basilisk.recon.fingerprint import FINGERPRINT_PROBES
    from basilisk.recon.guardrails import GUARDRAIL_PROBES
    from basilisk.recon.rag import RAG_PROBES
    from basilisk.recon.tools import TOOL_DISCOVERY_PROBES

    available = {
        "fingerprint": len(FINGERPRINT_PROBES),
        # An unknown context size is bounded by a binary search from 1,000 to
        # 200,000 tokens. Known model fingerprints complete without this cost.
        "context": math.ceil(math.log2(200_000 - 1_000 + 1)),
        "tools": len(TOOL_DISCOVERY_PROBES),
        "guardrails": sum(len(probes) for probes in GUARDRAIL_PROBES.values()),
        "rag": len(RAG_PROBES),
    }
    selected = config.recon_modules or list(available)
    return sum(available.get(name, 0) for name in selected)


def build_scan_cost_preview(
    config: BasiliskConfig,
    *,
    input_usd_per_million: float | None = None,
    output_usd_per_million: float | None = None,
) -> ScanCostPreview:
    """Calculate a deterministic upper estimate without resolving credentials or making I/O."""

    from basilisk.attacks.base import resolve_attack_modules

    policy = config.request_policy()
    modules = resolve_attack_modules(
        selected=config.modules,
        include_research=config.research_modules_enabled,
    )
    requested_probe_ids = set(config.probe_ids)
    probe_executions = 0
    attack_requests = 0
    for module in modules:
        probe_ids = list(module.applicable_probe_ids)
        if requested_probe_ids:
            probe_ids = [probe_id for probe_id in probe_ids if probe_id in requested_probe_ids]
        effective_probe_count = len(probe_ids) if probe_ids else (0 if requested_probe_ids else 1)
        probe_executions += effective_probe_count
        attack_requests += effective_probe_count * max(1, int(module.request_cost))

    recon_requests = _recon_request_estimate(config)
    # A high/critical candidate can require two replay attempts plus one clean
    # negative control. This is a reserve, not a claim that every probe finds a defect.
    verification_reserve = attack_requests * 3
    evolution_requests = 0
    if config.evolution.enabled and config.mode_profile.run_evolution:
        evolution_requests = max(0, config.evolution.population_size) * max(
            0, config.evolution.generations
        )

    uncapped = recon_requests + attack_requests + verification_reserve + evolution_requests
    estimated_requests = min(uncapped, policy.max_requests)
    estimated_input_tokens = min(policy.max_input_tokens, estimated_requests * 1_024)
    estimated_output_tokens = min(policy.max_output_tokens, estimated_requests * 512)

    price_supplied = input_usd_per_million is not None and output_usd_per_million is not None
    if price_supplied:
        input_rate = max(0.0, float(input_usd_per_million))
        output_rate = max(0.0, float(output_usd_per_million))
        estimated_cost = round(
            (estimated_input_tokens * input_rate + estimated_output_tokens * output_rate)
            / 1_000_000,
            6,
        )
        cost_basis = (
            f"operator rates: input ${input_rate:g}/1M, output ${output_rate:g}/1M tokens"
        )
    else:
        estimated_cost = None
        cost_basis = "provider/model pricing not supplied; token estimates and hard ceilings shown"

    return ScanCostPreview(
        mode=config.mode.value,
        module_count=len(modules),
        probe_executions=probe_executions,
        recon_requests=recon_requests,
        attack_requests=attack_requests,
        verification_reserve=verification_reserve,
        evolution_requests=evolution_requests,
        uncapped_request_estimate=uncapped,
        estimated_requests=estimated_requests,
        request_maximum=policy.max_requests,
        estimated_input_tokens=estimated_input_tokens,
        estimated_output_tokens=estimated_output_tokens,
        input_token_maximum=policy.max_input_tokens,
        output_token_maximum=policy.max_output_tokens,
        response_byte_maximum=policy.max_response_bytes,
        minimum_duration_seconds=round(
            max(0, estimated_requests - 1) * policy.minimum_delay_seconds,
            3,
        ),
        timeout_duration_maximum_seconds=round(
            estimated_requests * policy.timeout_seconds,
            3,
        ),
        estimated_cost_usd=estimated_cost,
        cost_basis=cost_basis,
        bounded_by_mode_ceiling=uncapped > policy.max_requests,
    )
