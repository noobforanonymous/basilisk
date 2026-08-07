"""Finding policy enforcement for production, beta, and research scans."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING

from basilisk.core.evidence import EvidenceVerdict
from basilisk.core.finding import Finding, FindingValidationLevel, Severity
from basilisk.policy.models import EvidenceThreshold

if TYPE_CHECKING:
    from basilisk.policy.models import ScanPolicy


@dataclass(frozen=True)
class _FindingDescriptor:
    trust_tier: str
    success_criteria: list[str]
    evidence_requirements: list[str]
    requires_tool_proof: bool
    supports_baseline_differential: bool


@lru_cache(maxsize=1)
def _descriptor_map() -> dict[str, _FindingDescriptor]:
    from basilisk.attacks.base import describe_attack_module, get_all_attack_modules

    mapping: dict[str, _FindingDescriptor] = {}
    for module in get_all_attack_modules():
        descriptor = describe_attack_module(module)
        payload = _FindingDescriptor(
            trust_tier=descriptor.trust_tier,
            success_criteria=descriptor.success_criteria,
            evidence_requirements=descriptor.evidence_requirements,
            requires_tool_proof=descriptor.requires_tool_proof,
            supports_baseline_differential=descriptor.supports_baseline_differential,
        )
        mapping[module.name] = payload
        mapping[f"basilisk.attacks.{module.name}"] = payload
    return mapping


def enforce_finding_policy(
    finding: Finding,
    policy: ScanPolicy,
    *,
    final: bool = True,
) -> Finding:
    """Downgrade or annotate findings that do not meet policy evidence requirements."""

    from basilisk.attacks.base import AttackTrustTier

    descriptor = _descriptor_map().get(
        finding.attack_module,
        _FindingDescriptor(
            trust_tier=AttackTrustTier.BETA,
            success_criteria=[],
            evidence_requirements=[],
            requires_tool_proof=False,
            supports_baseline_differential=False,
        ),
    )
    required = _required_verdict(policy.evidence_threshold, descriptor.trust_tier)
    actual = finding.evidence.verdict if finding.evidence else EvidenceVerdict.UNVERIFIED
    missing_requirements = _missing_requirements(finding, descriptor)
    finding.metadata = {
        **finding.metadata,
        "module_trust_tier": descriptor.trust_tier,
        "module_success_criteria": descriptor.success_criteria,
        "module_evidence_requirements": descriptor.evidence_requirements,
    }
    if finding.validation_level == FindingValidationLevel.OBSERVATION and actual in {
        EvidenceVerdict.PROBABLE,
        EvidenceVerdict.STRONG,
        EvidenceVerdict.CONFIRMED,
    }:
        finding.validation_level = FindingValidationLevel.CANDIDATE
    if not final:
        return finding
    if finding.severity in {Severity.CRITICAL, Severity.HIGH} and (
        finding.validation_level != FindingValidationLevel.VERIFIED
        or not _meets_threshold(actual, required)
        or missing_requirements
    ):
        finding.metadata = {
            **finding.metadata,
            "policy_downgraded": True,
            "original_severity": finding.severity.value,
            "required_evidence_verdict": required.value,
            "actual_evidence_verdict": actual.value,
            "policy_success_criteria": descriptor.success_criteria,
            "missing_evidence_requirements": missing_requirements,
            "validation_level": finding.validation_level.value,
        }
        finding.severity = Severity.MEDIUM
    return finding


def _required_verdict(threshold: EvidenceThreshold, trust_tier: str) -> EvidenceVerdict:
    from basilisk.attacks.base import AttackTrustTier

    baseline = {
        EvidenceThreshold.PROBABLE: EvidenceVerdict.PROBABLE,
        EvidenceThreshold.STRONG: EvidenceVerdict.STRONG,
        EvidenceThreshold.CONFIRMED: EvidenceVerdict.CONFIRMED,
    }[threshold]
    if trust_tier == AttackTrustTier.RESEARCH:
        return EvidenceVerdict.PROBABLE
    if trust_tier == AttackTrustTier.PRODUCTION:
        return baseline
    if baseline == EvidenceVerdict.CONFIRMED:
        return EvidenceVerdict.STRONG
    return baseline


def _meets_threshold(actual: EvidenceVerdict, required: EvidenceVerdict) -> bool:
    order = {
        EvidenceVerdict.UNVERIFIED: 0,
        EvidenceVerdict.WEAK: 1,
        EvidenceVerdict.PROBABLE: 2,
        EvidenceVerdict.STRONG: 3,
        EvidenceVerdict.CONFIRMED: 4,
    }
    return order[actual] >= order[required]


def _missing_requirements(finding: Finding, descriptor: _FindingDescriptor) -> list[str]:
    evidence = finding.evidence
    if evidence is None:
        return ["structured_evidence"]

    passed_kinds = {signal.kind.value for signal in evidence.signals if signal.passed}
    passed_name_keys = {
        f"{signal.kind.value}:{signal.name}"
        for signal in evidence.signals
        if signal.passed
    }
    missing: list[str] = []

    if descriptor.requires_tool_proof and "tool_call" not in passed_kinds:
        missing.append("tool_call_proof")
    if descriptor.supports_baseline_differential and "baseline_differential" not in passed_kinds:
        missing.append("baseline_differential")
    if descriptor.trust_tier == "production":
        for requirement in descriptor.evidence_requirements:
            variants = [variant.strip() for variant in requirement.split("|") if variant.strip()]
            if variants and not any(variant in passed_name_keys for variant in variants):
                missing.append(requirement)
        if not passed_kinds.intersection(
            {"response_marker", "tool_call", "baseline_differential", "provider_metadata"}
        ):
            missing.append("module_specific_proof")
    if not evidence.replay_steps:
        missing.append("replay_steps")
    return missing
