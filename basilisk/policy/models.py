"""Execution and governance policy for Basilisk scans."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ExecutionMode(str, Enum):
    RECON = "recon"
    VALIDATE = "validate"
    EXPLOIT_CHAIN = "exploit_chain"
    RESEARCH = "research"


class EvidenceThreshold(str, Enum):
    PROBABLE = "probable"
    STRONG = "strong"
    CONFIRMED = "confirmed"


class RawEvidenceMode(str, Enum):
    REDACTED = "redacted"
    OPERATOR = "operator"
    FULL = "full"


@dataclass
class ScanPolicy:
    """Operator controls and enterprise guardrails for a scan."""

    execution_mode: ExecutionMode = ExecutionMode.VALIDATE
    aggression: int = 3
    max_concurrency: int = 5
    rate_limit_delay: float = 0.0
    request_budget: int = 0
    dry_run: bool = False
    replay_session_id: str = ""
    evidence_threshold: EvidenceThreshold = EvidenceThreshold.PROBABLE
    raw_evidence_mode: RawEvidenceMode = RawEvidenceMode.REDACTED
    allow_modules: list[str] = field(default_factory=list)
    deny_modules: list[str] = field(default_factory=list)
    stop_on_severity: str = ""
    approval_required: bool = False
    approval_confirmed: bool = False
    retain_raw_findings: bool = False
    retain_conversations: bool = False
    retain_days: int = 30
    max_input_tokens: int = 1_000_000
    max_output_tokens: int = 16_384
    max_response_bytes: int = 1_048_576
    request_timeout: float = 30.0
    retry_attempts: int = 1
    isolated_environment: bool = False
    allow_private_targets: bool = False
    allow_insecure_http: bool = False
    allowed_hosts: list[str] = field(default_factory=list)
    max_redirects: int = 3

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.aggression < 1 or self.aggression > 5:
            errors.append("Policy aggression must be between 1 and 5")
        if self.max_concurrency < 1:
            errors.append("Policy max_concurrency must be >= 1")
        if self.rate_limit_delay < 0:
            errors.append("Policy rate_limit_delay cannot be negative")
        if self.request_budget < 0:
            errors.append("Policy request_budget cannot be negative")
        if self.retain_days < 0:
            errors.append("Policy retain_days cannot be negative")
        if self.max_input_tokens < 1 or self.max_output_tokens < 1:
            errors.append("Policy token budgets must be positive")
        if self.max_response_bytes < 1:
            errors.append("Policy max_response_bytes must be positive")
        if self.request_timeout <= 0:
            errors.append("Policy request_timeout must be positive")
        if self.retry_attempts < 0:
            errors.append("Policy retry_attempts cannot be negative")
        if self.max_redirects < 0 or self.max_redirects > 10:
            errors.append("Policy max_redirects must be between 0 and 10")
        return errors

    def allows_module(self, module_name: str) -> bool:
        if self.allow_modules:
            allowed = module_name in self.allow_modules or any(
                module_name.startswith(prefix) for prefix in self.allow_modules
            )
            if not allowed:
                return False
        if self.deny_modules:
            denied = module_name in self.deny_modules or any(
                module_name.startswith(prefix) for prefix in self.deny_modules
            )
            if denied:
                return False
        return True

    def should_run_attacks(self) -> bool:
        return self.execution_mode != ExecutionMode.RECON and not self.dry_run

    def should_run_evolution(self) -> bool:
        return self.should_run_attacks() and self.execution_mode in {
            ExecutionMode.EXPLOIT_CHAIN,
            ExecutionMode.RESEARCH,
        }
