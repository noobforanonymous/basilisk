"""
Basilisk Configuration — YAML-based configuration loading and validation.

Supports target definitions, provider credentials, scan mode settings,
evolution parameters, and output preferences.
"""

from __future__ import annotations

import os
import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import logging
import yaml

from basilisk.campaign import CampaignConfig
from basilisk.policy.models import RawEvidenceMode, ScanPolicy

logger = logging.getLogger("basilisk.config")


class ScanMode(str, Enum):
    """Scan aggressiveness modes."""
    QUICK = "quick"         # Top 50 payloads, no evolution
    STANDARD = "standard"   # Full payloads, 3 generations
    DEEP = "deep"           # Full payloads, 10+ generations, multi-turn
    STEALTH = "stealth"     # Rate-limited, human-like timing
    CHAOS = "chaos"         # Everything parallel, max evolution


@dataclass(frozen=True)
class ScanModeProfile:
    mode: ScanMode
    max_requests: int
    max_concurrency: int
    minimum_delay_seconds: float
    jitter_seconds: float
    timeout_seconds: float
    max_response_bytes: int
    max_input_tokens: int
    max_output_tokens: int
    retry_attempts: int
    run_recon: bool
    run_evolution: bool
    include_research: bool


MODE_PROFILES: dict[ScanMode, ScanModeProfile] = {
    ScanMode.QUICK: ScanModeProfile(ScanMode.QUICK, 60, 2, 0.0, 0.0, 20.0, 524_288, 150_000, 8_192, 0, False, False, False),
    ScanMode.STANDARD: ScanModeProfile(ScanMode.STANDARD, 400, 4, 0.1, 0.0, 30.0, 1_048_576, 1_000_000, 16_384, 1, True, True, False),
    ScanMode.DEEP: ScanModeProfile(ScanMode.DEEP, 1_600, 4, 0.1, 0.0, 45.0, 2_097_152, 4_000_000, 32_768, 1, True, True, False),
    ScanMode.STEALTH: ScanModeProfile(ScanMode.STEALTH, 250, 1, 1.0, 2.0, 30.0, 1_048_576, 750_000, 16_384, 0, True, False, False),
    ScanMode.CHAOS: ScanModeProfile(ScanMode.CHAOS, 5_000, 10, 0.0, 0.0, 60.0, 4_194_304, 10_000_000, 65_536, 0, True, True, True),
}


@dataclass
class TargetConfig:
    """Configuration for a single scan target."""
    url: str = ""
    provider: str = "openai"
    model: str = ""
    api_key: str = ""
    auth_header: str = ""
    custom_headers: dict[str, str] = field(default_factory=dict)
    system_prompt: str = ""
    timeout: float = 30.0
    max_retries: int = 3

    def resolve_api_key(self) -> str:
        """Resolve API key from config, environment variables, or files."""
        key = self.api_key
        if key:
            return _resolve_secret_reference(key, purpose="API key")

        # 3. Fallback to environment variables
        env_mapping = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "google": "GOOGLE_API_KEY",
            "azure": "AZURE_API_KEY",
            "xai": "XAI_API_KEY",
            'groq': 'GROQ_API_KEY',
            "nvidia": "NVIDIA_API_KEY",
        }
        env_var = env_mapping.get(self.provider, "BASILISK_API_KEY")
        return os.environ.get(env_var, "")

    def resolve_auth_header(self) -> str:
        """Resolve a custom Authorization header without requiring inline CLI input."""
        if self.auth_header:
            return _resolve_secret_reference(
                self.auth_header,
                purpose="authorization header",
            )
        return os.environ.get("BASILISK_AUTH_HEADER", "")

    def resolve_custom_headers(self) -> dict[str, str]:
        """Resolve sensitive header values only from environment/file references."""
        resolved: dict[str, str] = {}
        for key, value in self.custom_headers.items():
            resolved[key] = (
                _resolve_secret_reference(value, purpose=f"custom header {key}")
                if _looks_sensitive_key(key)
                else value
            )
        return resolved


def _read_secret_reference(value: str, *, purpose: str) -> str:
    raw_path = value[1:]
    path = Path(raw_path).expanduser().resolve()
    safe_roots = [
        Path("~/.basilisk").expanduser().resolve(),
        Path.cwd().resolve(),
    ]
    is_safe = any(path.is_relative_to(root) for root in safe_roots)
    allow_unsafe = os.environ.get("BASILISK_ALLOW_UNSAFE_CONFIG_READ", "").lower() == "true"
    if not is_safe and not allow_unsafe:
        logger.error(
            "Refusing %s file outside ~/.basilisk or the current workspace: %s",
            purpose,
            raw_path,
        )
        return ""
    try:
        return path.read_text("utf-8").strip() if path.is_file() else ""
    except OSError as exc:
        logger.error("Unable to read %s file %s: %s", purpose, raw_path, type(exc).__name__)
        return ""


def _resolve_secret_reference(value: str, *, purpose: str) -> str:
    if value.startswith("@"):
        return _read_secret_reference(value, purpose=purpose)
    if value.startswith("${") and value.endswith("}"):
        name = value[2:-1]
    elif value.startswith("$"):
        name = value[1:]
    else:
        logger.error("Refusing inline %s; use @file or $ENV_VAR", purpose)
        return ""
    if not name or not name[0].isalpha() or not name.replace("_", "").isalnum():
        logger.error("Invalid environment-variable reference for %s", purpose)
        return ""
    return os.environ.get(name, "")


def _is_secret_reference(value: str) -> bool:
    if not value:
        return True
    if value.startswith("@"):
        return len(value) > 1
    if value.startswith("${") and value.endswith("}"):
        value = f"${value[2:-1]}"
    if not value.startswith("$"):
        return False
    name = value[1:]
    return bool(name and name[0].isalpha() and name.replace("_", "").isalnum())


@dataclass
class EvolutionConfig:
    """Configuration for the genetic mutation engine."""
    enabled: bool = True
    population_size: int = 100
    generations: int = 5
    mutation_rate: float = 0.3
    crossover_rate: float = 0.5
    elite_count: int = 10
    fitness_threshold: float = 0.9
    tournament_size: int = 5
    stagnation_limit: int = 3       # Stop if no improvement for N generations
    attacker_provider: str = ""     # Optional: use a different provider for mutations
    attacker_model: str = ""        # Optional: model for mutations (e.g., gpt-4o)
    attacker_api_key: str = ""
    max_concurrent: int = 5
    temperature: float = 0.7
    exit_on_first: bool = False        # Stop after first breakthrough
    enable_cache: bool = True          # Cache payload evaluations
    cache_persist_path: str = ""       # Path to persist cache (empty = no persist)
    diversity_mode: str = "novelty"    # "off", "novelty", "niche"
    intent_weight: float = 0.15        # 0 = disabled, 0.15 = default
    operator_bandit: bool = True
    operator_reward_decay: float = 0.92
    operator_exploration_bias: float = 0.08
    multi_objective_mode: str = "pareto"
    random_seed: int = 0


@dataclass
class OutputConfig:
    """Report output configuration."""
    format: str = "html"            # html, json, sarif, markdown, pdf
    output_dir: str = "./basilisk-reports"
    include_conversations: bool = False
    include_raw_content: bool = False
    include_evolution_log: bool = True
    sarif_file: str = ""
    jira_url: str = ""
    jira_project: str = ""
    jira_token: str = ""
    defectdojo_url: str = ""
    defectdojo_token: str = ""
    webhook_url: str = ""


@dataclass
class DashboardConfig:
    """Web dashboard configuration."""
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 5000
    auto_open: bool = True


@dataclass
class StealthConfig:
    """Stealth mode settings for production target scanning."""
    min_delay: float = 1.0          # Minimum seconds between requests
    max_delay: float = 5.0          # Maximum seconds between requests
    jitter: bool = True             # Add random timing jitter
    human_like_typing: bool = True  # Simulate human typing speed
    rotate_user_agents: bool = True
    proxy_url: str = ""


@dataclass
class BasiliskConfig:
    """
    Root configuration object for a Basilisk scan session.

    Can be loaded from YAML config file, CLI arguments, or environment variables.
    CLI arguments override config file values. Environment variables override both.
    """
    target: TargetConfig = field(default_factory=TargetConfig)
    mode: ScanMode = ScanMode.STANDARD
    evolution: EvolutionConfig = field(default_factory=EvolutionConfig)
    campaign: CampaignConfig = field(default_factory=CampaignConfig)
    policy: ScanPolicy = field(default_factory=ScanPolicy)
    output: OutputConfig = field(default_factory=OutputConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    stealth: StealthConfig = field(default_factory=StealthConfig)
    modules: list[str] = field(default_factory=list)   # Empty = all attack modules
    probe_ids: list[str] = field(default_factory=list)  # Empty = every probe in module manifests
    recon_modules: list[str] = field(default_factory=list) # Empty = all recon steps
    exclude_modules: list[str] = field(default_factory=list)
    max_findings: int = 0           # 0 = unlimited
    fail_on: str = "high"           # CI/CD exit code threshold
    verbose: bool = False
    debug: bool = False
    skip_recon: bool = False
    session_db: str = "./basilisk-sessions.db"
    include_research_modules: bool = False
    persist_payloads: bool = False
    persist_responses: bool = False
    persist_conversations: bool = False

    @property
    def mode_profile(self) -> ScanModeProfile:
        return MODE_PROFILES[self.mode]

    @property
    def research_modules_enabled(self) -> bool:
        """Research modules require explicit opt-in except in isolated chaos mode."""
        return self.include_research_modules or self.mode_profile.include_research

    def request_policy(self):
        """Build a request policy that can only tighten immutable mode ceilings."""
        from basilisk.runtime.request_engine import RequestPolicy

        profile = self.mode_profile
        request_budget = self.policy.request_budget or profile.max_requests
        return RequestPolicy(
            max_requests=min(request_budget, profile.max_requests),
            max_input_tokens=min(self.policy.max_input_tokens, profile.max_input_tokens),
            max_output_tokens=min(self.policy.max_output_tokens, profile.max_output_tokens),
            max_response_bytes=min(self.policy.max_response_bytes, profile.max_response_bytes),
            timeout_seconds=min(self.policy.request_timeout, self.target.timeout, profile.timeout_seconds),
            max_concurrency=min(self.policy.max_concurrency, profile.max_concurrency),
            minimum_delay_seconds=max(self.policy.rate_limit_delay, profile.minimum_delay_seconds),
            jitter_seconds=profile.jitter_seconds,
            retry_attempts=min(self.policy.retry_attempts, profile.retry_attempts),
        )

    def cost_preview(
        self,
        *,
        input_usd_per_million: float | None = None,
        output_usd_per_million: float | None = None,
    ):
        """Build a no-network scan plan bounded by this mode's immutable ceilings."""
        from basilisk.core.cost import build_scan_cost_preview

        return build_scan_cost_preview(
            self,
            input_usd_per_million=input_usd_per_million,
            output_usd_per_million=output_usd_per_million,
        )

    @classmethod
    def from_yaml(cls, path: str | Path) -> BasiliskConfig:
        """Load configuration from a YAML file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        with open(path) as f:
            raw = yaml.safe_load(f) or {}

        config = cls()
        _apply_dict(config, raw)
        return config

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BasiliskConfig:
        """Load configuration from a nested dictionary."""
        config = cls()
        _apply_dict(config, data or {})
        return config

    @classmethod
    def from_cli_args(cls, **kwargs: Any) -> BasiliskConfig:
        """Build configuration from CLI arguments."""
        config = cls()

        if kwargs.get("config"):
            config = cls.from_yaml(kwargs["config"])

        # CLI overrides
        if kwargs.get("target"):
            config.target.url = kwargs["target"]
        if kwargs.get("provider"):
            config.target.provider = kwargs["provider"]
        if kwargs.get("model"):
            config.target.model = kwargs["model"]
        if kwargs.get("api_key"):
            config.target.api_key = kwargs["api_key"]
        if kwargs.get("auth"):
            config.target.auth_header = kwargs["auth"]
        if kwargs.get("mode"):
            config.mode = ScanMode(kwargs["mode"])
        if kwargs.get("evolve") is not None:
            config.evolution.enabled = kwargs["evolve"]
        if kwargs.get("generations"):
            config.evolution.generations = kwargs["generations"]
        if kwargs.get("attacker_provider"):
            config.evolution.attacker_provider = kwargs["attacker_provider"]
        if kwargs.get("attacker_model"):
            config.evolution.attacker_model = kwargs["attacker_model"]
        if kwargs.get("attacker_api_key"):
            config.evolution.attacker_api_key = kwargs["attacker_api_key"]
        if kwargs.get("campaign"):
            _apply_dict(config.campaign, kwargs["campaign"])
        if kwargs.get("policy"):
            _apply_dict(config.policy, kwargs["policy"])
        if kwargs.get("population_size"):
            config.evolution.population_size = int(kwargs["population_size"])
        if kwargs.get("fitness_threshold"):
            config.evolution.fitness_threshold = float(kwargs["fitness_threshold"])
        if kwargs.get("stagnation_limit"):
            config.evolution.stagnation_limit = int(kwargs["stagnation_limit"])
        if kwargs.get("exit_on_first") is not None:
            config.evolution.exit_on_first = kwargs["exit_on_first"]
        if kwargs.get("enable_cache") is not None:
            config.evolution.enable_cache = kwargs["enable_cache"]
        if kwargs.get("diversity_mode"):
            config.evolution.diversity_mode = kwargs["diversity_mode"]
        if kwargs.get("intent_weight") is not None:
            config.evolution.intent_weight = float(kwargs["intent_weight"])
        if kwargs.get("output"):
            config.output.format = kwargs["output"]
        if kwargs.get("output_dir"):
            config.output.output_dir = kwargs["output_dir"]
        if kwargs.get("module"):
            config.modules = list(kwargs["module"])
        if kwargs.get("probe_id"):
            config.probe_ids = list(dict.fromkeys(str(item) for item in kwargs["probe_id"]))
        if kwargs.get("verbose"):
            config.verbose = kwargs["verbose"]
        if kwargs.get("debug"):
            config.debug = kwargs["debug"]
        if kwargs.get("no_dashboard"):
            config.dashboard.enabled = False
        if kwargs.get("fail_on"):
            config.fail_on = kwargs["fail_on"]
        if kwargs.get("max_findings") is not None:
            config.max_findings = int(kwargs["max_findings"])
        if kwargs.get("skip_recon"):
            config.skip_recon = True
        if kwargs.get("recon_module"):
            config.recon_modules = list(kwargs["recon_module"])
        if kwargs.get("include_research_modules") is not None:
            config.include_research_modules = bool(kwargs["include_research_modules"])
        if kwargs.get("persist_payloads") is not None:
            config.persist_payloads = bool(kwargs["persist_payloads"])
        if kwargs.get("persist_responses") is not None:
            config.persist_responses = bool(kwargs["persist_responses"])
        if kwargs.get("persist_conversations") is not None:
            config.persist_conversations = bool(kwargs["persist_conversations"])
        if kwargs.get("include_conversations") is not None:
            config.output.include_conversations = bool(kwargs["include_conversations"])
        if kwargs.get("include_raw_content") is not None:
            config.output.include_raw_content = bool(kwargs["include_raw_content"])

        if config.policy.retain_raw_findings:
            config.persist_payloads = True
            config.persist_responses = True
        if config.policy.retain_conversations:
            config.persist_conversations = True
        if config.policy.raw_evidence_mode == RawEvidenceMode.FULL:
            config.output.include_raw_content = True
            config.output.include_conversations = config.persist_conversations

        return config

    def validate(self) -> list[str]:
        """Validate the configuration and return list of errors."""
        errors: list[str] = []
        secret_fields = {
            "target.api_key": self.target.api_key,
            "target.auth_header": self.target.auth_header,
            "evolution.attacker_api_key": self.evolution.attacker_api_key,
            "output.jira_token": self.output.jira_token,
            "output.defectdojo_token": self.output.defectdojo_token,
        }
        for field_name, value in secret_fields.items():
            if value and not _is_secret_reference(value):
                errors.append(
                    f"{field_name} must use @file or $ENV_VAR; inline secrets are rejected"
                )
        for header, value in self.target.custom_headers.items():
            if _looks_sensitive_key(header) and value and not _is_secret_reference(value):
                errors.append(
                    f"target.custom_headers.{header} must use @file or $ENV_VAR"
                )
        if self.probe_ids:
            from basilisk.payloads.loader import load_probes

            known_probe_ids = {probe.id for probe in load_probes()}
            unknown = sorted(set(self.probe_ids) - known_probe_ids)
            if unknown:
                errors.append(f"Unknown canonical probe IDs: {', '.join(unknown)}")
        if not self.target.url:
            errors.append("Target URL is required")
        keyless_providers = {"custom", "websocket"}
        is_websocket_target = self.target.url.startswith(("ws://", "wss://"))
        if (
            not self.target.resolve_api_key()
            and self.target.provider not in keyless_providers
            and not is_websocket_target
        ):
            errors.append(f"API key not found for provider '{self.target.provider}'")
        if self.evolution.population_size < 10:
            errors.append("Evolution population size must be >= 10")
        if self.evolution.generations < 1:
            errors.append("Evolution generations must be >= 1")
        errors.extend(self.policy.validate())
        if self.policy.execution_mode in ("exploit_chain", "research") and not self.campaign.authorization.operator:
            errors.append("Campaign operator is required for exploit_chain or research mode")
        if self.policy.approval_required and not self.campaign.authorization.approved:
            errors.append("Campaign approval is required by policy but not confirmed")
        if self.mode == ScanMode.CHAOS and not self.policy.isolated_environment:
            errors.append("Chaos mode requires policy.isolated_environment=true")
        return errors

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary (for saving/logging)."""
        return dataclasses.asdict(self)

    def to_safe_dict(self) -> dict[str, Any]:
        """Serialize configuration without persisting secrets."""
        data = dataclasses.asdict(self)

        target = data.get("target", {})
        if target:
            target["api_key"] = ""
            target["auth_header"] = ""
            if target.get("system_prompt"):
                target["system_prompt"] = "[redacted]"
            target["custom_headers"] = _redact_mapping(target.get("custom_headers", {}))

        evolution = data.get("evolution", {})
        if evolution:
            evolution["attacker_api_key"] = ""

        campaign = data.get("campaign", {})
        if campaign:
            auth = campaign.get("authorization", {})
            if auth:
                if auth.get("justification"):
                    auth["justification"] = "[redacted]"
                auth["signed_scope_hash"] = auth.get("signed_scope_hash", "")

        output = data.get("output", {})
        if output:
            output["jira_token"] = ""
            output["defectdojo_token"] = ""

        return data


def _redact_mapping(values: dict[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in values.items():
        if _looks_sensitive_key(key):
            redacted[key] = "[redacted]"
        else:
            redacted[key] = value
    return redacted


def _looks_sensitive_key(key: str) -> bool:
    lower = key.lower()
    return any(token in lower for token in ("key", "token", "secret", "auth", "password", "cookie"))


def _apply_dict(obj: Any, data: dict[str, Any]) -> None:
    """Recursively apply dictionary values to a dataclass instance."""
    for key, value in data.items():
        if hasattr(obj, key):
            attr = getattr(obj, key)
            if isinstance(value, dict) and hasattr(attr, "__dataclass_fields__"):
                _apply_dict(attr, value)
            elif isinstance(attr, Enum):
                setattr(obj, key, type(attr)(value))
            else:
                setattr(obj, key, value)
