"""
Basilisk Configuration — YAML-based configuration loading and validation.

Supports target definitions, provider credentials, scan mode settings,
evolution parameters, and output preferences.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml


class ScanMode(str, Enum):
    """Scan aggressiveness modes."""
    QUICK = "quick"         # Top 50 payloads, no evolution
    STANDARD = "standard"   # Full payloads, 3 generations
    DEEP = "deep"           # Full payloads, 10+ generations, multi-turn
    STEALTH = "stealth"     # Rate-limited, human-like timing
    CHAOS = "chaos"         # Everything parallel, max evolution


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
        
        # 1. Handle @filename syntax
        if key.startswith("@"):
            path = Path(key[1:])
            if path.exists():
                return path.read_text("utf-8").strip()
            # If specified as file but not found, return empty (validation will catch it)
            return ""

        # 2. Use explicit key if provided
        if key:
            return key

        # 3. Fallback to environment variables
        env_mapping = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "google": "GOOGLE_API_KEY",
            "azure": "AZURE_API_KEY",
        }
        env_var = env_mapping.get(self.provider, "BASILISK_API_KEY")
        return os.environ.get(env_var, "")


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


@dataclass
class OutputConfig:
    """Report output configuration."""
    format: str = "html"            # html, json, sarif, markdown, pdf
    output_dir: str = "./basilisk-reports"
    include_conversations: bool = True
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
    output: OutputConfig = field(default_factory=OutputConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    stealth: StealthConfig = field(default_factory=StealthConfig)
    modules: list[str] = field(default_factory=list)   # Empty = all modules
    exclude_modules: list[str] = field(default_factory=list)
    max_findings: int = 0           # 0 = unlimited
    fail_on: str = "high"           # CI/CD exit code threshold
    verbose: bool = False
    debug: bool = False
    session_db: str = "./basilisk-sessions.db"

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
        if kwargs.get("output"):
            config.output.format = kwargs["output"]
        if kwargs.get("output_dir"):
            config.output.output_dir = kwargs["output_dir"]
        if kwargs.get("module"):
            config.modules = list(kwargs["module"])
        if kwargs.get("verbose"):
            config.verbose = kwargs["verbose"]
        if kwargs.get("debug"):
            config.debug = kwargs["debug"]
        if kwargs.get("no_dashboard"):
            config.dashboard.enabled = False
        if kwargs.get("fail_on"):
            config.fail_on = kwargs["fail_on"]

        return config

    def validate(self) -> list[str]:
        """Validate the configuration and return list of errors."""
        errors: list[str] = []
        if not self.target.url:
            errors.append("Target URL is required")
        if not self.target.resolve_api_key() and self.target.provider != "custom":
            errors.append(f"API key not found for provider '{self.target.provider}'")
        if self.evolution.population_size < 10:
            errors.append("Evolution population size must be >= 10")
        if self.evolution.generations < 1:
            errors.append("Evolution generations must be >= 1")
        return errors

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary (for saving/logging)."""
        import dataclasses
        return dataclasses.asdict(self)


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
