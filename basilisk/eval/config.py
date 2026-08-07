"""
Basilisk Eval Config — YAML-based test suite definitions.

Parses eval configuration files that define targets, test cases,
and assertion criteria for automated security evaluation.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class Assertion:
    """Single assertion to evaluate against a model response."""
    type: str                          # must_refuse, must_not_contain, must_contain, etc.
    values: list[str] = field(default_factory=list)
    threshold: float = 0.0
    grader_prompt: str = ""
    expected: str = ""
    pattern: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"type": self.type}
        if self.values:
            d["values"] = self.values
        if self.threshold:
            d["threshold"] = self.threshold
        if self.grader_prompt:
            d["grader_prompt"] = self.grader_prompt
        if self.expected:
            d["expected"] = self.expected
        if self.pattern:
            d["pattern"] = self.pattern
        return d


@dataclass
class EvalTest:
    """Single test case within an eval suite."""
    id: str
    name: str
    prompt: str
    assertions: list[Assertion] = field(default_factory=list)
    context: str = ""                  # Optional system prompt / context
    provider_override: str = ""        # Override target provider for this test
    model_override: str = ""           # Override target model for this test
    tags: list[str] = field(default_factory=list)
    timeout: float = 0.0              # 0 = use default

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "prompt": self.prompt,
            "assertions": [a.to_dict() for a in self.assertions],
            "context": self.context,
            "tags": self.tags,
        }


@dataclass
class EvalDefaults:
    """Default settings applied to all tests unless overridden."""
    timeout: float = 30.0
    max_retries: int = 2
    temperature: float = 0.0          # Deterministic by default


@dataclass
class EvalTarget:
    """Target configuration for evaluation."""
    provider: str = "openai"
    model: str = ""
    api_key: str = ""
    api_base: str = ""
    auth: str = ""

    def resolve_api_key(self) -> str:
        """Resolve API key from config or environment."""
        if self.api_key:
            from basilisk.core.config import _resolve_secret_reference

            return _resolve_secret_reference(self.api_key, purpose="eval API key")
        env_mapping = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "google": "GOOGLE_API_KEY",
            "azure": "AZURE_API_KEY",
            "github": "GH_MODELS_TOKEN",
            "groq": "GROQ_API_KEY",
            "xai": "XAI_API_KEY",
            "nvidia": "NVIDIA_API_KEY",
        }
        env_var = env_mapping.get(self.provider, "BASILISK_API_KEY")
        return os.environ.get(env_var, "")


@dataclass
class EvalConfig:
    """Complete eval suite configuration."""
    target: EvalTarget = field(default_factory=EvalTarget)
    defaults: EvalDefaults = field(default_factory=EvalDefaults)
    tests: list[EvalTest] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def test_count(self) -> int:
        return len(self.tests)

    def filter_by_tags(self, tags: list[str]) -> list[EvalTest]:
        """Return tests matching any of the given tags."""
        tag_set = set(tags)
        return [t for t in self.tests if tag_set & set(t.tags)]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": {
                "provider": self.target.provider,
                "model": self.target.model,
            },
            "defaults": {
                "timeout": self.defaults.timeout,
                "max_retries": self.defaults.max_retries,
                "temperature": self.defaults.temperature,
            },
            "tests": [t.to_dict() for t in self.tests],
            "test_count": self.test_count,
        }


def _resolve_env_vars(text: str) -> str:
    """Replace ${VAR_NAME} patterns with environment variable values."""
    def replacer(match: re.Match) -> str:
        var_name = match.group(1)
        return os.environ.get(var_name, "")
    return re.sub(r"\$\{(\w+)\}", replacer, text)


def _parse_assertion(raw: dict[str, Any]) -> Assertion:
    """Parse a single assertion from YAML dict."""
    return Assertion(
        type=raw.get("type", ""),
        values=raw.get("values", []),
        threshold=float(raw.get("threshold", 0.0)),
        grader_prompt=raw.get("grader_prompt", ""),
        expected=raw.get("expected", ""),
        pattern=raw.get("pattern", ""),
    )


def _parse_test(raw: dict[str, Any]) -> EvalTest:
    """Parse a single test case from YAML dict."""
    assertions = [_parse_assertion(a) for a in raw.get("assertions", [])]
    return EvalTest(
        id=raw.get("id", ""),
        name=raw.get("name", raw.get("id", "")),
        prompt=raw.get("prompt", ""),
        assertions=assertions,
        context=raw.get("context", ""),
        provider_override=raw.get("provider", ""),
        model_override=raw.get("model", ""),
        tags=raw.get("tags", []),
        timeout=float(raw.get("timeout", 0.0)),
    )


def load_eval_config(path: str | Path) -> EvalConfig:
    """Load eval configuration from a YAML file.

    Supports environment variable substitution via ${VAR_NAME} syntax.

    Args:
        path: Path to the YAML config file.

    Returns:
        Parsed EvalConfig instance.

    Raises:
        FileNotFoundError: If config file doesn't exist.
        ValueError: If config is malformed.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Eval config not found: {path}")

    raw_text = path.read_text("utf-8")
    unresolved_data = yaml.safe_load(raw_text)
    unresolved_target = (
        unresolved_data.get("target", {})
        if isinstance(unresolved_data, dict)
        else {}
    )
    unresolved_api_key = str(unresolved_target.get("api_key", ""))
    if unresolved_api_key and not unresolved_api_key.startswith(("@", "$")):
        raise ValueError(
            "Inline eval API keys are not accepted; use $ENV, ${ENV}, or @file."
        )
    resolved = _resolve_env_vars(raw_text)
    data = yaml.safe_load(resolved)

    if not isinstance(data, dict):
        raise ValueError(f"Invalid eval config: expected mapping, got {type(data).__name__}")

    # Parse target
    target_raw = data.get("target", {})
    target = EvalTarget(
        provider=target_raw.get("provider", "openai"),
        model=target_raw.get("model", ""),
        api_key=unresolved_api_key,
        api_base=target_raw.get("api_base", ""),
        auth=target_raw.get("auth", ""),
    )

    # Parse defaults
    defaults_raw = data.get("defaults", {})
    defaults = EvalDefaults(
        timeout=float(defaults_raw.get("timeout", 30.0)),
        max_retries=int(defaults_raw.get("max_retries", 2)),
        temperature=float(defaults_raw.get("temperature", 0.0)),
    )

    # Parse tests
    tests_raw = data.get("tests", [])
    if not isinstance(tests_raw, list):
        raise ValueError("'tests' must be a list of test definitions")
    tests = [_parse_test(t) for t in tests_raw]

    # Validate
    if not tests:
        raise ValueError("Eval config must contain at least one test")

    seen_ids: set[str] = set()
    for test in tests:
        if not test.id:
            raise ValueError(f"Test missing 'id': {test.name}")
        if test.id in seen_ids:
            raise ValueError(f"Duplicate test id: {test.id}")
        seen_ids.add(test.id)
        if not test.prompt:
            raise ValueError(f"Test '{test.id}' missing 'prompt'")
        if not test.assertions:
            raise ValueError(f"Test '{test.id}' has no assertions")

    return EvalConfig(
        target=target,
        defaults=defaults,
        tests=tests,
        metadata=data.get("metadata", {}),
    )
