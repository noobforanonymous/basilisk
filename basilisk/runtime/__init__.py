"""Shared runtime services for CLI and desktop orchestration.

The orchestration module imports concrete providers.  Keeping those imports lazy
prevents a provider importing a small runtime policy helper from recursively
importing the provider itself.
"""

from __future__ import annotations

from typing import Any

from basilisk.runtime.request_engine import (
    RequestExecutor,
    RequestPolicy,
    RequestStats,
    request_module_context,
)

__all__ = [
    "ScanHooks",
    "create_provider",
    "execute_scan",
    "resolve_attack_modules",
    "run_recon_phase",
    "RequestExecutor",
    "RequestPolicy",
    "RequestStats",
    "request_module_context",
]


_ORCHESTRATOR_EXPORTS = {
    "ScanHooks",
    "create_provider",
    "execute_scan",
    "resolve_attack_modules",
    "run_recon_phase",
}


def __getattr__(name: str) -> Any:
    if name in _ORCHESTRATOR_EXPORTS:
        from basilisk.runtime import orchestrator

        return getattr(orchestrator, name)
    raise AttributeError(name)
