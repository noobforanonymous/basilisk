"""Focused API regression tests for preserved HTTP status handling."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from basilisk.api.scan import preview_scan, start_diff_scan
from basilisk.api.auth import AuthMatrixRequest, authorization_matrix
from basilisk.desktop_backend import create_app
from pydantic import ValidationError

from basilisk.api.shared import DiffConfig, PostureConfig, ScanConfig


async def test_diff_requires_two_targets_without_converting_400_to_500():
    config = DiffConfig(targets=[{"provider": "openai", "model": "gpt-4o"}])
    with pytest.raises(HTTPException) as exc:
        await start_diff_scan(config)
    assert exc.value.status_code == 400


async def test_scan_preview_is_no_network_and_mode_bounded():
    result = await preview_scan(ScanConfig(
        target="https://example.test",
        provider="custom",
        mode="quick",
        modules=["injection.direct"],
        probe_ids=["INJ-001"],
        skip_recon=True,
        evolve=False,
    ))
    preview = result["preview"]
    assert preview["estimated_requests"] == 4
    assert preview["request_maximum"] == 60
    assert preview["estimated_cost_usd"] is None


def test_ordinary_api_models_reject_inline_credentials():
    with pytest.raises(ValidationError):
        ScanConfig(target="https://example.test", api_key="secret")
    with pytest.raises(ValidationError):
        ScanConfig(target="https://example.test", auth="Bearer secret")
    with pytest.raises(ValidationError):
        PostureConfig(provider="openai", api_key="secret")
    with pytest.raises(ValidationError):
        DiffConfig(targets=[
            {"provider": "openai", "model": "one", "api_key": "secret"},
            {"provider": "anthropic", "model": "two"},
        ])


async def test_desktop_auth_matrix_rejects_missing_persona_source():
    with pytest.raises(HTTPException) as exc:
        await authorization_matrix(AuthMatrixRequest(
            target="http://127.0.0.1:8765/auth/secure/v1/chat/completions",
            isolated_environment=True,
        ))
    assert exc.value.status_code == 400


def test_desktop_auth_matrix_rejects_inline_credentials_and_is_registered():
    with pytest.raises(ValidationError):
        AuthMatrixRequest(
            target="http://127.0.0.1:8765/auth/secure/v1/chat/completions",
            lab_personas=True,
            api_key="must-not-be-accepted",
        )
    registered = set()
    for included in create_app().routes:
        router = getattr(included, "original_router", included)
        registered.update(
            route.path for route in getattr(router, "routes", []) if hasattr(route, "path")
        )
    assert "/api/auth/matrix" in registered
