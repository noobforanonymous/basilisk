"""Authorization persona and access-matrix policy tests."""

from __future__ import annotations

import os

from basilisk.auth_testing import (
    AuthMatrixReport,
    AuthObservation,
    AuthProbe,
    AuthPersona,
    CredentialState,
    lab_personas,
    run_auth_matrix,
)
from basilisk.core.config import BasiliskConfig
from basilisk.providers.base import ProviderResponse


def _observation(persona: AuthPersona, probe: AuthProbe, *, granted: bool) -> AuthObservation:
    return AuthObservation(
        persona=persona,
        probe=probe,
        granted=granted,
        refused=not granted,
        response_sha256="a" * 64,
        response_bytes=12,
        status_class="success" if granted else "forbidden",
    )


def test_lab_personas_cover_anonymous_roles_and_invalid_credential_states():
    personas = lab_personas()
    assert {persona.id for persona in personas} == {
        "anonymous", "user-a", "user-b", "admin", "expired", "revoked", "malformed",
    }
    assert {persona.credential_state for persona in personas} == set(CredentialState)
    assert {persona.role for persona in personas} >= {"anonymous", "user", "admin"}


def test_matrix_flags_cross_tenant_and_invalid_credential_access():
    tenant_a = AuthPersona("user-a", "user", "tenant-a")
    expired = AuthPersona("expired", "user", "tenant-a", CredentialState.EXPIRED)
    tenant_b_resource = AuthProbe("tenant-b-document", "read", "tenant-b", "rag_ownership")
    local_resource = AuthProbe("tenant-a-document", "read", "tenant-a", "rag_ownership")
    report = AuthMatrixReport(
        [tenant_a, expired],
        [tenant_b_resource, local_resource],
        [
            _observation(tenant_a, tenant_b_resource, granted=True),
            _observation(expired, local_resource, granted=True),
        ],
    )
    assert {item["type"] for item in report.violations} == {
        "cross_tenant_access", "invalid_credential_accepted",
    }


def test_matrix_does_not_flag_expected_denials():
    tenant_a = AuthPersona("user-a", "user", "tenant-a")
    foreign = AuthProbe("tenant-b-document", "read", "tenant-b", "rag_ownership")
    report = AuthMatrixReport(
        [tenant_a], [foreign], [_observation(tenant_a, foreign, granted=False)]
    )
    assert report.violations == []


async def test_matrix_passes_credentials_in_memory_without_temporary_environment(monkeypatch):
    monkeypatch.setenv("BASILISK_TEST_PERSONA_TOKEN", "persona-token")
    captured: list[dict] = []

    class FakeProvider:
        async def send(self, *_args, **_kwargs):
            return ProviderResponse(content="allowed")

        async def close(self):
            return None

    def fake_create_provider(_cfg, **kwargs):
        captured.append(kwargs)
        return FakeProvider()

    monkeypatch.setattr("basilisk.auth_testing.create_provider", fake_create_provider)
    before = {name for name in os.environ if name.startswith("BASILISK_AUTH_MATRIX_")}
    cfg = BasiliskConfig.from_dict({
        "target": {"url": "https://example.test", "provider": "custom"},
        "mode": "quick",
    })
    report = await run_auth_matrix(
        cfg,
        [AuthPersona(
            "user-a", "user", "tenant-a",
            authorization_env="BASILISK_TEST_PERSONA_TOKEN",
        )],
        [AuthProbe("tenant-a", "read", "tenant-a")],
    )
    after = {name for name in os.environ if name.startswith("BASILISK_AUTH_MATRIX_")}

    assert report.observations[0].granted is True
    assert before == after
    assert captured[0]["auth_header_override"] == "Bearer persona-token"
    assert captured[0]["custom_headers_override"]["X-Resource-Tenant"] == "tenant-a"
