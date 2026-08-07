"""Credential-safe authorization-matrix routes for the desktop backend."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from basilisk.api.shared import StrictRequestModel, verify_token
from basilisk.auth_testing import lab_personas, run_auth_matrix
from basilisk.core.config import BasiliskConfig, TargetConfig
from basilisk.policy.models import ScanPolicy

router = APIRouter()


class AuthMatrixRequest(StrictRequestModel):
    target: str
    provider: str = "custom"
    model: str = ""
    lab_personas: bool = False
    isolated_environment: bool = False


@router.post("/api/auth/matrix", dependencies=[Depends(verify_token)])
async def authorization_matrix(request: AuthMatrixRequest):
    """Run a bounded matrix without accepting or persisting inline credentials."""
    if not request.lab_personas:
        raise HTTPException(
            status_code=400,
            detail="Desktop authorization tests require a configured persona source.",
        )
    personas = lab_personas()
    cfg = BasiliskConfig(
        target=TargetConfig(
            url=request.target,
            provider=request.provider,
            model=request.model,
        ),
        policy=ScanPolicy(
            isolated_environment=request.isolated_environment,
            allow_private_targets=request.isolated_environment,
            allow_insecure_http=request.isolated_environment,
            request_budget=max(50, len(personas) * 8),
            max_concurrency=4,
        ),
    )
    errors = cfg.validate()
    if errors:
        raise HTTPException(status_code=400, detail="; ".join(errors))
    report = await run_auth_matrix(
        cfg,
        personas,
        known_canaries=["RAG_TENANT_A_CANARY_91C2", "RAG_TENANT_B_CANARY_4D8E"],
    )
    return report.to_dict()
