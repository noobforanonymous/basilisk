"""Settings and local secret management routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from basilisk.api import shared
from basilisk.api.shared import (
    ApiKeyRequest,
    SecretStatus,
    SecretStoreResponse,
    _PROVIDER_ENV_MAP,
    _api_key_store,
    verify_token,
)

router = APIRouter()


@router.post("/api/settings/apikey", dependencies=[Depends(verify_token)])
async def save_api_key(req: ApiKeyRequest):
    env_var = _PROVIDER_ENV_MAP.get(req.provider)
    if env_var:
        value = req.key.get_secret_value()
        _api_key_store[env_var] = value
        shared._secret_store.set(env_var, value)
        return {"status": "saved", "provider": req.provider}
    raise HTTPException(400, {"error": f"Unknown provider: {req.provider}"})


@router.get("/api/settings/secrets", response_model=SecretStoreResponse, dependencies=[Depends(verify_token)])
async def get_secret_store_status():
    meta = shared._secret_store.metadata()
    return SecretStoreResponse(
        **meta,
        providers=[
            SecretStatus(provider=provider, stored=bool(shared._secret_store.get(env_var)))
            for provider, env_var in sorted(_PROVIDER_ENV_MAP.items())
        ],
    )
