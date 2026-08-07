"""Shared state, models, and helpers for the desktop backend API."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
from typing import Any

from fastapi import Header, HTTPException, WebSocket
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from basilisk.core.secrets import SecretStore

logger = logging.getLogger("basilisk.desktop")

BASILISK_TOKEN = os.environ.get("BASILISK_TOKEN")
if not BASILISK_TOKEN:
    import secrets as _secrets
    BASILISK_TOKEN = _secrets.token_hex(32)
    logger.warning(
        "BASILISK_TOKEN not set — auto-generated token for this session. "
        "The desktop backend is now authenticated."
    )


async def verify_token(x_basilisk_token: str = Header(None)):
    provided = x_basilisk_token or ""
    if BASILISK_TOKEN and not secrets.compare_digest(provided, BASILISK_TOKEN):
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid Basilisk Token")


active_scans: dict[str, dict[str, Any]] = {}
scan_results: dict[str, dict[str, Any]] = {}
ws_clients: list[WebSocket] = []
_ws_lock = asyncio.Lock()
_api_key_store: dict[str, str] = {}
_eval_results: dict[str, dict[str, Any]] = {}
_secret_store = SecretStore()


class StrictRequestModel(BaseModel):
    """Reject unknown JSON fields instead of silently accepting unsafe input."""

    model_config = ConfigDict(extra="forbid")


class ScanConfig(StrictRequestModel):
    target: str
    provider: str = "openai"
    model: str = ""
    mode: str = "standard"
    evolve: bool = True
    generations: int = 5
    modules: list[str] = []
    probe_ids: list[str] = []
    skip_recon: bool = False
    recon_modules: list[str] = []
    attacker_provider: str = ""
    attacker_model: str = ""
    population_size: int = 10
    fitness_threshold: float = 0.9
    stagnation_limit: int = 3
    output_format: str = "html"
    exit_on_first: bool = False
    enable_cache: bool = True
    diversity_mode: str = "novelty"
    intent_weight: float = 0.15
    include_research_modules: bool = False
    max_findings: int = 0
    input_price_per_million: float | None = Field(default=None, ge=0)
    output_price_per_million: float | None = Field(default=None, ge=0)
    campaign: dict[str, Any] = {}
    policy: dict[str, Any] = {}


class ReportRequest(BaseModel):
    format: str = "html"
    path: str = ""
    open_browser: bool = False


class ApiKeyRequest(StrictRequestModel):
    provider: str
    key: SecretStr


class SecretStatus(BaseModel):
    provider: str
    stored: bool


class SecretStoreResponse(BaseModel):
    backend: str
    key_backend: str
    path: str
    stored_secrets: int
    providers: list[SecretStatus] = Field(default_factory=list)


class ScanStartResponse(BaseModel):
    session_id: str
    status: str


class ScanPolicySummary(BaseModel):
    execution_mode: str
    evidence_threshold: str
    dry_run: bool = False
    retain_days: int = 30
    raw_evidence_mode: str = "redacted"
    approval_required: bool = False


class SessionListEntry(BaseModel):
    id: str
    status: str
    target: str = ""
    started_at: str | None = None
    total_findings: int = 0
    campaign: dict[str, Any] = Field(default_factory=dict)
    policy: dict[str, Any] = Field(default_factory=dict)
    resumable: bool = False
    current_phase: str = ""


class SessionListResponse(BaseModel):
    sessions: list[SessionListEntry]


class SessionClearResponse(BaseModel):
    cleared_sessions: int = 0
    cleared_memory_sessions: int = 0
    cleared_runtime_dbs: int = 0


class SessionDetailResponse(BaseModel):
    session_id: str
    status: str
    findings: list[dict[str, Any]] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)
    profile: dict[str, Any] | None = None
    runtime_state: dict[str, Any] = Field(default_factory=dict)


class ScanStatusResponse(BaseModel):
    session_id: str
    status: str
    findings_count: int = 0
    findings: list[dict[str, Any]] = Field(default_factory=list)
    profile: dict[str, Any] | None = None
    campaign: dict[str, Any] = Field(default_factory=dict)
    policy: ScanPolicySummary | dict[str, Any] = Field(default_factory=dict)
    resumable: bool = False
    current_phase: str = ""
    progress: dict[str, Any] = Field(default_factory=dict)


class ReportResponse(BaseModel):
    path: str
    format: str


class AuditLogResponse(BaseModel):
    path: str
    entries: list[dict[str, Any]] = Field(default_factory=list)
    verification: dict[str, Any] = Field(default_factory=dict)


class DiffTarget(StrictRequestModel):
    provider: str
    model: str = ""
    url: str = ""
    api_base: str = ""


class DiffConfig(StrictRequestModel):
    targets: list[DiffTarget]
    categories: list[str] = []


class PostureConfig(StrictRequestModel):
    target: str = ""
    provider: str = "openai"
    model: str = ""


class EvalRunConfig(BaseModel):
    config_path: str = ""
    config_yaml: str = ""
    output_format: str = "json"
    parallel: int = 3
    tags: list[str] = []
    fail_mode: str = "any"


class CuriosityExploreRequest(BaseModel):
    responses: list[str] = []
    n_bins: int = 25


_PROVIDER_ENV_MAP = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "google": "GOOGLE_API_KEY",
    "azure": "AZURE_API_KEY",
    "xai": "XAI_API_KEY",
    "groq": "GROQ_API_KEY",
    "github": "GH_MODELS_TOKEN",
    "bedrock": "AWS_ACCESS_KEY_ID",
    "nvidia": "NVIDIA_API_KEY",
    "custom": "BASILISK_API_KEY",
}


def get_api_key(provider: str) -> str:
    env_var = _PROVIDER_ENV_MAP.get(provider, "")
    if not env_var:
        return ""
    return (
        _api_key_store.get(env_var, "")
        or _secret_store.get(env_var)
        or os.environ.get(env_var, "")
    )


async def broadcast(event: str, data: Any):
    message = json.dumps({"event": event, "data": data})
    disconnected = []
    async with _ws_lock:
        clients_snapshot = list(ws_clients)
    for ws in clients_snapshot:
        try:
            await ws.send_text(message)
        except Exception:
            disconnected.append(ws)
    if disconnected:
        async with _ws_lock:
            for ws in disconnected:
                if ws in ws_clients:
                    ws_clients.remove(ws)


def scan_stop_requested(session_id: str) -> bool:
    scan = active_scans.get(session_id)
    return scan is None or bool(scan.get("stop_requested"))


def require_active_scan(session_id: str) -> None:
    if scan_stop_requested(session_id):
        raise asyncio.CancelledError
