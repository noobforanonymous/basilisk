"""Scan, websocket, differential, and posture routes."""

from __future__ import annotations

import asyncio
import logging
import os
import tempfile
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect

from basilisk.api.shared import (
    BASILISK_TOKEN,
    DiffConfig,
    PostureConfig,
    ScanConfig,
    ScanPolicySummary,
    ScanStartResponse,
    ScanStatusResponse,
    active_scans,
    broadcast,
    get_api_key,
    require_active_scan,
    scan_results,
    verify_token,
    ws_clients,
    _ws_lock,
)
from basilisk.core.config import BasiliskConfig
from basilisk.core.database import BasiliskDatabase
from basilisk.core.evidence import EvidenceSignal, EvidenceSignalKind, build_evidence_bundle
from basilisk.core.finding import AttackCategory, Finding, Severity
from basilisk.core.profile import DetectedTool, GuardrailLevel, ModelProvider
from basilisk.core.redaction import sanitize_error_text
from basilisk.core.session import ScanSession

router = APIRouter()
logger = logging.getLogger("basilisk.desktop")
E2E_MODE = os.environ.get("BASILISK_E2E") == "1"


def _e2e_session_db_path() -> str:
    return os.path.join(tempfile.gettempdir(), f"basilisk-e2e-{os.getpid()}.db")


def _policy_summary(cfg: BasiliskConfig) -> dict[str, Any]:
    return {
        "execution_mode": cfg.policy.execution_mode.value,
        "evidence_threshold": cfg.policy.evidence_threshold.value,
        "dry_run": cfg.policy.dry_run,
        "retain_days": cfg.policy.retain_days,
        "raw_evidence_mode": cfg.policy.raw_evidence_mode.value,
        "approval_required": cfg.policy.approval_required,
    }


def _scan_config_summary(cfg: BasiliskConfig) -> dict[str, Any]:
    return {
        "target": cfg.target.url,
        "provider": cfg.target.provider,
        "model": cfg.target.model,
        "mode": cfg.mode.value,
        "modules": list(cfg.modules),
        "probe_ids": list(cfg.probe_ids),
        "skip_recon": cfg.skip_recon,
        "recon_modules": list(cfg.recon_modules),
        "include_research_modules": cfg.research_modules_enabled,
    }


def _config_from_request(config: ScanConfig) -> BasiliskConfig:
    """Map the strict API model to runtime config without resolving credentials."""
    return BasiliskConfig.from_cli_args(
        target=config.target,
        provider=config.provider,
        model=config.model,
        api_key="",
        auth="",
        mode=config.mode,
        evolve=config.evolve,
        generations=config.generations,
        module=config.modules,
        probe_id=config.probe_ids,
        output=config.output_format,
        skip_recon=config.skip_recon,
        recon_module=config.recon_modules,
        attacker_provider=config.attacker_provider,
        attacker_model=config.attacker_model,
        attacker_api_key="",
        campaign=config.campaign,
        policy=config.policy,
        population_size=config.population_size,
        fitness_threshold=config.fitness_threshold,
        stagnation_limit=config.stagnation_limit,
        exit_on_first=config.exit_on_first,
        enable_cache=config.enable_cache,
        diversity_mode=config.diversity_mode,
        intent_weight=config.intent_weight,
        include_research_modules=config.include_research_modules,
        max_findings=config.max_findings,
    )


async def _load_runtime_state(session_id: str, db_path: str = "./basilisk-sessions.db") -> dict[str, Any] | None:
    db = BasiliskDatabase(db_path)
    await db.connect()
    try:
        await db.mark_stale_scan_runtimes_interrupted(set(active_scans))
        return await db.get_scan_runtime(session_id)
    finally:
        await db.close()


@router.get("/health")
async def health():
    return {"status": "online", "version": "2.0.0", "timestamp": datetime.now(timezone.utc).isoformat()}


@router.get("/api/native/status", dependencies=[Depends(verify_token)])
async def native_status():
    try:
        from basilisk.native_bridge import native_status as get_status
        return get_status()
    except ImportError:
        return {"tokens_c": False, "encoder_c": False, "fuzzer_go": False, "matcher_go": False}


@router.post("/api/scan/preview", dependencies=[Depends(verify_token)])
async def preview_scan(config: ScanConfig):
    """Return the bounded no-network execution plan used by CLI and desktop."""
    try:
        cfg = _config_from_request(config)
        return {
            "preview": cfg.cost_preview(
                input_usd_per_million=config.input_price_per_million,
                output_usd_per_million=config.output_price_per_million,
            ).to_dict()
        }
    except Exception as exc:
        raise HTTPException(400, {"error": sanitize_error_text(exc)}) from exc


@router.post("/api/scan", response_model=ScanStartResponse, dependencies=[Depends(verify_token)])
async def start_scan(config: ScanConfig):
    try:
        target_credential = get_api_key(config.provider)
        attacker_credential = (
            get_api_key(config.attacker_provider)
            if config.attacker_provider
            else None
        )
        cfg = _config_from_request(config)
        if E2E_MODE and config.target.startswith("e2e://"):
            cfg.session_db = _e2e_session_db_path()
        errors = cfg.validate()
        if errors:
            raise HTTPException(400, {"errors": errors})

        session = ScanSession(cfg)
        await session.initialize()
        active_scans[session.id] = {
            "session": session,
            "config": _scan_config_summary(cfg),
            "started_at": datetime.now(timezone.utc).isoformat(),
            "status": "initializing",
            "stop_requested": False,
            "session_db": cfg.session_db,
            "campaign": cfg.campaign.to_summary(),
            "policy": _policy_summary(cfg),
        }
        await session.save_runtime_state(
            status="initializing",
            current_phase="initializing",
            progress={"progress": 0.0, "phase": "initializing"},
            stop_requested=False,
            resumable=True,
        )
        task_target = (
            _run_e2e_scan_background(session, cfg)
            if E2E_MODE and cfg.target.url.startswith("e2e://")
            else _run_scan_background(
                session,
                cfg,
                target_credential=target_credential,
                attacker_credential=attacker_credential,
            )
        )
        task = asyncio.create_task(task_target, name=f"basilisk-scan-{session.id}")
        active_scans[session.id]["task"] = task
        return {"session_id": session.id, "status": "started"}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, {"error": sanitize_error_text(exc)})


@router.post("/api/scan/{session_id}/stop", dependencies=[Depends(verify_token)])
async def stop_scan(session_id: str):
    if session_id in active_scans:
        scan = active_scans[session_id]
        scan["status"] = "stopping"
        scan["stop_requested"] = True
        await scan["session"].save_runtime_state(
            status="stopping",
            current_phase=scan["session"].current_phase,
            stop_requested=True,
            resumable=True,
        )
        task = scan.get("task")
        if task and not task.done():
            task.cancel()
        return {"status": "stopping"}
    raise HTTPException(404, {"error": "Session not found"})


@router.post("/api/scan/{session_id}/resume", response_model=ScanStartResponse, dependencies=[Depends(verify_token)])
async def resume_scan(session_id: str):
    if session_id in active_scans:
        raise HTTPException(409, {"error": "Session is already active"})

    runtime = await _load_runtime_state(session_id)
    if not runtime:
        raise HTTPException(404, {"error": "Session runtime state not found"})
    if not runtime.get("resumable", False):
        raise HTTPException(400, {"error": "Session is not resumable"})
    if runtime.get("status") == "completed":
        raise HTTPException(400, {"error": "Completed sessions do not need resume"})

    db_path = runtime.get("db_path") or "./basilisk-sessions.db"
    session = await ScanSession.resume(session_id, db_path=db_path)
    cfg = session.config
    target_credential = get_api_key(cfg.target.provider)
    attacker_credential = (
        get_api_key(cfg.evolution.attacker_provider)
        if cfg.evolution.attacker_provider
        else None
    )
    errors = cfg.validate()
    if errors:
        raise HTTPException(400, {"errors": errors})

    from basilisk.runtime import resolve_attack_modules

    completed_modules = session.completed_modules()
    resume_modules = [
        module
        for module in resolve_attack_modules(
            selected=cfg.modules,
            include_research=cfg.research_modules_enabled,
        )
        if module.name not in completed_modules and cfg.policy.allows_module(module.name)
    ]

    session.record_phase(
        "resume_requested",
        previous_status=runtime.get("status"),
        current_phase=runtime.get("current_phase", ""),
        completed_modules=sorted(completed_modules),
        remaining_modules=[module.name for module in resume_modules],
    )
    await session.save_runtime_state(
        status="resuming",
        current_phase="resuming",
        progress={
            "progress": 0.0,
            "phase": "resume",
            "remaining_modules": [module.name for module in resume_modules],
        },
        stop_requested=False,
        resumable=True,
        last_error=runtime.get("last_error", ""),
    )
    active_scans[session.id] = {
        "session": session,
        "config": _scan_config_summary(cfg),
        "started_at": session.started_at.isoformat(),
        "status": "resuming",
        "stop_requested": False,
        "session_db": db_path,
        "campaign": cfg.campaign.to_summary(),
        "policy": _policy_summary(cfg),
    }
    task = asyncio.create_task(
        _run_scan_background(
            session,
            cfg,
            modules_override=resume_modules,
            target_credential=target_credential,
            attacker_credential=attacker_credential,
        ),
        name=f"basilisk-scan-{session.id}-resume",
    )
    active_scans[session.id]["task"] = task
    return {"session_id": session.id, "status": "resumed"}


@router.get("/api/scan/{session_id}", response_model=ScanStatusResponse | dict[str, Any], dependencies=[Depends(verify_token)])
async def scan_status(session_id: str):
    if session_id in active_scans:
        scan = active_scans[session_id]
        session = scan["session"]
        return {
            "session_id": session_id,
            "status": scan["status"],
            "findings_count": len(session.findings),
            "findings": [f.to_dict() for f in session.findings[-10:]],
            "profile": session.profile.to_dict() if session.profile else None,
            "campaign": session.config.campaign.to_summary(),
            "policy": _policy_summary(session.config),
            "resumable": True,
            "current_phase": session.current_phase,
            "progress": session.last_progress,
        }
    if session_id in scan_results:
        return scan_results[session_id]
    runtime = await _load_runtime_state(session_id)
    if runtime:
        db = BasiliskDatabase(runtime.get("db_path") or "./basilisk-sessions.db")
        await db.connect()
        try:
            session_data = await db.get_session(session_id)
        finally:
            await db.close()
        config = (session_data or {}).get("config", {})
        summary = (session_data or {}).get("summary", {})
        profile = (session_data or {}).get("profile")
        return {
            "session_id": session_id,
            "status": runtime.get("status", (session_data or {}).get("status", "unknown")),
            "findings_count": summary.get("total_findings", 0),
            "findings": [],
            "profile": profile,
            "campaign": runtime.get("campaign") or config.get("campaign", {}),
            "policy": runtime.get("policy") or summary.get("policy", {}),
            "resumable": runtime.get("resumable", False),
            "current_phase": runtime.get("current_phase", ""),
            "progress": runtime.get("progress", {}),
        }
    raise HTTPException(404, {"error": "Session not found"})


@router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket, token: str = Query(None)):
    if BASILISK_TOKEN and token != BASILISK_TOKEN:
        await ws.close(code=1008)
        return
    await ws.accept()
    async with _ws_lock:
        ws_clients.append(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        async with _ws_lock:
            if ws in ws_clients:
                ws_clients.remove(ws)


async def _run_scan_background(
    session: ScanSession,
    cfg: BasiliskConfig,
    *,
    modules_override: list[Any] | None = None,
    target_credential: str | None = None,
    attacker_credential: str | None = None,
):
    sid = session.id
    completed = False
    stopped = False
    try:
        from basilisk.runtime import ScanHooks, execute_scan, resolve_attack_modules

        def ensure_active() -> None:
            require_active_scan(sid)

        async def on_phase(_: str, phase: str) -> None:
            ensure_active()
            phase_status = {
                "recon": "recon",
                "recon_skipped": "attacking",
                "attacking": "attacking",
                "evolving": "evolving",
            }.get(phase, phase)
            active_scans[sid]["status"] = phase_status
            await session.save_runtime_state(
                status=phase_status,
                current_phase=phase,
                progress={"phase": phase, "progress": 0.0},
                stop_requested=False,
                resumable=True,
            )
            await broadcast("scan:status", {"session_id": sid, "phase": phase})

        async def on_profile(_: str, profile: dict[str, Any]) -> None:
            ensure_active()
            await broadcast("scan:profile", {"session_id": sid, "profile": profile})

        async def on_progress(_: str, module_name: str, progress: float) -> None:
            ensure_active()
            await session.save_runtime_state(
                status=active_scans[sid]["status"],
                current_phase=session.current_phase,
                progress={
                    "phase": session.current_phase,
                    "module": module_name,
                    "progress": round(progress, 4),
                },
                stop_requested=False,
                resumable=True,
            )
            await broadcast("scan:progress", {
                "session_id": sid,
                "module": module_name,
                "progress": progress,
            })

        async def on_finding(_: str, finding) -> None:
            ensure_active()
            await broadcast("scan:finding", {"session_id": sid, "finding": finding.to_dict()})

        async def on_error(_: str, module_name: str, error: str) -> None:
            safe_error = sanitize_error_text(error)
            logger.error("Module %s failed: %s", module_name, safe_error)
            await session.save_runtime_state(
                status=active_scans.get(sid, {}).get("status", "error"),
                current_phase=session.current_phase,
                last_error=f"{module_name}: {safe_error}",
                resumable=True,
            )

        async def on_evolution_stats(_: str, stats: dict[str, Any]) -> None:
            ensure_active()
            await broadcast("scan:evolution_stats", {"session_id": sid, "stats": stats})

        hooks = ScanHooks(
            on_phase=on_phase,
            on_profile=on_profile,
            on_progress=on_progress,
            on_finding=on_finding,
            on_error=on_error,
            on_evolution_stats=on_evolution_stats,
        )
        modules = resolve_attack_modules(
            selected=cfg.modules,
            include_research=cfg.research_modules_enabled,
        )
        await execute_scan(
            cfg,
            session=session,
            hooks=hooks,
            modules=modules_override if modules_override is not None else modules,
            stop_check=ensure_active,
            target_credential=target_credential,
            attacker_credential=attacker_credential,
        )
        completed = True
    except asyncio.CancelledError:
        stopped = True
        logger.info("Scan %s was stopped", sid)
        if sid in active_scans:
            active_scans[sid]["status"] = "stopped"
        await session.save_runtime_state(
            status="stopped",
            current_phase=session.current_phase or "stopped",
            resumable=True,
            stop_requested=True,
        )
        await broadcast("scan:error", {"session_id": sid, "error": "Scan stopped by user"})
    except Exception as exc:
        safe_error = sanitize_error_text(exc)
        logger.error("Scan %s failed: %s", sid, safe_error)
        if sid in active_scans:
            active_scans[sid]["status"] = "error"
        await session.save_runtime_state(
            status="error",
            current_phase=session.current_phase or "error",
            resumable=True,
            last_error=safe_error,
        )
        await broadcast("scan:error", {"session_id": sid, "error": safe_error})
    finally:
        final_status = "completed" if completed else "stopped" if stopped else "error"
        try:
            await session.close(final_status)
        except Exception:
            logger.exception("Failed to close session %s", sid)
        if completed:
            scan_results[sid] = {
                "session_id": sid,
                "status": "completed",
                "target": cfg.target.url,
                "total_findings": len(session.findings),
                "findings": [
                    f.sanitized_dict(
                        include_payload=cfg.persist_payloads,
                        include_response=cfg.persist_responses,
                        include_conversation=cfg.persist_conversations,
                    )
                    for f in session.findings
                ],
                "profile": session.profile.to_dict(),
                "summary": session.summary,
                "session_db": cfg.session_db,
            }
            await session.save_runtime_state(
                status="completed",
                current_phase=session.current_phase or "completed",
                resumable=False,
            )
            await broadcast("scan:complete", {
                "session_id": sid,
                "total_findings": len(session.findings),
                "summary": session.summary,
            })
        active_scans.pop(sid, None)


async def _run_e2e_scan_background(session: ScanSession, cfg: BasiliskConfig) -> None:
    sid = session.id
    completed = False
    stopped = False
    try:
        session.profile.detected_model = "basilisk-e2e"
        session.profile.provider = ModelProvider.CUSTOM
        session.profile.context_window = 32768
        session.profile.guardrails.level = GuardrailLevel.MODERATE
        session.profile.rag_detected = True
        session.profile.detected_tools = [
            DetectedTool(name="web_search", risk_level="medium"),
            DetectedTool(name="db_query", risk_level="high"),
        ]
        await broadcast("scan:status", {"session_id": sid, "phase": "recon"})
        await broadcast("scan:profile", {"session_id": sid, "profile": session.profile.to_dict()})
        await session.save_runtime_state(
            status="recon",
            current_phase="recon",
            progress={"phase": "recon", "progress": 0.1},
            resumable=True,
            stop_requested=False,
        )
        await asyncio.sleep(0.15)

        await broadcast("scan:status", {"session_id": sid, "phase": "attacking"})
        if sid in active_scans:
            active_scans[sid]["status"] = "attacking"
        for idx in range(1, 6):
            await session.save_runtime_state(
                status="attacking",
                current_phase="attacking",
                progress={
                    "phase": "attacking",
                    "module": f"e2e.module.{idx}",
                    "progress": round(idx / 6, 4),
                },
                resumable=True,
                stop_requested=False,
            )
            await broadcast("scan:progress", {
                "session_id": sid,
                "module": f"e2e.module.{idx}",
                "progress": idx / 6,
            })
            if cfg.target.url.endswith("long"):
                await asyncio.sleep(0.2)
            else:
                await asyncio.sleep(0.08)

        if cfg.target.url.endswith("long"):
            await asyncio.sleep(1.0)

        finding = Finding(
            title="E2E Prompt Injection Chain",
            severity=Severity.HIGH,
            category=AttackCategory.PROMPT_INJECTION,
            attack_module="basilisk.attacks.injection.direct",
            description="Deterministic desktop E2E finding for UI flow validation.",
            confidence=0.91,
            evidence=build_evidence_bundle(
                signals=[
                    EvidenceSignal(
                        name="e2e_prompt_compliance",
                        kind=EvidenceSignalKind.RESPONSE_MARKER,
                        passed=True,
                        weight=1.0,
                        summary="Synthetic E2E attack response matched expected operator signal.",
                    ),
                    EvidenceSignal(
                        name="e2e_baseline_shift",
                        kind=EvidenceSignalKind.BASELINE_DIFFERENTIAL,
                        passed=True,
                        weight=1.0,
                        summary="Synthetic baseline-vs-attack shift recorded for desktop smoke coverage.",
                    ),
                ],
                confidence_basis="e2e-fixture",
                replay_steps=[
                    "launch desktop",
                    "start approved scan",
                    "wait for deterministic finding",
                ],
            ),
        )
        await session.add_finding(finding)
        await broadcast("scan:finding", {"session_id": sid, "finding": finding.to_dict()})
        completed = True
    except asyncio.CancelledError:
        stopped = True
        if sid in active_scans:
            active_scans[sid]["status"] = "stopped"
        await session.save_runtime_state(
            status="stopped",
            current_phase=session.current_phase or "stopped",
            resumable=True,
            stop_requested=True,
        )
        await broadcast("scan:error", {"session_id": sid, "error": "Scan stopped by user"})
    except Exception as exc:
        logger.error("E2E scan %s failed: %s", sid, exc)
        if sid in active_scans:
            active_scans[sid]["status"] = "error"
        await session.save_runtime_state(
            status="error",
            current_phase=session.current_phase or "error",
            resumable=True,
            last_error=sanitize_error_text(exc),
        )
        await broadcast(
            "scan:error",
            {"session_id": sid, "error": sanitize_error_text(exc)},
        )
    finally:
        final_status = "completed" if completed else "stopped" if stopped else "error"
        try:
            await session.close(final_status)
        except Exception:
            logger.exception("Failed to close E2E session %s", sid)
        if completed:
            scan_results[sid] = {
                "session_id": sid,
                "status": "completed",
                "target": cfg.target.url,
                "total_findings": len(session.findings),
                "findings": [f.to_dict() for f in session.findings],
                "profile": session.profile.to_dict(),
                "summary": session.summary,
                "session_db": cfg.session_db,
            }
            await session.save_runtime_state(
                status="completed",
                current_phase=session.current_phase or "completed",
                resumable=False,
            )
            await broadcast("scan:complete", {
                "session_id": sid,
                "total_findings": len(session.findings),
                "summary": session.summary,
            })
        active_scans.pop(sid, None)


@router.post("/api/diff", dependencies=[Depends(verify_token)])
async def start_diff_scan(config: DiffConfig):
    try:
        if len(config.targets) < 2:
            raise HTTPException(400, {"error": "Need at least 2 targets for differential scan"})
        from basilisk.differential import run_differential
        report = await run_differential(
            [
                {
                    **target.model_dump(),
                    "_credential": get_api_key(target.provider),
                }
                for target in config.targets
            ],
            categories=config.categories or None,
            verbose=False,
        )
        return report.to_dict()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, {"error": sanitize_error_text(exc)})


@router.post("/api/posture", dependencies=[Depends(verify_token)])
async def start_posture_scan(config: PostureConfig):
    try:
        cfg = BasiliskConfig.from_cli_args(
            target=config.target or "direct",
            provider=config.provider,
            model=config.model,
            api_key="",
        )
        from basilisk.posture import run_posture_scan, save_posture_report
        from basilisk.runtime import create_provider

        prov = create_provider(
            cfg,
            credential_override=get_api_key(config.provider),
        )
        try:
            report = await run_posture_scan(
                prov,
                target=config.target,
                provider_name=config.provider,
                model_name=config.model,
                verbose=False,
            )
        finally:
            await prov.close()

        path = save_posture_report(report)
        result = report.to_dict()
        result["report_path"] = path
        return result
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, {"error": sanitize_error_text(exc)})
