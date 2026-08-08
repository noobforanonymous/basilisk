"""Report and audit routes."""

from __future__ import annotations

import glob
import json
import os
import sys
import webbrowser

from fastapi import APIRouter, Depends, HTTPException

from basilisk.api.shared import AuditLogResponse, ReportRequest, ReportResponse, active_scans, scan_results, verify_token
from basilisk.core.config import OutputConfig
from basilisk.core.redaction import sanitize_error_text
from basilisk.core.session import ScanSession

router = APIRouter()


@router.post("/api/report/{session_id}", response_model=ReportResponse, dependencies=[Depends(verify_token)])
async def generate_report(session_id: str, req: ReportRequest):
    try:
        session = None
        if session_id in active_scans:
            session = active_scans[session_id]["session"]
        else:
            db_path = scan_results.get(session_id, {}).get("session_db", "./basilisk-sessions.db")
            try:
                session = await ScanSession.resume(session_id, db_path)
            except ValueError as exc:
                raise HTTPException(404, {"error": sanitize_error_text(exc)}) from exc
        if session is None:
            raise HTTPException(404, {"error": "Session data not found. The scan may have been cleared."})

        from basilisk.report.generator import generate_report as gen
        output_cfg = OutputConfig(format=req.format, output_dir="./basilisk-reports")
        path = os.path.abspath(await gen(session, output_cfg))
        if req.open_browser:
            file_url = f"file://{path}" if sys.platform != "win32" else path
            webbrowser.open(file_url)
        return {"path": path, "format": req.format}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, {"error": sanitize_error_text(exc)})


@router.post("/api/report/{session_id}/export", dependencies=[Depends(verify_token)])
async def export_report(session_id: str, req: ReportRequest):
    if req.path:
        raise HTTPException(400, {"error": "Custom export paths are no longer supported by the backend"})
    return await generate_report(session_id, req)


@router.get("/api/audit/{session_id}", response_model=AuditLogResponse, dependencies=[Depends(verify_token)])
async def get_audit_log(session_id: str):
    logs = glob.glob(f"./basilisk-reports/audit_{glob.escape(session_id)}_*.jsonl")
    if not logs:
        raise HTTPException(404, {"error": "No audit log found for this session"})
    log_path = max(logs, key=os.path.getmtime)
    entries = []
    with open(log_path, encoding="utf-8") as handle:
        for line in handle:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    from basilisk.core.audit import verify_audit_log

    verification = verify_audit_log(log_path).to_dict()
    return {"path": log_path, "entries": entries, "verification": verification}
