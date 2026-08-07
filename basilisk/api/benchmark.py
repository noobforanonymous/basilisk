"""Source-tree-only benchmark routes enabled exclusively in Electron E2E mode."""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException

from basilisk.api.shared import StrictRequestModel, verify_token

router = APIRouter()


class ProtocolBenchmarkRequest(StrictRequestModel):
    base_url: str


@router.post("/api/benchmark/protocol", dependencies=[Depends(verify_token)])
async def protocol_benchmark(request: ProtocolBenchmarkRequest):
    """Exercise hostile transport controls inside the authenticated desktop path."""
    if os.environ.get("BASILISK_E2E") != "1":
        raise HTTPException(status_code=404, detail="Not found")
    try:
        from benchmarks.protocol_suite import run_protocol_suite, summarize
    except ImportError as exc:
        raise HTTPException(
            status_code=503,
            detail="The source-tree protocol benchmark is unavailable.",
        ) from exc
    results = await run_protocol_suite(request.base_url)
    return {"summary": summarize(results), "results": results}
