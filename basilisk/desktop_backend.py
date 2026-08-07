"""
Basilisk Desktop Backend — FastAPI server for Electron IPC.

This module is intentionally thin in v2.0. Route implementations live under
`basilisk.api.*` so the desktop control plane does not collapse into a single
god-file.
"""

from __future__ import annotations

import argparse
import logging
import os
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from basilisk.api import eval as eval_api
from basilisk.api import auth as auth_api
from basilisk.api import benchmark as benchmark_api
from basilisk.api import modules as modules_api
from basilisk.api import reports as reports_api
from basilisk.api import scan as scan_api
from basilisk.api import sessions as sessions_api
from basilisk.api import settings as settings_api
from basilisk.api.shared import active_scans

logger = logging.getLogger("basilisk.desktop")


def _docs_enabled(default: bool = False) -> bool:
    value = os.environ.get("BASILISK_ENABLE_API_DOCS", "")
    if not value:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    logger.info("Desktop backend shutting down gracefully...")
    for scan in list(active_scans.values()):
        task = scan.get("task")
        if task and not task.done():
            task.cancel()
    for scan in list(active_scans.values()):
        if "session" in scan:
            try:
                await scan["session"].close("stopped")
            except Exception:
                pass


def create_app(*, enable_docs: bool | None = None) -> FastAPI:
    docs = _docs_enabled(default=False) if enable_docs is None else enable_docs
    app = FastAPI(
        title="Basilisk Desktop Backend",
        version="2.0.0",
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url="/openapi.json" if docs else None,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://127.0.0.1:8741",
            "http://localhost:8741",
        ],
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-Basilisk-Token",
        ],
    )

    app.include_router(scan_api.router)
    app.include_router(auth_api.router)
    if os.environ.get("BASILISK_E2E") == "1":
        app.include_router(benchmark_api.router)
    app.include_router(sessions_api.router)
    app.include_router(modules_api.router)
    app.include_router(reports_api.router)
    app.include_router(settings_api.router)
    app.include_router(eval_api.router)
    return app


app = create_app()


def main():
    parser = argparse.ArgumentParser(description="Basilisk Desktop Backend")
    parser.add_argument("--port", type=int, default=8741)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if os.environ.get("BASILISK_RESTRICTED_WORKER") == "1":
        from basilisk.runtime.isolation import WorkerLimits, apply_worker_limits

        backend = apply_worker_limits(WorkerLimits(), include_cpu=False)
        logger.info("Desktop backend process isolation: %s", backend)

    log_level = "debug" if args.debug else "info"
    uvicorn.run(
        create_app(enable_docs=bool(args.debug or _docs_enabled(default=False))),
        host=args.host,
        port=args.port,
        log_level=log_level,
    )


if __name__ == "__main__":
    main()
