"""Content-addressed runtime identity attached to reproducible findings."""

from __future__ import annotations

import hashlib
import os
import subprocess
from functools import lru_cache
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from basilisk.payloads.loader import find_probe_by_payload, probe_corpus_version


ROOT = Path(__file__).resolve().parents[2]


def _file_hash(path: Path) -> str:
    if not path.exists():
        return ""
    return hashlib.sha256(path.read_bytes()).hexdigest()


@lru_cache(maxsize=1)
def source_revision() -> str:
    explicit = os.environ.get("BASILISK_SOURCE_REVISION") or os.environ.get("GITHUB_SHA")
    if explicit:
        return explicit.strip()
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        )
        return result.stdout.strip()
    except Exception:
        return "unknown"


@lru_cache(maxsize=1)
def build_identity() -> dict[str, str]:
    try:
        package_version = version("basilisk-ai")
    except PackageNotFoundError:
        package_version = "source"
    dependency_hash = _file_hash(ROOT / "requirements.lock")
    desktop_lock_hash = _file_hash(ROOT / "desktop" / "package-lock.json")
    material = "\n".join(
        [source_revision(), dependency_hash, desktop_lock_hash, probe_corpus_version()]
    )
    return {
        "basilisk_version": package_version,
        "source_revision": source_revision(),
        "dependency_lock_sha256": dependency_hash,
        "desktop_lock_sha256": desktop_lock_hash,
        "probe_corpus_version": probe_corpus_version(),
        "build_identity_sha256": hashlib.sha256(material.encode()).hexdigest(),
    }


def finding_reproducibility(
    *,
    module: str,
    payload: str,
    response: str,
    provider_response: Any | None = None,
) -> dict[str, Any]:
    probe = find_probe_by_payload(payload)
    provider_meta = dict(getattr(provider_response, "raw_response", {}) or {})
    return {
        **build_identity(),
        "module": module,
        "module_version": "1",
        "probe_id": probe.id if probe else "",
        "probe_version": probe.version if probe else "",
        "request_sha256": hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest(),
        "response_sha256": hashlib.sha256(response.encode("utf-8", errors="replace")).hexdigest(),
        "provider_model": getattr(provider_response, "model", "") if provider_response else "",
        "provider_model_version": provider_meta.get(
            "model_version", provider_meta.get("system_fingerprint", "")
        ),
        "request_id": provider_meta.get("basilisk_request_id", ""),
        "latency_ms": float(getattr(provider_response, "latency_ms", 0.0) or 0.0),
    }
