"""
Basilisk Audit Logger — forensic logging for all scan operations.

Provides tamper-evident, append-only audit trails for every prompt sent,
response received, and finding discovered. On by default for legal
protection and enterprise compliance.
"""

from __future__ import annotations

import hmac
import json
import hashlib
import logging
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("basilisk.audit")


class AuditLogger:
    """
    Append-only audit logger for Basilisk scan operations.

    Creates a JSONL (JSON Lines) audit file that records every significant
    action taken during a scan. Each entry is checksummed for integrity
    verification. Enabled by default — set BASILISK_AUDIT=0 to disable.

    Audit log format:
        Each line is a JSON object with:
        - timestamp: ISO 8601 UTC timestamp
        - event: event type
        - data: event-specific payload
        - checksum: SHA-256 of previous entry for chain integrity
    """

    def __init__(
        self,
        output_dir: str = "./basilisk-reports",
        session_id: str = "",
        enabled: bool | None = None,
    ) -> None:
        # Check env override: BASILISK_AUDIT=0 disables
        if enabled is None:
            enabled = os.environ.get("BASILISK_AUDIT", "1") != "0"

        self.enabled = enabled
        self._session_id = session_id
        
        # Security: Use a secret for HMAC signatures to prevent tamper-and-recalculate attacks
        self._audit_secret = os.environ.get("BASILISK_AUDIT_SECRET")
        if not self._audit_secret and self.enabled:
            self._audit_secret = secrets.token_hex(32)
            logger.info(f"Audit Log Secret: {self._audit_secret} (Save this to verify integrity later)")
        
        self._last_checksum = "0" * 64
        self._entry_count = 0
        self._file = None
        self._log_path: Path | None = None

        if self.enabled:
            log_dir = Path(output_dir)
            log_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            self._log_path = log_dir / f"audit_{session_id}_{timestamp}.jsonl"
            self._file = open(self._log_path, "a", encoding="utf-8")
            self._write_entry("session_start", {
                "session_id": session_id,
                "basilisk_version": _get_version(),
                "pid": os.getpid(),
                "cwd": os.getcwd(),
            })

    def _write_entry(self, event: str, data: dict[str, Any]) -> None:
        """Write a single audit entry to the log file."""
        if not self.enabled or not self._file:
            return

        entry = {
            "seq": self._entry_count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "data": data,
            "prev_checksum": self._last_checksum,
        }

        entry_json = json.dumps(entry, default=str, separators=(",", ":"))
        
        # Calculate SHA-256 for chain integrity
        self._last_checksum = hashlib.sha256(entry_json.encode()).hexdigest()
        entry["checksum"] = self._last_checksum
        
        # Calculate HMAC signature for authenticity (tamper-evident)
        if self._audit_secret:
            sig = hmac.new(
                self._audit_secret.encode(),
                entry_json.encode(),
                hashlib.sha256
            ).hexdigest()
            entry["signature"] = sig

        self._file.write(json.dumps(entry, default=str) + "\n")
        self._file.flush()
        self._entry_count += 1

    def log_scan_config(self, config: dict[str, Any]) -> None:
        """Log the scan configuration (with API keys redacted)."""
        safe_config = _redact_secrets(config)
        self._write_entry("scan_config", safe_config)

    def log_prompt_sent(
        self,
        module: str,
        prompt: str,
        provider: str,
        model: str,
        target: str,
    ) -> None:
        """Log a prompt being sent to the target."""
        self._write_entry("prompt_sent", {
            "module": module,
            "prompt_preview": prompt[:500],
            "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest(),
            "prompt_length": len(prompt),
            "provider": provider,
            "model": model,
            "target": target,
        })

    def log_response_received(
        self,
        module: str,
        response: str,
        latency_ms: float,
        tokens_used: int = 0,
        was_refusal: bool = False,
    ) -> None:
        """Log a response received from the target."""
        self._write_entry("response_received", {
            "module": module,
            "response_preview": response[:500],
            "response_hash": hashlib.sha256(response.encode()).hexdigest(),
            "response_length": len(response),
            "latency_ms": round(latency_ms, 2),
            "tokens_used": tokens_used,
            "was_refusal": was_refusal,
        })

    def log_finding(self, finding_data: dict[str, Any]) -> None:
        """Log a vulnerability finding."""
        self._write_entry("finding_discovered", {
            "finding_id": finding_data.get("id", ""),
            "title": finding_data.get("title", ""),
            "severity": finding_data.get("severity", ""),
            "category": finding_data.get("category", ""),
            "owasp_id": finding_data.get("owasp_id", ""),
            "confidence": finding_data.get("confidence", 0),
            "module": finding_data.get("attack_module", ""),
        })

    def log_evolution_generation(
        self,
        generation: int,
        population_size: int,
        best_fitness: float,
        avg_fitness: float,
        breakthroughs: int,
    ) -> None:
        """Log an evolution generation."""
        self._write_entry("evolution_generation", {
            "generation": generation,
            "population_size": population_size,
            "best_fitness": round(best_fitness, 4),
            "avg_fitness": round(avg_fitness, 4),
            "breakthroughs": breakthroughs,
        })

    def log_recon_result(self, recon_type: str, result: dict[str, Any]) -> None:
        """Log a reconnaissance result."""
        self._write_entry("recon_result", {
            "recon_type": recon_type,
            "result": result,
        })

    def log_error(self, module: str, error: str) -> None:
        """Log an error."""
        self._write_entry("error", {
            "module": module,
            "error": error[:1000],
        })

    def log_report_generated(self, format: str, path: str) -> None:
        """Log report generation."""
        self._write_entry("report_generated", {
            "format": format,
            "path": path,
        })

    def close(self) -> None:
        """Close the audit log with a session summary."""
        self._write_entry("session_end", {
            "total_entries": self._entry_count,
            "final_checksum": self._last_checksum,
        })
        if self._file:
            self._file.close()
            self._file = None
        if self._log_path:
            logger.info(f"Audit log saved to: {self._log_path}")

    @property
    def log_path(self) -> str | None:
        """Return the path to the audit log file."""
        return str(self._log_path) if self._log_path else None

    def __del__(self) -> None:
        if self._file and not self._file.closed:
            self.close()


def _redact_secrets(data: dict[str, Any]) -> dict[str, Any]:
    """Redact sensitive fields from a config dictionary."""
    sensitive_keys = {"api_key", "token", "secret", "password", "auth_header", "authorization"}
    redacted = {}
    for key, value in data.items():
        if isinstance(value, dict):
            redacted[key] = _redact_secrets(value)
        elif any(s in key.lower() for s in sensitive_keys):
            redacted[key] = "***REDACTED***" if value else ""
        else:
            redacted[key] = value
    return redacted


def _get_version() -> str:
    """Get basilisk version."""
    try:
        from basilisk import __version__
        return __version__
    except ImportError:
        return "unknown"
