"""
Basilisk Audit Logger — forensic logging for all scan operations.

Provides tamper-evident, append-only audit trails for significant scan,
policy, finding, error, and report events. Prompt and response logging is
available to callers that explicitly enable those event hooks.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from basilisk.core.retention import prune_artifact_dir
from basilisk.core.redaction import redacted_descriptor, sanitize_error_text, sanitize_mapping
from basilisk.core.schema import SCHEMA_VERSION_LABEL
from basilisk.core.secrets import SecretStore

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError:  # pragma: no cover - depends on optional runtime state
    ed25519 = None
    serialization = None

logger = logging.getLogger("basilisk.audit")
_AUDIT_KEY_SECRET_NAME = "AUDIT_SIGNING_KEY"


@dataclass(frozen=True)
class AuditVerificationResult:
    """Result of independently checking an audit file's hash chain and signatures."""

    valid: bool
    entry_count: int
    chain_valid: bool
    signed: bool
    signatures_valid: bool
    trust_anchored: bool
    trusted_key_match: bool | None
    public_key: str
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "entry_count": self.entry_count,
            "chain_valid": self.chain_valid,
            "signed": self.signed,
            "signatures_valid": self.signatures_valid,
            "trust_anchored": self.trust_anchored,
            "trusted_key_match": self.trusted_key_match,
            "public_key": self.public_key,
            "errors": list(self.errors),
        }


def verify_audit_log(
    path: str | Path,
    *,
    trusted_public_key: str = "",
    allow_embedded_key: bool = False,
) -> AuditVerificationResult:
    """Verify chaining and signatures against an independently supplied trust anchor."""
    audit_path = Path(path)
    errors: list[str] = []
    entries: list[dict[str, Any]] = []
    try:
        for line_number, line in enumerate(
            audit_path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"line {line_number}: invalid JSON ({exc.msg})")
                continue
            if not isinstance(entry, dict):
                errors.append(f"line {line_number}: audit entry must be an object")
                continue
            entries.append(entry)
    except OSError as exc:
        return AuditVerificationResult(
            valid=False,
            entry_count=0,
            chain_valid=False,
            signed=False,
            signatures_valid=False,
            trust_anchored=False,
            trusted_key_match=None,
            public_key="",
            errors=(str(exc),),
        )

    trusted_public_key = _resolve_trusted_public_key(trusted_public_key)
    embedded_key = ""
    if entries:
        start_data = entries[0].get("data", {})
        if isinstance(start_data, dict):
            embedded_key = str(start_data.get("public_key", ""))
    trust_anchored = bool(trusted_public_key.strip())
    public_key_hex = trusted_public_key.strip() or embedded_key
    trusted_key_match = (
        None if not trusted_public_key else embedded_key == trusted_public_key.strip()
    )
    if trusted_key_match is False:
        errors.append("embedded audit public key does not match the trusted key")
    if not trust_anchored and not allow_embedded_key:
        errors.append(
            "no external audit trust anchor supplied; use --public-key/--public-key-file "
            "or configure BASILISK_AUDIT_TRUSTED_PUBLIC_KEY_FILE"
        )

    verifier = None
    if public_key_hex and ed25519 is not None:
        try:
            verifier = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        except (ValueError, TypeError) as exc:
            errors.append(f"invalid audit public key: {exc}")
    elif public_key_hex and ed25519 is None:
        errors.append("cryptography is unavailable; signatures cannot be verified")

    previous_checksum = "0" * 64
    chain_valid = True
    signatures_valid = True
    expects_signatures = bool(public_key_hex)
    signed = expects_signatures
    for expected_seq, entry in enumerate(entries):
        if entry.get("seq") != expected_seq:
            errors.append(f"entry {expected_seq}: unexpected sequence number")
            chain_valid = False
        if entry.get("prev_checksum") != previous_checksum:
            errors.append(f"entry {expected_seq}: previous checksum mismatch")
            chain_valid = False

        core = {
            "seq": entry.get("seq"),
            "timestamp": entry.get("timestamp"),
            "event": entry.get("event"),
            "data": entry.get("data"),
            "prev_checksum": entry.get("prev_checksum"),
        }
        core_json = json.dumps(core, default=str, separators=(",", ":"))
        calculated = hashlib.sha256(core_json.encode()).hexdigest()
        if entry.get("checksum") != calculated:
            errors.append(f"entry {expected_seq}: checksum mismatch")
            chain_valid = False

        raw_signature = entry.get("signature", "")
        signature = raw_signature if isinstance(raw_signature, str) else ""
        if signature:
            signed = True
            if verifier is None:
                signatures_valid = False
            else:
                try:
                    verifier.verify(bytes.fromhex(signature), core_json.encode())
                except (ValueError, TypeError) as exc:
                    errors.append(f"entry {expected_seq}: invalid signature ({exc})")
                    signatures_valid = False
                except Exception:
                    errors.append(f"entry {expected_seq}: signature verification failed")
                    signatures_valid = False
        elif expects_signatures:
            errors.append(f"entry {expected_seq}: signature missing")
            signatures_valid = False
        previous_checksum = calculated

    if not entries:
        errors.append("audit log contains no entries")
        chain_valid = False
    if signed and not public_key_hex:
        errors.append("signed entries have no verification key")
        signatures_valid = False

    valid = (
        chain_valid
        and signed
        and signatures_valid
        and trusted_key_match is not False
        and (trust_anchored or allow_embedded_key)
    )
    return AuditVerificationResult(
        valid=valid,
        entry_count=len(entries),
        chain_valid=chain_valid,
        signed=signed,
        signatures_valid=signatures_valid if signed else False,
        trust_anchored=trust_anchored,
        trusted_key_match=trusted_key_match,
        public_key=embedded_key,
        errors=tuple(errors),
    )


def _resolve_trusted_public_key(explicit: str) -> str:
    if explicit.strip():
        return explicit.strip()
    key_file = os.environ.get("BASILISK_AUDIT_TRUSTED_PUBLIC_KEY_FILE", "").strip()
    if key_file:
        try:
            return Path(key_file).expanduser().read_text(encoding="utf-8").strip()
        except OSError as exc:
            logger.error("Unable to read configured audit trust anchor: %s", exc)
            return ""
    return os.environ.get("BASILISK_AUDIT_TRUSTED_PUBLIC_KEY", "").strip()


def export_audit_trust_anchor(path: str | Path) -> str:
    """Export the persistent audit signing public key for independent distribution."""
    key_material = ""
    key_file = os.environ.get("BASILISK_AUDIT_KEY_FILE", "").strip()
    if key_file:
        key_material = Path(key_file).expanduser().read_text(encoding="utf-8").strip()
    if not key_material:
        key_material = SecretStore().get(_AUDIT_KEY_SECRET_NAME).strip()
    private_key = _load_private_key_material(key_material) if key_material else None
    if private_key is None or serialization is None:
        raise RuntimeError("No persistent Ed25519 audit signing key is available to export")
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    output = Path(path).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(public_key + "\n", encoding="utf-8", newline="\n")
    return public_key


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
        
        # Security: Use Ed25519 digital signatures for forensic authenticity
        self._private_key: Any | None = None
        self._public_key_hex: str = ""
        
        if self.enabled and ed25519 and serialization:
            self._private_key = self._load_or_create_private_key()
            
            # Derive public key for verification
            public_key = self._private_key.public_key()
            self._public_key_hex = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ).hex()
        elif self.enabled:
            logger.warning("cryptography not available — audit log signatures disabled")
        
        self._last_checksum = "0" * 64
        self._entry_count = 0
        self._file = None
        self._log_path: Path | None = None

        if self.enabled:
            log_dir = Path(output_dir)
            log_dir.mkdir(parents=True, exist_ok=True)
            prune_artifact_dir(log_dir, retain_days=30)
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            self._log_path = log_dir / f"audit_{session_id}_{timestamp}.jsonl"
            self._file = open(self._log_path, "a", encoding="utf-8")
            self._write_entry("session_start", {
                "session_id": session_id,
                "schema_version": SCHEMA_VERSION_LABEL,
                "basilisk_version": _get_version(),
                "pid": os.getpid(),
                "cwd": os.getcwd(),
                "public_key": self._public_key_hex,
            })

    def _load_or_create_private_key(self):
        key_material = ""
        key_file = os.environ.get("BASILISK_AUDIT_KEY_FILE", "").strip()
        store: SecretStore | None = None

        if key_file:
            try:
                key_material = Path(key_file).expanduser().read_text("utf-8").strip()
            except Exception as exc:
                logger.error("Failed to read BASILISK_AUDIT_KEY_FILE: %s", exc)

        if not key_material:
            try:
                store = SecretStore()
                key_material = store.get(_AUDIT_KEY_SECRET_NAME).strip()
            except Exception as exc:
                logger.debug("Audit key secret store unavailable: %s", exc)

        legacy_env_key = os.environ.get("BASILISK_AUDIT_KEY", "").strip()
        if not key_material and legacy_env_key:
            logger.warning(
                "BASILISK_AUDIT_KEY is a legacy transport and may leak via process metadata. "
                "Prefer BASILISK_AUDIT_KEY_FILE or the encrypted Basilisk secret store."
            )
            key_material = legacy_env_key

        if key_material:
            private_key = _load_private_key_material(key_material)
            if private_key:
                return private_key

        generated_key = ed25519.Ed25519PrivateKey.generate()
        generated_raw = generated_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ).hex()

        if store is None:
            try:
                store = SecretStore()
            except Exception:
                store = None

        if store is not None:
            try:
                store.set(_AUDIT_KEY_SECRET_NAME, generated_raw)
                logger.info("Generated persistent Ed25519 audit signing key in the encrypted secret store")
                return generated_key
            except Exception as exc:
                logger.warning("Failed to persist audit signing key to secret store: %s", exc)

        logger.warning(
            "No persistent audit signing key configured — generated an ephemeral Ed25519 key for this session. "
            "Logs will be signed but cannot be linked to a persistent identity."
        )
        return generated_key

    def _write_entry(self, event: str, data: dict[str, Any]) -> dict[str, Any] | None:
        """Write a single audit entry to the log file."""
        if not self.enabled or not self._file:
            return None

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
        
        # Calculate Ed25519 signature for forensic authenticity
        if self._private_key:
            sig = self._private_key.sign(entry_json.encode())
            entry["signature"] = sig.hex()

        self._file.write(json.dumps(entry, default=str) + "\n")
        self._file.flush()
        self._entry_count += 1
        return entry

    def log_scan_config(self, config: dict[str, Any]) -> None:
        """Log the scan configuration (with API keys redacted)."""
        safe_config = _redact_secrets(config)
        self._write_entry("scan_config", safe_config)

    def log_campaign_context(self, campaign: dict[str, Any], policy: dict[str, Any]) -> None:
        """Log campaign/operator intent and execution policy."""
        self._write_entry("campaign_context", {
            "campaign": _redact_secrets(campaign),
            "policy": _redact_secrets(policy),
        })

    def log_policy_event(self, event_type: str, details: dict[str, Any]) -> None:
        """Log a policy enforcement or operator control event."""
        self._write_entry("policy_event", {
            "type": event_type,
            "details": _redact_secrets(details),
        })

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
            "prompt_preview": redacted_descriptor(prompt),
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
            "response_preview": redacted_descriptor(response),
            "response_hash": hashlib.sha256(response.encode()).hexdigest(),
            "response_length": len(response),
            "latency_ms": round(latency_ms, 2),
            "tokens_used": tokens_used,
            "was_refusal": was_refusal,
        })

    def log_finding(self, finding_data: dict[str, Any]) -> dict[str, Any] | None:
        """Log a vulnerability finding."""
        return self._write_entry("finding_discovered", {
            "finding_id": finding_data.get("id", ""),
            "title": finding_data.get("title", ""),
            "severity": finding_data.get("severity", ""),
            "category": finding_data.get("category", ""),
            "owasp_id": finding_data.get("owasp_id", ""),
            "confidence": finding_data.get("confidence", 0),
            "module": finding_data.get("attack_module", ""),
            "validation_level": finding_data.get("validation_level", "observation"),
            "attempt_count": finding_data.get("attempt_count", 0),
            "success_count": finding_data.get("success_count", 0),
            "negative_control_passed": finding_data.get("negative_control_passed", False),
            "response_fingerprint": finding_data.get("response_fingerprint", ""),
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
            "error": sanitize_error_text(error),
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
    return sanitize_mapping(data, include_raw=False, redact_all_strings=False)


def _get_version() -> str:
    """Get basilisk version."""
    try:
        from basilisk import __version__
        return __version__
    except ImportError:
        return "unknown"


def _load_private_key_material(key_material: str):
    """Load Ed25519 private key material from hex or base64 text."""
    if not ed25519:
        return None
    candidates: list[bytes] = []
    try:
        candidates.append(bytes.fromhex(key_material))
    except ValueError:
        pass
    try:
        candidates.append(base64.b64decode(key_material, validate=True))
    except Exception:
        pass
    for raw in candidates:
        try:
            return ed25519.Ed25519PrivateKey.from_private_bytes(raw)
        except Exception:
            continue
    logger.error("Failed to load audit signing key material from configured source")
    return None
