"""
Basilisk secret storage with optional OS keyring integration.

API keys are stored encrypted at rest. If `keyring` is available, Basilisk uses
the OS keychain to protect the Fernet master key; otherwise it falls back to a
local key file with restricted permissions.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from threading import Lock
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

try:  # pragma: no cover - depends on host runtime
    import keyring
except ImportError:  # pragma: no cover - optional dependency
    keyring = None

_SERVICE_NAME = "basilisk-ai"
_MASTER_KEY_NAME = "master-key"


class SecretStore:
    """Encrypted local secret store for desktop and CLI settings."""

    def __init__(self, root_dir: str | None = None) -> None:
        base = (
            Path(root_dir)
            if root_dir
            else Path(os.environ.get("BASILISK_SECRET_STORE_DIR", "~/.basilisk")).expanduser()
        )
        self.root_dir = _resolve_store_dir(base)
        self._secrets_path = self.root_dir / "secrets.enc"
        self._key_path = self.root_dir / "master.key"
        self._lock = Lock()
        self._key_backend = "local_file"
        self._fernet = Fernet(self._load_or_create_master_key())

    def metadata(self) -> dict[str, Any]:
        return {
            "backend": "fernet_encrypted_file",
            "key_backend": self._key_backend,
            "path": str(self._secrets_path),
            "stored_secrets": len(self.list_keys()),
        }

    def get(self, key: str) -> str:
        with self._lock:
            return self._read_payload().get(key, "")

    def set(self, key: str, value: str) -> None:
        with self._lock:
            payload = self._read_payload()
            payload[key] = value
            self._write_payload(payload)

    def delete(self, key: str) -> None:
        with self._lock:
            payload = self._read_payload()
            if key in payload:
                del payload[key]
                self._write_payload(payload)

    def list_keys(self) -> list[str]:
        with self._lock:
            return sorted(self._read_payload().keys())

    def _load_or_create_master_key(self) -> bytes:
        env_key = os.environ.get("BASILISK_MASTER_KEY", "")
        if env_key:
            source = os.environ.get("BASILISK_MASTER_KEY_SOURCE", "").strip()
            self._key_backend = (
                source
                if source in {"electron_safe_storage", "environment"}
                else "environment"
            )
            return env_key.encode("utf-8")

        if keyring:
            try:
                stored = keyring.get_password(_SERVICE_NAME, _MASTER_KEY_NAME)
                if stored:
                    self._key_backend = "os_keychain"
                    return stored.encode("utf-8")
                generated = Fernet.generate_key()
                keyring.set_password(_SERVICE_NAME, _MASTER_KEY_NAME, generated.decode("utf-8"))
                self._key_backend = "os_keychain"
                return generated
            except Exception:
                pass

        if self._key_path.exists():
            return self._key_path.read_bytes().strip()

        generated = Fernet.generate_key()
        self._key_path.write_bytes(generated)
        try:
            os.chmod(self._key_path, 0o600)
        except PermissionError:
            pass
        return generated

    def _read_payload(self) -> dict[str, str]:
        if not self._secrets_path.exists():
            return {}
        blob = self._secrets_path.read_bytes()
        if not blob:
            return {}
        try:
            data = self._fernet.decrypt(blob)
        except InvalidToken as exc:
            raise ValueError(
                "Basilisk could not decrypt the secret store; refusing to overwrite it"
            ) from exc
        return json.loads(data.decode("utf-8"))

    def _write_payload(self, payload: dict[str, str]) -> None:
        encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
        encrypted = self._fernet.encrypt(encoded)
        self._secrets_path.write_bytes(encrypted)
        try:
            os.chmod(self._secrets_path, 0o600)
        except PermissionError:
            pass


def _resolve_store_dir(base: Path) -> Path:
    """Create the requested private store without falling back to shared directories."""
    expanded = base.expanduser()
    if expanded.exists() and expanded.is_symlink():
        raise OSError(f"Refusing symlinked Basilisk secret store: {expanded}")
    candidate = expanded.resolve(strict=False)
    try:
        candidate.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise OSError(f"Unable to create Basilisk secret store: {candidate}") from exc
    return candidate
