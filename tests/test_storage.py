"""
Tests for encrypted secret storage, retention enforcement, and desktop settings API.
"""

from __future__ import annotations

import os
import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from basilisk.api import shared
from basilisk.api.sessions import clear_session_history
from basilisk.api.settings import get_secret_store_status, save_api_key
from basilisk.core.audit import AuditLogger, verify_audit_log
from basilisk.core.database import BasiliskDatabase
from basilisk.core.retention import artifact_timestamp, prune_artifact_dir
import basilisk.core.secrets as secrets_module
from basilisk.core.secrets import SecretStore


class TestSecretStore:
    def test_secret_store_round_trip(self, tmp_path):
        store = SecretStore(str(tmp_path / "secrets"))
        store.set("OPENAI_API_KEY", "sk-test-123")
        assert store.get("OPENAI_API_KEY") == "sk-test-123"
        assert "OPENAI_API_KEY" in store.list_keys()

    def test_secret_store_refuses_corrupt_ciphertext(self, tmp_path):
        store = SecretStore(str(tmp_path / "secrets"))
        store.set("OPENAI_API_KEY", "sk-test-123")
        store._secrets_path.write_bytes(b"corrupt")
        with pytest.raises(ValueError, match="could not decrypt"):
            store.get("OPENAI_API_KEY")

    def test_secret_store_reports_electron_safe_storage_key(self, tmp_path, monkeypatch):
        key = secrets_module.Fernet.generate_key().decode("utf-8")
        monkeypatch.setenv("BASILISK_MASTER_KEY", key)
        monkeypatch.setenv("BASILISK_MASTER_KEY_SOURCE", "electron_safe_storage")

        store = SecretStore(str(tmp_path / "secrets"))
        store.set("NVIDIA_API_KEY", "nvapi-test-value")

        assert store.get("NVIDIA_API_KEY") == "nvapi-test-value"
        assert store.metadata()["key_backend"] == "electron_safe_storage"
        assert b"nvapi-test-value" not in store._secrets_path.read_bytes()

    def test_prune_artifact_dir_removes_old_files(self, tmp_path):
        old_file = tmp_path / "basilisk_old.json"
        old_file.write_text("{}")
        ancient = datetime.now(timezone.utc) - timedelta(days=40)
        os.utime(old_file, (ancient.timestamp(), ancient.timestamp()))

        fresh_file = tmp_path / "basilisk_new.json"
        fresh_file.write_text("{}")

        removed = prune_artifact_dir(tmp_path, retain_days=30)
        assert str(old_file) in removed
        assert not old_file.exists()
        assert fresh_file.exists()

    def test_prune_artifact_dir_prefers_embedded_filename_timestamp(self, tmp_path):
        old_report = tmp_path / "basilisk_deadbeef_20240101_000000.html"
        old_report.write_text("<html></html>")
        recent = datetime.now(timezone.utc).timestamp()
        os.utime(old_report, (recent, recent))

        fresh_report = tmp_path / "audit_sess_20991231_235959.jsonl"
        fresh_report.write_text("{}")

        removed = prune_artifact_dir(
            tmp_path,
            retain_days=30,
            now=datetime(2026, 3, 25, tzinfo=timezone.utc),
        )
        assert str(old_report) in removed
        assert not old_report.exists()
        assert fresh_report.exists()
        assert artifact_timestamp(fresh_report) == datetime(2099, 12, 31, 23, 59, 59, tzinfo=timezone.utc)

    def test_audit_logger_persists_signing_key_in_secret_store(self, tmp_path, monkeypatch):
        pytest.importorskip("cryptography")
        monkeypatch.setenv("BASILISK_SECRET_STORE_DIR", str(tmp_path / "secret-store"))
        monkeypatch.delenv("BASILISK_AUDIT_KEY", raising=False)
        monkeypatch.delenv("BASILISK_AUDIT_KEY_FILE", raising=False)
        monkeypatch.setattr(secrets_module, "keyring", None)

        first = AuditLogger(output_dir=str(tmp_path / "reports"), session_id="sess-1")
        first_public = first._public_key_hex
        first.close()

        second = AuditLogger(output_dir=str(tmp_path / "reports"), session_id="sess-2")
        second_public = second._public_key_hex
        second.close()

        assert first_public
        assert first_public == second_public

    def test_audit_log_verification_detects_tampering(self, tmp_path, monkeypatch):
        pytest.importorskip("cryptography")
        monkeypatch.setenv("BASILISK_SECRET_STORE_DIR", str(tmp_path / "secret-store"))
        monkeypatch.setattr(secrets_module, "keyring", None)

        audit = AuditLogger(output_dir=str(tmp_path), session_id="verified")
        audit.log_policy_event("test", {"approved": True})
        audit.close()
        path = next(tmp_path.glob("audit_verified_*.jsonl"))

        embedded_key = json.loads(path.read_text(encoding="utf-8").splitlines()[0])["data"]["public_key"]
        unanchored = verify_audit_log(path)
        assert not unanchored.valid
        assert not unanchored.trust_anchored
        assert any("external audit trust anchor" in error for error in unanchored.errors)

        integrity_only = verify_audit_log(path, allow_embedded_key=True)
        assert integrity_only.valid
        assert not integrity_only.trust_anchored

        verified = verify_audit_log(path, trusted_public_key=embedded_key)
        assert verified.valid
        assert verified.chain_valid
        assert verified.signed
        assert verified.signatures_valid
        assert verified.trust_anchored

        original = path.read_text(encoding="utf-8")
        unsigned_lines = original.splitlines()
        first_entry = json.loads(unsigned_lines[0])
        first_entry.pop("signature")
        unsigned_lines[0] = json.dumps(first_entry)
        path.write_text("\n".join(unsigned_lines) + "\n", encoding="utf-8")
        missing_signature = verify_audit_log(path, trusted_public_key=embedded_key)
        assert not missing_signature.valid
        assert not missing_signature.signatures_valid

        content = original.replace('"approved": true', '"approved": false')
        path.write_text(content, encoding="utf-8")
        tampered = verify_audit_log(path, trusted_public_key=embedded_key)
        assert not tampered.valid
        assert not tampered.chain_valid


class TestSettingsApi:
    async def test_settings_secret_status_endpoint(self, tmp_path):
        shared._secret_store = SecretStore(str(tmp_path / "secret-store"))
        await save_api_key(shared.ApiKeyRequest(provider="openai", key="sk-live-demo"))
        status = await get_secret_store_status()
        body = status.model_dump()
        assert body["backend"] == "fernet_encrypted_file"
        assert any(item["provider"] == "openai" and item["stored"] for item in body["providers"])


class TestRuntimePersistence:
    async def test_runtime_state_marks_stale_scans_interrupted(self, tmp_path):
        db = BasiliskDatabase(str(tmp_path / "session.db"))
        await db.connect()
        try:
            await db.save_session({
                "id": "sess-1",
                "target_url": "https://example.test",
                "provider": "custom",
                "mode": "standard",
                "profile": {},
                "config": {},
                "status": "running",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "finished_at": None,
                "summary": {},
            })
            await db.save_scan_runtime({
                "session_id": "sess-1",
                "db_path": str(tmp_path / "session.db"),
                "target_url": "https://example.test",
                "provider": "custom",
                "model": "",
                "status": "attacking",
                "current_phase": "attacking",
                "progress": {"progress": 0.5},
                "config": {},
                "campaign": {},
                "policy": {},
                "last_error": "",
                "stop_requested": False,
                "resumable": True,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            })
            updated = await db.mark_stale_scan_runtimes_interrupted(set())
            assert updated == 1
            runtime = await db.get_scan_runtime("sess-1")
            assert runtime["status"] == "interrupted"
            assert runtime["resumable"] is True
        finally:
            await db.close()

    async def test_shared_worker_handles_concurrent_database_clients(self, tmp_path):
        db_path = tmp_path / "shared.db"
        started_at = datetime.now(timezone.utc).isoformat()
        db1 = BasiliskDatabase(str(db_path))
        db2 = BasiliskDatabase(str(db_path))
        await db1.connect()
        await db2.connect()
        try:
            await asyncio.gather(
                db1.save_session({
                    "id": "sess-a",
                    "target_url": "https://one.test",
                    "provider": "custom",
                    "mode": "standard",
                    "profile": {},
                    "config": {},
                    "status": "completed",
                    "started_at": started_at,
                    "finished_at": started_at,
                    "summary": {"total_findings": 0},
                }),
                db2.save_session({
                    "id": "sess-b",
                    "target_url": "https://two.test",
                    "provider": "custom",
                    "mode": "standard",
                    "profile": {},
                    "config": {},
                    "status": "completed",
                    "started_at": started_at,
                    "finished_at": started_at,
                    "summary": {"total_findings": 1},
                }),
            )
            sessions = await db1.list_sessions(limit=10)
            assert {row["id"] for row in sessions} >= {"sess-a", "sess-b"}
        finally:
            await db1.close()
            await db2.close()


class TestSessionHistoryApi:
    async def test_clear_session_history_removes_local_history(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        shared.active_scans.clear()
        shared.scan_results.clear()

        db = BasiliskDatabase("basilisk-sessions.db")
        await db.connect()
        try:
            await db.save_session({
                "id": "sess-clear-1",
                "target_url": "https://example.test",
                "provider": "custom",
                "mode": "standard",
                "profile": {},
                "config": {},
                "status": "completed",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "summary": {"total_findings": 1},
            })
        finally:
            await db.close()

        shared.scan_results["sess-mem-1"] = {
            "session_id": "sess-mem-1",
            "target": "https://memory.test",
            "session_db": str(tmp_path / "basilisk-sessions.db"),
        }

        result = await clear_session_history()
        assert result["cleared_sessions"] == 1
        assert result["cleared_memory_sessions"] == 1
        assert result["cleared_runtime_dbs"] == 1
        assert shared.scan_results == {}

        db = BasiliskDatabase("basilisk-sessions.db")
        await db.connect()
        try:
            assert await db.list_sessions() == []
            assert await db.list_scan_runtimes() == []
        finally:
            await db.close()

    async def test_clear_session_history_rejects_active_scans(self):
        shared.scan_results.clear()
        shared.active_scans["active-1"] = {"status": "running"}
        try:
            with pytest.raises(HTTPException) as exc:
                await clear_session_history()
            assert exc.value.status_code == 409
        finally:
            shared.active_scans.clear()
