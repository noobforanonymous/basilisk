"""
Basilisk Session — manages the lifecycle of a single scan.

Orchestrates recon → attack → report pipeline with persistence,
resume capability, and real-time event broadcasting.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from basilisk.core.config import BasiliskConfig
from basilisk.core.database import BasiliskDatabase
from basilisk.core.finding import AttackCategory, Finding, Severity
from basilisk.core.profile import BasiliskProfile


class ScanSession:
    """
    Manages state for a single Basilisk scan.

    Tracks findings, conversations, evolution state, and provides
    persistence via SQLite for scan resume and replay.
    """

    def __init__(
        self,
        config: BasiliskConfig,
        session_id: str | None = None,
    ) -> None:
        self.id = session_id or uuid.uuid4().hex[:12]
        self.config = config
        self.profile = BasiliskProfile(
            target_url=config.target.url,
            target_name=config.target.url,
        )
        self.findings: list[Finding] = []
        self.errors: list[dict[str, Any]] = []
        self.status: str = "initialized"
        self.started_at: datetime = datetime.now(timezone.utc)
        self.finished_at: datetime | None = None
        self._db: BasiliskDatabase | None = None
        self._event_listeners: list[Callable[..., Any]] = []

    async def initialize(self) -> None:
        """Connect to database and prepare session."""
        self._db = BasiliskDatabase(self.config.session_db)
        await self._db.connect()
        self.status = "running"
        await self._persist_session()

    async def close(self) -> None:
        """Finalize session and close database."""
        self.status = "completed"
        self.finished_at = datetime.now(timezone.utc)
        await self._persist_session()
        if self._db:
            await self._db.close()

    async def add_finding(self, finding: Finding) -> None:
        """Add a finding and persist it."""
        self.findings.append(finding)
        if self._db:
            await self._db.save_finding(self.id, finding.to_dict())
        await self._emit("finding", finding)

    async def add_error(self, module: str, error: str, severity: str = "error") -> None:
        """Add a module-level error and persist it."""
        err_entry = {
            "module": module,
            "error": error,
            "severity": severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.errors.append(err_entry)
        await self._persist_session()
        await self._emit("error", err_entry)

    async def save_conversation(
        self,
        attack_module: str,
        messages: list[dict[str, Any]],
        result: str,
    ) -> None:
        """Save a conversation to the database."""
        if self._db:
            await self._db.save_conversation(
                self.id,
                attack_module,
                messages,
                result,
                datetime.now(timezone.utc).isoformat(),
            )

    async def save_evolution_entry(self, entry: dict[str, Any]) -> None:
        """Save an evolution generation entry."""
        if self._db:
            entry["timestamp"] = datetime.now(timezone.utc).isoformat()
            await self._db.save_evolution_entry(self.id, entry)
        await self._emit("evolution", entry)

    def on_event(self, listener: Callable[..., Any]) -> None:
        """Register an event listener for real-time updates (dashboard, CLI)."""
        self._event_listeners.append(listener)

    async def _emit(self, event_type: str, data: Any) -> None:
        """Emit an event to all registered listeners."""
        for listener in self._event_listeners:
            try:
                result = listener(event_type, data)
                if hasattr(result, "__await__"):
                    await result
            except Exception:
                pass  # Don't let listener errors break the scan

    async def _persist_session(self) -> None:
        """Save session state to database."""
        if not self._db:
            return
        await self._db.save_session({
            "id": self.id,
            "target_url": self.config.target.url,
            "provider": self.config.target.provider,
            "mode": self.config.mode.value,
            "profile": self.profile.to_dict(),
            "config": self.config.to_dict(),
            "status": self.status,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "summary": self.summary,
        })

    @classmethod
    async def resume(cls, session_id: str, db_path: str = "./basilisk-sessions.db") -> ScanSession:
        """Resume an interrupted scan session from the database."""
        db = BasiliskDatabase(db_path)
        await db.connect()
        session_data = await db.get_session(session_id)
        if not session_data:
            await db.close()
            raise ValueError(f"Session not found: {session_id}")

        config = BasiliskConfig.from_cli_args(**session_data.get("config", {}))
        session = cls(config, session_id=session_id)
        session._db = db
        session.status = "resumed"

        if session_data.get("profile"):
            session.profile = BasiliskProfile.from_dict(session_data["profile"])

        findings_data = await db.get_findings(session_id)
        for fd in findings_data:
            session.findings.append(Finding.from_dict(fd))

        if session_data.get("summary") and "errors" in session_data["summary"]:
            session.errors = session_data["summary"]["errors"]

        return session

    @property
    def summary(self) -> dict[str, Any]:
        """Generate a summary of the current scan state."""
        severity_counts = {s.value: 0 for s in Severity}
        category_counts: dict[str, int] = {}
        for f in self.findings:
            severity_counts[f.severity.value] += 1
            cat = f.category.value
            category_counts[cat] = category_counts.get(cat, 0) + 1

        return {
            "session_id": self.id,
            "target": self.config.target.url,
            "status": self.status,
            "total_findings": len(self.findings),
            "severity_counts": severity_counts,
            "category_counts": category_counts,
            "errors": self.errors,
            "total_errors": len(self.errors),
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "model": self.profile.detected_model,
            "attack_surface_score": self.profile.attack_surface_score,
        }

    @property
    def max_severity(self) -> Severity:
        """Return the highest severity finding."""
        if not self.findings:
            return Severity.INFO
        return max(self.findings, key=lambda f: f.severity.numeric).severity

    @property
    def exit_code(self) -> int:
        """CI/CD exit code based on fail_on threshold."""
        threshold = Severity(self.config.fail_on)
        if self.max_severity.numeric >= threshold.numeric:
            return 1
        return 0
