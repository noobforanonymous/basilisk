"""
Basilisk Session — manages the lifecycle of a single scan.

Orchestrates recon → attack → report pipeline with persistence,
resume capability, and real-time event broadcasting.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable

from basilisk.core.database import BasiliskDatabase
from basilisk.core.finding import AttackCategory, Finding, Severity
from basilisk.core.profile import BasiliskProfile
from basilisk.core.retention import retention_deadline
from basilisk.core.schema import SCHEMA_VERSION_LABEL

if TYPE_CHECKING:
    from basilisk.core.config import BasiliskConfig


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
        self.current_phase: str = "initialized"
        self.started_at: datetime = datetime.now(timezone.utc)
        self.finished_at: datetime | None = None
        self.phase_history: list[dict[str, Any]] = []
        self.last_progress: dict[str, Any] = {}
        self.last_error: str = ""
        self.stop_requested: bool = False
        self.stop_reason: str = ""
        self.attack_memory: dict[str, Any] = {
            "discovered_tools": [],
            "guardrail_level": "",
            "rag_detected": False,
            "completed_modules": [],
            "policy_events": [],
            "behavioral_notes": [],
            "refusal_patterns": [],
            "successful_framing_styles": [],
            "failed_operator_families": [],
            "best_probe_families": [],
            "operator_learning": {},
        }
        self._db: BasiliskDatabase | None = None
        self._event_listeners: list[Callable[..., Any]] = []

    async def initialize(self) -> None:
        """Connect to database and prepare session."""
        self._db = BasiliskDatabase(self.config.session_db)
        await self._db.connect()
        deadline = retention_deadline(retain_days=self.config.policy.retain_days)
        if deadline:
            purged = await self._db.purge_sessions_before(deadline.isoformat())
            if purged:
                self.record_phase("retention_prune", purged_sessions=purged, retain_days=self.config.policy.retain_days)
        self.status = "running"
        await self._persist_session()
        await self.save_runtime_state(status="running", current_phase=self.current_phase)

    async def close(self, status: str = "completed") -> None:
        """Finalize session and close database."""
        if self._db is None and self.finished_at is not None:
            self.status = status
            return
        self.status = status
        self.finished_at = datetime.now(timezone.utc)
        await self._persist_session()
        await self.save_runtime_state(
            status=status,
            current_phase=self.current_phase or status,
            resumable=status in {"error", "stopped", "interrupted"},
            last_error=self.last_error,
        )
        if self._db:
            await self._db.close()
            self._db = None

    async def add_finding(self, finding: Finding) -> None:
        """Add a finding and persist it."""
        from basilisk.policy.finding import enforce_finding_policy

        if self.config.max_findings and len(self.findings) >= self.config.max_findings:
            self.stop_requested = True
            self.stop_reason = f"maximum findings reached ({self.config.max_findings})"
            return
        finding = enforce_finding_policy(finding, self.config.policy, final=False)
        finding.metadata = {
            **finding.metadata,
            "target_configuration": {
                "provider": self.config.target.provider,
                "model": self.config.target.model,
                "target_sha256": __import__("hashlib").sha256(
                    self.config.target.url.encode("utf-8", errors="replace")
                ).hexdigest(),
            },
            "random_seed": self.config.evolution.random_seed,
        }
        self.findings.append(finding)
        if finding.evidence:
            verdict = finding.evidence.verdict.value
            self.attack_memory.setdefault("evidence_verdict_counts", {})
            counts = self.attack_memory["evidence_verdict_counts"]
            counts[verdict] = counts.get(verdict, 0) + 1
        if self.config.max_findings and len(self.findings) >= self.config.max_findings:
            self.stop_requested = True
            self.stop_reason = f"maximum findings reached ({self.config.max_findings})"
        await self._persist_finding(finding)
        await self._emit("finding", finding)

    async def reassess_finding(self, finding: Finding, *, final: bool = True) -> None:
        """Apply final evidence policy after replay and persist the updated result."""
        from basilisk.policy.finding import enforce_finding_policy

        enforce_finding_policy(finding, self.config.policy, final=final)
        threshold = self.config.policy.stop_on_severity.strip().casefold()
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        if (
            threshold in severity_order
            and finding.validation_level.value == "verified"
            and finding.severity.numeric >= severity_order[threshold]
        ):
            self.stop_requested = True
            self.stop_reason = (
                f"finding {finding.id} reached stop severity {threshold}"
            )
        if finding.metadata.get("policy_downgraded"):
            self.remember("policy_events", {
                "type": "finding_downgraded",
                "finding_id": finding.id,
                "module": finding.attack_module,
                "required": finding.metadata.get("required_evidence_verdict"),
                "actual": finding.metadata.get("actual_evidence_verdict"),
            })
        await self._persist_finding(finding)
        await self._emit("finding_updated", finding)

    async def finalize_findings(self) -> None:
        """Ensure no unverified high-impact result leaves the scan as confirmed."""
        for finding in self.findings:
            await self.reassess_finding(finding, final=True)

    async def _persist_finding(self, finding: Finding) -> None:
        if self._db:
            await self._db.save_finding(
                self.id,
                finding.sanitized_dict(
                    include_payload=self.config.persist_payloads,
                    include_response=self.config.persist_responses,
                    include_conversation=self.config.persist_conversations,
                ),
            )
    def check_continue(self) -> None:
        """Raise cancellation once an operator or finding policy requests a stop."""
        if self.stop_requested:
            raise asyncio.CancelledError(self.stop_reason or "scan stop requested")

    async def add_error(self, module: str, error: str, severity: str = "error") -> None:
        """Add a module-level error and persist it."""
        err_entry = {
            "module": module,
            "error": error,
            "severity": severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.errors.append(err_entry)
        self.last_error = error
        await self._persist_session()
        await self.save_runtime_state(last_error=error, status=self.status, current_phase=self.current_phase)
        await self._emit("error", err_entry)

    async def save_conversation(
        self,
        attack_module: str,
        messages: list[dict[str, Any]],
        result: str,
    ) -> None:
        """Save a conversation to the database."""
        if self._db and self.config.persist_conversations:
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

    def record_phase(self, phase: str, **details: Any) -> None:
        """Record phase transitions for replay and audits."""
        self.current_phase = phase
        self.phase_history.append({
            "phase": phase,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details,
        })

    def remember(self, key: str, value: Any) -> None:
        """Track operator-relevant memory discovered during the scan."""
        if key not in self.attack_memory:
            self.attack_memory[key] = value
            return
        current = self.attack_memory[key]
        if isinstance(current, list):
            if isinstance(value, list):
                for item in value:
                    if item not in current:
                        current.append(item)
            elif value not in current:
                current.append(value)
        elif isinstance(current, dict) and isinstance(value, dict):
            current.update(value)
        else:
            self.attack_memory[key] = value

    def sync_profile_memory(self) -> None:
        """Snapshot profile discoveries into scan memory."""
        self.attack_memory["discovered_tools"] = [
            tool.name for tool in getattr(self.profile, "detected_tools", []) or []
        ]
        self.attack_memory["guardrail_level"] = getattr(getattr(self.profile, "guardrails", None), "level", "")
        self.attack_memory["rag_detected"] = bool(getattr(self.profile, "rag_detected", False))

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
            "config": self.config.to_safe_dict(),
            "status": self.status,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "summary": self.summary,
        })

    async def save_runtime_state(
        self,
        *,
        status: str | None = None,
        current_phase: str | None = None,
        progress: dict[str, Any] | None = None,
        stop_requested: bool | None = None,
        resumable: bool = True,
        last_error: str | None = None,
    ) -> None:
        """Persist live scan runtime state for crash-soft resume and UI recovery."""
        if not self._db:
            return
        if status is not None:
            self.status = status
        if current_phase is not None:
            self.current_phase = current_phase
        if progress is not None:
            self.last_progress = progress
        if last_error:
            self.last_error = last_error
        await self._db.save_scan_runtime({
            "session_id": self.id,
            "db_path": self.config.session_db,
            "target_url": self.config.target.url,
            "provider": self.config.target.provider,
            "model": self.config.target.model,
            "status": self.status,
            "current_phase": self.current_phase,
            "progress": self.last_progress,
            "config": self.config.to_safe_dict(),
            "campaign": self.config.campaign.to_summary(),
            "policy": {
                "execution_mode": self.config.policy.execution_mode.value,
                "aggression": self.config.policy.aggression,
                "evidence_threshold": self.config.policy.evidence_threshold.value,
                "dry_run": self.config.policy.dry_run,
                "approval_required": self.config.policy.approval_required,
                "retain_days": self.config.policy.retain_days,
                "raw_evidence_mode": self.config.policy.raw_evidence_mode.value,
            },
            "last_error": self.last_error,
            "stop_requested": bool(stop_requested),
            "resumable": resumable,
            "started_at": self.started_at.isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })

    @classmethod
    async def resume(cls, session_id: str, db_path: str = "./basilisk-sessions.db") -> ScanSession:
        """Resume an interrupted scan session from the database."""
        from basilisk.core.config import BasiliskConfig

        db = BasiliskDatabase(db_path)
        await db.connect()
        session_data = await db.get_session(session_id)
        if not session_data:
            await db.close()
            raise ValueError(f"Session not found: {session_id}")

        config = BasiliskConfig.from_dict(session_data.get("config", {}))
        session = cls(config, session_id=session_id)
        session.status = session_data.get("status", "resumed")
        session.current_phase = session.status
        if session_data.get("started_at"):
            session.started_at = datetime.fromisoformat(session_data["started_at"])
        if session_data.get("finished_at"):
            session.finished_at = datetime.fromisoformat(session_data["finished_at"])

        if session_data.get("profile"):
            session.profile = BasiliskProfile.from_dict(session_data["profile"])

        findings_data = await db.get_findings(session_id)
        for fd in findings_data:
            session.findings.append(Finding.from_dict(fd))

        if session_data.get("summary") and "errors" in session_data["summary"]:
            session.errors = session_data["summary"]["errors"]
        if session_data.get("summary") and "attack_memory" in session_data["summary"]:
            session.attack_memory = session_data["summary"]["attack_memory"]
        if session_data.get("summary") and "phase_history" in session_data["summary"]:
            session.phase_history = session_data["summary"]["phase_history"]
        if session.phase_history:
            session.current_phase = session.phase_history[-1].get("phase", session.current_phase)

        await db.close()

        return session

    def completed_modules(self) -> set[str]:
        """Return the set of attack modules already completed in this session."""
        completed = self.attack_memory.get("completed_modules", [])
        return {str(item) for item in completed if item}

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
            "schema_version": SCHEMA_VERSION_LABEL,
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
            "campaign": self.config.campaign.to_summary(),
            "policy": {
                "execution_mode": self.config.policy.execution_mode.value,
                "aggression": self.config.policy.aggression,
                "evidence_threshold": self.config.policy.evidence_threshold.value,
                "dry_run": self.config.policy.dry_run,
                "approval_required": self.config.policy.approval_required,
                "raw_evidence_mode": self.config.policy.raw_evidence_mode.value,
                "retain_raw_findings": self.config.policy.retain_raw_findings,
                "retain_conversations": self.config.policy.retain_conversations,
                "retain_days": self.config.policy.retain_days,
            },
            "attack_memory": self.attack_memory,
            "phase_history": self.phase_history,
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
