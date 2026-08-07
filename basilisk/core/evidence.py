"""
Basilisk Evidence — structured proof objects for findings.

The v2.0 goal is to separate "interesting behavior" from
"defensible evidence" so findings can be calibrated and replayed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from basilisk.core.redaction import sanitize_mapping, sanitize_value


class EvidenceVerdict(str, Enum):
    """How strong the captured proof is for a finding."""

    CONFIRMED = "confirmed"
    STRONG = "strong"
    PROBABLE = "probable"
    WEAK = "weak"
    UNVERIFIED = "unverified"


class EvidenceSignalKind(str, Enum):
    """Structured signal types used to calibrate findings."""

    BASELINE_DIFFERENTIAL = "baseline_differential"
    TOOL_CALL = "tool_call"
    RESPONSE_MARKER = "response_marker"
    CONVERSATION_TRACE = "conversation_trace"
    PROVIDER_METADATA = "provider_metadata"
    PAYLOAD_MATCH = "payload_match"


@dataclass
class EvidenceSignal:
    """Single piece of evidence used to support or weaken a finding."""

    name: str
    kind: EvidenceSignalKind = EvidenceSignalKind.RESPONSE_MARKER
    passed: bool = False
    weight: float = 1.0
    summary: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind.value,
            "passed": self.passed,
            "weight": self.weight,
            "summary": self.summary,
            "details": self.details,
        }

    def sanitized_dict(self, *, include_raw: bool = False, max_chars: int = 160) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind.value,
            "passed": self.passed,
            "weight": self.weight,
            "summary": _sanitize_value(self.summary, include_raw=include_raw, max_chars=max_chars),
            "details": _sanitize_mapping(self.details, include_raw=include_raw, max_chars=max_chars),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvidenceSignal":
        return cls(
            name=data["name"],
            kind=EvidenceSignalKind(data.get("kind", EvidenceSignalKind.RESPONSE_MARKER.value)),
            passed=bool(data.get("passed", False)),
            weight=float(data.get("weight", 1.0)),
            summary=data.get("summary", ""),
            details=data.get("details", {}),
        )


@dataclass
class EvidenceBundle:
    """Collection of proof signals and replay data for a finding."""

    verdict: EvidenceVerdict = EvidenceVerdict.UNVERIFIED
    confidence_score: float = 0.0
    confidence_basis: str = "heuristic"
    replay_steps: list[str] = field(default_factory=list)
    signals: list[EvidenceSignal] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "confidence_score": round(self.confidence_score, 3),
            "confidence_basis": self.confidence_basis,
            "replay_steps": self.replay_steps,
            "signals": [signal.to_dict() for signal in self.signals],
            "artifacts": self.artifacts,
            "notes": self.notes,
        }

    def sanitized_dict(self, *, include_raw: bool = False, max_chars: int = 160) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "confidence_score": round(self.confidence_score, 3),
            "confidence_basis": self.confidence_basis,
            "replay_steps": [
                _sanitize_value(step, include_raw=include_raw, max_chars=max_chars)
                for step in self.replay_steps
            ],
            "signals": [
                signal.sanitized_dict(include_raw=include_raw, max_chars=max_chars)
                for signal in self.signals
            ],
            "artifacts": _sanitize_mapping(self.artifacts, include_raw=include_raw, max_chars=max_chars),
            "notes": [
                _sanitize_value(note, include_raw=include_raw, max_chars=max_chars)
                for note in self.notes
            ],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvidenceBundle":
        return cls(
            verdict=EvidenceVerdict(data.get("verdict", EvidenceVerdict.UNVERIFIED.value)),
            confidence_score=float(data.get("confidence_score", 0.0)),
            confidence_basis=data.get("confidence_basis", "heuristic"),
            replay_steps=list(data.get("replay_steps", [])),
            signals=[EvidenceSignal.from_dict(item) for item in data.get("signals", [])],
            artifacts=data.get("artifacts", {}),
            notes=list(data.get("notes", [])),
        )


def build_evidence_bundle(
    *,
    signals: list[EvidenceSignal] | None = None,
    confidence_basis: str = "heuristic",
    replay_steps: list[str] | None = None,
    artifacts: dict[str, Any] | None = None,
    notes: list[str] | None = None,
) -> EvidenceBundle:
    """
    Build a calibrated evidence bundle from weighted signals.

    The bundle score is intentionally conservative. Heuristic-only findings
    should not look as strong as findings backed by tool-call proof or a
    baseline-vs-attack behavioral shift.
    """

    items = list(signals or [])
    weighted_total = sum(max(signal.weight, 0.0) for signal in items)
    weighted_passed = sum(max(signal.weight, 0.0) for signal in items if signal.passed)
    score = (weighted_passed / weighted_total) if weighted_total else 0.0
    passed_kinds = {signal.kind for signal in items if signal.passed}
    passed_count = sum(1 for signal in items if signal.passed)

    if score >= 0.9 and len(passed_kinds) >= 2:
        verdict = EvidenceVerdict.CONFIRMED
    elif (
        EvidenceSignalKind.TOOL_CALL in passed_kinds
        or EvidenceSignalKind.BASELINE_DIFFERENTIAL in passed_kinds
        or (score >= 0.7 and len(passed_kinds) >= 2)
    ):
        verdict = EvidenceVerdict.STRONG
    elif score >= 0.5 or passed_count >= 2:
        verdict = EvidenceVerdict.PROBABLE
    elif score > 0:
        verdict = EvidenceVerdict.WEAK
    else:
        verdict = EvidenceVerdict.UNVERIFIED

    return EvidenceBundle(
        verdict=verdict,
        confidence_score=round(score, 3),
        confidence_basis=confidence_basis,
        replay_steps=list(replay_steps or []),
        signals=items,
        artifacts=artifacts or {},
        notes=list(notes or []),
    )


def calibrate_confidence(claimed_confidence: float, evidence: EvidenceBundle | None) -> float:
    """Calibrate a claimed finding confidence against the captured evidence."""

    claimed = min(max(claimed_confidence, 0.0), 1.0)
    if evidence is None:
        return round(claimed, 3)

    evidence_score = min(max(evidence.confidence_score, 0.0), 1.0)
    if evidence.verdict == EvidenceVerdict.CONFIRMED:
        return round(min(max(claimed, evidence_score), 0.99), 3)
    if evidence.verdict == EvidenceVerdict.STRONG:
        return round(min(max(claimed * 0.95, evidence_score), 0.94), 3)
    if evidence.verdict == EvidenceVerdict.PROBABLE:
        return round(min(max(evidence_score, 0.45), claimed, 0.79), 3)
    if evidence.verdict == EvidenceVerdict.WEAK:
        return round(min(claimed, max(evidence_score, 0.35)), 3)
    return round(min(claimed, 0.25), 3)


def _sanitize_mapping(values: dict[str, Any], *, include_raw: bool, max_chars: int) -> dict[str, Any]:
    return sanitize_mapping(values, include_raw=include_raw, redact_all_strings=True)


def _sanitize_sequence(values: list[Any], *, include_raw: bool, max_chars: int) -> list[Any]:
    return [_sanitize_value(value, include_raw=include_raw, max_chars=max_chars) for value in values]


def _sanitize_value(value: Any, *, include_raw: bool, max_chars: int) -> Any:
    return sanitize_value(value, include_raw=include_raw, redact_all_strings=True)
