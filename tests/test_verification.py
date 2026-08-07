"""Candidate reproduction and false-positive control tests."""

from __future__ import annotations

from basilisk.core.evidence import (
    EvidenceSignal,
    EvidenceSignalKind,
    build_evidence_bundle,
)
from basilisk.core.finding import Finding, FindingValidationLevel
from basilisk.core.verification import stable_response_fingerprint, verify_candidate

from conftest import MockProvider


def _candidate(response: str = "PROOF_MARKER") -> Finding:
    evidence = build_evidence_bundle(
        signals=[
            EvidenceSignal(
                name="reproduced marker",
                kind=EvidenceSignalKind.RESPONSE_MARKER,
                passed=True,
                weight=1.0,
                details={"matched_markers": ["PROOF_MARKER"]},
            ),
            EvidenceSignal(
                name="baseline differs",
                kind=EvidenceSignalKind.BASELINE_DIFFERENTIAL,
                passed=True,
                weight=1.0,
            ),
        ],
        confidence_basis="deterministic-test",
    )
    return Finding(
        attack_module="injection.direct",
        payload="repeat the proof marker",
        response=response,
        evidence=evidence,
        validation_level=FindingValidationLevel.CANDIDATE,
    )


async def test_candidate_is_verified_only_after_two_of_three_successes_and_clean_control():
    provider = MockProvider([
        "PROOF_MARKER replay one",
        "PROOF_MARKER replay two",
        "BENIGN_CONTROL_OK",
    ])
    finding = await verify_candidate(provider, _candidate())

    assert finding.validation_level == FindingValidationLevel.VERIFIED
    assert finding.success_count == 3
    assert finding.attempt_count == 3
    assert finding.negative_control_passed is True
    assert finding.metadata["verification"]["errors"] == []


async def test_non_reproducible_candidate_is_not_promoted():
    provider = MockProvider(["no marker", "still no marker", "BENIGN_CONTROL_OK"])
    finding = await verify_candidate(provider, _candidate())

    assert finding.validation_level == FindingValidationLevel.CANDIDATE
    assert finding.success_count == 1
    assert finding.negative_control_passed is True


def test_response_fingerprint_normalizes_dynamic_timestamps_and_ids():
    left = "event 2026-07-29T12:00:01Z id 9ea744f0-bad6-4a85-a170-edc048b0a3d9"
    right = "event 2026-07-30T13:22:33Z id f83ae682-acd6-46b1-ac4f-72074b8d57bd"
    assert stable_response_fingerprint(left) == stable_response_fingerprint(right)

