"""
Basilisk SARIF 2.1.0 Report Generator.

Generates Static Analysis Results Interchange Format (SARIF) reports
for CI/CD integration (GitHub Security tab, GitLab SAST, Azure DevOps).

SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from basilisk.core.session import ScanSession


def generate_sarif(session: ScanSession, path: Path) -> None:
    """Generate a SARIF 2.1.0 compliant report."""
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    seen_rules: set[str] = set()

    for finding in session.findings:
        rule_id = _to_rule_id(finding.attack_module)

        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": _sanitize(finding.title),
                "shortDescription": {"text": _sanitize(finding.description or finding.title)},
                "fullDescription": {"text": _sanitize(finding.remediation or finding.description or finding.title)},
                "defaultConfiguration": {
                    "level": _sarif_level(finding.severity.value),
                },
                "helpUri": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                "properties": {
                    "category": finding.category.value,
                    "owasp_id": finding.category.owasp_id,
                    "tags": ["security", "ai", "llm", finding.category.owasp_id],
                },
            })

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": list(seen_rules).index(rule_id),
            "level": _sarif_level(finding.severity.value),
            "message": {
                "text": (
                    f"{_sanitize(finding.title)}\n\n"
                    f"Severity: {finding.severity.value.upper()}\n"
                    f"Confidence: {finding.confidence:.0%}\n"
                    f"OWASP: {finding.category.owasp_id}\n\n"
                    f"Payload:\n{_sanitize(finding.payload[:500])}"
                ),
            },
            "properties": {
                "finding_id": finding.id,
                "confidence": finding.confidence,
                "severity": finding.severity.value,
                "attack_module": finding.attack_module,
                "remediation": finding.remediation,
                "evolution_generation": finding.evolution_generation,
            },
        }

        # Add fingerprints for deduplication
        result["fingerprints"] = {
            "basilisk/v1": f"{finding.attack_module}:{finding.title}",
        }

        # Partial results — if payload/response are in conversation
        if finding.conversation:
            result["codeFlows"] = [{
                "message": {"text": "Attack conversation flow"},
                "threadFlows": [{
                    "locations": [
                        {
                            "location": {
                                "message": {"text": f"[{msg.role}] {_sanitize(msg.content[:200])}"},
                            },
                        }
                        for msg in finding.conversation[:10]
                    ],
                }],
            }]

        results.append(result)

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Basilisk",
                    "version": "0.1.0",
                    "semanticVersion": "0.1.0",
                    "informationUri": "https://basilisk.rothackers.com",
                    "organization": "Rot Hackers",
                    "rules": rules,
                },
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": session.started_at.isoformat() + "Z" if not session.started_at.tzinfo else session.started_at.isoformat(),
                "endTimeUtc": (session.finished_at or datetime.now(timezone.utc)).isoformat(),
                "toolExecutionNotifications": [],
            }],
            "properties": {
                "session_id": session.id,
                "target": session.config.target.url,
                "mode": session.config.mode.value,
                "model": session.profile.detected_model,
            },
        }],
    }

    with open(path, "w") as f:
        json.dump(sarif_doc, f, indent=2, default=str)


def _sarif_level(severity: str) -> str:
    """Map Basilisk severity to SARIF level."""
    return {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "none",
    }.get(severity, "note")


def _to_rule_id(attack_module: str) -> str:
    """Convert module path to SARIF rule ID."""
    return attack_module.replace("basilisk.attacks.", "BSLK/").replace(".", "/")


def _sanitize(text: str) -> str:
    """Sanitize text for JSON embedding."""
    if not text:
        return ""
    return text.replace("\x00", "")
