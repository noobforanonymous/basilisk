"""
Basilisk Report Generator — multi-format vulnerability reporting.

Orchestrates report generation across HTML, JSON, SARIF, Markdown,
and PDF formats. Each format has its own module for detailed rendering.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from basilisk import __version__
from basilisk.core.config import OutputConfig
from basilisk.core.retention import prune_artifact_dir
from basilisk.core.schema import SCHEMA_VERSION_LABEL
from basilisk.core.session import ScanSession


async def generate_report(session: ScanSession, output_config: OutputConfig) -> str:
    """Generate a report in the configured format."""
    output_dir = Path(output_config.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    prune_artifact_dir(output_dir, retain_days=session.config.policy.retain_days)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base_name = f"basilisk_{session.id}_{timestamp}"
    include_raw = output_config.include_raw_content
    include_conversations = output_config.include_conversations and include_raw

    fmt = output_config.format.lower()
    if fmt == "json":
        path = output_dir / f"{base_name}.json"
        _write_json_report(session, path, include_raw=include_raw, include_conversations=include_conversations)
    elif fmt == "sarif":
        path = output_dir / f"{base_name}.sarif"
        from basilisk.report.sarif import generate_sarif
        generate_sarif(session, path, include_raw_content=include_raw, include_conversations=include_conversations)
    elif fmt == "markdown":
        path = output_dir / f"{base_name}.md"
        _write_markdown_report(session, path, include_raw=include_raw, include_conversations=include_conversations)
    elif fmt == "pdf":
        path = output_dir / f"{base_name}.pdf"
        from basilisk.report.pdf import generate_pdf
        generate_pdf(session, path, include_raw_content=include_raw, include_conversations=include_conversations)
    elif fmt == "html":
        path = output_dir / f"{base_name}.html"
        from basilisk.report.html import generate_html
        generate_html(session, path, include_raw_content=include_raw, include_conversations=include_conversations)
    else:
        raise ValueError(f"Unsupported report format: {output_config.format!r}")

    return str(path)


def _write_json_report(
    session: ScanSession,
    path: Path,
    *,
    include_raw: bool = False,
    include_conversations: bool = False,
) -> None:
    """Write a JSON report."""
    report = {
        "schema_version": SCHEMA_VERSION_LABEL,
        "basilisk_version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "session": session.summary,
        "profile": session.profile.to_dict(),
        "campaign": session.config.campaign.to_summary(),
        "retention": {
            "retain_days": session.config.policy.retain_days,
            "raw_evidence_mode": session.config.policy.raw_evidence_mode.value,
        },
        "findings": [
            finding.sanitized_dict(
                include_payload=include_raw,
                include_response=include_raw,
                include_conversation=include_conversations,
            )
            for finding in session.findings
        ],
    }
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, default=str)


def _write_markdown_report(
    session: ScanSession,
    path: Path,
    *,
    include_raw: bool = False,
    include_conversations: bool = False,
) -> None:
    """Write a Markdown report."""
    lines = [
        "# 🐍 Basilisk Scan Report",
        "",
        f"**Schema Version:** `{SCHEMA_VERSION_LABEL}`",
        f"**Session:** `{session.id}`",
        f"**Target:** `{session.config.target.url}`",
        f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Mode:** {session.config.mode.value}",
        f"**Execution Mode:** {session.config.policy.execution_mode.value}",
        f"**Model:** {session.profile.detected_model}",
        f"**Total Findings:** {len(session.findings)}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]

    summary = session.summary
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = summary["severity_counts"].get(sev, 0)
        lines.append(f"| {sev.upper()} | {count} |")

    lines.extend(["", "## Target Profile", ""])
    for line in session.profile.summary_lines():
        lines.append(f"- {line}")

    lines.extend(["", "## Campaign", ""])
    campaign = session.config.campaign.to_summary()
    lines.append(f"- Name: {campaign.get('name') or '—'}")
    lines.append(f"- Operator: {campaign.get('authorization', {}).get('operator') or '—'}")
    lines.append(f"- Ticket: {campaign.get('authorization', {}).get('ticket_id') or '—'}")
    lines.append(f"- Objective: {campaign.get('objective', {}).get('name') or '—'}")
    lines.append(f"- Retention: {session.config.policy.retain_days} days")
    lines.append(f"- Evidence Mode: {session.config.policy.raw_evidence_mode.value}")

    lines.extend(["", "## Findings", ""])

    for finding in sorted(session.findings, key=lambda item: item.severity.numeric, reverse=True):
        finding_data = finding.to_dict()
        lines.extend([
            f"### {finding.severity.icon} [{finding.severity.value.upper()}] {finding.title}",
            "",
            f"**ID:** `{finding.id}`",
            f"**Category:** {finding.category.value} ({finding.category.owasp_id})",
            f"**Module:** `{finding.attack_module}`",
            f"**Module Tier:** {finding_data['module_trust_tier']}",
            f"**Confidence:** {finding.confidence:.0%}",
            "",
            "**Payload:**",
            "```",
            f"{finding.payload if include_raw else '[redacted in report output]'}",
            "```",
            "",
            "**Response:**",
            "```",
            f"{finding.response[:500] if include_raw else '[redacted in report output]'}",
            "```",
            "",
            f"**Evidence Verdict:** {(finding.evidence.verdict.value if finding.evidence else 'unverified').upper()}",
            f"**Evidence Basis:** {finding.evidence.confidence_basis if finding.evidence else 'heuristic'}",
            f"**Remediation:** {finding.remediation}",
            "",
        ])
        if finding_data["module_success_criteria"]:
            lines.append("**Success Criteria:**")
            lines.append("")
            for criterion in finding_data["module_success_criteria"]:
                lines.append(f"- {criterion}")
            lines.append("")
        if finding_data["module_evidence_requirements"]:
            lines.append("**Required Proof:**")
            lines.append("")
            for requirement in finding_data["module_evidence_requirements"]:
                lines.append(f"- `{requirement}`")
            lines.append("")
        if finding_data["policy_downgraded"]:
            lines.append(
                f"**Policy Downgrade:** original={finding.metadata.get('original_severity', 'unknown')} "
                f"missing={', '.join(finding.metadata.get('missing_evidence_requirements', [])) or 'n/a'}"
            )
            lines.append("")
        if include_conversations and finding.conversation:
            lines.extend(["**Conversation:**", ""])
            for msg in finding.conversation:
                lines.append(f"> **{msg.role}:** {msg.content[:300]}")
            lines.append("")

        lines.extend(["---", ""])

    lines.extend([
        "",
        "---",
        f"*Generated by Basilisk v{__version__} — AI Red Teaming Framework | [Rot Hackers](https://rothackers.com)*",
    ])

    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines))
