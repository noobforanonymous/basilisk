"""
Basilisk CLI — Replay command implementation.

Loads a previous scan session from the SQLite database and displays
the full findings table, conversation transcripts, and evolution data
for post-scan analysis and reporting.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.syntax import Syntax

from basilisk import BANNER
from basilisk.core.finding import Severity
from basilisk.core.session import ScanSession
from basilisk.report.generator import generate_report

console = Console()


async def replay_session(
    session_id: str,
    db_path: str = "./basilisk-sessions.db",
    finding_id: str = "",
    export_format: str = "",
) -> None:
    """Replay a previous scan session with findings and conversations."""
    try:
        session = await ScanSession.resume(session_id, db_path)
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        return

    console.print(Panel(
        f"[bold]Session:[/bold] {session.id}\n"
        f"[bold]Target:[/bold] {session.config.target.url}\n"
        f"[bold]Provider:[/bold] {session.config.target.provider}\n"
        f"[bold]Mode:[/bold] {session.config.mode.value}\n"
        f"[bold]Findings:[/bold] {len(session.findings)}\n"
        f"[bold]Status:[/bold] {session.status}",
        title="📼 Session Replay",
        border_style="cyan",
    ))

    if finding_id:
        # Show a specific finding
        _show_finding_detail(session, finding_id)
    else:
        # Show all findings
        _print_findings_table(session)

    # Export if requested
    if export_format:
        session.config.output.format = export_format
        path = await generate_report(session, session.config.output)
        console.print(f"\n[green]✓[/green] Report exported: {path}")


async def list_sessions(db_path: str = "./basilisk-sessions.db") -> None:
    """List all saved scan sessions."""
    from basilisk.core.database import BasiliskDatabase

    db = BasiliskDatabase(db_path)
    await db.connect()

    sessions = await db.list_sessions()
    if not sessions:
        console.print("[dim]No sessions found.[/dim]")
        await db.close()
        return

    table = Table(title="Saved Sessions", show_lines=True)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Target", style="white")
    table.add_column("Status", style="green")
    table.add_column("Findings", style="yellow")
    table.add_column("Date", style="dim")

    for s in sessions:
        findings_count = s.get("total_findings", s.get("summary", {}).get("total_findings", "?"))
        date_str = s.get("started_at", "")[:19] if s.get("started_at") else "?"
        table.add_row(
            str(s.get("id", "?")),
            str(s.get("target_url", "?"))[:50],
            str(s.get("status", "?")),
            str(findings_count),
            date_str,
        )

    console.print(table)
    await db.close()


def _print_findings_table(session: ScanSession) -> None:
    """Print all findings in a sortable table."""
    if not session.findings:
        console.print("[dim]No findings in this session.[/dim]")
        return

    table = Table(title="Findings", show_lines=True)
    table.add_column("ID", style="dim", no_wrap=True)
    table.add_column("Sev", style="bold")
    table.add_column("OWASP")
    table.add_column("Module", style="dim")
    table.add_column("Title")
    table.add_column("Conf", style="dim")

    for f in sorted(session.findings, key=lambda x: x.severity.numeric, reverse=True):
        table.add_row(
            f.id,
            Text(f.severity.value.upper(), style=f.severity.color),
            f.category.owasp_id,
            f.attack_module.split(".")[-1] if "." in f.attack_module else f.attack_module,
            f.title,
            f"{f.confidence:.0%}",
        )
    console.print(table)

    # Severity summary
    console.print()
    severity_counts = {}
    for f in session.findings:
        severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1
    for sev_name in ["critical", "high", "medium", "low", "info"]:
        count = severity_counts.get(sev_name, 0)
        if count > 0:
            sev = Severity(sev_name)
            console.print(f"  {sev.icon} {sev_name.upper()}: {count}")
    console.print(f"\n  [bold]Total:[/bold] {len(session.findings)} findings")


def _show_finding_detail(session: ScanSession, finding_id: str) -> None:
    """Show detailed view of a single finding."""
    finding = None
    for f in session.findings:
        if f.id == finding_id or finding_id in f.id:
            finding = f
            break

    if not finding:
        console.print(f"[red]Finding not found: {finding_id}[/red]")
        console.print("[dim]Available IDs:[/dim]")
        for f in session.findings:
            console.print(f"  {f.id}: {f.title}")
        return

    console.print(Panel(
        f"[bold]ID:[/bold] {finding.id}\n"
        f"[bold]Title:[/bold] {finding.title}\n"
        f"[bold]Severity:[/bold] [{finding.severity.color}]{finding.severity.value.upper()}[/{finding.severity.color}]\n"
        f"[bold]Category:[/bold] {finding.category.value} ({finding.category.owasp_id})\n"
        f"[bold]Module:[/bold] {finding.attack_module}\n"
        f"[bold]Confidence:[/bold] {finding.confidence:.0%}\n"
        f"[bold]Evolution Gen:[/bold] {finding.evolution_generation or 'N/A'}",
        title=f"{finding.severity.icon} Finding Detail",
        border_style=finding.severity.color,
    ))

    if finding.payload:
        console.print("\n[bold]Payload:[/bold]")
        console.print(Panel(finding.payload[:1000], border_style="red"))

    if finding.response:
        console.print("\n[bold]Response:[/bold]")
        console.print(Panel(finding.response[:1000], border_style="green"))

    if finding.conversation:
        console.print("\n[bold]Conversation Replay:[/bold]")
        for msg in finding.conversation:
            role_style = "cyan" if msg.role == "user" else "green"
            console.print(f"  [{role_style}]{msg.role}:[/{role_style}] {msg.content[:300]}")

    if finding.remediation:
        console.print(f"\n[bold]Remediation:[/bold] {finding.remediation}")

    if finding.references:
        console.print("\n[bold]References:[/bold]")
        for ref in finding.references:
            console.print(f"  • {ref}")
