"""
Basilisk CLI Utilities — Shared rendering and UI helpers.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from basilisk.core.session import ScanSession
from basilisk.core.finding import Severity

console = Console()


def print_profile(session: ScanSession) -> None:
    """Print the recon profile in a structured table."""
    table = Table(title="Target Profile", show_lines=True)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")
    for line in session.profile.summary_lines():
        parts = line.split(": ", 1)
        if len(parts) == 2:
            table.add_row(parts[0], parts[1])
    console.print(table)


def print_findings_table(session: ScanSession) -> None:
    """Print all findings in a formatted table with severity color coding."""
    table = Table(title="Findings", show_lines=True)
    table.add_column("ID", style="dim")
    table.add_column("Severity", style="bold")
    table.add_column("Category")
    table.add_column("Title")

    for f in sorted(session.findings, key=lambda x: x.severity.numeric, reverse=True):
        table.add_row(
            f.id,
            Text(f.severity.value.upper(), style=f.severity.color),
            f.category.owasp_id,
            f.title,
        )
    console.print(table)
    console.print(f"\n[bold]Total:[/bold] {len(session.findings)} findings")

    severity_summary = {}
    for f in session.findings:
        severity_summary[f.severity.value] = severity_summary.get(f.severity.value, 0) + 1
    
    for sev in Severity:
        count = severity_summary.get(sev.value, 0)
        if count > 0:
            console.print(f"  {sev.icon} {sev.value.upper()}: {count}")


def print_summary(session: ScanSession) -> None:
    """Print the final scan summary panel."""
    summary = session.summary
    console.print(Panel(
        f"[bold]Total Findings:[/bold] {summary['total_findings']}\n"
        f"[bold]Critical:[/bold] {summary['severity_counts'].get('critical', 0)} | "
        f"[bold]High:[/bold] {summary['severity_counts'].get('high', 0)} | "
        f"[bold]Medium:[/bold] {summary['severity_counts'].get('medium', 0)} | "
        f"[bold]Low:[/bold] {summary['severity_counts'].get('low', 0)}\n"
        f"[bold]Exit Code:[/bold] {session.exit_code}",
        title=f"{'🔴' if session.exit_code else '🟢'} Scan Complete",
        border_style="red" if session.exit_code else "green",
    ))
