"""
Basilisk CLI — Main entry point with click + rich.

Commands:
  basilisk scan      — Run a full scan against a target
  basilisk recon     — Reconnaissance only
  basilisk replay    — Replay a previous session
  basilisk modules   — List available attack modules
  basilisk version   — Show version
"""

from __future__ import annotations

import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from basilisk import BANNER, __version__

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="basilisk")
def cli() -> None:
    """🐍 Basilisk — LLM/AI Red Teaming Framework"""
    pass


@cli.command("scan")
@click.option("-t", "--target", required=True, help="Target URL or API endpoint")
@click.option("-p", "--provider", default="openai", help="LLM provider (openai, anthropic, google, azure, ollama, custom)")
@click.option("-m", "--model", default="", help="Model name override")
@click.option("-k", "--api-key", default="", help="API key (or use env vars)")
@click.option("--auth", default="", help="Authorization header value")
@click.option("--mode", default="standard", type=click.Choice(["quick", "standard", "deep", "stealth", "chaos"]))
@click.option("--evolve/--no-evolve", default=True, help="Enable/disable evolution engine")
@click.option("--generations", default=5, help="Number of evolution generations")
@click.option("--module", multiple=True, help="Specific attack modules to run (default: all)")
@click.option("-o", "--output", default="html", type=click.Choice(["html", "json", "sarif", "markdown", "pdf"]))
@click.option("--output-dir", default="./basilisk-reports", help="Report output directory")
@click.option("--no-dashboard", is_flag=True, help="Disable web dashboard")
@click.option("--fail-on", default="high", type=click.Choice(["critical", "high", "medium", "low", "info"]))
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.option("--debug", is_flag=True, help="Debug mode")
@click.option("-c", "--config", default="", help="YAML config file path")
def scan(target, provider, model, api_key, auth, mode, evolve, generations, module, output, output_dir, no_dashboard, fail_on, verbose, debug, config) -> None:
    """Run a full red team scan against an AI target."""
    import asyncio

    console.print(BANNER, style="bold red")
    console.print()

    from basilisk.cli.scan import run_scan

    asyncio.run(run_scan(
        target=target, provider=provider, model=model, api_key=api_key,
        auth=auth, mode=mode, evolve=evolve, generations=generations,
        modules=list(module), output_format=output, output_dir=output_dir,
        no_dashboard=no_dashboard, fail_on=fail_on, verbose=verbose,
        debug=debug, config=config,
    ))


@cli.command("recon")
@click.option("-t", "--target", required=True, help="Target URL or API endpoint")
@click.option("-p", "--provider", default="openai", help="LLM provider")
@click.option("-k", "--api-key", default="", help="API key")
@click.option("--auth", default="", help="Authorization header")
@click.option("-v", "--verbose", is_flag=True)
def recon(target, provider, api_key, auth, verbose) -> None:
    """Run reconnaissance only — fingerprint the target AI system."""
    import asyncio

    console.print(BANNER, style="bold red")
    console.print()

    from basilisk.cli.scan import run_recon

    asyncio.run(run_recon(
        target=target, provider=provider, api_key=api_key,
        auth=auth, verbose=verbose,
    ))


@cli.command("replay")
@click.argument("session_id")
@click.option("--db", default="./basilisk-sessions.db", help="Session database path")
def replay(session_id, db) -> None:
    """Replay a previous scan session."""
    import asyncio

    console.print(BANNER, style="bold red")
    console.print()

    from basilisk.cli.scan import replay_session

    asyncio.run(replay_session(session_id=session_id, db_path=db))


@cli.command("modules")
def list_modules() -> None:
    """List all available attack modules."""
    console.print(BANNER, style="bold red")
    console.print()

    from rich.table import Table
    from basilisk.attacks.base import get_all_attack_modules

    table = Table(title="Basilisk Attack Modules", show_lines=True)
    table.add_column("Module", style="cyan", no_wrap=True)
    table.add_column("Category", style="green")
    table.add_column("Severity", style="yellow")
    table.add_column("Description")

    try:
        modules = get_all_attack_modules()
        for mod in modules:
            table.add_row(
                mod.name,
                f"{mod.category.value} ({mod.category.owasp_id})",
                mod.severity_default.value,
                mod.description,
            )
        console.print(table)
        console.print(f"\n[bold]{len(modules)}[/bold] modules available.")
    except Exception as e:
        console.print(f"[red]Error loading modules: {e}[/red]")


@cli.command("interactive")
@click.option("-t", "--target", required=True, help="Target URL or API endpoint")
@click.option("-p", "--provider", default="openai", help="LLM provider")
@click.option("-m", "--model", default="", help="Model name")
@click.option("-k", "--api-key", default="", help="API key")
@click.option("--auth", default="", help="Authorization header")
@click.option("-v", "--verbose", is_flag=True)
def interactive(target, provider, model, api_key, auth, verbose) -> None:
    """Launch interactive REPL for manual + assisted red teaming."""
    import asyncio

    console.print(BANNER, style="bold red")
    console.print()

    from basilisk.cli.interactive import run_interactive

    asyncio.run(run_interactive(
        target=target, provider=provider, model=model,
        api_key=api_key, auth=auth, verbose=verbose,
    ))


@cli.command("sessions")
@click.option("--db", default="./basilisk-sessions.db", help="Session database path")
def sessions(db) -> None:
    """List all saved scan sessions."""
    import asyncio

    console.print(BANNER, style="bold red")
    console.print()

    from basilisk.cli.replay import list_sessions

    asyncio.run(list_sessions(db_path=db))


@cli.command("version")
def version() -> None:
    """Show Basilisk version and system info."""
    console.print(BANNER, style="bold red")
    console.print(f"[bold]Version:[/bold] {__version__}")
    console.print(f"[bold]Python:[/bold] {sys.version}")
    console.print(f"[bold]Platform:[/bold] {sys.platform}")


def main() -> None:
    """Entrypoint for the basilisk CLI."""
    cli()


if __name__ == "__main__":
    main()
