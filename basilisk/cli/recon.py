"""
Basilisk CLI — Recon command implementation.

Thin wrapper around the core recon pipeline for standalone
reconnaissance execution. The heavy lifting is in cli/scan.py's
run_recon() function.
"""

from __future__ import annotations

import asyncio

from rich.console import Console
from rich.panel import Panel

from basilisk import BANNER
from basilisk.core.config import BasiliskConfig
from basilisk.core.session import ScanSession

console = Console()


async def run_recon_standalone(
    target: str,
    provider: str = "openai",
    api_key: str = "",
    auth: str = "",
    model: str = "",
    output: str = "",
    verbose: bool = False,
) -> None:
    """Execute standalone reconnaissance against a target AI system.

    This function performs model fingerprinting, guardrail profiling,
    tool discovery, context window measurement, and RAG detection
    without running any attacks.
    """
    cfg = BasiliskConfig.from_cli_args(
        target=target, provider=provider, api_key=api_key,
        auth=auth, model=model, verbose=verbose,
    )

    errors = cfg.validate()
    if errors:
        for err in errors:
            console.print(f"  [red]✗[/red] {err}")
        return

    from basilisk.cli.scan import _create_provider, _run_recon
    from .utils import print_profile
    async with _create_provider(cfg) as prov:
        # Health check
        console.print("[dim]Checking provider connection...[/dim]")
        healthy = await prov.health_check()
        if not healthy:
            console.print("[red]✗ Provider health check failed.[/red]")
            return
        console.print("[green]✓[/green] Provider connected\n")

        session = ScanSession(cfg)
        await session.initialize()

        console.print("[bold yellow]Phase 1: Reconnaissance[/bold yellow]\n")
        await _run_recon(prov, session)
        print_profile(session)

        # Optionally save profile
        if output:
            import json
            from pathlib import Path
            out_path = Path(output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w") as f:
                json.dump(session.profile.to_dict(), f, indent=2, default=str)
            console.print(f"\n[green]✓[/green] Profile saved to: {out_path}")

        await session.close()
