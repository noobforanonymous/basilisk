"""
Basilisk Scan — orchestrates the full scan pipeline.

Pipeline: Config → Provider → Recon → Attacks (+Evolution) → Report
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.text import Text

from basilisk.core.config import BasiliskConfig
from basilisk.core.finding import Severity
from basilisk.core.session import ScanSession
from basilisk.core.audit import AuditLogger
from basilisk.providers.base import ProviderMessage
from basilisk.providers.litellm_adapter import LiteLLMAdapter
from basilisk.providers.custom_http import CustomHTTPAdapter
from basilisk.providers.websocket import WebSocketAdapter

console = Console()
logger = logging.getLogger("basilisk")


async def run_scan(
    target: str,
    provider: str = "openai",
    model: str = "",
    api_key: str = "",
    auth: str = "",
    mode: str = "standard",
    evolve: bool = True,
    generations: int = 5,
    modules: list[str] | None = None,
    output_format: str = "html",
    output_dir: str = "./basilisk-reports",
    no_dashboard: bool = False,
    fail_on: str = "high",
    verbose: bool = False,
    debug: bool = False,
    config: str = "",
) -> int:
    """Main scan execution pipeline."""
    # Setup logging
    log_level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    logging.basicConfig(level=log_level, format="%(name)s | %(levelname)s | %(message)s")

    # Build config
    cfg = BasiliskConfig.from_cli_args(
        target=target, provider=provider, model=model, api_key=api_key,
        auth=auth, mode=mode, evolve=evolve, generations=generations,
        module=modules, output=output_format, output_dir=output_dir,
        no_dashboard=no_dashboard, fail_on=fail_on, verbose=verbose,
        debug=debug, config=config,
    )

    # Initialize audit logger (on by default)
    audit = AuditLogger(
        output_dir=output_dir,
        session_id=f"{target.split('/')[-1][:20]}",
    )
    audit.log_scan_config(cfg.to_dict())

    # Validate
    errors = cfg.validate()
    if errors:
        for err in errors:
            console.print(f"  [red]✗[/red] {err}")
        return 1

    # Create provider
    async with _create_provider(cfg) as prov:
        # Health check
        console.print("[dim]Checking provider connection...[/dim]")
        healthy = await prov.health_check()
        if not healthy:
            console.print("[red]✗ Provider health check failed. Check your API key and endpoint.[/red]")
            return 1
        console.print("[green]✓[/green] Provider connected\n")

        # Initialize session
        session = ScanSession(cfg)
        await session.initialize()
        console.print(Panel(
            f"[bold]Session:[/bold] {session.id}\n"
            f"[bold]Target:[/bold] {cfg.target.url}\n"
            f"[bold]Mode:[/bold] {cfg.mode.value}\n"
            f"[bold]Evolution:[/bold] {'Enabled' if cfg.evolution.enabled else 'Disabled'}",
            title="⚔️  Basilisk Scan Started",
            border_style="red",
            padding=(1, 2)
        ))

        # Phase 1: Recon
        console.print("\n[bold yellow]Phase 1: Reconnaissance[/bold yellow]")
        await _run_recon(prov, session)
        print_profile(session)

        # Phase 2: Attack
        console.print("\n[bold yellow]Phase 2: Attack Execution[/bold yellow]")
        from basilisk.attacks.base import get_all_attack_modules
        attack_modules = get_all_attack_modules()

        if modules:
            attack_modules = [m for m in attack_modules if m.name in modules or any(m.name.startswith(f) for f in modules)]

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}[/bold blue]"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Executing attack modules...", total=len(attack_modules))
            sem = asyncio.Semaphore(5)

            async def run_module(mod):
                async with sem:
                    try:
                        module_findings = await mod.execute(prov, session, session.profile)
                        for f in module_findings:
                            console.print(f"  {f.severity.icon} [{f.severity.color}]{f.severity.value.upper()}[/{f.severity.color}] {f.title}")
                            audit.log_finding(f.to_dict())
                    except Exception as e:
                        logger.error(f"Module {mod.name} failed: {e}")
                        await session.add_error(mod.name, str(e))
                        audit.log_error(mod.name, str(e))
                    finally:
                        progress.advance(task)

            await asyncio.gather(*(run_module(m) for m in attack_modules))

        # Phase 3: Evolution (if enabled and quick mode payloads available)
        if cfg.evolution.enabled and cfg.mode.value in ("standard", "deep", "chaos"):
            console.print("\n[bold yellow]Phase 3: Smart Prompt Evolution (SPE-NL)[/bold yellow]")
            await _run_evolution(prov, session, cfg)

        # Phase 4: Report
        console.print("\n[bold yellow]Phase 4: Report Generation[/bold yellow]")
        from basilisk.report.generator import generate_report
        report_path = await generate_report(session, cfg.output)
        console.print(f"  [green]✓[/green] Report saved to: {report_path}")
        audit.log_report_generated(cfg.output.format, report_path)

    # Summary
    await session.close()
    audit.close()
    from .utils import print_summary
    print_summary(session)
    if audit.log_path:
        console.print(f"  [dim]Audit log:[/dim] {audit.log_path}")

    return session.exit_code


async def run_recon(
    target: str,
    provider: str = "openai",
    api_key: str = "",
    auth: str = "",
    verbose: bool = False,
) -> None:
    """Run reconnaissance only."""
    cfg = BasiliskConfig.from_cli_args(
        target=target, provider=provider, api_key=api_key, auth=auth, verbose=verbose,
    )
    prov = _create_provider(cfg)
    session = ScanSession(cfg)
    await session.initialize()

    console.print("[bold yellow]Running Reconnaissance...[/bold yellow]\n")
    await _run_recon(prov, session)
    from .utils import print_profile
    print_profile(session)
    await session.close()


async def replay_session(session_id: str, db_path: str) -> None:
    """Replay a previous scan session."""
    try:
        session = await ScanSession.resume(session_id, db_path)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        return

    console.print(Panel(
        f"[bold]Session:[/bold] {session.id}\n"
        f"[bold]Target:[/bold] {session.config.target.url}\n"
        f"[bold]Findings:[/bold] {len(session.findings)}",
        title="📼 Session Replay",
        border_style="cyan",
    ))

    _print_findings_table(session)


def _create_provider(cfg: BasiliskConfig):
    """Create the appropriate provider adapter from config."""
    if cfg.target.provider == "custom":
        return CustomHTTPAdapter(
            base_url=cfg.target.url,
            auth_header=cfg.target.auth_header,
            custom_headers=cfg.target.custom_headers,
            timeout=cfg.target.timeout,
        )
    elif cfg.target.url.startswith("ws://") or cfg.target.url.startswith("wss://"):
        return WebSocketAdapter(
            ws_url=cfg.target.url,
            auth_header=cfg.target.auth_header,
            custom_headers=cfg.target.custom_headers,
            timeout=cfg.target.timeout,
        )
    else:
        return LiteLLMAdapter(
            api_key=cfg.target.resolve_api_key(),
            provider=cfg.target.provider,
            default_model=cfg.target.model,
            timeout=cfg.target.timeout,
            max_retries=cfg.target.max_retries,
            custom_headers=cfg.target.custom_headers or None,
        )


async def _run_recon(prov, session: ScanSession) -> None:
    """Execute all recon modules."""
    from basilisk.recon.fingerprint import fingerprint_model
    from basilisk.recon.guardrails import profile_guardrails
    from basilisk.recon.tools import discover_tools
    from basilisk.recon.context import measure_context_window
    from basilisk.recon.rag import detect_rag

    steps = [
        ("Model Fingerprinting", fingerprint_model),
        ("Context Window Detection", measure_context_window),
        ("Tool Discovery", discover_tools),
        ("Guardrail Profiling", profile_guardrails),
        ("RAG Detection", detect_rag),
    ]

    for name, func in steps:
        try:
            console.print(f"  [dim]→[/dim] {name}...", end="")
            await func(prov, session.profile)
            console.print(" [green]✓[/green]")
        except Exception as e:
            console.print(f" [red]✗ {e}[/red]")


async def _run_evolution(prov, session: ScanSession, cfg: BasiliskConfig) -> None:
    """Run the evolution engine on promising payloads."""
    from basilisk.evolution.engine import EvolutionEngine, EvolutionConfig
    from basilisk.evolution.fitness import AttackGoal

    # Seed from initial findings' payloads
    seed_payloads = [f.payload for f in session.findings if f.payload][:50]
    if not seed_payloads:
        from basilisk.attacks.injection.direct import PAYLOADS
        seed_payloads = PAYLOADS

    goal = AttackGoal(
        description="Bypass AI safety guardrails",
        success_keywords=["confirmed", "override", "injection", "compromised"],
        sensitive_patterns=[r"system\s*prompt", r"instructions:", r"you are\s+a"],
    )

    evo_config = EvolutionConfig(
        population_size=cfg.evolution.population_size,
        generations=cfg.evolution.generations,
        mutation_rate=cfg.evolution.mutation_rate,
        crossover_rate=cfg.evolution.crossover_rate,
        elite_count=cfg.evolution.elite_count,
        fitness_threshold=cfg.evolution.fitness_threshold,
        stagnation_limit=cfg.evolution.stagnation_limit,
    )

    async def on_gen(stats):
        gen = stats["generation"]
        best = stats.get("best_fitness", 0)
        avg = stats.get("avg_fitness", 0)
        bt = stats.get("breakthroughs", 0)
        console.print(f"  Gen {gen}: best={best:.3f} avg={avg:.3f} breakthroughs={bt}")

    async def on_bt(individual, gen):
        console.print(f"  🎯 [bold green]BREAKTHROUGH at Gen {gen}![/bold green] Fitness: {individual.fitness:.3f}")
        # Create a finding for the breakthrough
        from basilisk.core.finding import Finding, Severity, AttackCategory
        finding = Finding(
            title=f"Evolution Breakthrough — Gen {gen}",
            severity=Severity.HIGH,
            category=AttackCategory.PROMPT_INJECTION,
            attack_module="basilisk.evolution",
            payload=individual.payload,
            response=individual.response[:500] if individual.response else "",
            evolution_generation=gen,
            confidence=individual.fitness,
        )
        await session.add_finding(finding)

    engine = EvolutionEngine(prov, evo_config, on_generation=on_gen, on_breakthrough=on_bt)
    result = await engine.evolve(seed_payloads, goal)
    console.print(f"\n  Evolution complete: {result.total_generations} generations, {len(result.breakthroughs)} breakthroughs")
