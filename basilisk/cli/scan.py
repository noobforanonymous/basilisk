"""
Basilisk Scan — orchestrates the full scan pipeline.

Pipeline: Config → Provider → Recon → Attacks (+Evolution) → Report
"""

from __future__ import annotations

import asyncio
import logging

from rich.console import Console
from rich.panel import Panel

from basilisk.core.audit import AuditLogger
from basilisk.core.config import BasiliskConfig
from basilisk.core.session import ScanSession
from basilisk.runtime import ScanHooks, create_provider, execute_scan, resolve_attack_modules, run_recon_phase

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
    module: list[str] | None = None,
    probe_id: list[str] | None = None,
    recon_module: list[str] | None = None,
    output_format: str = "html",
    output_dir: str = "./basilisk-reports",
    no_dashboard: bool = False,
    fail_on: str = "high",
    verbose: bool = False,
    debug: bool = False,
    skip_recon: bool = False,
    attacker_provider: str = "",
    attacker_model: str = "",
    attacker_api_key: str = "",
    exit_on_first: bool = False,
    diversity_mode: str = "novelty",
    intent_weight: float = 0.15,
    enable_cache: bool = True,
    include_research_modules: bool = False,
    execution_mode: str = "validate",
    campaign_name: str = "",
    operator: str = "",
    ticket: str = "",
    approval_required: bool = False,
    approved: bool = False,
    dry_run: bool = False,
    max_findings: int = 0,
    stop_on_severity: str = "",
    allow_private_targets: bool = False,
    allow_insecure_http: bool = False,
    isolated_environment: bool = False,
    cost_preview_only: bool = False,
    input_price_per_million: float | None = None,
    output_price_per_million: float | None = None,
    config: str = "",
) -> int:
    """Main scan execution pipeline."""
    log_level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    logging.basicConfig(level=log_level, format="%(name)s | %(levelname)s | %(message)s")

    cfg = BasiliskConfig.from_cli_args(
        target=target, provider=provider, model=model, api_key=api_key, auth=auth, mode=mode, evolve=evolve, generations=generations,
        module=module, probe_id=probe_id, recon_module=recon_module,
        attacker_provider=attacker_provider, attacker_model=attacker_model,
        attacker_api_key=attacker_api_key, 
        campaign={
            "name": campaign_name,
            "objective": {"name": execution_mode},
            "authorization": {
                "operator": operator,
                "ticket_id": ticket,
                "approved": approved,
            },
        },
        policy={
            "execution_mode": execution_mode,
            "approval_required": approval_required,
            "approval_confirmed": approved,
            "dry_run": dry_run,
            "stop_on_severity": stop_on_severity,
            "allow_private_targets": allow_private_targets,
            "allow_insecure_http": allow_insecure_http,
            "isolated_environment": isolated_environment,
        },
        exit_on_first=exit_on_first, diversity_mode=diversity_mode,
        intent_weight=intent_weight, enable_cache=enable_cache,
        include_research_modules=include_research_modules,
        output=output_format, 
        output_dir=output_dir, no_dashboard=no_dashboard, fail_on=fail_on, 
        max_findings=max_findings,
        verbose=verbose, debug=debug, skip_recon=skip_recon, config=config,
    )

    preview = cfg.cost_preview(
        input_usd_per_million=input_price_per_million,
        output_usd_per_million=output_price_per_million,
    )
    cost_text = (
        f"${preview.estimated_cost_usd:.6f} USD"
        if preview.estimated_cost_usd is not None
        else "Unavailable until provider/model token rates are supplied"
    )
    console.print(Panel(
        f"[bold]Mode:[/bold] {preview.mode}\n"
        f"[bold]Modules:[/bold] {preview.module_count}\n"
        f"[bold]Probe executions:[/bold] {preview.probe_executions}\n"
        f"[bold]Planned requests:[/bold] {preview.estimated_requests} "
        f"(uncapped estimate {preview.uncapped_request_estimate})\n"
        f"[bold]Hard request ceiling:[/bold] {preview.request_maximum}\n"
        f"[bold]Estimated tokens:[/bold] {preview.estimated_input_tokens:,} input / "
        f"{preview.estimated_output_tokens:,} output\n"
        f"[bold]Provider cost estimate:[/bold] {cost_text}\n"
        f"[dim]{preview.cost_basis}[/dim]",
        title="Scan Cost Preview",
        border_style="yellow",
        padding=(1, 2),
    ))
    if cost_preview_only:
        return 0

    audit = AuditLogger(
        output_dir=output_dir,
        session_id=f"{target.split('/')[-1][:20]}",
    )
    audit.log_scan_config(cfg.to_safe_dict())

    errors = cfg.validate()
    if errors:
        for err in errors:
            console.print(f"  [red]✗[/red] {err}")
        return 1

    session = ScanSession(cfg)
    await session.initialize()
    modules_for_run = resolve_attack_modules(
        selected=cfg.modules,
        include_research=cfg.research_modules_enabled,
    )

    console.print(Panel(
        f"[bold]Session:[/bold] {session.id}\n"
        f"[bold]Target:[/bold] {cfg.target.url}\n"
        f"[bold]Mode:[/bold] {cfg.mode.value}\n"
        f"[bold]Modules:[/bold] {len(modules_for_run)}\n"
        f"[bold]Research Tier:[/bold] {'Enabled' if cfg.research_modules_enabled else 'Excluded by default'}\n"
        f"[bold]Evolution:[/bold] {'Enabled' if cfg.evolution.enabled else 'Disabled'}\n"
        f"[bold]Request Ceiling:[/bold] {cfg.request_policy().max_requests} actual API calls\n"
        f"[bold]Input Token Ceiling:[/bold] {cfg.request_policy().max_input_tokens:,}\n"
        f"[bold]Output Token Ceiling:[/bold] {cfg.request_policy().max_output_tokens:,}",
        title="⚔️  Basilisk Scan Started",
        border_style="red",
        padding=(1, 2),
    ))

    from .utils import print_profile, print_summary, print_findings_table

    async def on_phase(_: str, phase: str) -> None:
        labels = {
            "recon": "Phase 1: Reconnaissance",
            "recon_skipped": "Phase 1: Reconnaissance (Skipped)",
            "attacking": "Phase 2: Attack Execution",
            "evolving": "Phase 3: Smart Prompt Evolution (SPE-NL)",
        }
        if phase in labels:
            console.print(f"\n[bold yellow]{labels[phase]}[/bold yellow]")

    async def on_profile(_: str, _profile: dict) -> None:
        print_profile(session)

    async def on_finding(_: str, finding) -> None:
        console.print(f"  {finding.severity.icon} [{finding.severity.color}]{finding.severity.value.upper()}[/{finding.severity.color}] {finding.title} ({finding.evidence.verdict.value if finding.evidence else 'unverified'})")

    async def on_error(_: str, module_name: str, error: str) -> None:
        logger.error("Module %s failed: %s", module_name, error)

    hooks = ScanHooks(
        on_phase=on_phase,
        on_profile=on_profile,
        on_finding=on_finding,
        on_error=on_error,
    )

    final_status = "completed"
    try:
        console.print("[dim]Checking provider connection...[/dim]")
        await execute_scan(
            cfg,
            session=session,
            hooks=hooks,
            audit=audit,
            modules=modules_for_run,
        )
        # Reports must describe terminal state, not a still-running session.
        await session.close("completed")
        console.print("[green]✓[/green] Scan pipeline completed")

        console.print("\n[bold yellow]Phase 4: Report Generation[/bold yellow]")
        from basilisk.report.generator import generate_report

        report_path = await generate_report(session, cfg.output)
        console.print(f"  [green]✓[/green] Report saved to: {report_path}")
        audit.log_report_generated(cfg.output.format, report_path)
    except Exception as exc:
        final_status = "error"
        logger.exception("Scan failed")
        console.print(f"[red]✗ Scan failed: {exc}[/red]")
    finally:
        if session.finished_at is None:
            await session.close(final_status)
        audit.close()

    print_summary(session)
    if session.findings:
        print_findings_table(session)
    if audit.log_path:
        console.print(f"  [dim]Audit log:[/dim] {audit.log_path}")

    return 1 if final_status == "error" else session.exit_code


async def run_recon(
    target: str,
    provider: str = "openai",
    api_key: str = "",
    auth: str = "",
    recon_modules: list[str] | None = None,
    verbose: bool = False,
) -> None:
    """Run reconnaissance only."""
    cfg = BasiliskConfig.from_cli_args(
        target=target, provider=provider, api_key=api_key, auth=auth, 
        recon_module=recon_modules, verbose=verbose,
    )
    session = ScanSession(cfg)
    await session.initialize()
    prov = create_provider(cfg)

    console.print("[bold yellow]Running Reconnaissance...[/bold yellow]\n")
    try:
        await run_recon_phase(prov, session)
        from .utils import print_profile
        print_profile(session)
    finally:
        await prov.close()
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
    """Compatibility wrapper for the shared provider factory."""
    return create_provider(cfg)


async def _run_recon(prov, session: ScanSession) -> None:
    """Compatibility wrapper for the shared recon phase."""
    await run_recon_phase(prov, session)

def _print_findings_table(session: ScanSession) -> None:
    from .utils import print_findings_table

    print_findings_table(session)


def _print_profile(session: ScanSession) -> None:
    """Compatibility wrapper used by the interactive CLI."""
    from .utils import print_profile

    print_profile(session)


async def _run_evolution(
    prov,
    session: ScanSession,
    cfg: BasiliskConfig,
    seed_payload: str = "",
) -> None:
    """Run the shared evolution phase for an interactive session."""
    from basilisk.runtime.orchestrator import ScanHooks, _run_evolution_phase

    attacker = await _run_evolution_phase(
        prov,
        session,
        cfg,
        hooks=ScanHooks(),
        seed_payloads=[seed_payload] if seed_payload else None,
    )
    if attacker is not None:
        await attacker.close()
