"""
Basilisk CLI — Main entry point with click + rich.

Commands:
  basilisk scan        — Run a full scan against a target
  basilisk recon       — Reconnaissance only
  basilisk diff        — Differential scan across multiple models
  basilisk posture     — Guardrail posture assessment (recon-only)
  basilisk replay      — Replay a previous session
  basilisk sessions    — List saved sessions
  basilisk modules     — List available attack modules
  basilisk interactive — Manual + assisted red teaming REPL
  basilisk help        — Extended usage guide
  basilisk version     — Show version
"""

from __future__ import annotations

import os
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from basilisk import BANNER, __version__
from basilisk.cli.encoding import configure_output_encoding


configure_output_encoding()

console = Console()


def _validate_cli_secret_arg(option_name: str, value: str) -> str:
    """Reject inline secrets that would leak via process listings."""
    if not value:
        return value
    if value.startswith("@"):
        return value
    raise click.BadParameter(
        (
            f"{option_name} no longer accepts inline secret values because they leak via "
            "shell history and process listings. Use the appropriate environment variable "
            "or pass @/path/to/secret-file instead."
        ),
        param_hint=option_name,
    )


def _enforce_cli_secret_policy(
    *, api_key: str = "", attacker_api_key: str = "", auth: str = ""
) -> None:
    _validate_cli_secret_arg("--api-key", api_key)
    _validate_cli_secret_arg("--attacker-api-key", attacker_api_key)
    _validate_cli_secret_arg("--auth", auth)


@click.group()
@click.version_option(version=__version__, prog_name="basilisk")
def cli() -> None:
    """🐍 Basilisk — LLM/AI Red Teaming Framework"""
    pass


@cli.command("scan")
@click.option("-t", "--target", required=True, help="Target URL or API endpoint")
@click.option("-p", "--provider", default="openai", help="LLM provider (openai, anthropic, google, azure, nvidia, ollama, github, custom, websocket)")
@click.option("-m", "--model", default="", help="Model name override")
@click.option("-k", "--api-key", default="", help="API key file reference (@path) or use env vars")
@click.option("--auth", default="", help="Authorization header file reference (@path) or BASILISK_AUTH_HEADER")
@click.option("--mode", default="standard", type=click.Choice(["quick", "standard", "deep", "stealth", "chaos"]))
@click.option("--cost-preview", "cost_preview_only", is_flag=True, help="Show the bounded request/token/cost plan and exit without transmitting")
@click.option("--input-price-per-million", type=click.FloatRange(min=0), default=None, help="Optional provider input-token price in USD per million")
@click.option("--output-price-per-million", type=click.FloatRange(min=0), default=None, help="Optional provider output-token price in USD per million")
@click.option("--evolve/--no-evolve", default=True, help="Enable/disable evolution engine")
@click.option("--generations", default=5, help="Number of evolution generations")
@click.option("--module", multiple=True, help="Specific attack modules to run (default: all)")
@click.option("--probe-id", multiple=True, help="Run exact canonical probe IDs (repeatable)")
@click.option("-o", "--output", default="html", type=click.Choice(["html", "json", "sarif", "markdown", "pdf"]))
@click.option("--output-dir", default="./basilisk-reports", help="Report output directory")
@click.option("--no-dashboard", is_flag=True, help="Disable web dashboard")
@click.option("--fail-on", default="high", type=click.Choice(["critical", "high", "medium", "low", "info"]))
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.option("--debug", is_flag=True, help="Debug mode")
@click.option("--skip-recon", is_flag=True, help="Skip the reconnaissance phase")
@click.option("--recon-module", multiple=True, help="Specific recon modules to run")
@click.option("--attacker-provider", default="", help="Provider for mutation engine")
@click.option("--attacker-model", default="", help="Model for mutation engine")
@click.option("--attacker-api-key", default="", help="Mutation engine API key file reference (@path) or use env vars")
@click.option("--exit-on-first/--no-exit-on-first", default=False, help="Stop evolution after first breakthrough")
@click.option("--diversity-mode", default="novelty", type=click.Choice(["off", "novelty", "niche"]), help="Adversarial diversity strategy")
@click.option("--intent-weight", default=0.15, type=float, help="Strength of semantic intent preservation (0.0-1.0)")
@click.option("--cache/--no-cache", default=True, help="Enable/disable response caching")
@click.option("--include-research-modules/--no-include-research-modules", default=False, help="Include research-tier attack modules in the scan")
@click.option("--execution-mode", default="validate", type=click.Choice(["recon", "validate", "exploit_chain", "research"]), help="Operator execution policy")
@click.option("--campaign-name", default="", help="Campaign name for audit/governance context")
@click.option("--operator", default="", help="Named operator running the scan")
@click.option("--ticket", default="", help="Authorization or tracking ticket")
@click.option("--approval-required/--no-approval-required", default=False, help="Require explicit campaign approval")
@click.option("--approve/--no-approve", default=False, help="Mark campaign approval confirmed")
@click.option("--dry-run", is_flag=True, help="Plan the scan and stop after recon/policy evaluation")
@click.option("--max-findings", default=0, type=click.IntRange(min=0), help="Stop after this many persisted findings (0 = mode default/unlimited)")
@click.option("--stop-on-severity", default="", type=click.Choice(["", "critical", "high", "medium", "low", "info"]), help="Stop when a finding reaches this severity")
@click.option("--allow-private-targets", is_flag=True, help="Allow loopback/private destinations for an authorized local lab")
@click.option("--allow-insecure-http", is_flag=True, help="Allow unencrypted HTTP/WS for an authorized local lab")
@click.option("--isolated-environment", is_flag=True, help="Confirm the target is an isolated lab; required for chaos mode")
@click.option("-c", "--config", default="", help="YAML config file path")
def scan(target, provider, model, api_key, auth, mode, cost_preview_only, input_price_per_million, output_price_per_million, evolve, generations, module, probe_id, recon_module, attacker_provider, attacker_model, attacker_api_key, exit_on_first, diversity_mode, intent_weight, cache, include_research_modules, execution_mode, campaign_name, operator, ticket, approval_required, approve, dry_run, max_findings, stop_on_severity, allow_private_targets, allow_insecure_http, isolated_environment, output, output_dir, no_dashboard, fail_on, verbose, debug, skip_recon, config) -> None:
    """Run a full red team scan against a target."""
    import asyncio

    console.print(BANNER, style="bold red")
    console.print()
    _enforce_cli_secret_policy(api_key=api_key, attacker_api_key=attacker_api_key, auth=auth)

    if not cost_preview_only and os.environ.get("BASILISK_RESTRICTED_WORKER") != "1" and os.environ.get(
        "BASILISK_DISABLE_PROCESS_ISOLATION", ""
    ).casefold() not in {"1", "true", "yes", "on"}:
        from basilisk.runtime.isolation import spawn_restricted_scan

        exit_code = spawn_restricted_scan({
            "target": target, "provider": provider, "model": model,
            "api_key": api_key, "auth": auth, "mode": mode,
            "evolve": evolve, "generations": generations,
            "module": list(module), "probe_id": list(probe_id),
            "recon_module": list(recon_module), "attacker_provider": attacker_provider,
            "attacker_model": attacker_model, "attacker_api_key": attacker_api_key,
            "exit_on_first": exit_on_first, "diversity_mode": diversity_mode,
            "intent_weight": intent_weight, "enable_cache": cache,
            "include_research_modules": include_research_modules,
            "execution_mode": execution_mode, "campaign_name": campaign_name,
            "operator": operator, "ticket": ticket,
            "approval_required": approval_required, "approved": approve,
            "dry_run": dry_run, "max_findings": max_findings,
            "stop_on_severity": stop_on_severity,
            "allow_private_targets": allow_private_targets,
            "allow_insecure_http": allow_insecure_http,
            "isolated_environment": isolated_environment,
            "input_price_per_million": input_price_per_million,
            "output_price_per_million": output_price_per_million,
            "output_format": output, "output_dir": output_dir,
            "no_dashboard": no_dashboard, "fail_on": fail_on,
            "verbose": verbose, "debug": debug, "skip_recon": skip_recon,
            "config": config,
        })
        raise click.exceptions.Exit(exit_code)

    from basilisk.cli.scan import run_scan

    exit_code = asyncio.run(run_scan(
        target=target, provider=provider, model=model, api_key=api_key,
        auth=auth, mode=mode, evolve=evolve, generations=generations,
        module=list(module), probe_id=list(probe_id), recon_module=list(recon_module),
        attacker_provider=attacker_provider, attacker_model=attacker_model,
        attacker_api_key=attacker_api_key, 
        exit_on_first=exit_on_first, diversity_mode=diversity_mode,
        intent_weight=intent_weight, enable_cache=cache,
        include_research_modules=include_research_modules,
        execution_mode=execution_mode,
        campaign_name=campaign_name,
        operator=operator,
        ticket=ticket,
        approval_required=approval_required,
        approved=approve,
        dry_run=dry_run,
        max_findings=max_findings,
        stop_on_severity=stop_on_severity,
        allow_private_targets=allow_private_targets,
        allow_insecure_http=allow_insecure_http,
        isolated_environment=isolated_environment,
        cost_preview_only=cost_preview_only,
        input_price_per_million=input_price_per_million,
        output_price_per_million=output_price_per_million,
        output_format=output, 
        output_dir=output_dir, no_dashboard=no_dashboard, fail_on=fail_on, 
        verbose=verbose, debug=debug, skip_recon=skip_recon, config=config,
    ))
    if exit_code:
        raise click.exceptions.Exit(exit_code)


@cli.command("recon")
@click.option("-t", "--target", required=True, help="Target URL or API endpoint")
@click.option("-p", "--provider", default="openai", help="LLM provider")
@click.option("-k", "--api-key", default="", help="API key file reference (@path) or use env vars")
@click.option("--auth", default="", help="Authorization header file reference (@path) or BASILISK_AUTH_HEADER")
@click.option("--recon-module", multiple=True, help="Specific recon modules to run")
@click.option("-v", "--verbose", is_flag=True)
def recon(target, provider, api_key, auth, recon_module, verbose) -> None:
    """Run reconnaissance only — fingerprint the target system."""
    import asyncio

    console.print(BANNER, style="bold red")
    console.print()
    _enforce_cli_secret_policy(api_key=api_key, auth=auth)

    from basilisk.cli.scan import run_recon

    asyncio.run(run_recon(
        target=target, provider=provider, api_key=api_key,
        auth=auth, recon_modules=list(recon_module), verbose=verbose,
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
@click.option("--category", default="", help="Filter by category (injection, extraction, multiturn, etc.)")
@click.option("--include-research/--no-include-research", default=True, help="Show research-tier modules in the catalog")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def list_modules(category, include_research, json_output) -> None:
    """List all available attack modules."""
    if not json_output:
        console.print(BANNER, style="bold red")
        console.print()

    from rich.table import Table
    from basilisk.attacks.base import describe_attack_module, get_all_attack_modules

    try:
        modules = get_all_attack_modules()

        if category:
            modules = [m for m in modules if category.lower() in m.name.lower() or category.lower() in m.category.value.lower()]
        if not include_research:
            modules = [m for m in modules if m.trust_tier != "research"]

        if json_output:
            import json
            data = [
                {
                    **describe_attack_module(m).__dict__,
                    "category": m.category.value,
                    "severity": m.severity_default.value,
                }
                for m in modules
            ]
            print(json.dumps(data, indent=2))
            return

        table = Table(title="Basilisk Attack Modules", show_lines=True)
        table.add_column("#", style="dim", width=3)
        table.add_column("Module", style="cyan", no_wrap=True)
        table.add_column("Tier", style="magenta")
        table.add_column("Category", style="green")
        table.add_column("Severity", style="yellow")
        table.add_column("Description", max_width=60)

        for i, mod in enumerate(modules, 1):
            descriptor = describe_attack_module(mod)
            sev_style = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "blue",
            }.get(mod.severity_default.value.lower(), "white")

            table.add_row(
                str(i),
                mod.name,
                descriptor.trust_tier,
                f"{mod.category.value} ({mod.category.owasp_id})",
                f"[{sev_style}]{mod.severity_default.value}[/{sev_style}]",
                mod.description[:120],
            )
        console.print(table)
        console.print(f"\n[bold]{len(modules)}[/bold] modules loaded.")
        if not include_research:
            console.print("[dim]Research-tier modules are hidden in this view.[/dim]")

        # Summary by category
        from collections import Counter
        cats = Counter(m.category.value for m in modules)
        cat_summary = " · ".join(f"{v}: {c}" for v, c in cats.most_common())
        console.print(f"[dim]Categories: {cat_summary}[/dim]")
    except Exception as e:
        console.print(f"[red]Error loading modules: {e}[/red]")


@cli.command("probes")
@click.option("--category", default="", help="Filter by category (injection, extraction, dos, multiturn, etc.)")
@click.option("--tag", default="", help="Filter by tag")
@click.option("--severity", default="", type=click.Choice(["", "critical", "high", "medium", "low"]), help="Filter by severity")
@click.option("--query", default="", help="Free-text search in id, name, payload")
@click.option("--count", is_flag=True, help="Show count only")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.option("--stats", is_flag=True, help="Show aggregate statistics")
def probes_cmd(category, tag, severity, query, count, json_output, stats) -> None:
    """Browse and search the probe payload database."""
    if not json_output and not count:
        console.print(BANNER, style="bold red")
        console.print()

    from basilisk.payloads.loader import load_probes, probe_stats

    if stats:
        st = probe_stats()
        if json_output:
            import json
            print(json.dumps(st, indent=2))
        else:
            console.print(f"[bold]Total Probes:[/bold] {st['total']}")
            console.print()
            from rich.table import Table
            t = Table(title="By Category")
            t.add_column("Category", style="cyan")
            t.add_column("Count", style="green", justify="right")
            for cat, cnt in st["by_category"].items():
                t.add_row(cat, str(cnt))
            console.print(t)
            console.print()
            t2 = Table(title="By Severity")
            t2.add_column("Severity", style="yellow")
            t2.add_column("Count", justify="right")
            for sev, cnt in st["by_severity"].items():
                t2.add_row(sev, str(cnt))
            console.print(t2)
        return

    tags_list = [tag] if tag else None
    results = load_probes(category=category, tags=tags_list, severity=severity, query=query)

    if count:
        print(len(results))
        return

    if json_output:
        import json
        print(json.dumps([p.to_dict() for p in results], indent=2))
        return

    from rich.table import Table
    table = Table(title=f"Probe Library ({len(results)} probes)", show_lines=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="white")
    table.add_column("Category", style="green")
    table.add_column("Severity", style="yellow")
    table.add_column("Tags", max_width=30)

    for i, p in enumerate(results[:100], 1):
        sev_style = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "blue"}.get(p.severity, "white")
        table.add_row(
            str(i), p.id, p.name, p.category,
            f"[{sev_style}]{p.severity}[/{sev_style}]",
            ", ".join(p.tags[:5]),
        )

    console.print(table)
    if len(results) > 100:
        console.print(f"[dim]Showing first 100 of {len(results)}. Use --json for all.[/dim]")


@cli.command("auth-test")
@click.option("-t", "--target", required=True, help="Authorized AI endpoint to test")
@click.option("-p", "--provider", default="custom", help="Provider adapter")
@click.option("-m", "--model", default="", help="Target model")
@click.option("--personas", "personas_path", default="", help="JSON persona file using credential environment-variable references")
@click.option("--lab-personas", is_flag=True, help="Use the bundled local-lab personas")
@click.option("--isolated-environment", is_flag=True, help="Allow an authorized loopback/private lab target")
@click.option("--json-output", default="", help="Optional JSON report path")
def auth_test_cmd(target, provider, model, personas_path, lab_personas, isolated_environment, json_output) -> None:
    """Replay authorization probes across anonymous, user, admin, tenant, and invalid credentials."""
    import asyncio
    import json
    from pathlib import Path

    from basilisk.auth_testing import AuthPersona, CredentialState, lab_personas as default_lab_personas, run_auth_matrix
    from basilisk.core.config import BasiliskConfig, TargetConfig
    from basilisk.policy.models import ScanPolicy

    if lab_personas:
        selected_personas = default_lab_personas()
    elif personas_path:
        raw = json.loads(Path(personas_path).read_text("utf-8"))
        selected_personas = []
        for item in raw:
            if any(key in item for key in ("api_key", "authorization", "token", "password", "secret")):
                raise click.ClickException(
                    "Persona files must reference credentials through authorization_env; inline secrets are rejected."
                )
            selected_personas.append(AuthPersona(
                id=item["id"],
                role=item.get("role", "user"),
                tenant=item.get("tenant", "public"),
                credential_state=CredentialState(item.get("credential_state", "valid")),
                authorization_env=item.get("authorization_env", ""),
            ))
    else:
        raise click.ClickException("Choose --lab-personas or provide --personas PATH.")

    cfg = BasiliskConfig(
        target=TargetConfig(url=target, provider=provider, model=model),
        policy=ScanPolicy(
            isolated_environment=isolated_environment,
            allow_private_targets=isolated_environment,
            allow_insecure_http=isolated_environment,
            request_budget=max(50, len(selected_personas) * 8),
            max_concurrency=4,
        ),
    )
    errors = cfg.validate()
    if errors:
        raise click.ClickException("; ".join(errors))
    report = asyncio.run(run_auth_matrix(
        cfg,
        selected_personas,
        known_canaries=["RAG_TENANT_A_CANARY_91C2", "RAG_TENANT_B_CANARY_4D8E"],
    )).to_dict()
    rendered = json.dumps(report, indent=2)
    if json_output:
        Path(json_output).write_text(rendered + "\n", encoding="utf-8")
        console.print(f"[green]Authorization matrix saved to {json_output}[/green]")
    else:
        click.echo(rendered)


@cli.command("interactive")
@click.option("-t", "--target", required=True, help="Target URL or API endpoint")
@click.option("-p", "--provider", default="openai", help="LLM provider")
@click.option("-m", "--model", default="", help="Model name")
@click.option("-k", "--api-key", default="", help="API key file reference (@path) or use env vars")
@click.option("--auth", default="", help="Authorization header file reference (@path) or BASILISK_AUTH_HEADER")
@click.option("-v", "--verbose", is_flag=True)
def interactive(target, provider, model, api_key, auth, verbose) -> None:
    """Launch interactive REPL for manual + assisted red teaming."""
    import asyncio

    console.print(BANNER, style="bold red")
    console.print()
    _enforce_cli_secret_policy(api_key=api_key, auth=auth)

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


@cli.command("diff")
@click.option("-t", "--target", multiple=True, required=True, help="provider:model pair (e.g. openai:gpt-4)")
@click.option("-k", "--api-key", default="", help="Shared API key file reference (@path) or use env vars")
@click.option("--category", multiple=True, help="Probe categories (default: all)")
@click.option("-o", "--output-dir", default="./basilisk-reports", help="Report output directory")
@click.option("-v", "--verbose", is_flag=True)
def diff(target, api_key, category, output_dir, verbose) -> None:
    """Differential scan — same attacks across multiple models side-by-side."""
    import asyncio

    console.print(BANNER, style="bold red")
    console.print()
    _enforce_cli_secret_policy(api_key=api_key)

    # Parse targets: "provider:model" format
    targets = []
    for t in target:
        parts = t.split(":", 1)
        if len(parts) == 2:
            targets.append({"provider": parts[0], "model": parts[1], "api_key": api_key})
        else:
            targets.append({"provider": parts[0], "model": "", "api_key": api_key})

    if len(targets) < 2:
        console.print("[red]✗ Differential mode requires at least 2 targets.[/red]")
        console.print("[dim]Usage: basilisk diff -t openai:gpt-4 -t anthropic:claude-3-5-sonnet-20241022[/dim]")
        return

    from basilisk.differential import run_differential, print_diff_report

    categories = list(category) if category else None
    report = asyncio.run(run_differential(targets, categories=categories, verbose=verbose))
    print_diff_report(report)

    # Save report
    import json
    from pathlib import Path
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = Path(output_dir) / f"diff_{ts}.json"
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(report.to_dict(), f, indent=2, default=str)
    console.print(f"\n[green]✓[/green] Diff report saved to: {path}")


@cli.command("posture")
@click.option("-t", "--target", default="", help="Target URL (optional if using direct provider)")
@click.option("-p", "--provider", default="openai", help="LLM provider")
@click.option("-m", "--model", default="", help="Model name")
@click.option("-k", "--api-key", default="", help="API key file reference (@path) or use env vars")
@click.option("--auth", default="", help="Authorization header file reference (@path) or BASILISK_AUTH_HEADER")
@click.option("--output-dir", default="./basilisk-reports", help="Report output directory")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON only (for CI)")
@click.option("-v", "--verbose", is_flag=True)
def posture(target, provider, model, api_key, auth, output_dir, json_output, verbose) -> None:
    """Guardrail posture scan — recon-only, no attacks. CISO-friendly."""
    import asyncio

    if not json_output:
        console.print(BANNER, style="bold red")
        console.print()
    _enforce_cli_secret_policy(api_key=api_key, auth=auth)

    from basilisk.core.config import BasiliskConfig
    from basilisk.cli.scan import _create_provider
    from basilisk.posture import run_posture_scan, print_posture_report, save_posture_report

    cfg = BasiliskConfig.from_cli_args(
        target=target or "direct", provider=provider, model=model,
        api_key=api_key, auth=auth,
    )
    async def _do_posture():
        async with _create_provider(cfg) as prov:
            report = await run_posture_scan(
                prov, target=target, provider_name=provider,
                model_name=model, verbose=verbose,
            )
            return report

    report = asyncio.run(_do_posture())

    if json_output:
        import json as json_mod
        print(json_mod.dumps(report.to_dict(), indent=2, default=str))
    else:
        print_posture_report(report)

    path = save_posture_report(report, output_dir)
    if not json_output:
        console.print(f"\n[green]✓[/green] Posture report saved to: {path}")


@cli.command("version")
def version() -> None:
    """Show Basilisk version and system info."""
    console.print(BANNER, style="bold red")
    console.print(f"[bold]Version:[/bold] {__version__}")
    console.print(f"[bold]Python:[/bold] {sys.version}")
    console.print(f"[bold]Platform:[/bold] {sys.platform}")


@cli.command("help")
@click.argument("topic", default="overview")
def help_command(topic) -> None:
    """Extended usage guide. Topics: overview, scan, modules, evolution, diff, examples."""
    console.print(BANNER, style="bold red")
    console.print()

    # ── Topic-based help ──────────────────────────────────────────────────────
    topics = {
        "overview": _help_overview,
        "scan": _help_scan,
        "modules": _help_modules,
        "evolution": _help_evolution,
        "diff": _help_diff,
        "examples": _help_examples,
    }

    handler = topics.get(topic.lower())
    if handler:
        handler()
    else:
        console.print(f"[red]Unknown topic: {topic}[/red]")
        console.print(f"[dim]Available topics: {', '.join(topics.keys())}[/dim]")


def _help_overview() -> None:
    console.print(Panel.fit(
        "[bold cyan]Basilisk — LLM Red Teaming Framework[/bold cyan]\n\n"
        "Automated vulnerability discovery for large language models.\n"
        "Tests prompt injection, system prompt extraction, guardrail bypass,\n"
        "multi-turn manipulation, tool abuse, and more.\n\n"
        "[bold]Quick Start:[/bold]\n"
        "  OPENAI_API_KEY=... basilisk scan -t https://api.openai.com/v1 -p openai\n\n"
        "[bold]Commands:[/bold]\n"
        "  scan         Full red team scan\n"
        "  recon        Fingerprint target (no attacks)\n"
        "  posture      Guardrail assessment (CISO-friendly)\n"
        "  diff         Compare security across models\n"
        "  modules      List attack modules\n"
        "  sessions     List saved sessions\n"
        "  replay       Replay a session\n"
        "  interactive  Manual red teaming REPL\n"
        "  version      Version info\n"
        "  help         This guide\n\n"
        "[bold]Help Topics:[/bold]\n"
        "  basilisk help scan       — Scan options and modes\n"
        "  basilisk help modules    — Attack module categories\n"
        "  basilisk help evolution  — Evolution engine details\n"
        "  basilisk help diff       — Differential scanning\n"
        "  basilisk help examples   — Common usage patterns\n",
        title="Overview",
        border_style="cyan",
    ))


def _help_scan() -> None:
    console.print(Panel.fit(
        "[bold]Scan Modes:[/bold]\n"
        "  quick     — Fast scan, limited modules, no evolution\n"
        "  standard  — Balanced coverage with evolution retry\n"
        "  deep      — Full module coverage, extended evolution\n"
        "  stealth   — Low-rate, evasive probing\n"
        "  chaos     — Maximum aggression, all vectors\n\n"
        "[bold]Key Options:[/bold]\n"
        "  --module multiturn.cultivation    Run specific module only\n"
        "  --module multiturn                Run all multi-turn modules\n"
        "  --skip-recon                      Skip fingerprinting\n"
        "  --no-evolve                       Disable mutation engine\n"
        "  --generations 10                  More evolution cycles\n"
        "  --fail-on critical               CI exit code threshold\n\n"
        "[bold]Separate Attacker LLM:[/bold]\n"
        "  Use a different model to generate mutations:\n"
        "  --attacker-provider anthropic \\\n"
        "  --attacker-model claude-3-5-sonnet-20241022 \\\n"
        "  (set ANTHROPIC_API_KEY in the environment or use --attacker-api-key @file)\n\n"
        "[bold]Output Formats:[/bold]\n"
        "  html, json, sarif, markdown, pdf\n",
        title="Scan Options",
        border_style="green",
    ))


def _help_modules() -> None:
    console.print(Panel.fit(
        "[bold]Attack Module Categories:[/bold]\n\n"
        "  [cyan]injection[/cyan]      Direct, indirect, multilingual, encoding, split\n"
        "  [cyan]extraction[/cyan]     Role confusion, translation, simulation, gradient walk\n"
        "  [cyan]exfil[/cyan]          Training data, RAG data, tool schema\n"
        "  [cyan]toolabuse[/cyan]      SSRF, SQLi, command injection, chained\n"
        "  [cyan]guardrails[/cyan]     Roleplay, encoding bypass, logic trap, systematic\n"
        "  [cyan]dos[/cyan]            Token exhaustion, context bomb, loop trigger\n"
        "  [cyan]multiturn[/cyan]      Escalation, persona lock, memory manipulation,\n"
        "                   cultivation (13 scenarios), sycophancy (5 sequences),\n"
        "                   authority escalation (8 sequences)\n"
        "  [cyan]rag[/cyan]            Poisoning, document injection, knowledge enum\n\n"
        "[bold]Multi-turn Attack Highlights:[/bold]\n"
        "  • Cultivation: baseline divergence proof, adaptive shadow monitor,\n"
        "    documented transcripts, semantic drift tracking\n"
        "  • Authority Escalation: recursive delegation, temporal authority,\n"
        "    per-turn escalation arc tracking\n"
        "  • Sycophancy: identity acceptance arc, sycophancy acceleration,\n"
        "    peer researcher + progressive expertise vectors\n\n"
        "[bold]List all modules:[/bold] basilisk modules\n"
        "[bold]Filter:[/bold]          basilisk modules --category multiturn\n"
        "[bold]JSON output:[/bold]     basilisk modules --json\n",
        title="Attack Modules",
        border_style="magenta",
    ))


def _help_evolution() -> None:
    console.print(Panel.fit(
        "[bold]SPE-NL Evolution Engine[/bold]\n"
        "Smart Prompt Evolution for Natural Language\n\n"
        "[bold]How it works:[/bold]\n"
        "  When an attack scenario shows potential (high drift / partial\n"
        "  compliance) but doesn't fully succeed, the evolution engine\n"
        "  generates mutated variants and retries.\n\n"
        "[bold]Genetic operators:[/bold]\n"
        "  Mutation    — Metaphor swap, register prefix, opener/closer variants\n"
        "  Crossover   — Splice frame from scenario A with sleeper from B\n"
        "  Selection   — Tournament selection (k=3) by fitness score\n\n"
        "[bold]Adaptive features:[/bold]\n"
        "  • Mutation rate increases when evolution stagnates\n"
        "  • Population diversity tracking prevents convergence\n"
        "  • Lineage chains for full ancestry transparency\n"
        "  • Per-generation statistics (best/mean/worst fitness)\n\n"
        "[bold]CLI options:[/bold]\n"
        "  --evolve / --no-evolve    Toggle evolution\n"
        "  --generations N           Number of evolution cycles\n",
        title="Evolution Engine",
        border_style="yellow",
    ))


def _help_diff() -> None:
    console.print(Panel.fit(
        "[bold]Differential Scanning[/bold]\n"
        "Run identical attack vectors against multiple models\n"
        "and compare vulnerability profiles side-by-side.\n\n"
        "[bold]Usage:[/bold]\n"
        "  basilisk diff \\\n"
        "    -t openai:gpt-4o \\\n"
        "    -t anthropic:claude-3-5-sonnet-20241022 \\\n"
        "    -t google:gemini/gemini-2.0-flash\n\n"
        "[bold]Output:[/bold]\n"
        "  Per-model vulnerability matrix with severity breakdown,\n"
        "  comparative findings, and JSON export.\n\n"
        "[bold]Options:[/bold]\n"
        "  --category injection    Filter to specific category\n"
        "  -o ./reports            Custom output directory\n",
        title="Differential Scan",
        border_style="blue",
    ))


@cli.command("eval")
@click.argument("config_path", type=click.Path(exists=True))
@click.option("--format", "output_format", default="console", type=click.Choice(["console", "json", "junit", "markdown"]), help="Output format")
@click.option("--output", "output_path", default="", help="Save report to file")
@click.option("--fail-on", "fail_mode", default="any", type=click.Choice(["any", "all"]), help="Exit code 1 if any/all tests fail")
@click.option("--parallel/--no-parallel", default=False, help="Run tests concurrently")
@click.option("--diff", "diff_path", default="", help="Compare against previous JSON run")
@click.option("--tag", multiple=True, help="Filter tests by tag")
@click.option("-v", "--verbose", is_flag=True, help="Show full responses")
def eval_cmd(config_path, output_format, output_path, fail_mode, parallel, diff_path, tag, verbose) -> None:
    """Run an assertion-based eval suite against a target.

    CONFIG_PATH is a YAML file defining tests and assertions.

    \b
    Example:
      basilisk eval guardrails.yaml
      basilisk eval guardrails.yaml --format junit --output results.xml
      basilisk eval guardrails.yaml --diff previous_run.json
    """
    import asyncio
    from pathlib import Path

    console.print(BANNER, style="bold red")
    console.print()

    async def _run():
        from basilisk.eval.config import load_eval_config
        from basilisk.eval.runner import EvalRunner, diff_eval_results
        from basilisk.eval.report import (
            format_console as fmt_console,
            format_json, format_junit_xml, format_markdown,
            save_eval_report,
        )

        try:
            config = load_eval_config(config_path)
        except (FileNotFoundError, ValueError) as e:
            console.print(f"[red]Config error: {e}[/red]")
            sys.exit(1)

        if tag:
            config.tests = config.filter_by_tags(list(tag))
            if not config.tests:
                console.print(f"[yellow]No tests match tags: {list(tag)}[/yellow]")
                sys.exit(0)

        console.print(
            f"[bold]Eval:[/bold] {config.test_count} tests → "
            f"{config.target.provider}/{config.target.model}"
        )
        console.print()

        completed = [0]
        def on_complete(result):
            completed[0] += 1
            icon = "[green]✓[/green]" if result.passed else "[red]✗[/red]"
            console.print(
                f"  {icon} {result.test_id}: {result.test_name} "
                f"({result.duration_ms:.0f}ms)"
            )

        runner = EvalRunner(
            config,
            parallel=parallel,
            on_test_complete=on_complete if output_format == "console" else None,
        )
        result = await runner.run()
        result.config_path = config_path

        if output_format == "console":
            console.print(fmt_console(result))
        elif output_format == "json":
            output = format_json(result)
            if output_path:
                save_eval_report(result, "json", output_path)
                console.print(f"[green]Report saved: {output_path}[/green]")
            else:
                print(output)
        elif output_format == "junit":
            output = format_junit_xml(result)
            if output_path:
                save_eval_report(result, "junit", output_path)
                console.print(f"[green]JUnit XML saved: {output_path}[/green]")
            else:
                print(output)
        elif output_format == "markdown":
            output = format_markdown(result)
            if output_path:
                save_eval_report(result, "markdown", output_path)
                console.print(f"[green]Markdown saved: {output_path}[/green]")
            else:
                print(output)

        if diff_path:
            try:
                import json as _json
                prev_data = _json.loads(Path(diff_path).read_text())
                diff = diff_eval_results(prev_data, result)
                if diff["summary"]["total_regressions"] > 0:
                    console.print(
                        f"\n[red]⚠ {diff['summary']['total_regressions']} "
                        f"regression(s) detected![/red]"
                    )
            except Exception as e:
                console.print(f"[yellow]Diff failed: {e}[/yellow]")

        if fail_mode == "any" and result.failed_tests > 0:
            sys.exit(1)
        elif fail_mode == "all" and result.passed_tests == 0:
            sys.exit(1)

    asyncio.run(_run())


def _help_examples() -> None:
    console.print(Panel.fit(
        "[bold]Common Usage Patterns:[/bold]\n\n"
        "[cyan]1. Quick scan with OpenAI:[/cyan]\n"
        "  basilisk scan -t https://api.openai.com/v1 -p openai --mode quick\n\n"
        "[cyan]2. Deep scan with GitHub Models (free):[/cyan]\n"
        "  basilisk scan -t https://models.inference.ai.azure.com \\\n"
        "    -p github -m gpt-4o-mini --mode deep\n\n"
        "[cyan]3. Multi-turn only:[/cyan]\n"
        "  basilisk scan -t $TARGET -p openai --module multiturn\n\n"
        "[cyan]4. CI/CD pipeline (exit on critical):[/cyan]\n"
        "  basilisk scan -t $TARGET -p openai --mode quick \\\n"
        "    --fail-on critical -o sarif --no-dashboard\n\n"
        "[cyan]5. Posture check for compliance:[/cyan]\n"
        "  basilisk posture -p openai -m gpt-4o --json\n\n"
        "[cyan]6. Local model via Ollama:[/cyan]\n"
        "  basilisk scan -t http://localhost:11434 -p ollama -m llama3.1\n\n"
        "[cyan]7. Separate attacker model:[/cyan]\n"
        "  basilisk scan -t $TARGET -p openai \\\n"
        "    --attacker-provider anthropic \\\n"
        "    --attacker-model claude-3-5-sonnet-20241022\n",
        title="Examples",
        border_style="green",
    ))


@cli.command("audit-verify")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=str))
@click.option(
    "--public-key",
    default="",
    help="Trusted Ed25519 public key in hexadecimal form (recommended for authenticity).",
)
@click.option(
    "--public-key-file",
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    default="",
    help="File containing the independently distributed trusted public key.",
)
@click.option(
    "--allow-embedded-key",
    is_flag=True,
    help="Integrity-only diagnostic mode; does not establish external authenticity.",
)
def audit_verify(path: str, public_key: str, public_key_file: str, allow_embedded_key: bool) -> None:
    """Verify an audit JSONL hash chain and its available signatures."""
    from basilisk.core.audit import verify_audit_log

    if public_key and public_key_file:
        raise click.UsageError("Use either --public-key or --public-key-file, not both")
    trusted_key = public_key
    if public_key_file:
        from pathlib import Path

        trusted_key = Path(public_key_file).read_text(encoding="utf-8").strip()
    result = verify_audit_log(
        path,
        trusted_public_key=trusted_key,
        allow_embedded_key=allow_embedded_key,
    )
    color = "green" if result.valid else "red"
    console.print(
        f"[{color}]{'VALID' if result.valid else 'INVALID'}[/{color}] "
        f"entries={result.entry_count} chain={result.chain_valid} "
        f"signed={result.signed} signatures={result.signatures_valid} "
        f"trust_anchored={result.trust_anchored}"
    )
    for error in result.errors:
        console.print(f"[red]- {error}[/red]")
    if not result.valid:
        raise click.exceptions.Exit(1)


@cli.command("audit-trust-export")
@click.argument("path", type=click.Path(dir_okay=False, path_type=str))
def audit_trust_export(path: str) -> None:
    """Export the persistent audit public key for independent trusted storage."""
    from basilisk.core.audit import export_audit_trust_anchor

    export_audit_trust_anchor(path)
    console.print(f"[green]Exported audit trust anchor:[/green] {path}")


def main() -> None:
    """Entrypoint for the basilisk CLI."""
    cli()


if __name__ == "__main__":
    main()
