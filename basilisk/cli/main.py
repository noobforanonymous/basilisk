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
@click.option("-p", "--provider", default="openai", help="LLM provider (openai, anthropic, google, azure, ollama, github, custom)")
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
@click.option("--skip-recon", is_flag=True, help="Skip the reconnaissance phase")
@click.option("--recon-module", multiple=True, help="Specific recon modules to run")
@click.option("--attacker-provider", default="", help="Provider for mutation engine")
@click.option("--attacker-model", default="", help="Model for mutation engine")
@click.option("--attacker-api-key", default="", help="API key for mutation engine")
@click.option("-c", "--config", default="", help="YAML config file path")
def scan(target, provider, model, api_key, auth, mode, evolve, generations, module, recon_module, attacker_provider, attacker_model, attacker_api_key, output, output_dir, no_dashboard, fail_on, verbose, debug, skip_recon, config) -> None:
    """Run a full red team scan against a target."""
    import asyncio

    console.print(BANNER, style="bold red")
    console.print()

    from basilisk.cli.scan import run_scan

    asyncio.run(run_scan(
        target=target, provider=provider, model=model, api_key=api_key,
        auth=auth, mode=mode, evolve=evolve, generations=generations,
        module=list(module), recon_module=list(recon_module), 
        attacker_provider=attacker_provider, attacker_model=attacker_model,
        attacker_api_key=attacker_api_key, output_format=output, 
        output_dir=output_dir, no_dashboard=no_dashboard, fail_on=fail_on, 
        verbose=verbose, debug=debug, skip_recon=skip_recon, config=config,
    ))


@cli.command("recon")
@click.option("-t", "--target", required=True, help="Target URL or API endpoint")
@click.option("-p", "--provider", default="openai", help="LLM provider")
@click.option("-k", "--api-key", default="", help="API key")
@click.option("--auth", default="", help="Authorization header")
@click.option("--recon-module", multiple=True, help="Specific recon modules to run")
@click.option("-v", "--verbose", is_flag=True)
def recon(target, provider, api_key, auth, recon_module, verbose) -> None:
    """Run reconnaissance only — fingerprint the target system."""
    import asyncio

    console.print(BANNER, style="bold red")
    console.print()

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
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def list_modules(category, json_output) -> None:
    """List all available attack modules."""
    if not json_output:
        console.print(BANNER, style="bold red")
        console.print()

    from rich.table import Table
    from basilisk.attacks.base import get_all_attack_modules

    try:
        modules = get_all_attack_modules()

        if category:
            modules = [m for m in modules if category.lower() in m.name.lower() or category.lower() in m.category.value.lower()]

        if json_output:
            import json
            data = [
                {
                    "name": m.name,
                    "category": m.category.value,
                    "owasp_id": m.category.owasp_id,
                    "severity": m.severity_default.value,
                    "description": m.description,
                }
                for m in modules
            ]
            print(json.dumps(data, indent=2))
            return

        table = Table(title="Basilisk Attack Modules", show_lines=True)
        table.add_column("#", style="dim", width=3)
        table.add_column("Module", style="cyan", no_wrap=True)
        table.add_column("Category", style="green")
        table.add_column("Severity", style="yellow")
        table.add_column("Description", max_width=60)

        for i, mod in enumerate(modules, 1):
            sev_style = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "blue",
            }.get(mod.severity_default.value.lower(), "white")

            table.add_row(
                str(i),
                mod.name,
                f"{mod.category.value} ({mod.category.owasp_id})",
                f"[{sev_style}]{mod.severity_default.value}[/{sev_style}]",
                mod.description[:120],
            )
        console.print(table)
        console.print(f"\n[bold]{len(modules)}[/bold] modules loaded.")

        # Summary by category
        from collections import Counter
        cats = Counter(m.category.value for m in modules)
        cat_summary = " · ".join(f"{v}: {c}" for v, c in cats.most_common())
        console.print(f"[dim]Categories: {cat_summary}[/dim]")
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


@cli.command("diff")
@click.option("-t", "--target", multiple=True, required=True, help="provider:model pair (e.g. openai:gpt-4)")
@click.option("-k", "--api-key", default="", help="API key (shared across providers, or use env vars)")
@click.option("--category", multiple=True, help="Probe categories (default: all)")
@click.option("-o", "--output-dir", default="./basilisk-reports", help="Report output directory")
@click.option("-v", "--verbose", is_flag=True)
def diff(target, api_key, category, output_dir, verbose) -> None:
    """Differential scan — same attacks across multiple models side-by-side."""
    import asyncio

    console.print(BANNER, style="bold red")
    console.print()

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
    with open(path, "w") as f:
        json.dump(report.to_dict(), f, indent=2, default=str)
    console.print(f"\n[green]✓[/green] Diff report saved to: {path}")


@cli.command("posture")
@click.option("-t", "--target", default="", help="Target URL (optional if using direct provider)")
@click.option("-p", "--provider", default="openai", help="LLM provider")
@click.option("-m", "--model", default="", help="Model name")
@click.option("-k", "--api-key", default="", help="API key")
@click.option("--auth", default="", help="Authorization header")
@click.option("--output-dir", default="./basilisk-reports", help="Report output directory")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON only (for CI)")
@click.option("-v", "--verbose", is_flag=True)
def posture(target, provider, model, api_key, auth, output_dir, json_output, verbose) -> None:
    """Guardrail posture scan — recon-only, no attacks. CISO-friendly."""
    import asyncio

    if not json_output:
        console.print(BANNER, style="bold red")
        console.print()

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
        "  basilisk scan -t https://api.openai.com/v1 -p openai -k $OPENAI_API_KEY\n\n"
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
        "  --attacker-api-key $ANTHROPIC_API_KEY\n\n"
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


def main() -> None:
    """Entrypoint for the basilisk CLI."""
    cli()


if __name__ == "__main__":
    main()
