#!/usr/bin/env python3
"""
CyberSagacity Rule Aggregator - CLI
Command-line interface for managing security rule collection.
"""

import sys
import logging
import click
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.live import Live
from rich.layout import Layout
from rich.text import Text

from database import init_db, get_db, get_dashboard_stats, search_rules
from collectors import ALL_COLLECTORS

console = Console()


def setup_logging(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
def cli(verbose):
    """CyberSagacity Rule Aggregator - Security scanning rule intelligence."""
    setup_logging(verbose)


@cli.command()
def setup():
    """Initialize the database and register all vendors."""
    init_db()
    console.print("[green]Database initialized.[/green]")

    for CollectorClass in ALL_COLLECTORS:
        c = CollectorClass()
        c.register_vendor()
        console.print(f"  Registered: [cyan]{c.display_name}[/cyan]")

    console.print(f"\n[green]Registered {len(ALL_COLLECTORS)} vendors.[/green]")


@cli.command()
@click.option("--vendor", "-V", help="Sync only this vendor (by name)")
@click.option("--force", "-f", is_flag=True, help="Force sync even if no changes detected")
def sync(vendor, force):
    """Sync rules from all (or specified) vendors."""
    init_db()

    collectors = ALL_COLLECTORS
    if vendor:
        collectors = [c for c in ALL_COLLECTORS if c.name == vendor]
        if not collectors:
            console.print(f"[red]Unknown vendor: {vendor}[/red]")
            console.print("Available vendors:")
            for c in ALL_COLLECTORS:
                console.print(f"  - {c.name}")
            sys.exit(1)

    total_stats = {"added": 0, "updated": 0, "unchanged": 0, "removed": 0}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("Syncing vendors...", total=len(collectors))

        for CollectorClass in collectors:
            c = CollectorClass()
            progress.update(task, description=f"Syncing [cyan]{c.display_name}[/cyan]...")

            try:
                stats = c.sync(force=force)
                for k in total_stats:
                    total_stats[k] += stats.get(k, 0)
                console.print(
                    f"  [green]✓[/green] {c.display_name}: "
                    f"+{stats['added']} ~{stats['updated']} ={stats['unchanged']}"
                )
            except Exception as e:
                console.print(f"  [red]✗[/red] {c.display_name}: {e}")

            progress.advance(task)

    console.print()
    console.print(Panel(
        f"[bold green]Sync Complete[/bold green]\n\n"
        f"  Added:     [green]{total_stats['added']}[/green]\n"
        f"  Updated:   [yellow]{total_stats['updated']}[/yellow]\n"
        f"  Unchanged: [dim]{total_stats['unchanged']}[/dim]\n"
        f"  Removed:   [red]{total_stats['removed']}[/red]",
        title="Summary",
        border_style="green",
    ))


@cli.command()
def status():
    """Show current database status and vendor info."""
    init_db()
    stats = get_dashboard_stats()

    # Summary panel
    console.print(Panel(
        f"[bold]Total Rules:[/bold] [green]{stats['total_rules']:,}[/green]  |  "
        f"[bold]Vendors:[/bold] [cyan]{stats['total_vendors']}[/cyan]",
        title="CyberSagacity Rule Aggregator",
        subtitle="cybersagacity.com",
        border_style="blue",
    ))

    # Vendors table
    table = Table(title="Registered Vendors", show_lines=True)
    table.add_column("Vendor", style="cyan", min_width=25)
    table.add_column("Rules", justify="right", style="green")
    table.add_column("Last Sync", style="yellow")
    table.add_column("Status", justify="center")

    for v in stats["vendors"]:
        last_sync = v.get("last_successful_sync", "Never")
        if last_sync and last_sync != "Never":
            last_sync = last_sync[:19]
        rules = str(v.get("active_rules", 0))
        status_icon = "[green]●[/green]" if v.get("active_rules", 0) > 0 else "[dim]○[/dim]"
        table.add_row(v["display_name"], rules, str(last_sync), status_icon)

    console.print(table)

    # Severity distribution
    if stats["severity_distribution"]:
        sev_table = Table(title="Severity Distribution")
        sev_table.add_column("Severity")
        sev_table.add_column("Count", justify="right")
        sev_colors = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "blue", "info": "dim"}
        for s in stats["severity_distribution"]:
            color = sev_colors.get(s["severity"], "white")
            sev_table.add_row(f"[{color}]{s['severity']}[/{color}]", str(s["count"]))
        console.print(sev_table)


@cli.command()
@click.argument("query", required=False, default="")
@click.option("--vendor", "-V", help="Filter by vendor name")
@click.option("--severity", "-s", type=click.Choice(["critical", "high", "medium", "low", "info"]))
@click.option("--language", "-l", help="Filter by programming language")
@click.option("--limit", "-n", default=20, help="Number of results")
def search(query, vendor, severity, language, limit):
    """Search rules across all vendors."""
    init_db()
    results = search_rules(
        query=query, vendor=vendor, severity=severity,
        language=language, per_page=limit,
    )

    console.print(f"\n[bold]{results['total']} rules found[/bold] (showing {len(results['rules'])})\n")

    sev_colors = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "blue", "info": "dim"}

    for r in results["rules"]:
        color = sev_colors.get(r["severity"], "white")
        console.print(
            f"  [{color}]{r['severity']:8s}[/{color}] "
            f"[cyan]{r['vendor_display_name']:20s}[/cyan] "
            f"[bold]{r['rule_id']}[/bold]"
        )
        console.print(f"           {r['title'][:100]}")
        if r.get("language"):
            console.print(f"           [dim]Language: {r['language']}[/dim]")
        console.print()


@cli.command()
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", default=8080, help="Port to listen on")
@click.option("--debug", is_flag=True, help="Enable debug mode")
def serve(host, port, debug):
    """Start the web dashboard."""
    init_db()
    from app import app
    console.print(f"\n[bold green]Starting CyberSagacity Rule Dashboard[/bold green]")
    console.print(f"  → http://{host}:{port}\n")
    app.run(host=host, port=port, debug=debug)


@cli.command()
def vendors():
    """List all available vendor collectors."""
    table = Table(title="Available Collectors")
    table.add_column("Name", style="cyan")
    table.add_column("Display Name", style="bold")
    table.add_column("Source", style="green")
    table.add_column("Description", max_width=60)

    for CollectorClass in ALL_COLLECTORS:
        c = CollectorClass()
        table.add_row(c.name, c.display_name, c.source_type, c.description[:60] + "...")

    console.print(table)


@cli.command()
@click.argument("rule_id")
def show(rule_id):
    """Show detailed info about a specific rule."""
    init_db()
    with get_db() as conn:
        row = conn.execute("""
            SELECT r.*, v.display_name as vendor_name
            FROM rules r JOIN vendors v ON r.vendor_id=v.id
            WHERE r.rule_id=? LIMIT 1
        """, (rule_id,)).fetchone()

    if not row:
        console.print(f"[red]Rule not found: {rule_id}[/red]")
        sys.exit(1)

    r = dict(row)
    console.print(Panel(
        f"[bold]{r['title']}[/bold]\n\n"
        f"  Vendor:    [cyan]{r['vendor_name']}[/cyan]\n"
        f"  Rule ID:   {r['rule_id']}\n"
        f"  Severity:  {r['severity']}\n"
        f"  Language:  {r['language'] or 'N/A'}\n"
        f"  Category:  {r['category'] or 'N/A'}\n"
        f"  CWEs:      {r['cwe_ids']}\n"
        f"  Format:    {r['rule_format']}\n"
        f"  Source:    {r['source_file']}\n"
        f"  First seen: {r['first_seen_at']}\n"
        f"  Updated:    {r['last_updated_at']}\n\n"
        f"[dim]{r['description'][:500]}[/dim]",
        title=f"Rule: {rule_id}",
        border_style="blue",
    ))

    if r.get("rule_content"):
        console.print("\n[bold]Rule Content:[/bold]")
        console.print(r["rule_content"][:2000])


@cli.command()
def export():
    """Export all rules as JSON to stdout."""
    import json
    init_db()
    with get_db() as conn:
        rows = conn.execute("""
            SELECT r.*, v.name as vendor_name, v.display_name as vendor_display_name
            FROM rules r JOIN vendors v ON r.vendor_id=v.id
            WHERE r.is_active=1
            ORDER BY v.name, r.rule_id
        """).fetchall()

    rules = [dict(r) for r in rows]
    click.echo(json.dumps(rules, indent=2, default=str))


if __name__ == "__main__":
    cli()
