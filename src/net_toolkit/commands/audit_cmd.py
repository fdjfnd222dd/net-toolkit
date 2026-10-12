"""`nt audit`: static security audit of Cisco IOS configs."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.table import Table

from net_toolkit import samples
from net_toolkit.audit import Report, Severity, audit_text
from net_toolkit.ui import console, err_console

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def audit_command(
    configs: list[Path] = typer.Argument(None, help="One or more IOS config files.", show_default=False),
    as_json: bool = typer.Option(False, "--json", help="Print JSON instead of tables."),
    min_severity: str = typer.Option("info", "--min-severity", help="Hide findings below this level."),
    fail_on: str = typer.Option(None, "--fail-on", help="Exit 1 if any finding is at or above this level (for CI)."),
    demo: bool = typer.Option(False, "--demo", help="Audit the bundled edge-rtr1.cfg example."),
) -> None:
    """Telnet, password encryption, SSHv1, VLAN 1 trunks, logging, NTP, SNMP, unused ACLs."""
    try:
        floor = Severity.parse(min_severity)
        threshold = Severity.parse(fail_on) if fail_on else None
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    if demo:
        configs = [samples.example("configs", "edge-rtr1.cfg")]
    if not configs:
        raise typer.BadParameter("give at least one config file (or use --demo)", param_hint="CONFIGS")

    reports = []
    for path in configs:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            err_console.print(f"[bold red]error:[/bold red] cannot read {path}: {exc.strerror}")
            raise typer.Exit(2) from exc
        report = audit_text(text, source=str(path) if not demo else path.name)
        report.findings = [f for f in report.findings if f.severity >= floor]
        reports.append(report)

    if as_json:
        payload = [r.to_dict() for r in reports]
        # plain echo, not Rich: machine output must never be wrapped or styled
        typer.echo(json.dumps(payload[0] if len(payload) == 1 else payload, indent=2))
    else:
        for report in reports:
            console.print(render_report(report))

    if threshold is not None and any((r.worst() or -1) >= threshold for r in reports):
        raise typer.Exit(1)


def render_report(report: Report) -> Table | str:
    name = report.hostname or "?"
    if not report.findings:
        return f"[bold]{name}[/bold]  [dim]{report.source}[/dim]  [green]no findings[/green]\n"
    table = Table(title=f"[bold]{name}[/bold]  [dim]{report.source}[/dim]", title_justify="left")
    table.add_column("severity", no_wrap=True)
    table.add_column("rule", style="dim", no_wrap=True)
    table.add_column("line", justify="right")
    table.add_column("finding", ratio=3)
    table.add_column("fix", ratio=2, style="green")
    for finding in report.findings:
        table.add_row(
            f"[{SEVERITY_STYLE[finding.severity]}]{finding.severity.name}[/]",
            finding.rule,
            str(finding.line) if finding.line else "-",
            finding.message,
            finding.fix,
        )
    counts = report.counts()
    table.caption = "  ".join(f"{k}: {v}" for k, v in counts.items() if v)
    table.caption_justify = "left"
    return table
