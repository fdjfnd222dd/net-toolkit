"""`nt scan`: who is alive on a subnet and which common TCP ports answer."""

from __future__ import annotations

import json
import time

import typer
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeRemainingColumn
from rich.table import Table

from net_toolkit import scan
from net_toolkit.pcap import SERVICES
from net_toolkit.scan import HostResult
from net_toolkit.ui import console, err_console

EXTRA_NAMES = {135: "msrpc", 139: "netbios", 830: "netconf", 1433: "mssql", 5432: "postgres", 5900: "vnc"}


def port_label(port: int) -> str:
    name = SERVICES.get(port) or EXTRA_NAMES.get(port)
    return f"{port}/{name}" if name else str(port)


def scan_command(
    target: str = typer.Argument(None, help="Prefix to sweep, e.g. 192.168.1.0/24.", show_default=False),
    ports: str = typer.Option("common", "--ports", "-p", help="'common', or a list like 22,80,8000-8010."),
    rate: float = typer.Option(100.0, "--rate", "-r", min=0.1, help="Max probes per second (all threads)."),
    timeout: float = typer.Option(1.0, "--timeout", "-t", min=0.05, help="Seconds to wait per probe."),
    workers: int = typer.Option(64, "--workers", "-w", min=1, max=512, help="Concurrent probes."),
    icmp: bool = typer.Option(True, "--icmp/--no-icmp", help="Ping each host as well as TCP connect."),
    i_own_this: bool = typer.Option(False, "--i-own-this", help="Confirm you may scan a non-private range."),
    max_hosts: int = typer.Option(scan.MAX_HOSTS, "--max-hosts", min=1, help="Refuse larger prefixes."),
    as_json: bool = typer.Option(False, "--json", help="Print JSON instead of a table."),
    demo: bool = typer.Option(False, "--demo", help="Sweep a canned lab; no packets are sent."),
) -> None:
    """ICMP + TCP connect sweep with a rate limit. Refuses public ranges unless --i-own-this."""
    try:
        port_list = scan.parse_ports(ports)
        if demo:
            target = scan.DEMO_NETWORK
        if not target:
            raise typer.BadParameter("give a prefix to scan (or use --demo)", param_hint="TARGET")
        network = scan.check_target(target, i_own_this, max_hosts)
    except (ValueError, scan.ScanRefused) as exc:
        if isinstance(exc, typer.BadParameter):
            raise
        err_console.print(f"[bold red]refused:[/bold red] {exc}")
        raise typer.Exit(2) from exc

    hosts = sum(1 for _ in network.hosts())  # capped at --max-hosts, so cheap
    total = hosts * (len(port_list) + (1 if icmp else 0))
    started = time.monotonic()
    if demo:
        results = scan.sweep(network, port_list, rate=None, icmp=icmp,
                             pinger=scan.demo_pinger, connector=scan.demo_connector)
    else:
        with Progress(
            TextColumn("[cyan]scanning {task.description}"), BarColumn(), MofNCompleteColumn(),
            TimeRemainingColumn(), console=err_console, transient=True,
        ) as progress:
            task = progress.add_task(str(network), total=total)
            results = scan.sweep(
                network, port_list, rate=rate, timeout=timeout, workers=workers, icmp=icmp,
                on_probe=lambda: progress.advance(task),
            )
    elapsed = time.monotonic() - started
    alive = [r for r in results if r.up]

    if as_json:
        typer.echo(json.dumps({
            "target": str(network),
            "probes": total,
            "hosts_scanned": len(results),
            "hosts_up": [
                {"address": r.address, "icmp_rtt_ms": r.rtt_ms, "open_ports": r.open_ports}
                for r in alive
            ],
        }, indent=2))
        return
    console.print(render(network, alive, len(results), total, elapsed, None if demo else rate))


def render(network, alive: list[HostResult], scanned: int, probes: int, elapsed: float,
           rate: float | None) -> Table:
    table = Table(title=f"[bold]scan {network}[/bold]", title_justify="left")
    table.add_column("host", no_wrap=True)
    table.add_column("icmp", justify="right")
    table.add_column("open tcp ports")
    table.add_column("note", style="dim")
    for host in alive:
        rtt = f"{host.rtt_ms:.2f} ms" if host.rtt_ms is not None else "[dim]no reply[/dim]"
        ports = ", ".join(port_label(p) for p in host.open_ports) or "[dim]-[/dim]"
        note = ""
        if host.rtt_ms is None:
            note = "ICMP filtered, alive via TCP"
        elif not host.open_ports:
            note = "alive, every probed port closed"
        table.add_row(host.address, rtt, ports, note)
    limit = f" at <= {rate:g}/s" if rate else ""
    table.caption = f"{len(alive)}/{scanned} hosts up, {probes:,} probes in {elapsed:.1f}s{limit}"
    table.caption_justify = "left"
    return table
