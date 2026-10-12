"""`nt pcap summary`: who talked, over what, and what went wrong, from a capture file."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.table import Table

from net_toolkit import samples
from net_toolkit.pcap import SERVICES, PcapError, Summary, summarize
from net_toolkit.ui import console, err_console, kv_table

pcap_app = typer.Typer(help="Capture file triage.", no_args_is_help=True)


def human_bytes(count: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if count < 1024 or unit == "GB":
            return f"{count:.0f} {unit}" if unit == "B" else f"{count:.1f} {unit}"
        count /= 1024
    return f"{count:.1f} GB"  # pragma: no cover - loop always returns


@pcap_app.command("summary")
def summary_command(
    capture: Path = typer.Argument(None, help="A .pcap or .pcapng file.", show_default=False),
    top: int = typer.Option(10, "--top", "-n", min=1, help="Rows per table."),
    as_json: bool = typer.Option(False, "--json", help="Print JSON instead of tables."),
    demo: bool = typer.Option(False, "--demo", help="Summarise the bundled invented sample.pcap."),
) -> None:
    """Top talkers, protocols, DNS queries and TCP resets."""
    if demo:
        capture = samples.example("sample.pcap")
    if capture is None:
        raise typer.BadParameter("give a capture file (or use --demo)", param_hint="CAPTURE")
    try:
        result = summarize(capture)
    except (OSError, PcapError) as exc:
        err_console.print(f"[bold red]error:[/bold red] {exc}")
        raise typer.Exit(2) from exc
    if demo:
        result.source = capture.name
    if as_json:
        typer.echo(json.dumps(result.to_dict(top), indent=2))
        return
    for renderable in render(result, top):
        console.print(renderable)


def _when(ts: float | None) -> str:
    if not ts:
        return "-"
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def render(s: Summary, top: int) -> list:
    rate = f"{s.packets / s.duration:.1f} pkt/s" if s.duration else "-"
    rows = [
        ("file", f"{s.source} ({s.format})"),
        ("packets", f"{s.packets:,}"),
        ("bytes", human_bytes(s.bytes)),
        ("first / last", f"{_when(s.first_ts)}  ->  {_when(s.last_ts)}"),
        ("duration", f"{s.duration:.2f} s  ({rate})"),
    ]
    if s.vlans:
        rows.append(("802.1Q VLANs", ", ".join(f"{v} ({n} pkts)" for v, n in sorted(s.vlans.items()))))
    if s.truncated:
        rows.append(("warning", "[yellow]file ends mid-packet (capture was cut off)[/yellow]"))
    out: list = [kv_table(rows, title="[bold]capture[/bold]")]

    talkers = _table("top talkers", ("host", "pkts sent", "sent", "received", "total"))
    for host, stats in s.top_hosts(top):
        talkers.add_row(host, str(stats.packets), human_bytes(stats.sent),
                        human_bytes(stats.received), human_bytes(stats.total))
    out.append(talkers)

    protocols = _table("protocols", ("protocol", "packets", "bytes", "share"))
    for proto, count in s.protocols.most_common(top):
        share = s.protocol_bytes[proto] / s.bytes * 100 if s.bytes else 0
        protocols.add_row(proto, str(count), human_bytes(s.protocol_bytes[proto]), f"{share:.1f}%")
    out.append(protocols)

    if s.services:
        services = _table("services", ("service (by port)", "packets"))
        for name, count in s.services.most_common(top):
            services.add_row(name, str(count))
        out.append(services)

    if s.sites:
        sites = _table("sites", ("site", "connections", "bytes", "seen via"))
        for name, stats, volume in s.top_sites(top):
            sites.add_row(name, str(stats.connections), human_bytes(volume) if volume else "-",
                          ", ".join(sorted(stats.via)))
        out.append(sites)

    dns = _table("DNS queries", ("name", "type", "count", "NXDOMAIN"))
    for (name, qtype), count in s.dns_queries.most_common(top):
        nx = s.dns_nxdomain[name]
        dns.add_row(name, qtype, str(count), f"[red]{nx}[/red]" if nx else "-")
    out.append(dns if s.dns_queries else "[dim]no DNS queries[/dim]\n")

    resets = _table("TCP resets", ("from", "to", "port", "count"))
    for (src, dst, port), count in s.resets.most_common(top):
        label = f"{port} ({SERVICES[port]})" if port in SERVICES else str(port)
        resets.add_row(src, dst, label, str(count))
    out.append(resets if s.resets else "[dim]no TCP resets[/dim]\n")
    return out


def _table(title: str, columns: tuple[str, ...]) -> Table:
    table = Table(title=f"[bold]{title}[/bold]", title_justify="left")
    for index, name in enumerate(columns):
        left = index == 0 or name in ("to", "type", "port", "seen via")
        table.add_column(name, justify="left" if left else "right")
    return table
