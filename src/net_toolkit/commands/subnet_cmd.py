"""`nt subnet`: describe a prefix, optionally split it or allocate it VLSM-style."""

from __future__ import annotations

import typer
from rich.table import Table

from net_toolkit import subnet as calc
from net_toolkit.ui import console, err_console, kv_table

DEMO_ARGS = ("10.20.0.0/22", 4, "Users=200,Voice=50,Printers=20,Mgmt=10,WAN=2")


def subnet_command(
    cidr: str = typer.Argument(None, help="Prefix such as 10.20.0.0/22 or '10.20.1.5 255.255.252.0'."),
    split: int = typer.Option(None, "--split", "-s", help="Carve into N equal subnets."),
    vlsm: str = typer.Option(None, "--vlsm", "-v", help="Host counts, e.g. 50,20,10 or Sales=50,Eng=20."),
    demo: bool = typer.Option(False, "--demo", help="Run on a canned example."),
) -> None:
    """Network, broadcast, usable range, wildcard mask, equal splits and VLSM."""
    if demo:
        cidr, split, vlsm = DEMO_ARGS
        console.print(f"[dim]demo: nt subnet {cidr} --split {split} --vlsm {vlsm}[/dim]\n")
    if not cidr:
        raise typer.BadParameter("a prefix is required (or use --demo)", param_hint="CIDR")
    try:
        info = calc.describe(cidr)
        console.print(render_info(info))
        if split:
            console.print(render_split(info.network, split))
        if vlsm:
            console.print(render_vlsm(info.network, calc.parse_vlsm(vlsm)))
    except ValueError as exc:
        err_console.print(f"[bold red]error:[/bold red] {exc}")
        raise typer.Exit(2) from exc


def render_info(info: calc.SubnetInfo) -> Table:
    net = info.network
    rows = []
    if info.address != net.network_address:
        rows.append(("address", f"{info.address} (host bits set)"))
    rows += [
        ("network", f"{net.network_address}/{net.prefixlen}"),
        ("netmask", str(info.netmask)),
        ("wildcard", str(info.wildcard)),
    ]
    if info.broadcast is not None:
        rows.append(("broadcast", str(info.broadcast)))
    rows += [
        ("usable range", f"{info.first_usable} - {info.last_usable}"),
        ("usable hosts", f"{info.usable:,}"),
        ("total addresses", f"{info.total:,}"),
        ("scope", info.scope),
    ]
    if info.ip_class:
        rows.append(("class", info.ip_class))
    if info.version == 4 and info.prefixlen == 31:
        rows.append(("note", "point-to-point link, both addresses usable (RFC 3021)"))
    return kv_table(rows, title=f"[bold]{net}[/bold]")


def render_split(network: calc.Network, count: int) -> Table:
    pieces = calc.split(network, count)
    title = f"[bold]{network} split into {count}[/bold]"
    if len(pieces) != count:
        title += f" [dim](rounded up to {len(pieces)}, subnets come in powers of two)[/dim]"
    table = Table(title=title, title_justify="left")
    for col in ("#", "subnet", "usable range", "broadcast", "hosts"):
        table.add_column(col, justify="right" if col in ("#", "hosts") else "left")
    for index, piece in enumerate(pieces, start=1):
        info = calc.describe(str(piece))
        style = "dim" if index > count else None
        table.add_row(
            str(index) + (" spare" if index > count else ""),
            str(piece),
            f"{info.first_usable} - {info.last_usable}",
            str(info.broadcast or "-"),
            f"{info.usable:,}",
            style=style,
        )
    return table


def render_vlsm(network: calc.Network, requests: list[tuple[str, int]]) -> Table:
    allocations, free = calc.vlsm(network, requests)
    table = Table(title=f"[bold]VLSM in {network}[/bold] (largest first)", title_justify="left")
    for col in ("name", "need", "subnet", "mask", "usable range", "usable", "waste"):
        table.add_column(col, justify="right" if col in ("need", "usable", "waste") else "left")
    for alloc in allocations:
        info = calc.describe(str(alloc.subnet))
        table.add_row(
            alloc.name,
            str(alloc.requested),
            str(alloc.subnet),
            str(alloc.subnet.netmask),
            f"{info.first_usable} - {info.last_usable}",
            str(alloc.usable),
            str(alloc.waste),
        )
    free_text = ", ".join(str(block) for block in free) if free else "none"
    table.caption = f"free: {free_text}"
    table.caption_justify = "left"
    return table
