"""`nt ping-matrix`: loss/latency/jitter table over N rounds, optionally refreshed live."""

from __future__ import annotations

import time
from pathlib import Path

import typer
from rich.live import Live
from rich.table import Table

from net_toolkit import inventory, pingmatrix, samples
from net_toolkit.pingmatrix import Series
from net_toolkit.ui import console, err_console


def ms(value: float | None) -> str:
    return f"{value:.2f}" if value is not None else "-"


def render(series: list[Series], rounds_done: int, rounds_total: int) -> Table:
    progress = f"{rounds_done}/{rounds_total}" if rounds_total else f"{rounds_done}, Ctrl-C to stop"
    table = Table(title=f"[bold]ping matrix[/bold]  [dim]round {progress}[/dim]", title_justify="left")
    for col in ("device", "address", "sent", "loss", "min", "avg", "max", "jitter", "recent"):
        table.add_column(col + (" ms" if col in ("min", "avg", "max", "jitter") else ""),
                         justify="left" if col in ("device", "address", "recent") else "right")
    for item in series:
        loss = item.loss_pct
        style = "red" if loss >= 20 else "yellow" if loss > 0 else "green"
        table.add_row(
            item.name, item.host, str(item.sent), f"[{style}]{loss:.0f}%[/{style}]",
            ms(item.min), ms(item.avg), ms(item.max), ms(item.jitter),
            pingmatrix.sparkline(item.samples),
        )
    return table


def ping_matrix_command(
    inventory_file: Path = typer.Argument(None, help="hosts.yml (or a YAML list of addresses).", show_default=False),
    rounds: int = typer.Option(5, "--rounds", "-n", min=0, help="Rounds to run (0 = until Ctrl-C, with --watch)."),
    interval: float = typer.Option(1.0, "--interval", min=0.0, help="Seconds between rounds."),
    timeout: float = typer.Option(1.0, "--timeout", "-t", min=0.1, help="Seconds to wait for each reply."),
    watch: bool = typer.Option(False, "--watch", help="Refresh the table live after every round."),
    demo: bool = typer.Option(False, "--demo", help="Use canned latencies; no packets are sent."),
) -> None:
    """Latency and loss to every host in the inventory over N rounds."""
    if demo:
        inventory_file = samples.example("hosts.yml")
    if inventory_file is None:
        raise typer.BadParameter("give an inventory file (or use --demo)", param_hint="INVENTORY_FILE")
    if rounds == 0 and not watch:
        raise typer.BadParameter("--rounds 0 (run forever) only makes sense with --watch")
    try:
        devices = inventory.load(inventory_file)
    except inventory.InventoryError as exc:
        err_console.print(f"[bold red]error:[/bold red] {exc}")
        raise typer.Exit(2) from exc

    series = [Series(d.name, d.host) for d in devices]
    pinger = pingmatrix.DemoPinger({d.host: d.name for d in devices}) if demo else pingmatrix.probes.ping
    if demo and not watch:
        interval = 0.0  # nothing real to wait for

    done = 0

    def keep_going() -> bool:
        return rounds == 0 or done < rounds

    try:
        if watch:
            with Live(render(series, 0, rounds), console=console, refresh_per_second=4) as live:
                while keep_going():
                    pingmatrix.run_round(series, pinger, timeout)
                    done += 1
                    live.update(render(series, done, rounds))
                    if keep_going():
                        time.sleep(interval)
            return
        with console.status("pinging...") if not demo else _NullContext():
            while keep_going():
                pingmatrix.run_round(series, pinger, timeout)
                done += 1
                if keep_going() and interval:
                    time.sleep(interval)
    except KeyboardInterrupt:
        if watch:  # the live view already shows the latest table
            return
    console.print(render(series, done, rounds))


class _NullContext:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False
