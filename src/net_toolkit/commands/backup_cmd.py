"""`nt backup` and `nt diff`: config history for Cisco IOS/NX-OS and Arista EOS."""

from __future__ import annotations

import os
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import typer
from rich.table import Table
from rich.text import Text

from net_toolkit import backup, inventory, samples
from net_toolkit.inventory import Device
from net_toolkit.ui import console, err_console

DEMO_CONFIGS = {"CORE-SW1": "core-sw1.cfg", "DIST-SW2": "dist-sw2.cfg", "EDGE-RTR1": "edge-rtr1.cfg"}
DEMO_FAILURES = {
    "NX-LEAF1": "Authentication to device failed.",
    "EOS-SPINE1": "TCP connection to device failed (timed out after 10s).",
}


class DemoConnection:
    """Stands in for a Netmiko connection; serves the bundled example configs."""

    def __init__(self, device: Device):
        self.device = device

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def send_command(self, command: str, **kwargs) -> str:
        header = "Building configuration...\n\nCurrent configuration : 4120 bytes\n"
        return header + samples.example("configs", DEMO_CONFIGS[self.device.name]).read_text()


def demo_connect(device: Device, password: str) -> DemoConnection:
    if device.name in DEMO_FAILURES:
        raise ConnectionError(DEMO_FAILURES[device.name])
    return DemoConnection(device)


def _passwords(devices: list[Device]) -> dict[str, str]:
    """One prompt per environment variable name that is not already set."""
    found: dict[str, str] = {}
    for env in sorted({d.password_env for d in devices}):
        found[env] = os.environ.get(env) or typer.prompt(
            f"Password ({env} is not set)", hide_input=True
        )
    return found


def backup_command(
    inventory_file: Path = typer.Option(None, "--inventory", "-i", help="hosts.yml with the devices."),
    out: Path = typer.Option(Path("backups"), "--out", "-o", help="Backup root directory."),
    only: list[str] = typer.Option(None, "--only", help="Back up just these device names (repeatable)."),
    workers: int = typer.Option(4, "--workers", "-w", min=1, max=32, help="Devices at a time."),
    demo: bool = typer.Option(False, "--demo", help="Use canned devices and a throwaway directory."),
) -> None:
    """Save running-configs to backups/<host>/<date>.cfg over SSH (Netmiko)."""
    if demo:
        # canned devices, written to a throwaway directory that is removed afterwards
        with tempfile.TemporaryDirectory(prefix="nt-demo-") as tmp:
            _backup(samples.example("hosts.yml"), Path(tmp) / "backups", only, workers, demo_connect, True)
        return
    if inventory_file is None:
        raise typer.BadParameter("give an inventory with -i hosts.yml (or use --demo)")
    _backup(inventory_file, out, only, workers, backup.netmiko_connect, False)


def _backup(inventory_file: Path, out: Path, only: list[str] | None, workers: int,
            connect: backup.Connect, demo: bool) -> None:
    try:
        devices = inventory.load(inventory_file)
    except inventory.InventoryError as exc:
        err_console.print(f"[bold red]error:[/bold red] {exc}")
        raise typer.Exit(2) from exc
    if only:
        unknown = set(only) - {d.name for d in devices}
        if unknown:
            raise typer.BadParameter(f"not in inventory: {', '.join(sorted(unknown))}")
        devices = [d for d in devices if d.name in only]

    passwords = {d.password_env: "demo" for d in devices} if demo else _passwords(devices)

    def run(device: Device):
        try:
            text = backup.fetch(device, passwords[device.password_env], connect)
            return device, backup.save(out, device.name, text), None
        except Exception as exc:  # one bad device must not stop the rest
            message = str(exc).strip()
            return device, None, message.splitlines()[0] if message else type(exc).__name__

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(run, devices))

    title = "backups (demo: temporary directory)" if demo else str(out)
    table = Table(title=f"[bold]backup -> {title}[/bold]", title_justify="left")
    for col in ("device", "platform", "status", "file", "lines"):
        table.add_column(col, justify="right" if col == "lines" else "left")
    failures = 0
    for device, saved, error in results:
        if saved is None:
            failures += 1
            table.add_row(device.name, device.device_type, "[red]failed[/red]", f"[red]{error}[/red]", "-")
            continue
        status = "[green]saved[/green]" if saved.changed else "[dim]unchanged[/dim]"
        shown = saved.path.relative_to(out.parent) if demo else saved.path
        table.add_row(device.name, device.device_type, status, str(shown), str(saved.lines))
    table.caption = f"{len(results) - failures} ok, {failures} failed"
    table.caption_justify = "left"
    console.print(table)
    if failures and not demo:  # the demo's failures are simulated on purpose
        raise typer.Exit(1)


def diff_command(
    host: str = typer.Argument(None, help="Device name as used in hosts.yml.", show_default=False),
    root: Path = typer.Option(Path("backups"), "--dir", "-d", help="Backup root directory."),
    context: int = typer.Option(3, "--context", "-U", min=0, help="Lines of context."),
    demo: bool = typer.Option(False, "--demo", help="Diff the two bundled CORE-SW1 backups."),
) -> None:
    """Unified diff of the last two backups of HOST, colour-highlighted."""
    if demo:
        host, root = "CORE-SW1", samples.example("backups")
    if not host:
        raise typer.BadParameter("give a device name (or use --demo)", param_hint="HOST")
    try:
        _, _, lines = backup.diff_latest(root, host, context)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[bold red]error:[/bold red] {exc}")
        raise typer.Exit(2) from exc
    if not lines:
        console.print(f"[green]{host}: no differences between the last two backups[/green]")
        return
    added = sum(1 for line in lines if line.startswith("+") and not line.startswith("+++"))
    removed = sum(1 for line in lines if line.startswith("-") and not line.startswith("---"))
    for line in lines:
        console.print(colour(line), soft_wrap=True)
    console.print(f"\n[green]+{added}[/green] [red]-{removed}[/red] lines")


def colour(line: str) -> Text:
    if line.startswith(("+++", "---")):
        return Text(line, style="bold")
    if line.startswith("@@"):
        return Text(line, style="cyan")
    if line.startswith("+"):
        return Text(line, style="green")
    if line.startswith("-"):
        return Text(line, style="red")
    return Text(line)
