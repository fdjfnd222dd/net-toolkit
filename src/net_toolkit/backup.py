"""Pull running-configs over SSH with Netmiko and keep a dated history per device.

Layout: <root>/<device>/<YYYY-MM-DD>.cfg, plus <YYYY-MM-DD>_<HHMMSS>.cfg when the
config changes twice in one day. Both sort correctly as plain strings.
"""

from __future__ import annotations

import difflib
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from net_toolkit.inventory import SAFE_NAME, Device

SHOW_RUN = {
    "cisco_ios": "show running-config",
    "cisco_xe": "show running-config",
    "cisco_nxos": "show running-config",
    "arista_eos": "show running-config",
}
# Lines that change on every pull without a real config change; dropping them keeps diffs honest.
VOLATILE = re.compile(
    r"^(Building configuration|Current configuration\s*:|! Last configuration change|"
    r"! NVRAM config last updated|! No configuration change since|!Time:|!Running configuration last done|"
    r"ntp clock-period)"
)


def clean(text: str) -> str:
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").split("\n")]
    kept = [line for line in lines if not VOLATILE.match(line)]
    while kept and not kept[0]:
        kept.pop(0)
    while kept and not kept[-1]:
        kept.pop()
    return "\n".join(kept) + "\n"


Connect = Callable[[Device, str], object]


def netmiko_connect(device: Device, password: str):  # pragma: no cover - needs a real device
    from netmiko import ConnectHandler  # imported lazily: it takes ~1s to load

    return ConnectHandler(
        device_type=device.device_type,
        host=device.host,
        port=device.port,
        username=device.username,
        password=password,
        secret=password,
        conn_timeout=10,
        fast_cli=False,
    )


def fetch(device: Device, password: str, connect: Connect = netmiko_connect) -> str:
    connection = connect(device, password)
    with connection:  # Netmiko connections disconnect on exit
        return connection.send_command(SHOW_RUN[device.device_type], read_timeout=60)


def history(root: Path, name: str) -> list[Path]:
    if not SAFE_NAME.match(name):
        raise ValueError(f"unsafe device name {name!r}")
    folder = root / name
    return sorted(folder.glob("*.cfg")) if folder.is_dir() else []


@dataclass
class Saved:
    path: Path
    changed: bool
    lines: int


def save(root: Path, name: str, text: str, now: datetime | None = None) -> Saved:
    """Write a new backup unless it is identical to the latest one."""
    now = now or datetime.now()
    config = clean(text)
    previous = history(root, name)
    if previous and previous[-1].read_text(encoding="utf-8") == config:
        return Saved(previous[-1], False, config.count("\n"))
    folder = root / name
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{now:%Y-%m-%d}.cfg"
    if path.exists():
        path = folder / f"{now:%Y-%m-%d_%H%M%S}.cfg"
    path.write_text(config, encoding="utf-8")
    return Saved(path, True, config.count("\n"))


def diff_latest(root: Path, name: str, context: int = 3) -> tuple[Path, Path, list[str]]:
    """Unified diff of the two most recent backups for one device."""
    files = history(root, name)
    if len(files) < 2:
        found = "only one backup" if files else "no backups"
        raise FileNotFoundError(f"{found} for {name} under {root}; need two to diff")
    old, new = files[-2], files[-1]
    lines = list(difflib.unified_diff(
        old.read_text(encoding="utf-8").splitlines(),
        new.read_text(encoding="utf-8").splitlines(),
        fromfile=f"{name}/{old.name}",
        tofile=f"{name}/{new.name}",
        n=context,
        lineterm="",
    ))
    return old, new, lines
