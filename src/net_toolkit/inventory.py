"""hosts.yml loader shared by `backup` and `ping-matrix`.

Passwords never live in the file: each device names an environment variable
(default NT_PASSWORD) and the CLI prompts if it is unset.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

PLATFORMS = {  # accepted spellings -> Netmiko device_type
    "cisco_ios": "cisco_ios", "ios": "cisco_ios",
    "cisco_xe": "cisco_xe", "iosxe": "cisco_xe", "ios-xe": "cisco_xe",
    "cisco_nxos": "cisco_nxos", "nxos": "cisco_nxos", "nx-os": "cisco_nxos",
    "arista_eos": "arista_eos", "eos": "arista_eos",
}
SAFE_NAME = re.compile(r"^[A-Za-z0-9:][A-Za-z0-9._:-]*$")  # also a directory name: no "/" or leading "."


class InventoryError(ValueError):
    pass


@dataclass(frozen=True)
class Device:
    name: str
    host: str
    device_type: str = "cisco_ios"
    username: str | None = None
    password_env: str = "NT_PASSWORD"
    port: int = 22


def load(path: str | Path) -> list[Device]:
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise InventoryError(f"cannot read {path}: {exc.strerror}") from exc
    except yaml.YAMLError as exc:
        raise InventoryError(f"{path} is not valid YAML: {exc}") from exc
    return parse(data, str(path))


def parse(data: object, source: str = "inventory") -> list[Device]:
    """Accept {defaults, devices: [...]}, {hosts: [...]}, or a bare list of names/IPs."""
    defaults: dict = {}
    if isinstance(data, dict):
        defaults = data.get("defaults") or {}
        entries = data.get("devices", data.get("hosts"))
    else:
        entries = data
    if not isinstance(entries, list) or not entries:
        raise InventoryError(f"{source}: expected a non-empty 'devices' list")
    if not isinstance(defaults, dict):
        raise InventoryError(f"{source}: 'defaults' must be a mapping")

    devices: list[Device] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries, start=1):
        if isinstance(entry, str):
            entry = {"host": entry}
        if not isinstance(entry, dict) or not entry.get("host"):
            raise InventoryError(f"{source}: device #{index} needs a 'host'")
        merged = {**defaults, **entry}
        name = str(merged.get("name") or merged["host"])
        if not SAFE_NAME.match(name):
            raise InventoryError(f"{source}: device name {name!r} has unsafe characters")
        if name in seen:
            raise InventoryError(f"{source}: duplicate device name {name!r}")
        seen.add(name)
        platform = str(merged.get("device_type", "cisco_ios")).lower()
        if platform not in PLATFORMS:
            supported = ", ".join(sorted(set(PLATFORMS.values())))
            raise InventoryError(f"{source}: {name}: unsupported device_type {platform!r} ({supported})")
        try:
            port = int(merged.get("port", 22))
        except (TypeError, ValueError) as exc:
            raise InventoryError(f"{source}: {name}: port must be a number") from exc
        devices.append(Device(
            name=name,
            host=str(merged["host"]),
            device_type=PLATFORMS[platform],
            username=merged.get("username"),
            password_env=str(merged.get("password_env", "NT_PASSWORD")),
            port=port,
        ))
    return devices
