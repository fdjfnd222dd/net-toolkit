"""Put a name and a maker on the IP addresses a sweep finds.

* MAC address: read from the kernel's neighbour (ARP) table, which the sweep itself
  just filled in. Only works for hosts on the same LAN segment.
* Vendor: the first three bytes of the MAC, looked up in the IEEE registry
  (data/oui.tsv.gz). Phones and laptops often use randomised "private" MACs,
  which are flagged instead of guessed.
* Name: reverse DNS (home routers usually know DHCP hostnames), then a direct
  mDNS query (Apple, Android, printers, Linux), then a NetBIOS status query (Windows).
"""

from __future__ import annotations

import gzip
import ipaddress
import re
import socket
import struct
import subprocess
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path

from net_toolkit.pcap import _dns_name as read_dns_name

MAC_RE = re.compile(r"([0-9a-f]{1,2}[:-]){5}[0-9a-f]{1,2}", re.IGNORECASE)
RANDOM_MAC = "random or virtual MAC"


def normalise_mac(mac: str) -> str:
    return ":".join(part.zfill(2) for part in re.split(r"[:-]", mac.lower()))


@lru_cache(maxsize=1)
def oui_table() -> dict[str, str]:
    data = resources.files("net_toolkit").joinpath("data", "oui.tsv.gz").read_bytes()
    table = {}
    for line in gzip.decompress(data).decode("utf-8").splitlines():
        prefix, _, vendor = line.partition("\t")
        table[prefix] = vendor
    return table


def vendor_for(mac: str | None) -> str | None:
    if not mac:
        return None
    mac = normalise_mac(mac)
    if int(mac[:2], 16) & 0x02:  # locally administered bit: phone privacy MACs, VMs, containers
        return RANDOM_MAC
    return oui_table().get(mac.replace(":", "")[:6].upper())


# --- neighbour table -------------------------------------------------------------------

def neighbours(proc_arp: str = "/proc/net/arp") -> dict[str, str]:
    """IPv4 address -> MAC from the OS neighbour cache."""
    path = Path(proc_arp)
    if path.exists():  # Linux: cheapest and needs no external tool
        table = {}
        for line in path.read_text().splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 4 and fields[2] != "0x0" and fields[3] != "00:00:00:00:00:00":
                table[fields[0]] = normalise_mac(fields[3])
        return table
    for command in (["ip", "neigh", "show"], ["arp", "-an"]):  # pragma: no cover - non-Linux
        try:
            output = subprocess.run(command, capture_output=True, text=True, timeout=5).stdout
        except (OSError, subprocess.TimeoutExpired):
            continue
        return parse_neighbour_output(output)
    return {}  # pragma: no cover


def parse_neighbour_output(text: str) -> dict[str, str]:
    """Parse `ip neigh` (Linux) or `arp -an` (macOS/BSD/Windows) output."""
    table = {}
    for line in text.splitlines():
        ip = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
        mac = MAC_RE.search(line)
        if ip and mac and "incomplete" not in line.lower():
            table[ip.group(1)] = normalise_mac(mac.group(0))
    return table


def local_address(target: str) -> str | None:
    """Which of our own addresses would talk to `target` (no packet is sent)."""
    family = socket.AF_INET6 if ":" in target else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.connect((target, 9))
            return sock.getsockname()[0]
    except OSError:
        return None


# --- name lookups ----------------------------------------------------------------------

def default_gateway(proc_route: str = "/proc/net/route") -> str | None:
    """IPv4 default gateway from the Linux routing table (None elsewhere)."""
    try:
        lines = Path(proc_route).read_text().splitlines()[1:]
    except OSError:
        return None
    for line in lines:
        fields = line.split()
        if len(fields) >= 3 and fields[1] == "00000000":
            return str(ipaddress.IPv4Address(struct.pack("<I", int(fields[2], 16))))
    return None


SYNTHETIC_NAMES = {"_gateway", "_outbound", "localhost"}  # made up by systemd-resolved


def reverse_dns(ip: str, timeout: float = 1.0) -> str | None:
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return None
    if name == ip or name.endswith((".in-addr.arpa", ".ip6.arpa")) or name in SYNTHETIC_NAMES:
        return None
    return name


def _udp_query(ip: str, port: int, payload: bytes, timeout: float) -> bytes | None:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(payload, (ip, port))
            return sock.recvfrom(4096)[0]
    except OSError:
        return None


def build_ptr_query(ip: str, txid: int = 0x4E54) -> bytes:
    labels = ipaddress.ip_address(ip).reverse_pointer.split(".")
    name = b"".join(bytes([len(label)]) + label.encode() for label in labels) + b"\x00"
    return struct.pack("!HHHHHH", txid, 0, 1, 0, 0, 0) + name + struct.pack("!HH", 12, 1)


def parse_ptr_answer(data: bytes) -> str | None:
    """First PTR target in a DNS/mDNS response, without a trailing '.local'."""
    if len(data) < 12:
        return None
    qdcount, ancount = struct.unpack("!HH", data[4:8])
    offset = 12
    for _ in range(qdcount):
        _, offset = read_dns_name(data, offset)
        offset += 4
    for _ in range(ancount):
        _, offset = read_dns_name(data, offset)
        if offset + 10 > len(data):
            return None
        rtype, _, _, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        if rtype == 12:
            name, _ = read_dns_name(data, offset)
            cleaned = (name or "").removesuffix(".").removesuffix(".local")
            if cleaned:
                return cleaned
        offset += rdlength
    return None


def mdns_name(ip: str, timeout: float = 1.0) -> str | None:
    """Ask the device itself over mDNS (port 5353) what its name is."""
    reply = _udp_query(ip, 5353, build_ptr_query(ip), timeout)
    return parse_ptr_answer(reply) if reply else None


NBSTAT_QUERY = (
    struct.pack("!HHHHHH", 0x4E54, 0, 1, 0, 0, 0)
    + b"\x20" + b"CK" + b"AA" * 15 + b"\x00"  # first-level encoding of "*" padded with NULs
    + struct.pack("!HH", 0x21, 1)  # NBSTAT, IN
)


def parse_nbstat(data: bytes) -> str | None:
    """Workstation name (suffix 0x00, unique) from a NetBIOS node status reply."""
    if len(data) < 12:
        return None
    _, offset = read_dns_name(data, 12)
    offset += 10  # type, class, ttl, rdlength
    if offset >= len(data):
        return None
    count = data[offset]
    offset += 1
    for _ in range(count):
        entry = data[offset:offset + 18]
        if len(entry) < 18:
            return None
        name, suffix, flags = entry[:15], entry[15], struct.unpack("!H", entry[16:18])[0]
        if suffix == 0x00 and not flags & 0x8000:
            return name.decode("ascii", errors="replace").strip() or None
        offset += 18
    return None


def netbios_name(ip: str, timeout: float = 1.0) -> str | None:
    if ":" in ip:
        return None
    reply = _udp_query(ip, 137, NBSTAT_QUERY, timeout)
    return parse_nbstat(reply) if reply else None


def lookup_name(ip: str, timeout: float = 1.0) -> str | None:
    for method in (reverse_dns, mdns_name, netbios_name):
        name = method(ip, timeout)
        if name:
            return name
    return None


# --- putting it together ---------------------------------------------------------------

@dataclass
class Identity:
    mac: str | None = None
    vendor: str | None = None
    name: str | None = None
    is_self: bool = False
    is_gateway: bool = False


def identify(
    addresses: list[str],
    *,
    timeout: float = 1.0,
    neighbour_table: Callable[[], dict[str, str]] = neighbours,
    namer: Callable[[str, float], str | None] = lookup_name,
    gateway: Callable[[], str | None] = default_gateway,
    local: Callable[[str], str | None] = local_address,
    workers: int = 32,
) -> dict[str, Identity]:
    if not addresses:
        return {}
    table = neighbour_table()
    me = local(addresses[0])
    router = gateway()
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(addresses)))) as pool:
        names = list(pool.map(lambda ip: namer(ip, timeout), addresses))
    found = {}
    for ip, name in zip(addresses, names, strict=True):
        mac = table.get(ip)
        is_self = ip == me
        if is_self and not name:
            name = socket.gethostname()
        found[ip] = Identity(mac, vendor_for(mac), name, is_self, ip == router)
    return found
