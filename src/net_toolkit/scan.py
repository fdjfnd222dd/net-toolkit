"""ICMP + TCP connect sweep of a prefix, rate limited, with a guard against public space."""

from __future__ import annotations

import ipaddress
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from net_toolkit import probes

# Ports an infrastructure person usually cares about first.
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 179, 389, 443, 445,
    636, 830, 993, 1433, 3306, 3389, 5432, 5900, 8080, 8443,
]
MAX_HOSTS = 4096


class ScanRefused(ValueError):
    """The target is outside what we are willing to scan without confirmation."""


@dataclass
class HostResult:
    address: str
    rtt_ms: float | None = None
    open_ports: list[int] = field(default_factory=list)
    refused: int = 0  # ports that answered RST: proves the host is alive
    mac: str | None = None
    vendor: str | None = None
    name: str | None = None
    is_self: bool = False
    is_gateway: bool = False

    @property
    def up(self) -> bool:
        return self.rtt_ms is not None or bool(self.open_ports) or self.refused > 0


def parse_ports(spec: str) -> list[int]:
    """'22,80,8000-8010' -> sorted unique list; 'common' -> COMMON_PORTS."""
    if spec.strip().lower() == "common":
        return list(COMMON_PORTS)
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        start, _, end = part.partition("-")
        try:
            low, high = int(start), int(end or start)
        except ValueError as exc:
            raise ValueError(f"bad port {part!r}") from exc
        if not (1 <= low <= high <= 65535):
            raise ValueError(f"port out of range: {part!r}")
        ports.update(range(low, high + 1))
    return sorted(ports)


def is_internal(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    """RFC 1918 / ULA / loopback / link-local / documentation space only.

    100.64.0.0/10 (carrier-grade NAT) deliberately does not count: it belongs to an ISP.
    """
    return network.is_private or network.is_loopback or network.is_link_local


def check_target(target: str, i_own_this: bool = False, max_hosts: int = MAX_HOSTS):
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise ScanRefused(f"not an IP address or prefix: {target!r}") from exc
    if not is_internal(network) and not i_own_this:
        raise ScanRefused(
            f"{network} is not private address space (public or carrier NAT). Only scan "
            "networks you own or are authorised to test; re-run with --i-own-this to confirm."
        )
    if network.num_addresses > max_hosts:
        raise ScanRefused(
            f"{network} has {network.num_addresses:,} addresses; the limit is {max_hosts:,} "
            "(raise it with --max-hosts)"
        )
    return network


Pinger = Callable[[str, float], "float | None"]
Connector = Callable[[str, int, float], str]


def sweep(
    network,
    ports: list[int],
    *,
    rate: float | None = 100,
    timeout: float = 1.0,
    workers: int = 64,
    icmp: bool = True,
    pinger: Pinger = probes.ping,
    connector: Connector = probes.tcp_probe,
    on_probe: Callable[[], None] | None = None,
) -> list[HostResult]:
    """Run every (host, probe) pair through a shared rate limiter and thread pool."""
    hosts = [str(h) for h in network.hosts()]
    results = {h: HostResult(h) for h in hosts}
    limiter = probes.RateLimiter(rate)
    lock = threading.Lock()
    jobs: list[tuple[str, int | None]] = []
    for host in hosts:
        if icmp:
            jobs.append((host, None))
        jobs.extend((host, port) for port in ports)

    def run(job: tuple[str, int | None]) -> None:
        host, port = job
        limiter.acquire()
        try:
            if port is None:
                rtt = pinger(host, timeout)
                with lock:
                    results[host].rtt_ms = rtt
            else:
                state = connector(host, port, timeout)
                with lock:
                    if state == probes.OPEN:
                        results[host].open_ports.append(port)
                    elif state == probes.CLOSED:
                        results[host].refused += 1
        finally:
            if on_probe:
                on_probe()

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        list(pool.map(run, jobs))
    for result in results.values():
        result.open_ports.sort()
    return [results[h] for h in hosts]


# --- canned lab for --demo -------------------------------------------------------------

DEMO_NETWORK = "10.10.10.0/24"
DEMO_LAB = {  # host -> (rtt ms or None, open ports, answers RST on closed ports)
    "10.10.10.1": (0.61, [22, 179, 443], True),
    "10.10.10.2": (0.84, [22, 830], True),
    "10.10.10.10": (1.12, [53, 389, 636, 445, 135, 139], True),
    "10.10.10.21": (3.40, [3389], False),
    "10.10.10.22": (None, [22, 80], True),  # ICMP blocked by host firewall, TCP still answers
    "10.10.10.40": (2.05, [80, 443, 8443], True),
    "10.10.10.50": (0.97, [22, 5432], True),
    "10.10.10.60": (12.8, [], True),  # printer that answers ping and RSTs everything
}


def demo_pinger(host: str, timeout: float) -> float | None:
    return DEMO_LAB.get(host, (None, [], False))[0]


def demo_connector(host: str, port: int, timeout: float) -> str:
    _, open_ports, rst = DEMO_LAB.get(host, (None, [], False))
    if port in open_ports:
        return probes.OPEN
    return probes.CLOSED if rst else probes.FILTERED


DEMO_IDENTITY = {  # host -> (MAC, name); MAC prefixes are real vendor OUIs, the rest is invented
    "10.10.10.1": ("00:00:0c:9f:f0:01", "core-gw"),
    "10.10.10.2": ("00:1c:73:4a:10:02", "dist-sw2"),
    "10.10.10.10": ("00:06:5b:21:7c:10", "dc01"),
    "10.10.10.21": ("10:c5:95:3e:44:21", "LAB-PC21"),
    "10.10.10.22": ("28:cd:c1:0b:5e:22", "pihole"),
    "10.10.10.40": ("00:11:32:7a:90:40", "nas01"),
    "10.10.10.50": ("52:54:00:6d:1a:50", None),
    "10.10.10.60": ("3c:2a:f4:88:01:60", "BRW3C2AF4880160"),
}


def demo_neighbours() -> dict[str, str]:
    return {ip: mac for ip, (mac, _) in DEMO_IDENTITY.items()}


def demo_namer(ip: str, timeout: float) -> str | None:
    return DEMO_IDENTITY.get(ip, (None, None))[1]
