"""Subnet math: describe a prefix, carve it into equal pieces, or allocate it VLSM-style.

Everything here is pure `ipaddress` arithmetic so it can be unit-tested without a network.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
Address = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(frozen=True)
class SubnetInfo:
    """Everything a person usually works out by hand for one prefix."""

    address: Address  # what the user typed, may have host bits set
    network: Network
    netmask: Address
    wildcard: Address
    broadcast: Address | None  # IPv6 has no broadcast
    first_usable: Address
    last_usable: Address
    total: int
    usable: int
    scope: str
    ip_class: str | None  # classful label, IPv4 only, for study purposes

    @property
    def version(self) -> int:
        return self.network.version

    @property
    def prefixlen(self) -> int:
        return self.network.prefixlen


def parse(cidr: str) -> tuple[Address, Network]:
    """Accept `10.20.1.5/22`, `10.20.0.0/22`, `10.20.0.0 255.255.252.0` or a bare address."""
    text = cidr.strip()
    if " " in text:  # "address mask" as typed on IOS
        addr, mask = text.split(None, 1)
        text = f"{addr}/{mask.strip()}"
    try:
        iface = ipaddress.ip_interface(text)
    except ValueError as exc:
        raise ValueError(f"not a valid address or prefix: {cidr!r}") from exc
    return iface.ip, iface.network


RFC1918 = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def scope_of(network: Network) -> str:
    """Human label for the address block, checked from most to least specific."""
    if network.is_loopback:
        return "loopback"
    if network.is_link_local:
        return "link-local"
    if network.is_multicast:
        return "multicast"
    if network.version == 4 and network.subnet_of(ipaddress.ip_network("100.64.0.0/10")):
        return "shared (CGNAT, RFC 6598)"
    for doc in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"):
        doc_net = ipaddress.ip_network(doc)
        if doc_net.version == network.version and network.subnet_of(doc_net):
            return "documentation (RFC 5737/3849)"
    if network.is_reserved or network.is_unspecified:
        return "reserved"
    for block in RFC1918:
        if network.version == 4 and network.subnet_of(block):
            return "private (RFC 1918)"
    if network.version == 6 and network.subnet_of(ipaddress.ip_network("fc00::/7")):
        return "private (ULA)"
    if network.is_private:  # benchmarking, protocol assignments, this-network, ...
        return "special-use (not routed)"
    return "public"


def classful(address: ipaddress.IPv4Address) -> str:
    first = int(address) >> 24
    if first < 128:
        return "A"
    if first < 192:
        return "B"
    if first < 224:
        return "C"
    if first < 240:
        return "D (multicast)"
    return "E (reserved)"


def describe(cidr: str) -> SubnetInfo:
    address, network = parse(cidr)
    total = network.num_addresses
    if network.version == 4:
        wildcard = ipaddress.IPv4Address(int(network.hostmask))
        if network.prefixlen >= 31:  # /31 point-to-point (RFC 3021) and /32 host routes
            first, last, usable, broadcast = network[0], network[-1], total, None
        else:
            first, last, usable = network[1], network[-2], total - 2
            broadcast = network.broadcast_address
        ip_class: str | None = classful(network.network_address)
    else:
        wildcard = network.hostmask
        first, last, usable, broadcast, ip_class = network[0], network[-1], total, None, None
    return SubnetInfo(
        address=address,
        network=network,
        netmask=network.netmask,
        wildcard=wildcard,
        broadcast=broadcast,
        first_usable=first,
        last_usable=last,
        total=total,
        usable=usable,
        scope=scope_of(network),
        ip_class=ip_class,
    )


MAX_SPLIT = 4096  # keeps a typo like `--split 65536` from printing forever


def split(network: Network, count: int) -> list[Network]:
    """Carve `network` into `count` equal subnets.

    Subnets only come in powers of two, so a count like 3 is rounded up to 4; the
    caller decides how to present the spare ones.
    """
    if count < 1:
        raise ValueError("split count must be at least 1")
    if count > MAX_SPLIT:
        raise ValueError(f"split count is capped at {MAX_SPLIT}")
    bits = (count - 1).bit_length()  # ceil(log2(count))
    if network.prefixlen + bits > network.max_prefixlen:
        raise ValueError(
            f"{network} is too small to split into {count} subnets "
            f"(would need a /{network.prefixlen + bits})"
        )
    return list(network.subnets(prefixlen_diff=bits))


@dataclass(frozen=True)
class Allocation:
    name: str
    requested: int
    subnet: ipaddress.IPv4Network

    @property
    def usable(self) -> int:
        return self.subnet.num_addresses - 2

    @property
    def waste(self) -> int:
        return self.usable - self.requested


def parse_vlsm(spec: str) -> list[tuple[str, int]]:
    """Parse `50,20,10` or `Sales=50,Eng=20,10` into (name, hosts) pairs."""
    requests: list[tuple[str, int]] = []
    for index, raw in enumerate(spec.split(","), start=1):
        item = raw.strip()
        if not item:
            continue
        name, _, hosts = item.rpartition("=")
        try:
            count = int(hosts)
        except ValueError as exc:
            raise ValueError(f"bad VLSM entry {item!r}: host count must be a number") from exc
        if count < 1:
            raise ValueError(f"bad VLSM entry {item!r}: host count must be at least 1")
        requests.append((name.strip() or f"net{index}", count))
    if not requests:
        raise ValueError("VLSM spec is empty")
    return requests


def prefix_for_hosts(hosts: int) -> int:
    """Smallest IPv4 prefix whose usable range (minus network + broadcast) fits `hosts`."""
    host_bits = (hosts + 2 - 1).bit_length()  # ceil(log2(hosts + 2))
    host_bits = max(host_bits, 2)  # never hand out a /31 or /32 from VLSM
    return 32 - host_bits


def vlsm(network: Network, requests: list[tuple[str, int]]) -> tuple[list[Allocation], list[Network]]:
    """Allocate the largest request first so every block lands on its natural boundary.

    Returns the allocations (largest first) and the free space left over, summarised.
    """
    if network.version != 4:
        raise ValueError("VLSM allocation is IPv4 only")
    ordered = sorted(requests, key=lambda item: item[1], reverse=True)  # stable for ties
    cursor = int(network.network_address)
    end = int(network.broadcast_address)
    allocations: list[Allocation] = []
    for name, hosts in ordered:
        prefix = prefix_for_hosts(hosts)
        size = 1 << (32 - prefix)
        if prefix < network.prefixlen or cursor + size - 1 > end:
            remaining = end - cursor + 1
            raise ValueError(
                f"{name} ({hosts} hosts) needs a /{prefix} ({size} addresses) but only "
                f"{remaining} addresses remain in {network}"
            )
        allocations.append(Allocation(name, hosts, ipaddress.IPv4Network((cursor, prefix))))
        cursor += size
    free: list[Network] = []
    if cursor <= end:
        free = list(
            ipaddress.summarize_address_range(
                ipaddress.IPv4Address(cursor), ipaddress.IPv4Address(end)
            )
        )
    return allocations, free
