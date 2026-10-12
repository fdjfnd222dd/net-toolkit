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
    if network.is_private:
        return "private (RFC 1918)" if network.version == 4 else "private (ULA)"
    if network.is_reserved or network.is_unspecified:
        return "reserved"
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
