"""Small, dependency-free pcap / pcapng reader and protocol summariser.

Parsing is done by hand with `struct` so the summary works anywhere the CLI does,
and so each header layout is visible in one place. Scapy is only used to *write*
the invented sample capture (scripts/make_sample_pcap.py) and in tests.
"""

from __future__ import annotations

import ipaddress
import struct
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO


class PcapError(ValueError):
    """The file is not something we can read."""


# --- containers -------------------------------------------------------------------------

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW_BSD = 12
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),  # little-endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),  # nanosecond variant
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"


@dataclass(frozen=True)
class RawPacket:
    ts: float
    linktype: int
    data: bytes
    wirelen: int


class PcapReader:
    """Iterate over link-layer frames in a classic pcap or a pcapng file."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.truncated = False  # set when the file ends mid-record (capture was cut off)
        self.format = "?"

    def __iter__(self) -> Iterator[RawPacket]:
        with self.path.open("rb") as fh:
            magic = fh.read(4)
            if magic in PCAP_MAGIC:
                self.format = "pcap"
                yield from self._classic(fh, magic)
            elif magic == PCAPNG_SHB:
                self.format = "pcapng"
                yield from self._pcapng(fh)
            else:
                raise PcapError(f"{self.path} is not a pcap or pcapng file")

    def _read(self, fh: BinaryIO, size: int) -> bytes | None:
        data = fh.read(size)
        if len(data) < size:
            if data:
                self.truncated = True
            return None
        return data

    def _classic(self, fh: BinaryIO, magic: bytes) -> Iterator[RawPacket]:
        endian, resolution = PCAP_MAGIC[magic]
        header = self._read(fh, 20)
        if header is None:
            raise PcapError(f"{self.path}: global header is truncated")
        linktype = struct.unpack(endian + "HHiIII", header)[5] & 0x0FFFFFFF  # top bits = FCS info
        while True:
            record = self._read(fh, 16)
            if record is None:
                return
            sec, frac, caplen, wirelen = struct.unpack(endian + "IIII", record)
            data = self._read(fh, caplen)
            if data is None:
                return
            yield RawPacket(sec + frac * resolution, linktype, data, wirelen)

    def _pcapng(self, fh: BinaryIO) -> Iterator[RawPacket]:
        endian = "<"
        interfaces: list[tuple[int, float]] = []  # (linktype, seconds per tick)
        block_type = PCAPNG_SHB
        first = True
        while True:
            if not first:
                block_type = self._read(fh, 4)
                if block_type is None:
                    return
            first = False
            raw_len = self._read(fh, 4)
            if raw_len is None:
                return
            if block_type == PCAPNG_SHB:
                bom = self._read(fh, 4)
                if bom is None:
                    return
                endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
                if bom not in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"):
                    raise PcapError(f"{self.path}: bad pcapng byte-order magic")
                total = struct.unpack(endian + "I", raw_len)[0]
                if self._read(fh, total - 12) is None:
                    return
                interfaces = []  # a new section starts a new interface list
                continue
            kind = struct.unpack(endian + "I", block_type)[0]
            total = struct.unpack(endian + "I", raw_len)[0]
            if total < 12 or total % 4:
                raise PcapError(f"{self.path}: corrupt pcapng block length {total}")
            body = self._read(fh, total - 8)
            if body is None:
                return
            body = body[:-4]  # drop trailing copy of the block length
            if kind == 1:  # Interface Description Block
                linktype = struct.unpack(endian + "H", body[:2])[0]
                interfaces.append((linktype, _tsresol(body[8:], endian)))
            elif kind == 6:  # Enhanced Packet Block
                iface, hi, lo, caplen, wirelen = struct.unpack(endian + "IIIII", body[:20])
                linktype, tick = interfaces[iface] if iface < len(interfaces) else (LINKTYPE_ETHERNET, 1e-6)
                ts = ((hi << 32) | lo) * tick
                yield RawPacket(ts, linktype, body[20:20 + caplen], wirelen)
            elif kind == 3:  # Simple Packet Block: no timestamp, interface 0
                wirelen = struct.unpack(endian + "I", body[:4])[0]
                linktype = interfaces[0][0] if interfaces else LINKTYPE_ETHERNET
                yield RawPacket(0.0, linktype, body[4:4 + wirelen], wirelen)
            # every other block type (stats, name resolution, custom) is skipped


def _tsresol(options: bytes, endian: str) -> float:
    """Read if_tsresol (option 9) from IDB options; default is microseconds."""
    offset = 0
    while offset + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[offset:offset + 4])
        if code == 0:
            break
        if code == 9 and length >= 1:
            value = options[offset + 4]
            return 2.0 ** -(value & 0x7F) if value & 0x80 else 10.0 ** -value
        offset += 4 + length + (-length % 4)
    return 1e-6


# --- protocol decoding ------------------------------------------------------------------

IP_PROTOCOLS = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH",
    58: "ICMPv6", 88: "EIGRP", 89: "OSPF", 103: "PIM", 112: "VRRP", 132: "SCTP",
}
SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp",
    68: "dhcp", 69: "tftp", 80: "http", 110: "pop3", 123: "ntp", 137: "netbios", 143: "imap",
    161: "snmp", 162: "snmp-trap", 179: "bgp", 389: "ldap", 443: "https", 445: "smb",
    514: "syslog", 546: "dhcpv6", 547: "dhcpv6", 636: "ldaps", 853: "dns-over-tls",
    993: "imaps", 1812: "radius", 1900: "ssdp", 3306: "mysql", 3389: "rdp", 5060: "sip",
    5353: "mdns", 5355: "llmnr", 8080: "http-alt", 8443: "https-alt",
}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
             28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY"}
TCP_FIN, TCP_SYN, TCP_RST, TCP_ACK = 0x01, 0x02, 0x04, 0x10
DNS_PORTS = (53, 5353, 5355)


@dataclass
class DnsMessage:
    name: str
    qtype: str
    response: bool
    rcode: int
    answers: list[str] = field(default_factory=list)  # A/AAAA addresses in a response


@dataclass
class Packet:
    ts: float
    length: int
    l3: str = "other"  # IPv4, IPv6, ARP, other
    proto: str = "other"  # TCP, UDP, ICMP, OSPF, ARP, ...
    src: str | None = None
    dst: str | None = None
    sport: int | None = None
    dport: int | None = None
    tcp_flags: int = 0
    vlan: int | None = None
    dns: DnsMessage | None = None
    payload: bytes = b""  # TCP/UDP payload, kept only while the packet is being summarised

    @property
    def service(self) -> str | None:
        """Best guess at the application, from the lower well-known port."""
        ports = [p for p in (self.sport, self.dport) if p is not None]
        known = sorted(p for p in ports if p in SERVICES)
        if known:
            return SERVICES[known[0]]
        return None


def decode(raw: RawPacket) -> Packet:
    """Decode as far as we understand; anything unknown just stays 'other'."""
    pkt = Packet(raw.ts, raw.wirelen)
    data = raw.data
    if raw.linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return pkt
        ethertype = struct.unpack("!H", data[12:14])[0]
        offset = 14
        while ethertype in (0x8100, 0x88A8) and len(data) >= offset + 4:  # 802.1Q / QinQ
            tci, ethertype = struct.unpack("!HH", data[offset:offset + 4])
            pkt.vlan = tci & 0x0FFF
            offset += 4
        _decode_ethertype(pkt, ethertype, data[offset:])
    elif raw.linktype in (LINKTYPE_RAW, LINKTYPE_RAW_BSD):
        version = data[0] >> 4 if data else 0
        _decode_ethertype(pkt, {4: 0x0800, 6: 0x86DD}.get(version, 0), data)
    elif raw.linktype == LINKTYPE_LINUX_SLL and len(data) >= 16:
        _decode_ethertype(pkt, struct.unpack("!H", data[14:16])[0], data[16:])
    elif raw.linktype == LINKTYPE_LINUX_SLL2 and len(data) >= 20:
        _decode_ethertype(pkt, struct.unpack("!H", data[0:2])[0], data[20:])
    elif raw.linktype == LINKTYPE_NULL and len(data) >= 4:
        family = struct.unpack("<I", data[:4])[0]
        if family > 0xFFFF:  # written on a big-endian host
            family = struct.unpack(">I", data[:4])[0]
        ethertype = 0x0800 if family == 2 else 0x86DD if family in (10, 24, 28, 30) else 0
        _decode_ethertype(pkt, ethertype, data[4:])
    return pkt


def _decode_ethertype(pkt: Packet, ethertype: int, data: bytes) -> None:
    if ethertype == 0x0800:
        _decode_ipv4(pkt, data)
    elif ethertype == 0x86DD:
        _decode_ipv6(pkt, data)
    elif ethertype == 0x0806 and len(data) >= 28:
        pkt.l3 = pkt.proto = "ARP"
        pkt.src = str(ipaddress.IPv4Address(data[14:18]))  # sender protocol address
        pkt.dst = str(ipaddress.IPv4Address(data[24:28]))  # target protocol address


def _decode_ipv4(pkt: Packet, data: bytes) -> None:
    if len(data) < 20 or data[0] >> 4 != 4:
        return
    ihl = (data[0] & 0x0F) * 4
    frag = struct.unpack("!H", data[6:8])[0] & 0x1FFF
    proto = data[9]
    pkt.l3 = "IPv4"
    pkt.src = str(ipaddress.IPv4Address(data[12:16]))
    pkt.dst = str(ipaddress.IPv4Address(data[16:20]))
    pkt.proto = IP_PROTOCOLS.get(proto, f"ip-proto-{proto}")
    if frag == 0:  # only the first fragment carries the L4 header
        _decode_l4(pkt, proto, data[ihl:])


IPV6_EXTENSION_HEADERS = {0, 43, 60}  # hop-by-hop, routing, destination options


def _decode_ipv6(pkt: Packet, data: bytes) -> None:
    if len(data) < 40 or data[0] >> 4 != 6:
        return
    pkt.l3 = "IPv6"
    pkt.src = str(ipaddress.IPv6Address(data[8:24]))
    pkt.dst = str(ipaddress.IPv6Address(data[24:40]))
    next_header, payload = data[6], data[40:]
    while next_header in IPV6_EXTENSION_HEADERS and len(payload) >= 8:
        next_header, payload = payload[0], payload[(payload[1] + 1) * 8:]
    if next_header == 44 and len(payload) >= 8:  # fragment header
        offset = struct.unpack("!H", payload[2:4])[0] >> 3
        next_header, payload = payload[0], payload[8:]
        if offset:
            pkt.proto = IP_PROTOCOLS.get(next_header, f"ip-proto-{next_header}")
            return
    pkt.proto = IP_PROTOCOLS.get(next_header, f"ip-proto-{next_header}")
    _decode_l4(pkt, next_header, payload)


def _decode_l4(pkt: Packet, proto: int, data: bytes) -> None:
    if proto == 6 and len(data) >= 20:
        pkt.sport, pkt.dport = struct.unpack("!HH", data[:4])
        pkt.tcp_flags = data[13]
        pkt.payload = data[(data[12] >> 4) * 4:]
        if 53 in (pkt.sport, pkt.dport) and len(pkt.payload) > 2:
            pkt.dns = parse_dns(pkt.payload[2:])  # DNS over TCP has a 2-byte length prefix
    elif proto == 17 and len(data) >= 8:
        pkt.sport, pkt.dport = struct.unpack("!HH", data[:4])
        pkt.payload = data[8:]
        if pkt.sport in DNS_PORTS or pkt.dport in DNS_PORTS:
            pkt.dns = parse_dns(pkt.payload)


def parse_dns(data: bytes) -> DnsMessage | None:
    """Pull the first question (and any A/AAAA answers) out of a DNS message."""
    if len(data) < 12:
        return None
    flags, qdcount, ancount = struct.unpack("!HHH", data[2:8])
    if qdcount == 0:
        return None
    name, offset = _dns_name(data, 12)
    if name is None or offset + 4 > len(data):
        return None
    qtype = struct.unpack("!H", data[offset:offset + 2])[0]
    message = DnsMessage(name, DNS_TYPES.get(qtype, f"TYPE{qtype}"), bool(flags & 0x8000), flags & 0x000F)
    offset += 4
    for _ in range(qdcount - 1):  # almost always zero
        _, offset = _dns_name(data, offset)
        offset += 4
    for _ in range(ancount):
        rr_name, offset = _dns_name(data, offset)
        if rr_name is None or offset + 10 > len(data):
            break
        rtype, _, _, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        rdata = data[offset + 10:offset + 10 + rdlength]
        offset += 10 + rdlength
        if rtype == 1 and len(rdata) == 4:
            message.answers.append(str(ipaddress.IPv4Address(rdata)))
        elif rtype == 28 and len(rdata) == 16:
            message.answers.append(str(ipaddress.IPv6Address(rdata)))
    return message


# --- application names: TLS SNI, HTTP Host, QUIC -----------------------------------------

HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ")


def tls_record_length(data: bytes) -> int | None:
    """Total bytes of the TLS record if `data` starts a ClientHello, else None."""
    if len(data) >= 6 and data[0] == 0x16 and data[1] == 0x03 and data[5] == 0x01:
        return 5 + struct.unpack("!H", data[3:5])[0]
    return None


def parse_sni(data: bytes) -> str | None:
    """Server name from a TLS ClientHello (the record header included)."""
    if tls_record_length(data) is None:
        return None
    body = data[9:]  # 5-byte record header + 4-byte handshake header
    offset = 2 + 32  # client_version, random
    try:
        offset += 1 + body[offset]  # session id
        offset += 2 + struct.unpack("!H", body[offset:offset + 2])[0]  # cipher suites
        offset += 1 + body[offset]  # compression methods
        end = offset + 2 + struct.unpack("!H", body[offset:offset + 2])[0]
        offset += 2
        while offset + 4 <= min(end, len(body)):
            ext_type, ext_len = struct.unpack("!HH", body[offset:offset + 4])
            if ext_type == 0:  # server_name: list length, type (0 = host), name length, name
                name_len = struct.unpack("!H", body[offset + 7:offset + 9])[0]
                name = body[offset + 9:offset + 9 + name_len]
                if len(name) == name_len and name:
                    return name.decode("ascii", errors="replace").lower()
                return None
            offset += 4 + ext_len
    except (IndexError, struct.error):
        return None
    return None


def parse_http_host(data: bytes) -> str | None:
    if not data.startswith(HTTP_METHODS):
        return None
    for line in data[:4096].split(b"\r\n")[1:]:
        if not line:
            break
        key, _, value = line.partition(b":")
        if key.strip().lower() == b"host":
            host = value.strip().decode("ascii", errors="replace").lower()
            return host.rsplit(":", 1)[0] if host.count(":") == 1 else host or None
    return None


def is_quic_initial(pkt: Packet) -> bool:
    """Client-to-server QUIC long-header Initial packet (the name inside is encrypted)."""
    data = pkt.payload
    return (pkt.proto == "UDP" and pkt.dport == 443 and len(data) >= 5
            and data[0] & 0xC0 == 0xC0 and data[1:5] != b"\x00\x00\x00\x00")


def _dns_name(data: bytes, offset: int) -> tuple[str | None, int]:
    labels: list[str] = []
    end = None  # where parsing resumes after the name, if we followed a pointer
    for _ in range(128):  # bounded so a pointer loop cannot hang us
        if offset >= len(data):
            return None, offset
        length = data[offset]
        if length == 0:
            return ".".join(labels) or ".", end if end is not None else offset + 1
        if length & 0xC0 == 0xC0:  # compression pointer
            if offset + 1 >= len(data):
                return None, offset
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            continue
        label = data[offset + 1:offset + 1 + length]
        if len(label) < length:
            return None, offset
        labels.append(label.decode("ascii", errors="replace"))
        offset += 1 + length
    return None, offset


# --- summary ----------------------------------------------------------------------------


@dataclass
class HostStats:
    packets: int = 0
    sent: int = 0
    received: int = 0

    @property
    def total(self) -> int:
        return self.sent + self.received


@dataclass
class SiteStats:
    connections: int = 0
    via: set[str] = field(default_factory=set)


MAX_PENDING_HELLOS = 4096  # half-received ClientHellos we are willing to buffer


@dataclass
class Summary:
    source: str
    format: str = "?"
    packets: int = 0
    bytes: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    truncated: bool = False
    hosts: dict[str, HostStats] = field(default_factory=dict)
    protocols: Counter[str] = field(default_factory=Counter)
    protocol_bytes: Counter[str] = field(default_factory=Counter)
    services: Counter[str] = field(default_factory=Counter)
    vlans: Counter[int] = field(default_factory=Counter)
    dns_queries: Counter[tuple[str, str]] = field(default_factory=Counter)
    dns_nxdomain: Counter[str] = field(default_factory=Counter)
    resets: Counter[tuple[str, str, int]] = field(default_factory=Counter)
    sites: dict[str, SiteStats] = field(default_factory=dict)
    ip_names: dict[str, Counter[str]] = field(default_factory=dict)  # server IP -> names seen
    _pending: dict[tuple, tuple[bytearray, int]] = field(default_factory=dict, repr=False)
    _quic_flows: set[tuple] = field(default_factory=set, repr=False)

    @property
    def duration(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return self.last_ts - self.first_ts

    def add(self, pkt: Packet) -> None:
        self.packets += 1
        self.bytes += pkt.length
        if pkt.ts:
            self.first_ts = pkt.ts if self.first_ts is None else min(self.first_ts, pkt.ts)
            self.last_ts = pkt.ts if self.last_ts is None else max(self.last_ts, pkt.ts)
        self.protocols[pkt.proto] += 1
        self.protocol_bytes[pkt.proto] += pkt.length
        if pkt.service:
            self.services[f"{pkt.service} ({pkt.proto.lower()})"] += 1
        if pkt.vlan is not None:
            self.vlans[pkt.vlan] += 1
        if pkt.src and pkt.dst:
            sender = self.hosts.setdefault(pkt.src, HostStats())
            sender.packets += 1
            sender.sent += pkt.length
            self.hosts.setdefault(pkt.dst, HostStats()).received += pkt.length
        if pkt.dns and not pkt.dns.response:
            self.dns_queries[(pkt.dns.name, pkt.dns.qtype)] += 1
        if pkt.dns and pkt.dns.response and pkt.dns.rcode == 3:
            self.dns_nxdomain[pkt.dns.name] += 1
        if pkt.dns and pkt.dns.response:
            for address in pkt.dns.answers:
                self._name(address, pkt.dns.name, weight=0)
        if pkt.payload and pkt.src and pkt.dst:
            self._application(pkt)
        if pkt.tcp_flags & TCP_RST and pkt.src and pkt.dst and pkt.sport and pkt.dport:
            # the side sending RST is usually the server refusing or tearing down
            port = pkt.sport if (pkt.sport in SERVICES or pkt.sport < pkt.dport) else pkt.dport
            self.resets[(pkt.src, pkt.dst, port)] += 1

    def _name(self, address: str, name: str, weight: int = 1) -> None:
        names = self.ip_names.setdefault(address, Counter())
        names[name] += weight  # a DNS answer only seeds the name; real connections outvote it

    def _site(self, name: str, via: str, server: str) -> None:
        site = self.sites.setdefault(name, SiteStats())
        site.connections += 1
        site.via.add(via)
        self._name(server, name)

    def _application(self, pkt: Packet) -> None:
        flow = (pkt.src, pkt.sport, pkt.dst, pkt.dport)
        if pkt.proto == "TCP":
            if flow in self._pending:  # ClientHello bigger than one segment: keep collecting
                buffer, needed = self._pending[flow]
                buffer += pkt.payload
                if len(buffer) >= needed:
                    del self._pending[flow]
                    self._hello(bytes(buffer), pkt)
                return
            needed = tls_record_length(pkt.payload)
            if needed is not None:
                if len(pkt.payload) >= needed:
                    self._hello(pkt.payload, pkt)
                elif len(self._pending) < MAX_PENDING_HELLOS:
                    self._pending[flow] = (bytearray(pkt.payload), needed)
                return
            host = parse_http_host(pkt.payload)
            if host:
                self._site(host, "http", pkt.dst)  # type: ignore[arg-type]
        elif is_quic_initial(pkt) and flow not in self._quic_flows:
            self._quic_flows.add(flow)
            self._site(self.name_for(pkt.dst) or pkt.dst, "quic", pkt.dst)  # type: ignore[arg-type]

    def _hello(self, data: bytes, pkt: Packet) -> None:
        sni = parse_sni(data)
        if sni:
            self._site(sni, "tls", pkt.dst)  # type: ignore[arg-type]

    def name_for(self, address: str | None) -> str | None:
        names = self.ip_names.get(address or "")
        return names.most_common(1)[0][0] if names else None

    def site_bytes(self) -> Counter[str]:
        """Traffic per site, giving each server IP's bytes to the name it was used for most."""
        totals: Counter[str] = Counter()
        for address, stats in self.hosts.items():
            name = self.name_for(address)
            if name in self.sites:
                totals[name] += stats.total
        return totals

    def top_sites(self, n: int) -> list[tuple[str, SiteStats, int]]:
        volume = self.site_bytes()
        ranked = sorted(self.sites.items(), key=lambda kv: (-volume[kv[0]], -kv[1].connections, kv[0]))
        return [(name, stats, volume[name]) for name, stats in ranked[:n]]

    def top_hosts(self, n: int) -> list[tuple[str, HostStats]]:
        return sorted(self.hosts.items(), key=lambda kv: (-kv[1].total, kv[0]))[:n]

    def to_dict(self, top: int = 10) -> dict:
        return {
            "source": self.source,
            "format": self.format,
            "packets": self.packets,
            "bytes": self.bytes,
            "duration_seconds": round(self.duration, 6),
            "truncated": self.truncated,
            "top_talkers": [
                {"host": host, "packets_sent": s.packets, "bytes_sent": s.sent,
                 "bytes_received": s.received}
                for host, s in self.top_hosts(top)
            ],
            "protocols": [
                {"protocol": p, "packets": c, "bytes": self.protocol_bytes[p]}
                for p, c in self.protocols.most_common()
            ],
            "services": dict(self.services.most_common(top)),
            "vlans": {str(k): v for k, v in sorted(self.vlans.items())},
            "sites": [
                {"site": name, "connections": s.connections, "bytes": volume, "via": sorted(s.via)}
                for name, s, volume in self.top_sites(top)
            ],
            "dns_queries": [
                {"name": name, "type": qtype, "count": c, "nxdomain": self.dns_nxdomain[name]}
                for (name, qtype), c in self.dns_queries.most_common(top)
            ],
            "tcp_resets": [
                {"from": src, "to": dst, "port": port, "count": c}
                for (src, dst, port), c in self.resets.most_common(top)
            ],
        }


def summarize(path: str | Path) -> Summary:
    reader = PcapReader(path)
    summary = Summary(source=str(path))
    for raw in reader:
        summary.add(decode(raw))
    summary.format = reader.format
    summary.truncated = reader.truncated
    return summary
