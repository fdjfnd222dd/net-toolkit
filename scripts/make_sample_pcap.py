#!/usr/bin/env python3
"""Generate examples/sample.pcap: a small, entirely invented lab capture.

Nothing here comes from a real network. Hosts live in 10.10.0.0/16 (lab LAN),
"internet" servers use the RFC 5737 documentation ranges, IPv6 uses 2001:db8::/32,
MACs are locally administered (02:...) and DNS names are RFC 2606 example domains.
Timestamps are fixed, so re-running the script produces a byte-identical file.

    pip install scapy  # or: pip install -e '.[dev]'
    python scripts/make_sample_pcap.py [output.pcap]
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6ND_NS, IPv6
from scapy.layers.l2 import ARP, Dot1Q, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

START = 1767268800.0  # 2026-01-01 12:00:00 UTC

GW_MAC, SW_MAC = "02:00:00:00:00:01", "02:00:00:00:00:fe"
CLIENTS = {
    "10.10.10.21": "02:00:00:0a:00:21",
    "10.10.10.22": "02:00:00:0a:00:22",
    "10.10.10.23": "02:00:00:0a:00:23",
}
DNS_SERVER, NTP_SERVER, SYSLOG = "10.10.99.53", "10.10.99.10", "10.10.99.50"
WEB_A, WEB_B, VIDEO = "198.51.100.10", "203.0.113.80", "203.0.113.50"

packets = []
clock = START


def emit(pkt, gap=0.004):
    """Append a packet with a deterministic, slowly advancing timestamp."""
    global clock
    clock += gap
    pkt.time = clock
    packets.append(pkt)


def eth(src_ip, dst_mac=GW_MAC):
    return Ether(src=CLIENTS.get(src_ip, SW_MAC), dst=dst_mac)


def dns_exchange(client, name, qtype="A", answer=None, sport=40000):
    query = DNS(id=sport & 0xFFFF, rd=1, qd=DNSQR(qname=name, qtype=qtype))
    emit(eth(client) / IP(src=client, dst=DNS_SERVER) / UDP(sport=sport, dport=53) / query)
    if answer is None:  # NXDOMAIN
        reply = DNS(id=sport & 0xFFFF, qr=1, rd=1, ra=1, rcode=3, qd=DNSQR(qname=name, qtype=qtype))
    else:
        reply = DNS(id=sport & 0xFFFF, qr=1, rd=1, ra=1, qd=DNSQR(qname=name, qtype=qtype),
                    an=DNSRR(rrname=name, type=qtype, ttl=300, rdata=answer))
    emit(Ether(src=GW_MAC, dst=CLIENTS[client]) / IP(src=DNS_SERVER, dst=client)
         / UDP(sport=53, dport=sport) / reply, gap=0.012)


def client_hello(server_name: str) -> bytes:
    """A minimal TLS 1.3 ClientHello carrying SNI and ALPN (random/session id zeroed)."""
    name = server_name.encode()
    sni = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    alpn_list = b"\x02h2\x08http/1.1"
    alpn = struct.pack("!HHH", 16, len(alpn_list) + 2, len(alpn_list)) + alpn_list
    versions = struct.pack("!HHB", 43, 3, 2) + b"\x03\x04"
    extensions = sni + alpn + versions
    body = (b"\x03\x03" + bytes(32) + b"\x20" + bytes(32) + struct.pack("!H", 4) + b"\x13\x01\x13\x02"
            + b"\x01\x00" + struct.pack("!H", len(extensions)) + extensions)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def http_get(host: str) -> bytes:
    return f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: lab-client\r\nAccept: */*\r\n\r\n".encode()


def tcp_session(client, server, dport, sport, segments, size, request=b"G" * 300):
    """Handshake, a client request, `segments` server->client packets of `size` bytes, FIN/ACK."""
    c2s = eth(client) / IP(src=client, dst=server)
    s2c = Ether(src=GW_MAC, dst=CLIENTS[client]) / IP(src=server, dst=client)
    seq, ack = 1000, 5000
    emit(c2s / TCP(sport=sport, dport=dport, flags="S", seq=seq))
    emit(s2c / TCP(sport=dport, dport=sport, flags="SA", seq=ack, ack=seq + 1), gap=0.020)
    emit(c2s / TCP(sport=sport, dport=dport, flags="A", seq=seq + 1, ack=ack + 1))
    emit(c2s / TCP(sport=sport, dport=dport, flags="PA", seq=seq + 1, ack=ack + 1) / Raw(request))
    sent = len(request)
    ack += 1
    for _ in range(segments):
        emit(s2c / TCP(sport=dport, dport=sport, flags="A", seq=ack, ack=seq + 1 + sent) / Raw(b"x" * size), gap=0.002)
        ack += size
    emit(c2s / TCP(sport=sport, dport=dport, flags="FA", seq=seq + 1 + sent, ack=ack))
    emit(s2c / TCP(sport=dport, dport=sport, flags="FA", seq=ack, ack=seq + 2 + sent))


def refused(client, server, dport, sport, mac=SW_MAC):
    emit(eth(client, mac) / IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="S"))
    emit(Ether(src=mac, dst=CLIENTS[client]) / IP(src=server, dst=client)
         / TCP(sport=dport, dport=sport, flags="RA", ack=1), gap=0.001)


def build():
    # ARP for the default gateway
    emit(Ether(src=CLIENTS["10.10.10.21"], dst="ff:ff:ff:ff:ff:ff")
         / ARP(op=1, hwsrc=CLIENTS["10.10.10.21"], psrc="10.10.10.21", pdst="10.10.10.1"))
    emit(Ether(src=GW_MAC, dst=CLIENTS["10.10.10.21"])
         / ARP(op=2, hwsrc=GW_MAC, psrc="10.10.10.1", hwdst=CLIENTS["10.10.10.21"], pdst="10.10.10.21"))

    # name lookups, including one typo that comes back NXDOMAIN
    dns_exchange("10.10.10.21", "www.example.com", answer=WEB_A, sport=40001)
    dns_exchange("10.10.10.22", "intranet.example.net", answer=WEB_B, sport=40002)
    dns_exchange("10.10.10.21", "www.example.com", answer=WEB_A, sport=40003)
    dns_exchange("10.10.10.23", "updates.example.org", "AAAA", answer="2001:db8:5::10", sport=40004)
    dns_exchange("10.10.10.22", "fileshare.exmaple.com", answer=None, sport=40005)
    dns_exchange("10.10.10.23", "video.example.org", answer=VIDEO, sport=40006)

    # the bulk of the bytes: one HTTPS download (TLS SNI names it) and a small HTTP page
    tcp_session("10.10.10.21", WEB_A, 443, 51000, segments=24, size=1400, request=client_hello("www.example.com"))
    tcp_session("10.10.10.22", WEB_B, 80, 51001, segments=4, size=900, request=http_get("intranet.example.net"))

    # QUIC (HTTP/3) stream: the name inside is encrypted, so only the DNS answer above names it
    quic_c2s = eth("10.10.10.23") / IP(src="10.10.10.23", dst=VIDEO) / UDP(sport=52000, dport=443)
    quic_s2c = Ether(src=GW_MAC, dst=CLIENTS["10.10.10.23"]) / IP(src=VIDEO, dst="10.10.10.23") / UDP(sport=443, dport=52000)
    emit(quic_c2s / Raw(b"\xc3\x00\x00\x00\x01" + b"\x08" + bytes(8) + b"\x00" + b"q" * 1180))
    for _ in range(8):
        emit(quic_s2c / Raw(b"\x43" + b"v" * 1250), gap=0.003)

    # admin SSH session to the core switch management SVI
    tcp_session("10.10.10.23", "10.10.99.1", 22, 51002, segments=6, size=160)

    # someone trying telnet and RDP on hosts that refuse it
    for port in (51010, 51011, 51012):
        refused("10.10.10.23", "10.10.99.12", 23, port)
    refused("10.10.10.22", "10.10.10.40", 3389, 51020)

    # pings to the gateway, plus an unreachable host
    for seq in range(1, 5):
        emit(eth("10.10.10.21") / IP(src="10.10.10.21", dst="10.10.10.1") / ICMP(type=8, id=7, seq=seq), gap=0.25)
        emit(Ether(src=GW_MAC, dst=CLIENTS["10.10.10.21"]) / IP(src="10.10.10.1", dst="10.10.10.21")
             / ICMP(type=0, id=7, seq=seq), gap=0.001)
    emit(Ether(src=GW_MAC, dst=CLIENTS["10.10.10.22"]) / IP(src="10.10.10.1", dst="10.10.10.22")
         / ICMP(type=3, code=1) / IP(src="10.10.10.22", dst="10.10.30.99") / UDP(sport=50000, dport=33434))

    # infrastructure chatter: NTP, syslog, SNMP poll, OSPF hellos on the routed uplink
    emit(Ether(src=SW_MAC, dst=GW_MAC) / IP(src="10.10.99.1", dst=NTP_SERVER) / UDP(sport=123, dport=123) / Raw(b"\x23" + b"\x00" * 47))
    emit(Ether(src=SW_MAC, dst=GW_MAC) / IP(src="10.10.99.1", dst=SYSLOG) / UDP(sport=514, dport=514)
         / Raw(b"<189>CORE-SW1: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/48, changed state to up"))
    emit(Ether(src=SW_MAC, dst=GW_MAC) / IP(src=SYSLOG, dst="10.10.99.1") / UDP(sport=49152, dport=161) / Raw(b"\x30\x26" + b"\x00" * 38))
    for _ in range(3):
        emit(Ether(src=GW_MAC, dst="01:00:5e:00:00:05") / IP(src="10.10.0.1", dst="224.0.0.5", ttl=1)
             / OSPF_Hdr(src="10.255.0.1", area="0.0.0.0") / OSPF_Hello(mask="255.255.255.252", neighbors=["10.255.0.2"]),
             gap=1.0)

    # a few frames from a trunk SPAN: voice VLAN 20 SIP keepalives
    for port in (5060, 5060):
        emit(Ether(src="02:00:00:14:00:31", dst=GW_MAC) / Dot1Q(vlan=20) / IP(src="10.10.20.31", dst="10.10.20.5")
             / UDP(sport=port, dport=5060) / Raw(b"OPTIONS sip:pbx.example.net SIP/2.0\r\n\r\n"))

    # IPv6: neighbour solicitation and an AAAA lookup over v6
    emit(Ether(src="02:00:00:0a:00:21", dst="33:33:ff:00:00:01")
         / IPv6(src="fe80::21", dst="ff02::1:ff00:1") / ICMPv6ND_NS(tgt="2001:db8:10::1"))
    query = DNS(id=7, rd=1, qd=DNSQR(qname="www.example.com", qtype="AAAA"))
    emit(Ether(src="02:00:00:0a:00:21", dst=GW_MAC) / IPv6(src="2001:db8:10::21", dst="2001:db8:10::53")
         / UDP(sport=40100, dport=53) / query)


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "examples" / "sample.pcap"
    build()
    wrpcap(str(out), packets)
    print(f"wrote {len(packets)} packets to {out}")


if __name__ == "__main__":
    main()
