import json
import struct

import pytest

from net_toolkit import pcap
from net_toolkit.cli import app
from net_toolkit.commands.pcap_cmd import human_bytes
from net_toolkit.pcap import PcapError, PcapReader, RawPacket, decode, parse_dns, summarize

from .conftest import EXAMPLES

scapy = pytest.importorskip("scapy.all")
from scapy.layers.dns import DNS, DNSQR  # noqa: E402
from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment, IPv6ExtHdrHopByHop  # noqa: E402
from scapy.layers.l2 import ARP, Dot1Q, Ether  # noqa: E402
from scapy.utils import PcapNgWriter, PcapWriter, wrpcap  # noqa: E402

SAMPLE = EXAMPLES / "sample.pcap"
MAC = "02:00:00:00:00:02"  # explicit, so scapy never tries ARP to fill it in


def frame(pkt, linktype=pcap.LINKTYPE_ETHERNET):
    data = bytes(pkt)
    return decode(RawPacket(1.0, linktype, data, len(data)))


def write_classic(path, frames, endian="<", nano=False, linktype=1):
    """Hand-built classic pcap so we can test byte orders scapy will not write."""
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    out = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype)
    for ts, data in frames:
        sec, frac = int(ts), round((ts % 1) * (1e9 if nano else 1e6))
        out += struct.pack(endian + "IIII", sec, frac, len(data), len(data)) + data
    path.write_bytes(out)
    return path


class TestSample:
    def test_totals(self):
        s = summarize(SAMPLE)
        assert (s.format, s.packets, s.truncated) == ("pcap", 91, False)
        assert s.protocols["TCP"] == 60 and s.protocols["OSPF"] == 3 and s.protocols["ARP"] == 2
        assert round(s.duration, 3) == 4.328
        assert s.vlans == {20: 2}

    def test_top_talker(self):
        host, stats = summarize(SAMPLE).top_hosts(1)[0]
        assert host == "10.10.10.21" and stats.received > 30_000

    def test_dns_and_nxdomain(self):
        s = summarize(SAMPLE)
        assert s.dns_queries[("www.example.com", "A")] == 2
        assert s.dns_queries[("www.example.com", "AAAA")] == 1
        assert s.dns_nxdomain == {"fileshare.exmaple.com": 1}

    def test_resets(self):
        s = summarize(SAMPLE)
        assert s.resets[("10.10.99.12", "10.10.10.23", 23)] == 3
        assert s.resets[("10.10.10.40", "10.10.10.22", 3389)] == 1

    def test_to_dict(self):
        data = summarize(SAMPLE).to_dict(top=3)
        assert len(data["top_talkers"]) == 3 and data["vlans"] == {"20": 2}
        assert data["tcp_resets"][0] == {"from": "10.10.99.12", "to": "10.10.10.23", "port": 23, "count": 3}
        json.dumps(data)  # must be serialisable


class TestContainers:
    def test_scapy_pcap_roundtrip(self, tmp_path):
        path = tmp_path / "a.pcap"
        pkt = Ether(dst=MAC) / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()
        pkt.time = 1700000000.25
        wrpcap(str(path), [pkt])
        [raw] = list(PcapReader(path))
        assert raw.ts == pytest.approx(1700000000.25) and raw.linktype == 1

    def test_nanosecond_pcap(self, tmp_path):
        path = tmp_path / "ns.pcap"
        pkt = Ether(dst=MAC) / IP() / UDP()
        pkt.time = 1700000000.123456789
        with PcapWriter(str(path), nano=True) as writer:
            writer.write(pkt)
        assert list(PcapReader(path))[0].ts == pytest.approx(1700000000.123456789)

    @pytest.mark.parametrize("endian", ["<", ">"])
    def test_both_byte_orders(self, tmp_path, endian):
        data = bytes(Ether(dst=MAC) / IP(src="192.0.2.1", dst="192.0.2.2") / TCP(sport=40000, dport=22))
        path = write_classic(tmp_path / "x.pcap", [(5.5, data)], endian=endian)
        s = summarize(path)
        assert s.packets == 1 and s.services["ssh (tcp)"] == 1 and s.first_ts == 5.5

    def test_pcapng(self, tmp_path):
        path = tmp_path / "a.pcapng"
        pkts = [Ether(dst=MAC) / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=443) for _ in range(3)]
        for i, p in enumerate(pkts):
            p.time = 1700000000 + i
        with PcapNgWriter(str(path)) as writer:
            for p in pkts:
                writer.write(p)
        s = summarize(path)
        assert (s.format, s.packets, s.duration) == ("pcapng", 3, pytest.approx(2.0))

    def test_pcapng_big_endian_tsresol_and_simple_packet(self, tmp_path):
        data = bytes(Ether(dst=MAC) / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(dport=123))

        def block(kind, body):
            body += b"\x00" * (-len(body) % 4)
            return struct.pack(">II", kind, len(body) + 12) + body + struct.pack(">I", len(body) + 12)

        shb = block(0x0A0D0D0A, struct.pack(">IHHq", 0x1A2B3C4D, 1, 0, -1))
        tsresol = struct.pack(">HHB3x", 9, 1, 9) + struct.pack(">HH", 0, 0)  # nanoseconds
        idb = block(1, struct.pack(">HHI", 1, 0, 65535) + tsresol)
        ticks = 1_700_000_000_500_000_000
        epb = block(6, struct.pack(">IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(data), len(data)) + data)
        spb = block(3, struct.pack(">I", len(data)) + data)
        nrb = block(4, b"\x00\x00\x00\x00")  # name resolution block: skipped
        path = tmp_path / "be.pcapng"
        path.write_bytes(shb + idb + epb + spb + nrb)
        raws = list(PcapReader(path))
        assert len(raws) == 2
        assert raws[0].ts == pytest.approx(1_700_000_000.5)
        assert raws[1].ts == 0.0 and raws[1].data == data

    def test_tsresol_power_of_two(self):
        assert pcap._tsresol(struct.pack("<HHB3x", 9, 1, 0x80 | 10), "<") == 2.0 ** -10
        assert pcap._tsresol(struct.pack("<HH4s", 2, 4, b"eth0"), "<") == 1e-6
        assert pcap._tsresol(struct.pack("<HHHHB3x", 0, 0, 9, 1, 3), "<") == 1e-6  # after end-of-options

    def test_bad_magic(self, tmp_path):
        path = tmp_path / "x.pcap"
        path.write_bytes(b"not a capture at all")
        with pytest.raises(PcapError, match="not a pcap"):
            list(PcapReader(path))

    def test_truncated_global_header(self, tmp_path):
        path = tmp_path / "x.pcap"
        path.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00")
        with pytest.raises(PcapError, match="global header"):
            list(PcapReader(path))

    def test_truncated_record(self, tmp_path):
        data = bytes(Ether(dst=MAC) / IP() / ICMP())
        path = write_classic(tmp_path / "x.pcap", [(1.0, data), (2.0, data)])
        path.write_bytes(path.read_bytes()[:-10])
        s = summarize(path)
        assert s.packets == 1 and s.truncated

    def test_truncated_record_header(self, tmp_path):
        path = write_classic(tmp_path / "x.pcap", [(1.0, bytes(Ether(dst=MAC) / IP()))])
        path.write_bytes(path.read_bytes() + b"\x01\x02")
        reader = PcapReader(path)
        assert len(list(reader)) == 1 and reader.truncated

    def test_pcapng_bad_bom_and_block_length(self, tmp_path):
        path = tmp_path / "x.pcapng"
        path.write_bytes(b"\x0a\x0d\x0d\x0a" + struct.pack("<I", 28) + b"\xde\xad\xbe\xef" + b"\x00" * 16)
        with pytest.raises(PcapError, match="byte-order"):
            list(PcapReader(path))
        shb = b"\x0a\x0d\x0d\x0a" + struct.pack("<II", 28, 0x1A2B3C4D) + struct.pack("<HHq", 1, 0, -1) + struct.pack("<I", 28)
        path.write_bytes(shb + struct.pack("<II", 6, 13))
        with pytest.raises(PcapError, match="corrupt"):
            list(PcapReader(path))

    def test_pcapng_cut_off(self, tmp_path):
        shb = b"\x0a\x0d\x0d\x0a" + struct.pack("<II", 28, 0x1A2B3C4D) + struct.pack("<HHq", 1, 0, -1) + struct.pack("<I", 28)
        path = tmp_path / "x.pcapng"
        for tail in (b"\x01\x00", struct.pack("<II", 6, 64) + b"\x00" * 8, b"\x0a\x0d\x0d\x0a\x1c\x00\x00\x00\x4d\x3c"):
            path.write_bytes(shb + tail)
            reader = PcapReader(path)
            assert list(reader) == [] and reader.truncated
        for cut in (shb[:6], shb[:10], shb[:20]):
            path.write_bytes(cut)
            assert list(PcapReader(path)) == []


class TestDecode:
    def test_vlan_tagged(self):
        pkt = frame(Ether(dst=MAC) / Dot1Q(vlan=30) / IP(src="10.0.30.5", dst="10.0.30.1") / UDP(sport=5000, dport=161))
        assert (pkt.vlan, pkt.proto, pkt.service) == (30, "UDP", "snmp")

    def test_qinq(self):
        pkt = frame(Ether(dst=MAC) / Dot1Q(vlan=100, type=0x8100) / Dot1Q(vlan=7) / IP() / ICMP())
        assert pkt.vlan == 7 and pkt.proto == "ICMP"

    def test_arp(self):
        pkt = frame(Ether(dst=MAC) / ARP(psrc="10.0.0.5", pdst="10.0.0.1"))
        assert (pkt.proto, pkt.src, pkt.dst) == ("ARP", "10.0.0.5", "10.0.0.1")

    def test_runt_and_unknown_ethertype(self):
        assert decode(RawPacket(0, 1, b"\x00" * 10, 10)).proto == "other"
        assert frame(Ether(dst=MAC, type=0x88CC) / b"lldp").proto == "other"

    def test_unknown_ip_protocol(self):
        assert frame(Ether(dst=MAC) / IP(proto=253) / b"x").proto == "ip-proto-253"

    def test_ipv4_fragment_skips_l4(self):
        pkt = frame(Ether(dst=MAC) / IP(frag=100, proto=6) / (b"\x00" * 20))
        assert pkt.proto == "TCP" and pkt.sport is None

    def test_ipv6_with_hop_by_hop(self):
        pkt = frame(Ether(dst=MAC) / IPv6(src="2001:db8::1", dst="2001:db8::2") / IPv6ExtHdrHopByHop() / UDP(dport=53)
                    / DNS(qd=DNSQR(qname="v6.example.com", qtype="AAAA")))
        assert pkt.l3 == "IPv6" and pkt.dns.name == "v6.example.com" and pkt.dns.qtype == "AAAA"

    def test_ipv6_fragments(self):
        first = frame(Ether(dst=MAC) / IPv6() / IPv6ExtHdrFragment(offset=0, nh=17) / UDP(sport=1, dport=514))
        later = frame(Ether(dst=MAC) / IPv6() / IPv6ExtHdrFragment(offset=10, nh=17) / (b"\x00" * 16))
        assert first.service == "syslog" and later.proto == "UDP" and later.sport is None

    def test_bad_ip_versions(self):
        assert frame(Ether(dst=MAC, type=0x0800) / (b"\x60" + b"\x00" * 30)).l3 == "other"
        assert frame(Ether(dst=MAC, type=0x86DD) / (b"\x45" + b"\x00" * 50)).l3 == "other"

    @pytest.mark.parametrize("linktype, prefix", [
        (pcap.LINKTYPE_RAW, b""),
        (pcap.LINKTYPE_RAW_BSD, b""),
        (pcap.LINKTYPE_LINUX_SLL, b"\x00" * 14 + b"\x08\x00"),
        (pcap.LINKTYPE_LINUX_SLL2, b"\x08\x00" + b"\x00" * 18),
        (pcap.LINKTYPE_NULL, struct.pack("<I", 2)),
        (pcap.LINKTYPE_NULL, struct.pack(">I", 2)),
    ])
    def test_linktypes(self, linktype, prefix):
        data = prefix + bytes(IP(src="10.1.1.1", dst="10.1.1.2") / TCP(sport=40000, dport=80))
        pkt = decode(RawPacket(0, linktype, data, len(data)))
        assert (pkt.src, pkt.service) == ("10.1.1.1", "http")

    def test_null_linktype_ipv6(self):
        data = struct.pack("<I", 30) + bytes(IPv6() / ICMP())
        assert decode(RawPacket(0, pcap.LINKTYPE_NULL, data, len(data))).l3 == "IPv6"

    def test_unknown_linktype(self):
        assert decode(RawPacket(0, 147, b"\x45" * 40, 40)).proto == "other"

    def test_dns_over_tcp(self):
        dns = bytes(DNS(qd=DNSQR(qname="axfr.example.net", qtype="SOA")))
        pkt = frame(Ether(dst=MAC) / IP() / TCP(sport=50000, dport=53) / (struct.pack("!H", len(dns)) + dns))
        assert pkt.dns.name == "axfr.example.net" and pkt.dns.qtype == "SOA"

    def test_service_prefers_known_port(self):
        assert frame(Ether(dst=MAC) / IP() / TCP(sport=443, dport=3389)).service == "https"
        assert frame(Ether(dst=MAC) / IP() / TCP(sport=40000, dport=40001)).service is None


class TestDnsParser:
    def test_compression_pointer(self):
        header = struct.pack("!HHHHHH", 1, 0x8183, 1, 0, 0, 0)  # response, NXDOMAIN
        name = b"\x03www\x07example\x03com\x00"
        msg = header + name + struct.pack("!HH", 1, 1)
        msg = msg + b"\xc0\x0c" + struct.pack("!HH", 1, 1)
        parsed = parse_dns(msg)
        assert (parsed.name, parsed.response, parsed.rcode) == ("www.example.com", True, 3)
        assert pcap._dns_name(msg, len(msg) - 6) == ("www.example.com", len(msg) - 4)

    def test_pointer_loop_is_bounded(self):
        msg = struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\xc0\x0c"
        assert parse_dns(msg) is None

    @pytest.mark.parametrize("msg", [
        b"\x00" * 5,  # too short
        struct.pack("!HHHHHH", 1, 0, 0, 0, 0, 0),  # no questions
        struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\x05ab",  # label runs off the end
        struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\x02ab",  # name never terminates
        struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\x02ab\x00\x00",  # qtype cut off
        struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\xc0",  # half a pointer
    ])
    def test_malformed(self, msg):
        assert parse_dns(msg) is None

    def test_root_and_unknown_type(self):
        msg = struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\x00" + struct.pack("!HH", 999, 1)
        assert (parse_dns(msg).name, parse_dns(msg).qtype) == (".", "TYPE999")


class TestSummary:
    def test_empty_capture(self, tmp_path):
        s = summarize(write_classic(tmp_path / "e.pcap", []))
        assert s.packets == 0 and s.duration == 0.0 and s.to_dict()["top_talkers"] == []

    def test_reset_port_heuristic(self, tmp_path):
        frames = [
            (1.0, bytes(Ether(dst=MAC) / IP(src="10.0.0.9", dst="10.0.0.5") / TCP(sport=443, dport=50000, flags="R"))),
            (2.0, bytes(Ether(dst=MAC) / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=50000, dport=9999, flags="R"))),
        ]
        s = summarize(write_classic(tmp_path / "r.pcap", frames))
        assert set(s.resets) == {("10.0.0.9", "10.0.0.5", 443), ("10.0.0.5", "10.0.0.9", 9999)}


class TestCli:
    def test_demo(self, runner):
        result = runner.invoke(app, ["pcap", "summary", "--demo"])
        assert result.exit_code == 0
        for text in ("top talkers", "198.51.100.10", "fileshare.exmaple.com", "23 (telnet)", "OSPF"):
            assert text in result.output

    def test_json(self, runner):
        result = runner.invoke(app, ["pcap", "summary", str(SAMPLE), "--json", "--top", "2"])
        data = json.loads(result.output)
        assert data["packets"] == 91 and len(data["dns_queries"]) == 2

    def test_empty_and_truncated(self, runner, tmp_path):
        path = write_classic(tmp_path / "x.pcap", [(1.0, bytes(Ether(dst=MAC) / IP() / UDP(sport=9, dport=9)))])
        path.write_bytes(path.read_bytes() + b"\x00\x00")
        result = runner.invoke(app, ["pcap", "summary", str(path)])
        assert "cut off" in result.output and "no DNS queries" in result.output
        assert "no TCP resets" in result.output

    def test_errors(self, runner, tmp_path):
        bad = tmp_path / "bad.pcap"
        bad.write_text("hello")
        assert runner.invoke(app, ["pcap", "summary", str(bad)]).exit_code == 2
        assert runner.invoke(app, ["pcap", "summary", str(tmp_path / "missing.pcap")]).exit_code == 2
        assert runner.invoke(app, ["pcap", "summary"]).exit_code == 2

    @pytest.mark.parametrize("count, text", [(0, "0 B"), (1023, "1023 B"), (2048, "2.0 KB"),
                                             (5 * 1024**2, "5.0 MB"), (3 * 1024**4, "3072.0 GB")])
    def test_human_bytes(self, count, text):
        assert human_bytes(count) == text
