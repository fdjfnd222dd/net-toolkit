import socket
import struct
import threading

import pytest

from net_toolkit import devices
from net_toolkit.devices import (
    Identity, build_ptr_query, identify, parse_nbstat, parse_neighbour_output, parse_ptr_answer, vendor_for,
)


def name_bytes(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


class TestVendor:
    @pytest.mark.parametrize("mac, vendor", [
        ("f0:18:98:aa:bb:cc", "Apple"),
        ("0:1c:73:1:2:3", "Arista Networks"),
        ("00-00-0C-12-34-56", "Cisco Systems"),
        ("da:18:98:aa:bb:cc", devices.RANDOM_MAC),  # locally administered bit set
        ("52:54:00:12:34:56", devices.RANDOM_MAC),  # QEMU/KVM guest
        ("00:00:00:00:00:01", "XEROX"),
        (None, None),
    ])
    def test_lookup(self, mac, vendor):
        assert vendor_for(mac) == vendor

    def test_unknown_prefix(self, monkeypatch):
        monkeypatch.setattr(devices, "oui_table", lambda: {})
        assert vendor_for("00:11:22:33:44:55") is None

    def test_table_is_complete(self):
        assert len(devices.oui_table()) > 30_000


class TestNeighbours:
    def test_proc_arp(self, tmp_path):
        arp = tmp_path / "arp"
        arp.write_text(
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.1.1      0x1         0x2         8c:8d:28:00:00:01     *        wlan0\n"
            "192.168.1.50     0x1         0x0         00:00:00:00:00:00     *        wlan0\n"
            "192.168.1.60     0x1         0x2         00:00:00:00:00:00     *        wlan0\n"
        )
        assert devices.neighbours(str(arp)) == {"192.168.1.1": "8c:8d:28:00:00:01"}

    def test_ip_neigh_and_arp_output(self):
        text = (
            "10.0.0.1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n"
            "10.0.0.9 dev eth0 INCOMPLETE\n"
            "? (10.0.0.2) at 0:1c:73:a:b:c on en0 ifscope [ethernet]\n"
            "  10.0.0.3          f0-18-98-aa-bb-cc     dynamic\n"
        )
        assert parse_neighbour_output(text) == {
            "10.0.0.1": "aa:bb:cc:dd:ee:01",
            "10.0.0.2": "00:1c:73:0a:0b:0c",
            "10.0.0.3": "f0:18:98:aa:bb:cc",
        }

    def test_default_gateway(self, tmp_path):
        route = tmp_path / "route"
        route.write_text(
            "Iface\tDestination\tGateway \tFlags\n"
            "wlan0\t0001A8C0\t00000000\t0001\n"
            "wlan0\t00000000\t0101A8C0\t0003\n"
        )
        assert devices.default_gateway(str(route)) == "192.168.1.1"
        route.write_text("Iface\tDestination\tGateway\n")
        assert devices.default_gateway(str(route)) is None
        assert devices.default_gateway(str(tmp_path / "missing")) is None

    def test_local_address(self, monkeypatch):
        assert devices.local_address("127.0.0.1") == "127.0.0.1"

        def broken(*args):
            raise OSError("network unreachable")
        monkeypatch.setattr(devices.socket, "socket", broken)
        assert devices.local_address("2001:db8::1") is None


class TestReverseDns:
    @pytest.mark.parametrize("answer, expected", [
        ("printer.home.arpa", "printer.home.arpa"),
        ("nas01.lan", "nas01.lan"),
        ("_gateway", None),
        ("10.0.0.5", None),
        ("5.0.0.10.in-addr.arpa", None),
    ])
    def test_names(self, monkeypatch, answer, expected):
        monkeypatch.setattr(devices.socket, "gethostbyaddr", lambda ip: (answer, [], [ip]))
        assert devices.reverse_dns("10.0.0.5") == expected

    def test_failure(self, monkeypatch):
        def fail(ip):
            raise socket.herror("unknown host")
        monkeypatch.setattr(devices.socket, "gethostbyaddr", fail)
        assert devices.reverse_dns("10.0.0.5") is None


class TestMdns:
    def test_query_shape(self):
        query = build_ptr_query("192.168.1.20", txid=7)
        assert query[:12] == struct.pack("!HHHHHH", 7, 0, 1, 0, 0, 0)
        assert name_bytes("20.1.168.192.in-addr.arpa") in query and query.endswith(b"\x00\x0c\x00\x01")

    def test_parse_answer_after_question_and_other_records(self):
        question = name_bytes("20.1.168.192.in-addr.arpa") + struct.pack("!HH", 12, 1)
        a_record = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 120, 4) + bytes(4)
        target = name_bytes("Living-Room-TV.local")
        ptr = b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 120, len(target)) + target
        reply = struct.pack("!HHHHHH", 7, 0x8400, 1, 2, 0, 0) + question + a_record + ptr
        assert parse_ptr_answer(reply) == "Living-Room-TV"

    @pytest.mark.parametrize("reply", [
        b"\x00" * 5,
        struct.pack("!HHHHHH", 0, 0x8400, 0, 0, 0, 0),
        struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0) + b"\x00" + b"\x00\x0c",  # cut-off record
        struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0) + b"\x00" + struct.pack("!HHIH", 12, 1, 1, 1) + b"\x00",
    ])
    def test_unusable_replies(self, reply):
        assert parse_ptr_answer(reply) is None

    def test_mdns_name_uses_udp(self, monkeypatch):
        target = name_bytes("pi.local")
        reply = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0) + b"\x00" + struct.pack("!HHIH", 12, 1, 1, len(target)) + target
        sent = []
        monkeypatch.setattr(devices, "_udp_query", lambda ip, port, data, t: sent.append(port) or reply)
        assert devices.mdns_name("10.0.0.7") == "pi" and sent == [5353]
        monkeypatch.setattr(devices, "_udp_query", lambda *a: None)
        assert devices.mdns_name("10.0.0.7") is None


class TestNetbios:
    def reply(self, entries):
        body = bytes([len(entries)]) + b"".join(
            name.ljust(15).encode() + bytes([suffix]) + struct.pack("!H", flags) for name, suffix, flags in entries)
        rr = b"\x20" + b"CK" + b"AA" * 15 + b"\x00" + struct.pack("!HHIH", 0x21, 1, 0, len(body))
        return struct.pack("!HHHHHH", 0x4E54, 0x8400, 0, 1, 0, 0) + rr + body

    def test_picks_unique_workstation_name(self):
        data = self.reply([("WORKGROUP", 0x00, 0x8400), ("DESKTOP-7Q2", 0x20, 0x0400), ("DESKTOP-7Q2", 0x00, 0x0400)])
        assert parse_nbstat(data) == "DESKTOP-7Q2"

    def test_no_match_and_truncation(self):
        assert parse_nbstat(self.reply([("WORKGROUP", 0x00, 0x8400)])) is None
        assert parse_nbstat(self.reply([("PC", 0x00, 0)])[:-5]) is None
        assert parse_nbstat(b"\x00" * 8) is None
        assert parse_nbstat(self.reply([])[:-1]) is None

    def test_netbios_name(self, monkeypatch):
        monkeypatch.setattr(devices, "_udp_query", lambda ip, port, data, t: self.reply([("NAS", 0, 0)]))
        assert devices.netbios_name("10.0.0.8") == "NAS"
        assert devices.netbios_name("fe80::1") is None
        monkeypatch.setattr(devices, "_udp_query", lambda *a: None)
        assert devices.netbios_name("10.0.0.8") is None


def test_udp_query_round_trip_and_failure():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]

    def echo():
        data, addr = server.recvfrom(100)
        server.sendto(data.upper(), addr)

    thread = threading.Thread(target=echo)
    thread.start()
    assert devices._udp_query("127.0.0.1", port, b"hello", 2.0) == b"HELLO"
    thread.join()
    server.close()
    assert devices._udp_query("127.0.0.1", port, b"x", 0.2) is None  # nothing listening now


def test_lookup_name_order(monkeypatch):
    calls = []
    monkeypatch.setattr(devices, "reverse_dns", lambda ip, t: calls.append("dns"))
    monkeypatch.setattr(devices, "mdns_name", lambda ip, t: calls.append("mdns") or "tv")
    monkeypatch.setattr(devices, "netbios_name", lambda ip, t: calls.append("netbios"))
    assert devices.lookup_name("10.0.0.1") == "tv" and calls == ["dns", "mdns"]
    monkeypatch.setattr(devices, "mdns_name", lambda ip, t: None)
    assert devices.lookup_name("10.0.0.1") is None


def test_identify(monkeypatch):
    monkeypatch.setattr(devices.socket, "gethostname", lambda: "laptop")
    found = identify(
        ["10.0.0.1", "10.0.0.5", "10.0.0.9"],
        neighbour_table=lambda: {"10.0.0.1": "00:00:0c:00:00:01", "10.0.0.9": "f0:18:98:00:00:09"},
        namer=lambda ip, t: {"10.0.0.9": "phone"}.get(ip),
        gateway=lambda: "10.0.0.1",
        local=lambda target: "10.0.0.5",
    )
    assert found["10.0.0.1"] == Identity("00:00:0c:00:00:01", "Cisco Systems", None, False, True)
    assert found["10.0.0.5"] == Identity(None, None, "laptop", True, False)
    assert found["10.0.0.9"].name == "phone" and found["10.0.0.9"].vendor == "Apple"
    assert identify([]) == {}
