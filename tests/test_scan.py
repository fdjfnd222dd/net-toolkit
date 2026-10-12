import ipaddress
import json

import pytest

from net_toolkit import probes, scan
from net_toolkit.cli import app
from net_toolkit.commands.scan_cmd import port_label
from net_toolkit.scan import HostResult, ScanRefused, check_target, parse_ports, sweep


class TestPorts:
    def test_common(self):
        assert parse_ports("common") == scan.COMMON_PORTS
        assert parse_ports("COMMON") is not scan.COMMON_PORTS  # a copy, safe to mutate

    def test_list_and_ranges(self):
        assert parse_ports("443, 22,8000-8002,,22") == [22, 443, 8000, 8001, 8002]

    @pytest.mark.parametrize("spec", ["ssh", "0", "70000", "90-80", "1-x"])
    def test_bad(self, spec):
        with pytest.raises(ValueError):
            parse_ports(spec)

    def test_labels(self):
        assert port_label(22) == "22/ssh" and port_label(830) == "830/netconf" and port_label(9999) == "9999"


class TestGuard:
    @pytest.mark.parametrize("target", ["192.168.1.0/24", "10.20.0.0/22", "172.16.5.4", "127.0.0.1",
                                        "fe80::/120", "fd00::/120", "192.0.2.0/24"])
    def test_allowed(self, target):
        assert check_target(target).num_addresses >= 1

    @pytest.mark.parametrize("target", ["8.8.8.0/24", "1.1.1.1", "100.64.0.0/24", "2001:4860::/120"])
    def test_public_refused(self, target):
        with pytest.raises(ScanRefused, match="--i-own-this"):
            check_target(target)

    def test_public_with_confirmation(self):
        assert str(check_target("8.8.8.0/30", i_own_this=True)) == "8.8.8.0/30"

    def test_size_cap(self):
        with pytest.raises(ScanRefused, match="--max-hosts"):
            check_target("10.0.0.0/16")
        assert check_target("10.0.0.0/16", max_hosts=70000).prefixlen == 16

    def test_garbage(self):
        with pytest.raises(ScanRefused, match="not an IP"):
            check_target("example.com")


class TestSweep:
    def test_results(self):
        net = ipaddress.ip_network("10.0.0.0/29")
        calls = []

        def pinger(host, timeout):
            calls.append(("icmp", host))
            return 1.5 if host == "10.0.0.1" else None

        def connector(host, port, timeout):
            calls.append(("tcp", host, port))
            if host == "10.0.0.2" and port == 22:
                return probes.OPEN
            if host == "10.0.0.3":
                return probes.CLOSED
            return probes.FILTERED

        ticks = []
        results = sweep(net, [443, 22], rate=None, pinger=pinger, connector=connector,
                        on_probe=lambda: ticks.append(1))
        assert [r.address for r in results] == [f"10.0.0.{i}" for i in range(1, 7)]
        up = {r.address: r for r in results if r.up}
        assert set(up) == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
        assert up["10.0.0.2"].open_ports == [22] and up["10.0.0.3"].refused == 2
        assert len(calls) == len(ticks) == 6 * 3

    def test_no_icmp(self):
        seen = []
        sweep(ipaddress.ip_network("10.0.0.0/30"), [80], rate=None, icmp=False,
              pinger=lambda h, t: seen.append(h), connector=lambda h, p, t: probes.FILTERED)
        assert seen == []

    def test_rate_limit_is_used(self, monkeypatch):
        acquired = []
        monkeypatch.setattr(probes.RateLimiter, "acquire", lambda self: acquired.append(self.interval))
        sweep(ipaddress.ip_network("10.0.0.0/30"), [80], rate=50, pinger=lambda h, t: None,
              connector=lambda h, p, t: probes.FILTERED)
        assert acquired == [0.02] * 4

    def test_slash_32(self):
        [result] = sweep(ipaddress.ip_network("10.9.9.9/32"), [], rate=None, pinger=lambda h, t: 0.2)
        assert result.up and result.address == "10.9.9.9"

    def test_host_result(self):
        assert not HostResult("x").up
        assert HostResult("x", refused=1).up


class TestCli:
    def test_demo_table(self, runner):
        result = runner.invoke(app, ["scan", "--demo"])
        assert result.exit_code == 0
        assert "8/254 hosts up" in result.output and "ICMP filtered" in result.output

    def test_demo_json(self, runner):
        data = json.loads(runner.invoke(app, ["scan", "--demo", "--json", "-p", "22"]).output)
        assert data["probes"] == 254 * 2
        assert [h["address"] for h in data["hosts_up"] if h["open_ports"] == [22]][:2] == ["10.10.10.1", "10.10.10.2"]

    def test_public_refused(self, runner):
        result = runner.invoke(app, ["scan", "8.8.8.0/24"])
        assert result.exit_code == 2 and "refused" in result.output

    def test_bad_ports_and_missing_target(self, runner):
        assert runner.invoke(app, ["scan", "10.0.0.0/30", "-p", "http"]).exit_code == 2
        assert runner.invoke(app, ["scan"]).exit_code == 2

    def test_real_sweep_of_loopback(self, runner, monkeypatch):
        monkeypatch.setattr(probes, "ping", lambda host, timeout=1.0: 0.05)
        monkeypatch.setattr(scan.probes, "tcp_probe", lambda h, p, t=1.0: probes.CLOSED)
        # defaults were bound at import time, so patch the sweep defaults too
        monkeypatch.setattr(scan.sweep, "__kwdefaults__", {
            **scan.sweep.__kwdefaults__, "pinger": probes.ping, "connector": scan.probes.tcp_probe})
        result = runner.invoke(app, ["scan", "127.0.0.1", "-p", "22,80", "--rate", "1000"])
        assert result.exit_code == 0 and "1/1 hosts up" in result.output and "<= 1000/s" in result.output
