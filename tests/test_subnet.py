import ipaddress

import pytest

from net_toolkit import subnet as calc
from net_toolkit.cli import app


def net(text):
    return ipaddress.ip_network(text)


class TestDescribe:
    def test_slash_22(self):
        info = calc.describe("10.20.0.0/22")
        assert str(info.network) == "10.20.0.0/22"
        assert str(info.netmask) == "255.255.252.0"
        assert str(info.wildcard) == "0.0.3.255"
        assert str(info.broadcast) == "10.20.3.255"
        assert (str(info.first_usable), str(info.last_usable)) == ("10.20.0.1", "10.20.3.254")
        assert (info.total, info.usable) == (1024, 1022)
        assert info.scope == "private (RFC 1918)"
        assert info.ip_class == "A"
        assert info.version == 4 and info.prefixlen == 22

    def test_host_bits_and_dotted_mask(self):
        info = calc.describe("10.20.1.5 255.255.252.0")
        assert str(info.address) == "10.20.1.5"
        assert str(info.network) == "10.20.0.0/22"

    def test_bare_address_is_slash_32(self):
        info = calc.describe("172.16.5.4")
        assert info.prefixlen == 32 and info.usable == 1 and info.broadcast is None
        assert info.ip_class == "B"

    def test_slash_31_point_to_point(self):
        info = calc.describe("192.0.2.6/31")
        assert info.usable == 2 and info.broadcast is None
        assert str(info.first_usable) == "192.0.2.6"
        assert info.scope.startswith("documentation")

    def test_slash_30(self):
        info = calc.describe("10.0.0.0/30")
        assert info.usable == 2 and str(info.broadcast) == "10.0.0.3"

    def test_ipv6(self):
        info = calc.describe("2001:db8:10::/64")
        assert info.broadcast is None and info.ip_class is None
        assert info.total == 2**64
        assert str(info.wildcard) == "::ffff:ffff:ffff:ffff"

    def test_invalid(self):
        with pytest.raises(ValueError, match="not a valid"):
            calc.describe("10.300.0.0/24")

    @pytest.mark.parametrize(
        "cidr, scope",
        [
            ("127.0.0.0/8", "loopback"),
            ("169.254.0.0/16", "link-local"),
            ("224.0.0.0/24", "multicast"),
            ("100.64.0.0/10", "shared (CGNAT, RFC 6598)"),
            ("198.51.100.0/24", "documentation (RFC 5737/3849)"),
            ("fd00::/8", "private (ULA)"),
            ("240.0.0.0/4", "reserved"),
            ("0.0.0.0/32", "reserved"),
            ("198.18.0.0/15", "special-use (not routed)"),
            ("172.16.8.0/24", "private (RFC 1918)"),
            ("8.8.8.0/24", "public"),
        ],
    )
    def test_scope(self, cidr, scope):
        assert calc.scope_of(net(cidr)) == scope

    @pytest.mark.parametrize(
        "addr, cls",
        [("10.0.0.0", "A"), ("172.16.0.0", "B"), ("192.168.0.0", "C"),
         ("224.0.0.1", "D (multicast)"), ("250.0.0.0", "E (reserved)")],
    )
    def test_classful(self, addr, cls):
        assert calc.classful(ipaddress.IPv4Address(addr)) == cls


class TestSplit:
    def test_four_ways(self):
        assert [str(n) for n in calc.split(net("10.20.0.0/22"), 4)] == [
            "10.20.0.0/24", "10.20.1.0/24", "10.20.2.0/24", "10.20.3.0/24",
        ]

    def test_rounds_up_to_power_of_two(self):
        assert len(calc.split(net("10.0.0.0/24"), 3)) == 4
        assert len(calc.split(net("10.0.0.0/24"), 1)) == 1

    def test_too_small(self):
        with pytest.raises(ValueError, match="too small"):
            calc.split(net("10.0.0.0/30"), 8)

    @pytest.mark.parametrize("count", [0, calc.MAX_SPLIT + 1])
    def test_bounds(self, count):
        with pytest.raises(ValueError):
            calc.split(net("10.0.0.0/8"), count)

    def test_ipv6(self):
        assert str(calc.split(net("2001:db8::/48"), 2)[1]) == "2001:db8:0:8000::/49"


class TestVlsm:
    def test_parse(self):
        assert calc.parse_vlsm("50, Eng=20,,10") == [("net1", 50), ("Eng", 20), ("net4", 10)]

    @pytest.mark.parametrize("spec", ["", "abc", "Sales=0", " , "])
    def test_parse_errors(self, spec):
        with pytest.raises(ValueError):
            calc.parse_vlsm(spec)

    @pytest.mark.parametrize("hosts, prefix", [(1, 30), (2, 30), (3, 29), (6, 29), (14, 28),
                                               (30, 27), (62, 26), (126, 25), (254, 24), (255, 23)])
    def test_prefix_for_hosts(self, hosts, prefix):
        assert calc.prefix_for_hosts(hosts) == prefix

    def test_classic_lab(self):
        allocations, free = calc.vlsm(net("10.20.0.0/22"), calc.parse_vlsm("10,50,20"))
        assert [(a.name, str(a.subnet)) for a in allocations] == [
            ("net2", "10.20.0.0/26"), ("net3", "10.20.0.64/27"), ("net1", "10.20.0.96/28"),
        ]
        assert [a.waste for a in allocations] == [12, 10, 4]
        assert [str(f) for f in free] == ["10.20.0.112/28", "10.20.0.128/25", "10.20.1.0/24",
                                          "10.20.2.0/23"]

    def test_exact_fit_leaves_no_free_space(self):
        allocations, free = calc.vlsm(net("10.0.0.0/25"), [("a", 62), ("b", 62)])
        assert len(allocations) == 2 and free == []

    def test_does_not_fit(self):
        with pytest.raises(ValueError, match="only 0 addresses remain"):
            calc.vlsm(net("10.0.0.0/26"), [("a", 60), ("b", 10)])

    def test_request_bigger_than_block(self):
        with pytest.raises(ValueError, match="needs a /23"):
            calc.vlsm(net("10.0.0.0/24"), [("big", 300)])

    def test_ipv6_rejected(self):
        with pytest.raises(ValueError, match="IPv4 only"):
            calc.vlsm(net("2001:db8::/64"), [("a", 10)])


class TestCli:
    def test_basic(self, runner):
        result = runner.invoke(app, ["subnet", "10.20.0.0/22"])
        assert result.exit_code == 0
        assert "10.20.3.255" in result.output and "0.0.3.255" in result.output

    def test_split_and_vlsm(self, runner):
        result = runner.invoke(app, ["subnet", "10.0.0.0/24", "--split", "3", "--vlsm", "Lab=20"])
        assert result.exit_code == 0
        assert "4 spare" in result.output and "rounded up to 4" in result.output
        assert "10.0.0.0/27" in result.output

    def test_host_bits_and_p2p_note(self, runner):
        result = runner.invoke(app, ["subnet", "192.0.2.7/31"])
        assert "host bits set" in result.output and "RFC 3021" in result.output

    def test_demo(self, runner):
        result = runner.invoke(app, ["subnet", "--demo"])
        assert result.exit_code == 0
        assert "VLSM in 10.20.0.0/22" in result.output and "WAN" in result.output

    def test_error_exit_code(self, runner):
        result = runner.invoke(app, ["subnet", "10.0.0.0/30", "--vlsm", "50"])
        assert result.exit_code == 2
        assert "only 4 addresses remain" in result.output

    def test_missing_argument(self, runner):
        assert runner.invoke(app, ["subnet"]).exit_code == 2

    def test_completion_options_exposed(self, runner):
        result = runner.invoke(app, ["--help"])
        assert "--install-completion" in result.output and "--show-completion" in result.output

    def test_version(self, runner):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0 and result.output.startswith("nt ")
