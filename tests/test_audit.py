import json

import pytest

from net_toolkit import audit
from net_toolkit.audit import Severity, audit_text, parse_config, trunk_allowed, vlan_list
from net_toolkit.cli import app

from .conftest import EXAMPLES

HARDENED = """\
hostname GOOD
service password-encryption
enable secret 9 $9$x$y
ip ssh version 2
logging host 10.0.0.50
ntp server 10.0.0.10
ip access-list standard MGMT
 permit 10.0.0.0 0.0.0.255
line vty 0 4
 access-class MGMT in
 transport input ssh
"""


def rules_hit(text):
    return {f.rule for f in audit_text(text).findings}


def with_lines(*extra):
    return HARDENED + "\n".join(extra) + "\n"


def test_hardened_baseline_is_clean():
    assert audit_text(HARDENED).findings == []


class TestParser:
    def test_blocks_children_and_line_numbers(self):
        cfg = parse_config("hostname R1\n!\ninterface Gi0/1\n description x\n shutdown\n")
        assert [b.text for b in cfg.blocks] == ["hostname R1", "interface Gi0/1"]
        assert [c.number for c in cfg.blocks[1].children] == [4, 5]
        assert cfg.hostname == "R1"

    def test_banner_body_is_skipped(self):
        cfg = parse_config("banner motd ^C\nline vty 0 4\n transport input telnet\n^C\nhostname X\n")
        assert [b.text for b in cfg.blocks] == ["banner motd ^C", "hostname X"]

    def test_single_line_banner(self):
        cfg = parse_config("banner login #Keep out#\nhostname X\n")
        assert cfg.hostname == "X"

    def test_no_hostname(self):
        assert parse_config("interface Gi0/1\n").hostname is None

    def test_orphan_indented_line_becomes_block(self):
        assert parse_config(" stray\n").blocks[0].text == "stray"


class TestRules:
    @pytest.mark.parametrize("transport, severity", [
        ("transport input telnet", Severity.HIGH),
        ("transport input all", Severity.HIGH),
        ("transport input telnet ssh", Severity.HIGH),
    ])
    def test_telnet(self, transport, severity):
        text = f"line vty 0 4\n access-class MGMT in\n {transport}\n" + HARDENED.split("line vty")[0]
        findings = [f for f in audit_text(text).findings if f.rule == "telnet-enabled"]
        assert [f.severity for f in findings] == [severity]
        assert findings[0].line == 3

    def test_missing_transport_input(self):
        findings = audit_text(with_lines("line vty 5 15", " access-class MGMT in")).findings
        assert [(f.rule, f.severity) for f in findings] == [("telnet-enabled", Severity.MEDIUM)]

    def test_password_encryption(self):
        text = HARDENED.replace("service password-encryption", "no service password-encryption")
        assert rules_hit(text) == {"no-password-encryption"}

    def test_enable_password_is_redacted(self):
        finding = audit_text(with_lines("enable password 7 0822455D0A16")).findings[0]
        assert finding.rule == "enable-password" and "0822" not in finding.evidence

    def test_ssh_v1_explicit(self):
        text = HARDENED.replace("ip ssh version 2", "ip ssh version 1")
        [finding] = audit_text(text).findings
        assert (finding.rule, finding.severity) == ("ssh-v1", Severity.HIGH)

    def test_ssh_not_pinned(self):
        [finding] = audit_text(HARDENED.replace("ip ssh version 2\n", "")).findings
        assert (finding.rule, finding.severity) == ("ssh-v1", Severity.LOW)

    def test_logging_old_syntax_counts(self):
        text = HARDENED.replace("logging host 10.0.0.50", "logging 10.0.0.50")
        assert audit_text(text).findings == []

    def test_logging_buffered_only(self):
        text = HARDENED.replace("logging host 10.0.0.50", "logging buffered 16384")
        assert rules_hit(text) == {"no-logging"}

    def test_ntp(self):
        assert rules_hit(HARDENED.replace("ntp server", "ntp source")) == {"no-ntp"}

    @pytest.mark.parametrize("line, severity", [
        ("snmp-server community public RO", Severity.HIGH),
        ("snmp-server community private RW", Severity.CRITICAL),
        ("snmp-server community shorty RO MGMT", Severity.HIGH),
        ("snmp-server community LongRandom123 view ALL RO", Severity.MEDIUM),
        ("snmp-server community LongRandom123 RW", Severity.HIGH),
    ])
    def test_snmp(self, line, severity):
        findings = [f for f in audit_text(with_lines(line)).findings if f.rule == "weak-snmp"]
        assert [f.severity for f in findings] == [severity]

    def test_snmp_strong_with_acl_is_fine(self):
        assert audit_text(with_lines("snmp-server community LongRandom123 RO MGMT")).findings == []

    def test_snmp_strong_community_is_masked(self):
        finding = audit_text(with_lines("snmp-server community LongRandom123 RO")).findings[0]
        assert "LongRandom123" not in finding.evidence and finding.evidence.count("*") == 11

    def test_unused_acls_named_and_numbered(self):
        text = with_lines(
            "access-list 10 permit 10.0.0.0 0.0.0.255",
            "access-list 10 deny any",
            "ip access-list extended SPARE",
            " permit ip any any",
        )
        findings = audit_text(text).findings
        assert sorted(f.message for f in findings) == [
            "ACL '10' is defined but never applied",
            "ACL 'SPARE' is defined but never applied",
        ]

    @pytest.mark.parametrize("reference", [
        "interface Gi0/1\n ip access-group SPARE in",
        "ip nat inside source list SPARE interface Gi0/0 overload",
        "route-map RM permit 10\n match ip address OTHER SPARE",
        "class-map match-any C\n match access-group name SPARE",
        "snmp-server community LongRandom123 RO SPARE",
        "router ospf 1\n distribute-list SPARE in",
        "ntp access-group peer SPARE",
        "interface Gi0/1\n ipv6 traffic-filter SPARE in",
    ])
    def test_acl_references(self, reference):
        text = with_lines("ip access-list extended SPARE", " permit ip any any", reference)
        assert "unused-acl" not in rules_hit(text)

    def test_http_server(self):
        assert rules_hit(with_lines("ip http server")) == {"http-server"}
        assert rules_hit(with_lines("no ip http server")) == set()

    def test_vty_access_class(self):
        assert rules_hit(HARDENED.replace(" access-class MGMT in\n", "")) == {"vty-no-acl", "unused-acl"}
        assert rules_hit(with_lines("line vty 5 15", " transport input none")) == set()


class TestTrunks:
    def trunk(self, *lines):
        return with_lines("interface Gi0/48", " switchport mode trunk", *lines)

    def test_defaults(self):
        [finding] = audit_text(self.trunk()).findings
        assert finding.message == "Gi0/48: native VLAN is 1; all VLANs allowed (including 1)"

    def test_clean_trunk(self):
        assert audit_text(self.trunk(" switchport trunk native vlan 999",
                                     " switchport trunk allowed vlan 10,20")).findings == []

    def test_vlan1_allowed_via_range(self):
        [finding] = audit_text(self.trunk(" switchport trunk native vlan 999",
                                          " switchport trunk allowed vlan 1-30")).findings
        assert finding.message.endswith("VLAN 1 is in the allowed list")

    def test_access_port_ignored(self):
        assert audit_text(with_lines("interface Gi0/2", " switchport mode access")).findings == []

    @pytest.mark.parametrize("lines, expected", [
        ([], None),
        (["switchport trunk allowed vlan 10,20"], {10, 20}),
        (["switchport trunk allowed vlan 10", "switchport trunk allowed vlan add 1-2"], {1, 2, 10}),
        (["switchport trunk allowed vlan 1-5", "switchport trunk allowed vlan remove 1"], {2, 3, 4, 5}),
        (["switchport trunk allowed vlan remove 1"], set(range(2, 4095))),
        (["switchport trunk allowed vlan except 1"], set(range(2, 4095))),
        (["switchport trunk allowed vlan none"], set()),
        (["switchport trunk allowed vlan 10", "switchport trunk allowed vlan add all"], None),
        (["switchport trunk allowed vlan all"], None),
    ])
    def test_trunk_allowed(self, lines, expected):
        block = parse_config("interface Gi0/1\n" + "".join(f" {line}\n" for line in lines)).blocks[0]
        assert trunk_allowed(block) == expected

    def test_vlan_list(self):
        assert vlan_list("1-3,7") == {1, 2, 3, 7}
        assert vlan_list("all") is None and vlan_list("none") == set()


class TestReport:
    def test_sorted_worst_first(self):
        report = audit_text((EXAMPLES / "configs" / "edge-rtr1.cfg").read_text())
        severities = [f.severity for f in report.findings]
        assert severities == sorted(severities, reverse=True)
        assert report.worst() == Severity.CRITICAL
        assert report.counts() == {"critical": 1, "high": 3, "medium": 4, "low": 3, "info": 0}

    def test_examples(self):
        expected = {"edge-rtr1": 11, "core-sw1": 3, "dist-sw2": 3, "lab-rtr3": 0}
        for name, count in expected.items():
            report = audit_text((EXAMPLES / "configs" / f"{name}.cfg").read_text())
            assert len(report.findings) == count, name
        assert audit.Report("x", None, []).worst() is None

    def test_severity_parse(self):
        assert Severity.parse(" High ") == Severity.HIGH
        with pytest.raises(ValueError, match="unknown severity"):
            Severity.parse("urgent")

    def test_every_rule_registered_once(self):
        assert len(audit.RULES) == len({r.__name__ for r in audit.RULES}) == 11


class TestCli:
    def test_demo(self, runner):
        result = runner.invoke(app, ["audit", "--demo"])
        assert result.exit_code == 0
        assert "EDGE-RTR1" in result.output and "CRITICAL" in result.output

    def test_json_single(self, runner):
        result = runner.invoke(app, ["audit", str(EXAMPLES / "configs" / "core-sw1.cfg"), "--json"])
        data = json.loads(result.output)
        assert data["hostname"] == "CORE-SW1" and data["summary"]["medium"] == 2

    def test_json_many_with_floor(self, runner):
        paths = [str(p) for p in sorted((EXAMPLES / "configs").glob("*.cfg"))]
        result = runner.invoke(app, ["audit", *paths, "--json", "--min-severity", "high"])
        data = json.loads(result.output)
        assert len(data) == 4
        assert all(f["severity"] in ("high", "critical") for r in data for f in r["findings"])

    def test_fail_on(self, runner):
        edge = str(EXAMPLES / "configs" / "edge-rtr1.cfg")
        clean = str(EXAMPLES / "configs" / "lab-rtr3.cfg")
        assert runner.invoke(app, ["audit", edge, "--fail-on", "high"]).exit_code == 1
        result = runner.invoke(app, ["audit", clean, "--fail-on", "low"])
        assert result.exit_code == 0 and "no findings" in result.output

    def test_bad_severity(self, runner):
        assert runner.invoke(app, ["audit", "--demo", "--fail-on", "urgent"]).exit_code == 2

    def test_missing_file(self, runner, tmp_path):
        result = runner.invoke(app, ["audit", str(tmp_path / "nope.cfg")])
        assert result.exit_code == 2

    def test_no_args(self, runner):
        assert runner.invoke(app, ["audit"]).exit_code == 2
