"""Static audit of a Cisco IOS running-config.

The config is parsed into top-level blocks (a line plus its indented children), then a
list of small rule functions each look for one weakness. Rules never touch a device.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, text: str) -> Severity:
        try:
            return cls[text.strip().upper()]
        except KeyError as exc:
            choices = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {text!r} (choose from {choices})") from exc


@dataclass(frozen=True)
class Line:
    number: int  # 1-based line number in the file, for pointing people at the problem
    text: str


@dataclass
class Block:
    line: Line
    children: list[Line] = field(default_factory=list)

    @property
    def text(self) -> str:
        return self.line.text

    def child(self, pattern: str) -> Line | None:
        regex = re.compile(pattern)
        return next((c for c in self.children if regex.search(c.text)), None)


@dataclass
class Config:
    blocks: list[Block]

    @property
    def hostname(self) -> str | None:
        found = self.find(r"^hostname\s+(\S+)")
        return found[0][1].group(1) if found else None

    def find(self, pattern: str) -> list[tuple[Line, re.Match[str]]]:
        """Top-level lines matching `pattern`."""
        regex = re.compile(pattern)
        hits = []
        for block in self.blocks:
            match = regex.search(block.text)
            if match:
                hits.append((block.line, match))
        return hits

    def blocks_matching(self, pattern: str) -> list[Block]:
        regex = re.compile(pattern)
        return [b for b in self.blocks if regex.search(b.text)]

    def all_lines(self) -> Iterator[Line]:
        for block in self.blocks:
            yield block.line
            yield from block.children


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: Severity
    message: str
    fix: str
    line: int | None = None
    evidence: str | None = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.name.lower()
        return data


def parse_config(text: str) -> Config:
    """Split IOS config text into blocks, skipping `!` separators and banner bodies."""
    blocks: list[Block] = []
    banner_end: str | None = None
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        if banner_end is not None:  # inside a multi-line banner: ignore until delimiter
            if banner_end in line:
                banner_end = None
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("!"):
            continue
        banner = re.match(r"^banner\s+\S+\s+(\^C|\S)(.*)$", line)
        if banner:
            delimiter, rest = banner.groups()
            if delimiter not in rest:
                banner_end = delimiter
            blocks.append(Block(Line(number, stripped)))
            continue
        if line[0].isspace() and blocks:
            blocks[-1].children.append(Line(number, stripped))
        else:
            blocks.append(Block(Line(number, stripped)))
    return Config(blocks)


# --- rules -------------------------------------------------------------------------------

Rule = Callable[[Config], list[Finding]]
RULES: list[Rule] = []


def rule(func: Rule) -> Rule:
    RULES.append(func)
    return func


@rule
def telnet_enabled(cfg: Config) -> list[Finding]:
    findings = []
    for block in cfg.blocks_matching(r"^line\s+vty\b"):
        transport = block.child(r"^transport\s+input\b")
        if transport is None:
            findings.append(Finding(
                "telnet-enabled", Severity.MEDIUM,
                f"'{block.text}' has no 'transport input' (older IOS allows telnet)",
                "Add 'transport input ssh'.",
                block.line.number, block.text,
            ))
        elif re.search(r"\b(telnet|all)\b", transport.text):
            findings.append(Finding(
                "telnet-enabled", Severity.HIGH,
                f"Telnet allowed on '{block.text}' (clear-text logins)",
                "Use 'transport input ssh'.",
                transport.number, transport.text,
            ))
    return findings


@rule
def password_encryption(cfg: Config) -> list[Finding]:
    if cfg.find(r"^service\s+password-encryption\b"):
        return []
    return [Finding(
        "no-password-encryption", Severity.MEDIUM,
        "'service password-encryption' is off; type 0 passwords readable",
        "Enable 'service password-encryption'; use type 8/9 secrets.",
    )]


@rule
def enable_password(cfg: Config) -> list[Finding]:
    return [
        Finding(
            "enable-password", Severity.HIGH,
            "'enable password' uses reversible encryption",
            "Use 'enable algorithm-type scrypt secret'.",
            line.number, "enable password <redacted>",
        )
        for line, _ in cfg.find(r"^enable\s+password\b")
    ]


@rule
def ssh_version(cfg: Config) -> list[Finding]:
    v1 = cfg.find(r"^ip\s+ssh\s+version\s+1\b")
    if v1:
        line = v1[0][0]
        return [Finding(
            "ssh-v1", Severity.HIGH, "SSH version 1 is enabled (broken protocol)",
            "Set 'ip ssh version 2'.", line.number, line.text,
        )]
    if not cfg.find(r"^ip\s+ssh\s+version\s+2\b"):
        return [Finding(
            "ssh-v1", Severity.LOW,
            "SSH version not pinned; default 1.99 still accepts SSHv1",
            "Set 'ip ssh version 2'.",
        )]
    return []


def vlan_list(text: str) -> set[int] | None:
    """Expand '1-5,10,20-22' to a set. Returns None for 'all'."""
    text = text.strip()
    if text == "all":
        return None
    vlans: set[int] = set()
    if text in ("none", ""):
        return vlans
    for part in text.split(","):
        start, _, end = part.partition("-")
        vlans.update(range(int(start), int(end or start) + 1))
    return vlans


def trunk_allowed(block: Block) -> set[int] | None:
    """Work out the allowed VLANs on a trunk, following 'add' and 'remove' lines."""
    allowed: set[int] | None = None  # no command means all VLANs
    for child in block.children:
        match = re.match(r"^switchport\s+trunk\s+allowed\s+vlan\s+(add\s+|remove\s+|except\s+)?(\S+)", child.text)
        if not match:
            continue
        verb, value = (match.group(1) or "").strip(), match.group(2)
        vlans = vlan_list(value)
        if verb == "add":
            allowed = None if allowed is None or vlans is None else allowed | vlans
        elif verb == "remove" and allowed is not None and vlans is not None:
            allowed -= vlans
        elif verb == "remove" and vlans is not None:
            allowed = set(range(1, 4095)) - vlans
        elif verb == "except" and vlans is not None:
            allowed = set(range(1, 4095)) - vlans
        else:
            allowed = vlans
    return allowed


@rule
def vlan1_on_trunks(cfg: Config) -> list[Finding]:
    findings = []
    for block in cfg.blocks_matching(r"^interface\s+"):
        if not block.child(r"^switchport\s+mode\s+trunk\b"):
            continue
        reasons = []
        native = block.child(r"^switchport\s+trunk\s+native\s+vlan\s+\d+")
        if native is None or native.text.split()[-1] == "1":
            reasons.append("native VLAN is 1")
        allowed = trunk_allowed(block)
        if allowed is None:
            reasons.append("all VLANs allowed (including 1)")
        elif 1 in allowed:
            reasons.append("VLAN 1 is in the allowed list")
        if reasons:
            findings.append(Finding(
                "vlan1-trunk", Severity.MEDIUM,
                f"{block.text.split(None, 1)[1]}: " + "; ".join(reasons),
                "Use an unused native VLAN; prune the allowed list.",
                block.line.number, block.text,
            ))
    return findings


@rule
def remote_logging(cfg: Config) -> list[Finding]:
    if cfg.find(r"^logging\s+(host\s+\S+|\d+\.\d+\.\d+\.\d+|server\s+\S+)"):
        return []
    return [Finding(
        "no-logging", Severity.MEDIUM, "No remote syslog server is configured",
        "Add 'logging host <collector>'.",
    )]


@rule
def ntp_configured(cfg: Config) -> list[Finding]:
    if cfg.find(r"^ntp\s+(server|peer)\s+"):
        return []
    return [Finding(
        "no-ntp", Severity.MEDIUM, "No NTP server; log timestamps cannot be trusted",
        "Add two authenticated 'ntp server' lines.",
    )]


WEAK_COMMUNITIES = {
    "public", "private", "cisco", "community", "snmp", "admin", "manager",
    "secret", "password", "default", "test", "monitor", "read", "write",
}


def mask(secret: str) -> str:
    return secret if secret.lower() in WEAK_COMMUNITIES else secret[:2] + "*" * (len(secret) - 2)


@rule
def snmp_communities(cfg: Config) -> list[Finding]:
    findings = []
    pattern = r"^snmp-server\s+community\s+(\S+)(?:\s+view\s+\S+)?(?:\s+(RO|RW))?(?:\s+ipv6\s+\S+)?(?:\s+(\S+))?"
    for line, match in cfg.find(pattern):
        community, mode, acl = match.group(1), (match.group(2) or "RO").upper(), match.group(3)
        evidence = line.text.replace(community, mask(community), 1)
        weak = community.lower() in WEAK_COMMUNITIES or len(community) < 8
        if weak:
            findings.append(Finding(
                "weak-snmp", Severity.CRITICAL if mode == "RW" else Severity.HIGH,
                f"Guessable SNMP community with {mode} access",
                "Use SNMPv3 authPriv, or a long random community + ACL.",
                line.number, evidence,
            ))
        elif acl is None:
            findings.append(Finding(
                "weak-snmp", Severity.HIGH if mode == "RW" else Severity.MEDIUM,
                f"SNMP {mode} community has no ACL restricting who can poll",
                "Append an ACL that permits only the NMS.",
                line.number, evidence,
            ))
    return findings


ACL_REFERENCE_PATTERNS = [
    r"\baccess-group\s+(?:(?:peer|serve|serve-only|query-only|name)\s+)?(\S+)",
    r"\baccess-class\s+(\S+)",
    r"\btraffic-filter\s+(\S+)",
    r"\bmatch\s+(?:ip\s+)?address\s+(?!prefix-list)(.+)",
    r"\bip\s+nat\s+.*\blist\s+(\S+)",
    r"\bdistribute-list\s+(\S+)",
    r"^snmp-server\s+community\s+\S+.*\s(\S+)$",
]


@rule
def unused_acls(cfg: Config) -> list[Finding]:
    defined: dict[str, Line] = {}
    for line, match in cfg.find(r"^ip\s+access-list\s+(?:standard|extended)\s+(\S+)"):
        defined.setdefault(match.group(1), line)
    for line, match in cfg.find(r"^access-list\s+(\d+)\s"):
        defined.setdefault(match.group(1), line)
    used: set[str] = set()
    for line in cfg.all_lines():
        if re.match(r"^(ip\s+)?access-list\b", line.text):
            continue
        for pattern in ACL_REFERENCE_PATTERNS:
            match = re.search(pattern, line.text)
            if match:
                used.update(match.group(1).split())
    return [
        Finding(
            "unused-acl", Severity.LOW, f"ACL '{name}' is defined but never applied",
            "Apply it or remove it.",
            line.number, line.text,
        )
        for name, line in defined.items()
        if name not in used
    ]


@rule
def http_server(cfg: Config) -> list[Finding]:
    return [
        Finding(
            "http-server", Severity.MEDIUM, "Plain-text HTTP management server is enabled",
            "Use 'no ip http server'.",
            line.number, line.text,
        )
        for line, _ in cfg.find(r"^ip\s+http\s+server\b")
    ]


@rule
def vty_access_class(cfg: Config) -> list[Finding]:
    return [
        Finding(
            "vty-no-acl", Severity.LOW,
            f"'{block.text}' accepts logins from any source",
            "Add 'access-class <mgmt-acl> in'.",
            block.line.number, block.text,
        )
        for block in cfg.blocks_matching(r"^line\s+vty\b")
        if not block.child(r"^access-class\s+\S+\s+in\b")
        and not block.child(r"^transport\s+input\s+none\b")
    ]


@dataclass
class Report:
    source: str
    hostname: str | None
    findings: list[Finding]

    def counts(self) -> dict[str, int]:
        return {
            sev.name.lower(): sum(1 for f in self.findings if f.severity == sev)
            for sev in sorted(Severity, reverse=True)
        }

    def worst(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "hostname": self.hostname,
            "summary": self.counts(),
            "findings": [f.to_dict() for f in self.findings],
        }


def audit_text(text: str, source: str = "<config>") -> Report:
    cfg = parse_config(text)
    findings = [finding for check in RULES for finding in check(cfg)]
    findings.sort(key=lambda f: (-f.severity, f.line or 0, f.rule))
    return Report(source, cfg.hostname, findings)
