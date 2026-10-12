# net-toolkit

[![CI](https://github.com/fdjfnd222dd/net-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/fdjfnd222dd/net-toolkit/actions/workflows/ci.yml)

One `nt` command for everyday network work: subnetting, sweeps, config backups and diffs, IOS security audits, pcap triage and latency matrices.

Every command takes `--demo`, which runs on bundled, invented data and sends no packets. You can try the whole toolkit without a lab.

## Demo

All output below was captured from the commands shown (colour removed). Hostnames, addresses and the capture are invented. "Internet" addresses come from the RFC 5737 documentation ranges.

### `nt subnet`: subnet math, equal splits and VLSM

```text
$ nt subnet 10.20.0.0/22 --split 4 --vlsm Users=200,Voice=50,Printers=20,Mgmt=10,WAN=2
10.20.0.0/22
┌─────────────────┬─────────────────────────┐
│ network         │ 10.20.0.0/22            │
│ netmask         │ 255.255.252.0           │
│ wildcard        │ 0.0.3.255               │
│ broadcast       │ 10.20.3.255             │
│ usable range    │ 10.20.0.1 - 10.20.3.254 │
│ usable hosts    │ 1,022                   │
│ total addresses │ 1,024                   │
│ scope           │ private (RFC 1918)      │
│ class           │ A                       │
└─────────────────┴─────────────────────────┘
10.20.0.0/22 split into 4
┏━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━┓
┃ # ┃ subnet       ┃ usable range            ┃ broadcast   ┃ hosts ┃
┡━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━┩
│ 1 │ 10.20.0.0/24 │ 10.20.0.1 - 10.20.0.254 │ 10.20.0.255 │   254 │
│ 2 │ 10.20.1.0/24 │ 10.20.1.1 - 10.20.1.254 │ 10.20.1.255 │   254 │
│ 3 │ 10.20.2.0/24 │ 10.20.2.1 - 10.20.2.254 │ 10.20.2.255 │   254 │
│ 4 │ 10.20.3.0/24 │ 10.20.3.1 - 10.20.3.254 │ 10.20.3.255 │   254 │
└───┴──────────────┴─────────────────────────┴─────────────┴───────┘
VLSM in 10.20.0.0/22 (largest first)
┏━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━┓
┃ name     ┃ need ┃ subnet         ┃ mask            ┃ usable range              ┃ usable ┃ waste ┃
┡━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━┩
│ Users    │  200 │ 10.20.0.0/24   │ 255.255.255.0   │ 10.20.0.1 - 10.20.0.254   │    254 │    54 │
│ Voice    │   50 │ 10.20.1.0/26   │ 255.255.255.192 │ 10.20.1.1 - 10.20.1.62    │     62 │    12 │
│ Printers │   20 │ 10.20.1.64/27  │ 255.255.255.224 │ 10.20.1.65 - 10.20.1.94   │     30 │    10 │
│ Mgmt     │   10 │ 10.20.1.96/28  │ 255.255.255.240 │ 10.20.1.97 - 10.20.1.110  │     14 │     4 │
│ WAN      │    2 │ 10.20.1.112/30 │ 255.255.255.252 │ 10.20.1.113 - 10.20.1.114 │      2 │     0 │
└──────────┴──────┴────────────────┴─────────────────┴───────────────────────────┴────────┴───────┘
free: 10.20.1.116/30, 10.20.1.120/29, 10.20.1.128/25, 10.20.2.0/23
```

### `nt scan`: ICMP + TCP connect sweep

```text
$ nt scan --demo
scan 10.10.10.0/24
┏━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ host        ┃     icmp ┃ open tcp ports                        ┃ note                            ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 10.10.10.1  │  0.61 ms │ 22/ssh, 179/bgp, 443/https            │                                 │
│ 10.10.10.2  │  0.84 ms │ 22/ssh, 830/netconf                   │                                 │
│ 10.10.10.10 │  1.12 ms │ 53/dns, 135/msrpc, 139/netbios,       │                                 │
│             │          │ 389/ldap, 445/smb, 636/ldaps          │                                 │
│ 10.10.10.21 │  3.40 ms │ 3389/rdp                              │                                 │
│ 10.10.10.22 │ no reply │ 22/ssh, 80/http                       │ ICMP filtered, alive via TCP    │
│ 10.10.10.40 │  2.05 ms │ 80/http, 443/https, 8443/https-alt    │                                 │
│ 10.10.10.50 │  0.97 ms │ 22/ssh, 5432/postgres                 │                                 │
│ 10.10.10.60 │ 12.80 ms │ -                                     │ alive, every probed port closed │
└─────────────┴──────────┴───────────────────────────────────────┴─────────────────────────────────┘
8/254 hosts up, 6,350 probes in 0.2s
```

It will not touch public address space unless you confirm you own it:

```text
$ nt scan 8.8.8.0/24
refused: 8.8.8.0/24 is not private address space (public or carrier NAT). Only scan networks you own
or are authorised to test; re-run with --i-own-this to confirm.
```

### `nt backup` and `nt diff`: config history over SSH

```text
$ nt backup --demo
backup -> backups (demo: temporary directory)
┏━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ device     ┃ platform   ┃ status ┃ file                                                  ┃ lines ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ CORE-SW1   │ cisco_ios  │ saved  │ backups/CORE-SW1/2026-10-12.cfg                       │    91 │
│ DIST-SW2   │ cisco_ios  │ saved  │ backups/DIST-SW2/2026-10-12.cfg                       │    54 │
│ EDGE-RTR1  │ cisco_ios  │ saved  │ backups/EDGE-RTR1/2026-10-12.cfg                      │    73 │
│ NX-LEAF1   │ cisco_nxos │ failed │ Authentication to device failed.                      │     - │
│ EOS-SPINE1 │ arista_eos │ failed │ TCP connection to device failed (timed out after      │     - │
│            │            │        │ 10s).                                                 │       │
└────────────┴────────────┴────────┴───────────────────────────────────────────────────────┴───────┘
3 ok, 2 failed
```

```text
$ nt diff CORE-SW1 --dir examples/backups
--- CORE-SW1/2026-10-01.cfg
+++ CORE-SW1/2026-10-08.cfg
@@ -27,6 +27,8 @@
  name VOICE
 vlan 30
  name PRINTERS
+vlan 40
+ name CAMERAS
 vlan 99
  name MGMT
 vlan 999
@@ -41,7 +43,7 @@
 interface GigabitEthernet1/0/47
  description Trunk to DIST-SW2 (pruned, native moved off VLAN 1)
  switchport trunk native vlan 999
- switchport trunk allowed vlan 10,20,30,99
+ switchport trunk allowed vlan 10,20,30,40,99
  switchport mode trunk
 !
 interface GigabitEthernet1/0/48
@@ -56,6 +58,10 @@
  ip address 10.10.20.1 255.255.255.0
  ip ospf 1 area 0
 !
+interface Vlan40
+ ip address 10.10.40.1 255.255.255.0
+ ip ospf 1 area 0
+!
 interface Vlan99
  ip address 10.10.99.1 255.255.255.0
  ip ospf 1 area 0
@@ -64,6 +70,7 @@
  router-id 10.255.0.2
  passive-interface default
  no passive-interface GigabitEthernet1/0/1
+ area 0 authentication message-digest
 !
 ip access-list standard MGMT-ONLY
  permit 10.10.99.0 0.0.0.255
@@ -73,7 +80,10 @@
  deny   ip 10.10.50.0 0.0.0.255 10.10.0.0 0.0.255.255
  permit ip 10.10.50.0 0.0.0.255 any
 !
-logging buffered 16384
+logging host 10.10.99.50
+logging trap informational
+ntp server 10.10.99.10
+ntp server 10.10.99.11
 !
 snmp-server community Mon1toringRO24 RO
 !

+12 -2 lines
```

### `nt audit`: static security audit of Cisco IOS configs

```text
$ nt audit examples/configs/edge-rtr1.cfg
EDGE-RTR1  examples/configs/edge-rtr1.cfg
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ severity ┃ rule                   ┃ line ┃ finding                   ┃ fix                       ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CRITICAL │ weak-snmp              │   64 │ Guessable SNMP community  │ Use SNMPv3 authPriv, or a │
│          │                        │      │ with RW access            │ long random community +   │
│          │                        │      │                           │ ACL.                      │
│ HIGH     │ enable-password        │   15 │ 'enable password' uses    │ Use 'enable               │
│          │                        │      │ reversible encryption     │ algorithm-type scrypt     │
│          │                        │      │                           │ secret'.                  │
│ HIGH     │ weak-snmp              │   63 │ Guessable SNMP community  │ Use SNMPv3 authPriv, or a │
│          │                        │      │ with RO access            │ long random community +   │
│          │                        │      │                           │ ACL.                      │
│ HIGH     │ telnet-enabled         │   71 │ Telnet allowed on 'line   │ Use 'transport input      │
│          │                        │      │ vty 0 4' (clear-text      │ ssh'.                     │
│          │                        │      │ logins)                   │                           │
│ MEDIUM   │ no-logging             │    - │ No remote syslog server   │ Add 'logging host         │
│          │                        │      │ is configured             │ <collector>'.             │
│ MEDIUM   │ no-ntp                 │    - │ No NTP server; log        │ Add two authenticated     │
│          │                        │      │ timestamps cannot be      │ 'ntp server' lines.       │
│          │                        │      │ trusted                   │                           │
│ MEDIUM   │ no-password-encryption │    - │ 'service                  │ Enable 'service           │
│          │                        │      │ password-encryption' is   │ password-encryption'; use │
│          │                        │      │ off; type 0 passwords     │ type 8/9 secrets.         │
│          │                        │      │ readable                  │                           │
│ MEDIUM   │ http-server            │   49 │ Plain-text HTTP           │ Use 'no ip http server'.  │
│          │                        │      │ management server is      │                           │
│          │                        │      │ enabled                   │                           │
│ LOW      │ ssh-v1                 │    - │ SSH version not pinned;   │ Set 'ip ssh version 2'.   │
│          │                        │      │ default 1.99 still        │                           │
│          │                        │      │ accepts SSHv1             │                           │
│ LOW      │ unused-acl             │   55 │ ACL 'WAN-IN' is defined   │ Apply it or remove it.    │
│          │                        │      │ but never applied         │                           │
│ LOW      │ vty-no-acl             │   68 │ 'line vty 0 4' accepts    │ Add 'access-class         │
│          │                        │      │ logins from any source    │ <mgmt-acl> in'.           │
└──────────┴────────────────────────┴──────┴───────────────────────────┴───────────────────────────┘
critical: 1  high: 3  medium: 4  low: 3
```

```text
$ nt audit examples/configs/*.cfg --json --min-severity medium | jq -c '.[] | {hostname, summary}'
{"hostname":"CORE-SW1","summary":{"critical":0,"high":0,"medium":2,"low":0,"info":0}}
{"hostname":"DIST-SW2","summary":{"critical":0,"high":0,"medium":3,"low":0,"info":0}}
{"hostname":"EDGE-RTR1","summary":{"critical":1,"high":3,"medium":4,"low":0,"info":0}}
{"hostname":"LAB-RTR3","summary":{"critical":0,"high":0,"medium":0,"low":0,"info":0}}
```

### `nt pcap summary`: capture triage

```text
$ nt pcap summary examples/sample.pcap --top 5
capture
┌──────────────┬──────────────────────────────────────────────────────┐
│ file         │ examples/sample.pcap (pcap)                          │
│ packets      │ 91                                                   │
│ bytes        │ 43.6 KB                                              │
│ first / last │ 2026-01-01 12:00:00 UTC  ->  2026-01-01 12:00:04 UTC │
│ duration     │ 4.33 s  (21.0 pkt/s)                                 │
│ 802.1Q VLANs │ 20 (2 pkts)                                          │
└──────────────┴──────────────────────────────────────────────────────┘
top talkers
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━┓
┃ host          ┃ pkts sent ┃    sent ┃ received ┃   total ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━┩
│ 10.10.10.21   │        11 │   876 B │  34.6 KB │ 35.5 KB │
│ 198.51.100.10 │        26 │ 34.2 KB │    516 B │ 34.7 KB │
│ 10.10.10.22   │         7 │   731 B │   4.1 KB │  4.9 KB │
│ 203.0.113.80  │         6 │  3.8 KB │    516 B │  4.3 KB │
│ 10.10.10.23   │         8 │   757 B │   1.6 KB │  2.4 KB │
└───────────────┴───────────┴─────────┴──────────┴─────────┘
protocols
┏━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┳━━━━━━━┓
┃ protocol ┃ packets ┃   bytes ┃ share ┃
┡━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━╇━━━━━━━┩
│ TCP      │      60 │ 41.3 KB │ 94.8% │
│ UDP      │      16 │  1.5 KB │  3.3% │
│ ICMP     │       9 │   406 B │  0.9% │
│ OSPF     │       3 │   246 B │  0.6% │
│ ARP      │       2 │    84 B │  0.2% │
└──────────┴─────────┴─────────┴───────┘
services
┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┓
┃ service (by port) ┃ packets ┃
┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━┩
│ https (tcp)       │      30 │
│ ssh (tcp)         │      12 │
│ dns (udp)         │      11 │
│ http (tcp)        │      10 │
│ telnet (tcp)      │       6 │
└───────────────────┴─────────┘
DNS queries
┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━┳━━━━━━━━━━┓
┃ name                  ┃ type ┃ count ┃ NXDOMAIN ┃
┡━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━╇━━━━━━━━━━┩
│ www.example.com       │ A    │     2 │        - │
│ intranet.example.net  │ A    │     1 │        - │
│ updates.example.org   │ AAAA │     1 │        - │
│ fileshare.exmaple.com │ A    │     1 │        1 │
│ www.example.com       │ AAAA │     1 │        - │
└───────────────────────┴──────┴───────┴──────────┘
TCP resets
┏━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━┓
┃ from        ┃ to          ┃ port        ┃ count ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━┩
│ 10.10.99.12 │ 10.10.10.23 │ 23 (telnet) │     3 │
│ 10.10.10.40 │ 10.10.10.22 │ 3389 (rdp)  │     1 │
└─────────────┴─────────────┴─────────────┴───────┘
```

### `nt ping-matrix`: loss, latency and jitter over N rounds

```text
$ nt ping-matrix --demo --rounds 12
ping matrix  round 12/12
┏━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━┳━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ device     ┃ address     ┃ sent ┃ loss ┃ min ms ┃ avg ms ┃ max ms ┃ jitter ms ┃ recent       ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━╇━━━━━━╇━━━━━━━━╇━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ CORE-SW1   │ 10.10.99.1  │   12 │   0% │   0.61 │   0.70 │   0.75 │      0.05 │ ▇▂▁█▇██▇▃▇▆▂ │
│ DIST-SW2   │ 10.10.99.12 │   12 │   0% │   1.10 │   1.27 │   1.36 │      0.15 │ ▁█▃█▄█▁▅█▇▄█ │
│ EDGE-RTR1  │ 10.10.0.1   │   12 │   0% │   0.91 │   1.00 │   1.08 │      0.08 │ ▁▄▃▆█▂▁█▇▇▁▇ │
│ NX-LEAF1   │ 10.10.99.21 │   12 │   8% │   2.49 │   3.41 │   4.10 │      0.59 │ ▆▆×▂▅█▆█▁▃▄▅ │
│ EOS-SPINE1 │ 10.10.99.31 │   12 │  33% │   4.15 │   5.34 │   6.27 │      1.34 │ ▆▁█××▃▆▁▆█×× │
└────────────┴─────────────┴──────┴──────┴────────┴────────┴────────┴───────────┴──────────────┘
```

`--watch` redraws the table live after every round; `--rounds 0 --watch` keeps going until Ctrl-C.

## Install

Python 3.11 or newer.

```bash
git clone https://github.com/fdjfnd222dd/net-toolkit.git
cd net-toolkit
pipx install .
nt --help
```

For development, use a repo-local virtual environment:

```bash
python -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest --cov=net_toolkit
```

## Usage

| Command | What it does | Useful options |
| --- | --- | --- |
| `nt subnet CIDR` | Network, broadcast, usable range, host count, wildcard mask, scope and class. Accepts `10.20.1.5/22` or `10.20.1.5 255.255.252.0`. | `--split N`, `--vlsm 50,20,10` or `--vlsm Sales=50,Eng=20`, `--json` |
| `nt scan CIDR` | Ping plus TCP connect sweep with a progress bar. A port that answers RST still proves the host is up. | `--ports common\|22,80,8000-8010`, `--rate 100`, `--timeout`, `--no-icmp`, `--json`, `--i-own-this`, `--max-hosts` |
| `nt backup -i hosts.yml` | Pulls `show running-config` from Cisco IOS/IOS-XE/NX-OS and Arista EOS with Netmiko into `backups/<host>/<date>.cfg`. Skips the write when nothing changed. | `--out DIR`, `--only NAME`, `--workers` |
| `nt diff HOST` | Unified diff of the two newest backups for HOST, coloured. | `--dir DIR`, `-U N` |
| `nt audit FILE...` | Checks for telnet on vty lines, missing `service password-encryption`, `enable password`, SSHv1, VLAN 1 on trunks, no remote syslog, no NTP, weak or unrestricted SNMP communities, unused ACLs, the HTTP server and vty lines with no ACL. | `--json`, `--min-severity`, `--fail-on high` (exits 1 so CI can gate on it) |
| `nt pcap summary FILE` | Top talkers, protocols, services, 802.1Q VLANs, DNS queries (with NXDOMAIN) and TCP resets, from pcap or pcapng. | `--top N`, `--json` |
| `nt ping-matrix hosts.yml` | Pings every host for N rounds and reports loss, min/avg/max, jitter and a sparkline. | `--rounds N`, `--interval`, `--watch` |

### Inventory (`hosts.yml`)

`backup` and `ping-matrix` share one inventory format. See [`examples/hosts.yml`](examples/hosts.yml):

```yaml
defaults:
  username: netadmin
  password_env: NT_PASSWORD   # name of an environment variable, never the password
  device_type: cisco_ios      # cisco_ios, cisco_xe, cisco_nxos, arista_eos

devices:
  - name: CORE-SW1
    host: 10.10.99.1
  - name: NX-LEAF1
    host: 10.10.99.21
    device_type: cisco_nxos
```

Passwords are never read from the file. If the named environment variable is unset, `nt backup` prompts once for each variable. For `ping-matrix`, a plain YAML list of addresses also works.

### Scanning responsibly

`nt scan` only sweeps private, loopback and link-local space unless you pass `--i-own-this`. It caps a sweep at 4,096 addresses unless you raise `--max-hosts`, and `--rate` limits probes per second across all threads. ICMP goes through the system `ping` binary and TCP uses a normal `connect()`, so nothing needs root. Only scan networks you own or have permission to test.

### Example files

| Path | What it is |
| --- | --- |
| `examples/configs/*.cfg` | Four invented IOS configs: a neglected edge router, a core switch with sloppy trunks, an access switch with a few gaps, and a hardened router that audits clean. |
| `examples/backups/CORE-SW1/` | Two dated backups of the same switch, a week apart, for `nt diff`. |
| `examples/sample.pcap` | 91 invented packets: ARP, DNS (with one NXDOMAIN typo), HTTPS/HTTP/SSH sessions, refused telnet and RDP, ICMP, NTP, syslog, SNMP, OSPF hellos, tagged SIP and some IPv6. |
| `scripts/make_sample_pcap.py` | Rebuilds `sample.pcap` with Scapy. Its timestamps are fixed, so every run produces the same file byte for byte. |

## Why I built it

Lab work kept needing the same handful of throwaway scripts: a subnet calculator, a quick sweep, a config grab before a change, a look inside a capture. One tested CLI made them dependable enough for lab sessions and for studying subnetting, VLAN trunking and OSPF. Because every command has an offline `--demo`, the toolkit also works as a study aid with no lab hardware.

## Built with

- [Typer](https://typer.tiangolo.com/) for the CLI and [Rich](https://rich.readthedocs.io/) for tables, progress bars and the live view
- [Netmiko](https://github.com/ktbyers/netmiko) for SSH to Cisco and Arista gear (plus PyYAML, which Netmiko already installs)
- Python's standard library for everything else: `ipaddress` for subnet math, `struct` for a hand-written pcap/pcapng parser, `difflib` for diffs
- [Scapy](https://scapy.net/) to generate the sample capture and build test packets (development only)
- pytest and pytest-cov, with GitHub Actions running the suite on Python 3.11 and 3.12

## License

[MIT](LICENSE) © Nick B
