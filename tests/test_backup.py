from datetime import datetime

import pytest

from net_toolkit import backup
from net_toolkit.cli import app
from net_toolkit.commands import backup_cmd
from net_toolkit.inventory import Device

from .conftest import EXAMPLES

RAW = """Building configuration...

Current configuration : 1234 bytes
!
! Last configuration change at 10:00:00 UTC Mon Oct 5 2026 by netadmin
!\r
hostname R1\r
ntp clock-period 17179869
interface Gi0/1   
 description uplink
end

"""


def test_clean_drops_volatile_lines():
    assert backup.clean(RAW) == "!\n!\nhostname R1\ninterface Gi0/1\n description uplink\nend\n"


def test_save_dedupes_and_handles_same_day(tmp_path):
    first = backup.save(tmp_path, "R1", RAW, datetime(2026, 10, 1, 9, 0, 0))
    assert first.changed and first.path.name == "2026-10-01.cfg" and first.lines == 6
    again = backup.save(tmp_path, "R1", RAW + "\n", datetime(2026, 10, 1, 9, 30, 0))
    assert not again.changed and again.path == first.path
    changed = backup.save(tmp_path, "R1", RAW.replace("uplink", "core"), datetime(2026, 10, 1, 14, 5, 9))
    assert changed.path.name == "2026-10-01_140509.cfg"
    later = backup.save(tmp_path, "R1", RAW, datetime(2026, 10, 2))
    assert [p.name for p in backup.history(tmp_path, "R1")] == [
        "2026-10-01.cfg", "2026-10-01_140509.cfg", "2026-10-02.cfg"]
    assert later.changed
    assert backup.save(tmp_path, "R2", RAW).changed  # default timestamp path


def test_history_rejects_path_tricks(tmp_path):
    with pytest.raises(ValueError):
        backup.history(tmp_path, "../etc")
    assert backup.history(tmp_path, "nobody") == []


def test_diff_latest():
    old, new, lines = backup.diff_latest(EXAMPLES / "backups", "CORE-SW1")
    assert (old.name, new.name) == ("2026-10-01.cfg", "2026-10-08.cfg")
    assert lines[0] == "--- CORE-SW1/2026-10-01.cfg"
    assert "+ name CAMERAS" in lines and "-logging buffered 16384" in lines


def test_diff_needs_two(tmp_path):
    with pytest.raises(FileNotFoundError, match="no backups"):
        backup.diff_latest(tmp_path, "R1")
    backup.save(tmp_path, "R1", RAW)
    with pytest.raises(FileNotFoundError, match="only one"):
        backup.diff_latest(tmp_path, "R1")


def test_fetch_uses_platform_command():
    sent = []

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            sent.append("closed")

        def send_command(self, command, **kwargs):
            sent.append(command)
            return "hostname X"

    device = Device("X", "10.0.0.1", "cisco_nxos")
    assert backup.fetch(device, "pw", lambda d, p: Conn()) == "hostname X"
    assert sent == ["show running-config", "closed"]


class TestCli:
    def test_backup_demo_leaves_nothing_behind(self, runner, tmp_path, monkeypatch):
        monkeypatch.setenv("TMPDIR", str(tmp_path))
        import tempfile
        monkeypatch.setattr(tempfile, "tempdir", None)
        result = runner.invoke(app, ["backup", "--demo"])
        assert result.exit_code == 0
        assert "backups/CORE-SW1/" in result.output and "Authentication" in result.output
        assert "3 ok, 2 failed" in result.output
        assert list(tmp_path.iterdir()) == []

    def test_backup_real_path_with_fake_connection(self, runner, tmp_path, monkeypatch):
        monkeypatch.setattr(backup, "netmiko_connect", backup_cmd.demo_connect)
        monkeypatch.setenv("NT_PASSWORD", "x")
        out = tmp_path / "bk"
        args = ["backup", "-i", str(EXAMPLES / "hosts.yml"), "-o", str(out), "--only", "CORE-SW1"]
        first = runner.invoke(app, args)
        assert first.exit_code == 0 and "saved" in first.output
        second = runner.invoke(app, args)
        assert "unchanged" in second.output
        failing = runner.invoke(app, args[:-1] + ["NX-LEAF1"])
        assert failing.exit_code == 1 and "failed" in failing.output

    def test_backup_prompts_for_missing_password(self, runner, tmp_path, monkeypatch):
        seen = []
        monkeypatch.delenv("NT_PASSWORD", raising=False)
        monkeypatch.setattr(backup, "netmiko_connect",
                            lambda d, p: seen.append(p) or backup_cmd.demo_connect(d, p))
        inv = tmp_path / "hosts.yml"
        inv.write_text("devices:\n  - {name: CORE-SW1, host: 10.0.0.1}\n  - {name: DIST-SW2, host: 10.0.0.2}\n")
        result = runner.invoke(app, ["backup", "-i", str(inv), "-o", str(tmp_path / "b")], input="s3cret\n")
        assert result.exit_code == 0 and seen == ["s3cret", "s3cret"]  # asked once, used twice
        assert "s3cret" not in result.output

    def test_backup_errors(self, runner, tmp_path):
        assert runner.invoke(app, ["backup"]).exit_code == 2
        assert runner.invoke(app, ["backup", "-i", str(tmp_path / "none.yml")]).exit_code == 2
        result = runner.invoke(app, ["backup", "-i", str(EXAMPLES / "hosts.yml"), "--only", "NOPE"])
        assert result.exit_code == 2

    def test_unexplained_exception_is_named(self, runner, tmp_path, monkeypatch):
        def boom(device, password):
            raise TimeoutError()
        monkeypatch.setattr(backup, "netmiko_connect", boom)
        monkeypatch.setenv("NT_PASSWORD", "x")
        result = runner.invoke(app, ["backup", "-i", str(EXAMPLES / "hosts.yml"), "-o", str(tmp_path),
                                     "--only", "CORE-SW1"])
        assert "TimeoutError" in result.output

    def test_diff_demo(self, runner):
        result = runner.invoke(app, ["diff", "--demo"])
        assert result.exit_code == 0
        assert "+vlan 40" in result.output and "+12 -2 lines" in result.output

    def test_diff_identical_and_missing(self, runner, tmp_path):
        backup.save(tmp_path, "R1", "hostname R1\n", datetime(2026, 1, 1))
        (tmp_path / "R1" / "2026-01-02.cfg").write_text("hostname R1\n")
        result = runner.invoke(app, ["diff", "R1", "--dir", str(tmp_path)])
        assert "no differences" in result.output
        assert runner.invoke(app, ["diff", "R9", "--dir", str(tmp_path)]).exit_code == 2
        assert runner.invoke(app, ["diff"]).exit_code == 2

    def test_colour(self):
        styles = [backup_cmd.colour(x).style for x in ("--- a", "+++ b", "@@ -1 +1 @@", "+x", "-y", " z")]
        assert styles == ["bold", "bold", "cyan", "green", "red", ""]
