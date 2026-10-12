import pytest

from net_toolkit import pingmatrix
from net_toolkit.cli import app
from net_toolkit.commands import ping_cmd
from net_toolkit.pingmatrix import DemoPinger, Series, run_round, sparkline

from .conftest import EXAMPLES


def test_series_stats():
    s = Series("r1", "10.0.0.1", [1.0, None, 3.0, 2.0])
    assert (s.sent, s.loss_pct, s.min, s.max, s.avg) == (4, 25.0, 1.0, 3.0, 2.0)
    assert s.jitter == pytest.approx(1.5)  # |3-1| and |2-3|


def test_series_empty_and_single():
    empty = Series("x", "h")
    assert (empty.loss_pct, empty.min, empty.avg, empty.max, empty.jitter) == (0.0, None, None, None, None)
    assert Series("x", "h", [None, 5.0]).jitter is None


def test_sparkline():
    assert sparkline([1.0, 2.0, 3.0, None, 8.0]) == "▁▂▃×█"
    assert sparkline([None, None]) == "××"
    assert sparkline([4.0, 4.0]) == "▁▁"
    assert len(sparkline([1.0] * 30, width=12)) == 12


def test_run_round_keeps_order():
    series = [Series("a", "h1"), Series("b", "h2")]
    run_round(series, lambda host, timeout: {"h1": 1.0, "h2": None}[host])
    assert [s.samples for s in series] == [[1.0], [None]]


def test_demo_pinger_is_deterministic():
    hosts = {"10.0.0.1": "CORE-SW1", "10.0.0.2": "EOS-SPINE1", "10.0.0.3": "unknown"}
    a, b = DemoPinger(hosts), DemoPinger(hosts)
    runs_a = [[a(h, 1) for h in hosts] for _ in range(20)]
    assert runs_a == [[b(h, 1) for h in hosts] for _ in range(20)]
    assert None in [row[1] for row in runs_a]  # the lossy spine drops some
    assert a("192.0.2.9", 1) is not None  # host outside the map still answers


class TestCli:
    def test_demo(self, runner):
        result = runner.invoke(app, ["ping-matrix", "--demo", "--rounds", "8"])
        assert result.exit_code == 0
        assert "round 8/8" in result.output and "EOS-SPINE1" in result.output

    def test_real_path_with_fake_ping(self, runner, monkeypatch, tmp_path):
        monkeypatch.setattr(pingmatrix.probes, "ping", lambda host, timeout: 0.5)
        hosts = tmp_path / "h.yml"
        hosts.write_text("- 127.0.0.1\n- ::1\n")
        result = runner.invoke(app, ["ping-matrix", str(hosts), "--rounds", "2", "--interval", "0"])
        assert result.exit_code == 0 and "::1" in result.output and "0.50" in result.output

    def test_interval_sleeps_between_rounds(self, runner, monkeypatch):
        sleeps = []
        monkeypatch.setattr(ping_cmd.time, "sleep", sleeps.append)
        monkeypatch.setattr(pingmatrix.probes, "ping", lambda host, timeout: 0.5)
        result = runner.invoke(app, ["ping-matrix", str(EXAMPLES / "hosts.yml"), "-n", "3", "--interval", "0.2"])
        assert result.exit_code == 0 and sleeps == [0.2, 0.2]

    def test_watch(self, runner, monkeypatch):
        sleeps = []
        monkeypatch.setattr(ping_cmd.time, "sleep", sleeps.append)
        result = runner.invoke(app, ["ping-matrix", "--demo", "--watch", "--rounds", "3", "--interval", "0.1"])
        assert result.exit_code == 0 and sleeps == [0.1, 0.1] and "round 3/3" in result.output

    def test_watch_forever_until_ctrl_c(self, runner, monkeypatch):
        calls = []

        def fake_sleep(seconds):
            calls.append(seconds)
            if len(calls) == 4:
                raise KeyboardInterrupt

        monkeypatch.setattr(ping_cmd.time, "sleep", fake_sleep)
        result = runner.invoke(app, ["ping-matrix", "--demo", "--watch", "--rounds", "0"])
        assert result.exit_code == 0 and "round 4, Ctrl-C to stop" in result.output

    def test_ctrl_c_without_watch_prints_partial(self, runner, monkeypatch):
        def interrupted(series, pinger, timeout):
            raise KeyboardInterrupt
        monkeypatch.setattr(pingmatrix, "run_round", interrupted)
        result = runner.invoke(app, ["ping-matrix", "--demo"])
        assert result.exit_code == 0 and "round 0/5" in result.output

    def test_errors(self, runner, tmp_path):
        assert runner.invoke(app, ["ping-matrix"]).exit_code == 2
        assert runner.invoke(app, ["ping-matrix", "--demo", "--rounds", "0"]).exit_code == 2
        assert runner.invoke(app, ["ping-matrix", str(tmp_path / "x.yml")]).exit_code == 2
