import errno
import socket
import subprocess

import pytest

from net_toolkit import probes
from net_toolkit.probes import RateLimiter, ping, ping_command, tcp_probe


@pytest.mark.parametrize("platform, expected", [
    ("linux", ["ping", "-n", "-c", "1", "-W", "1", "h"]),
    ("linux", ["ping", "-n", "-c", "1", "-W", "2", "h"]),
    ("darwin", ["ping", "-n", "-c", "1", "-W", "1500", "h"]),
    ("win32", ["ping", "-n", "1", "-w", "1500", "h"]),
])
def test_ping_command(platform, expected):
    timeout = 0.5 if expected[-2] == "1" else 1.5
    assert ping_command("h", timeout, platform) == expected


class FakeRun:
    def __init__(self, returncode=0, stdout="", exc=None):
        self.returncode, self.stdout, self.exc = returncode, stdout, exc

    def __call__(self, *args, **kwargs):
        if self.exc:
            raise self.exc
        return subprocess.CompletedProcess(args, self.returncode, self.stdout, "")


@pytest.mark.parametrize("fake, expected", [
    (FakeRun(stdout="64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.734 ms"), 0.734),
    (FakeRun(stdout="Reply from 10.0.0.1: bytes=32 time<1ms TTL=64"), 1.0),
    (FakeRun(stdout="reply, but no timing line"), 0.0),
    (FakeRun(returncode=1), None),
    (FakeRun(exc=FileNotFoundError()), None),
    (FakeRun(exc=subprocess.TimeoutExpired("ping", 3)), None),
])
def test_ping_parsing(monkeypatch, fake, expected):
    monkeypatch.setattr(probes.subprocess, "run", fake)
    assert ping("10.0.0.1") == expected


def test_tcp_probe_open_and_closed():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        assert tcp_probe("127.0.0.1", port, 1.0) == probes.OPEN
    assert tcp_probe("127.0.0.1", port, 1.0) == probes.CLOSED  # listener gone -> RST


class FakeSocket:
    def __init__(self, code=None, exc=None):
        self.code, self.exc = code, exc

    def __call__(self, *args):
        if self.exc:
            raise self.exc
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def settimeout(self, value):
        pass

    def connect_ex(self, addr):
        return self.code


@pytest.mark.parametrize("fake, expected", [
    (FakeSocket(code=errno.EHOSTUNREACH), probes.FILTERED),
    (FakeSocket(code=errno.EAGAIN), probes.FILTERED),
    (FakeSocket(exc=OSError("no route")), probes.FILTERED),
])
def test_tcp_probe_filtered(monkeypatch, fake, expected):
    monkeypatch.setattr(probes.socket, "socket", fake)
    assert tcp_probe("2001:db8::1", 22) == expected


class FakeClock:
    def __init__(self):
        self.now = 100.0
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(round(seconds, 6))
        self.now += seconds


def test_rate_limiter_spaces_calls():
    clock = FakeClock()
    limiter = RateLimiter(4, clock=clock, sleep=clock.sleep)
    for _ in range(5):
        limiter.acquire()
    assert clock.sleeps == [0.25, 0.25, 0.25, 0.25]
    assert clock.now == pytest.approx(101.0)


def test_rate_limiter_does_not_bank_idle_time():
    clock = FakeClock()
    limiter = RateLimiter(2, clock=clock, sleep=clock.sleep)
    limiter.acquire()
    clock.now += 10  # idle for a while: no burst allowed afterwards beyond one slot
    limiter.acquire()
    limiter.acquire()
    assert clock.sleeps == [0.5]


def test_rate_limiter_unlimited_and_invalid():
    RateLimiter(None).acquire()
    with pytest.raises(ValueError):
        RateLimiter(0)
