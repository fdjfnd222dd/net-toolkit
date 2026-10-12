"""Low-level probes shared by `scan` and `ping-matrix`.

ICMP goes through the system `ping` binary so nothing needs root or raw sockets;
TCP uses a plain connect(), which any unprivileged user can do.
"""

from __future__ import annotations

import errno
import math
import re
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable

RTT_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)


def ping_command(host: str, timeout: float, platform: str = sys.platform) -> list[str]:
    """Build a one-shot ping for this OS; each one spells 'wait this long' differently."""
    if platform.startswith("win"):
        return ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    if platform == "darwin" or "bsd" in platform:
        return ["ping", "-n", "-c", "1", "-W", str(int(timeout * 1000)), host]
    return ["ping", "-n", "-c", "1", "-W", str(max(1, math.ceil(timeout))), host]


def ping(host: str, timeout: float = 1.0) -> float | None:
    """Round-trip time in ms, or None if there was no reply (or no ping binary)."""
    try:
        proc = subprocess.run(
            ping_command(host, timeout), capture_output=True, text=True, timeout=timeout + 2
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    match = RTT_RE.search(proc.stdout)
    return float(match.group(1)) if match else 0.0


OPEN, CLOSED, FILTERED = "open", "closed", "filtered"


def tcp_probe(host: str, port: int, timeout: float = 1.0) -> str:
    """Full TCP connect. 'closed' means the host answered with RST, so it is alive."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            code = sock.connect_ex((host, port))
    except OSError:
        return FILTERED
    if code == 0:
        return OPEN
    if code == errno.ECONNREFUSED:
        return CLOSED
    return FILTERED


class RateLimiter:
    """Spaces calls evenly at `rate` per second across all threads (None = unlimited)."""

    def __init__(
        self,
        rate: float | None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        if rate is not None and rate <= 0:
            raise ValueError("rate must be positive")
        self.interval = 1.0 / rate if rate else 0.0
        self._clock, self._sleep = clock, sleep
        self._next = clock()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        if not self.interval:
            return
        with self._lock:
            now = self._clock()
            slot = max(now, self._next)
            self._next = slot + self.interval
        if slot > now:
            self._sleep(slot - now)
