"""Repeated pings to a set of hosts: loss, latency and jitter per host over N rounds."""

from __future__ import annotations

import random
import statistics
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from net_toolkit import probes

SPARK = "▁▂▃▄▅▆▇█"
LOSS_MARK = "×"


@dataclass
class Series:
    name: str
    host: str
    samples: list[float | None] = field(default_factory=list)  # None = lost

    @property
    def sent(self) -> int:
        return len(self.samples)

    @property
    def replies(self) -> list[float]:
        return [s for s in self.samples if s is not None]

    @property
    def loss_pct(self) -> float:
        return 100.0 * (self.sent - len(self.replies)) / self.sent if self.sent else 0.0

    @property
    def min(self) -> float | None:
        return min(self.replies, default=None)

    @property
    def avg(self) -> float | None:
        return statistics.fmean(self.replies) if self.replies else None

    @property
    def max(self) -> float | None:
        return max(self.replies, default=None)

    @property
    def jitter(self) -> float | None:
        """Mean absolute difference between consecutive replies (RFC 3550 style, unsmoothed)."""
        replies = self.replies
        if len(replies) < 2:
            return None
        return statistics.fmean(abs(b - a) for a, b in zip(replies, replies[1:], strict=False))


def sparkline(samples: list[float | None], width: int = 12) -> str:
    """Last `width` samples as bars scaled to the window's own min..max; × marks a loss."""
    window = samples[-width:]
    values = [s for s in window if s is not None]
    if not values:
        return LOSS_MARK * len(window)
    low, high = min(values), max(values)
    span = high - low or 1.0
    out = []
    for sample in window:
        if sample is None:
            out.append(LOSS_MARK)
        else:
            out.append(SPARK[min(len(SPARK) - 1, int((sample - low) / span * (len(SPARK) - 1) + 0.5))])
    return "".join(out)


Pinger = Callable[[str, float], "float | None"]


def run_round(series: list[Series], pinger: Pinger = probes.ping, timeout: float = 1.0,
              workers: int = 32) -> None:
    """Ping every host once, in parallel, and append one sample to each series."""
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(series)))) as pool:
        results = list(pool.map(lambda s: pinger(s.host, timeout), series))
    for item, rtt in zip(series, results, strict=True):
        item.samples.append(rtt)


# --- canned lab for --demo -------------------------------------------------------------

DEMO_PROFILES = {  # name -> (base ms, spread ms, loss probability)
    "CORE-SW1": (0.6, 0.15, 0.0),
    "DIST-SW2": (1.1, 0.3, 0.0),
    "EDGE-RTR1": (0.9, 0.2, 0.0),
    "NX-LEAF1": (2.4, 1.8, 0.05),
    "EOS-SPINE1": (4.0, 2.5, 0.3),
}


class DemoPinger:
    """Deterministic fake latencies so demo output is the same on every run."""

    def __init__(self, names_by_host: dict[str, str], seed: int = 7):
        self.names = names_by_host
        self.rng = {host: random.Random(f"{seed}-{name}") for host, name in names_by_host.items()}

    def __call__(self, host: str, timeout: float) -> float | None:
        base, spread, loss = DEMO_PROFILES.get(self.names.get(host, ""), (1.0, 0.2, 0.0))
        rng = self.rng.setdefault(host, random.Random(host))
        if rng.random() < loss:
            return None
        return round(base + rng.random() * spread, 3)
