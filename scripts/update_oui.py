#!/usr/bin/env python3
"""Rebuild src/net_toolkit/data/oui.tsv.gz from the IEEE MA-L registry.

The IEEE publishes which company owns each 24-bit MAC prefix (OUI). We keep just
"PREFIX<TAB>short vendor name", gzipped, so `nt scan` can label devices offline.

    python scripts/update_oui.py            # download from the IEEE
    python scripts/update_oui.py oui.csv    # or use a CSV you already have
"""

from __future__ import annotations

import csv
import gzip
import io
import re
import sys
import urllib.request
from pathlib import Path

URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUT = Path(__file__).resolve().parents[1] / "src" / "net_toolkit" / "data" / "oui.tsv.gz"

# Legal suffixes that make a table column wide without telling anyone anything.
SUFFIXES = re.compile(
    r"[,\s]+(co\.?,?\s*ltd\.?|company limited|corporation|corp\.?|incorporated|inc\.?|"
    r"corporate|llc|l\.l\.c\.|ltd\.?|limited|gmbh|ag|s\.a\.|sa|s\.p\.a\.|b\.v\.|bv|oy|ab|a/s|as|"
    r"pte\.?|pty\.?|plc|kg|co\.|co|technology|technologies|electronics)$",
    re.IGNORECASE,
)


def short_name(name: str) -> str:
    name = " ".join(name.replace(" ", " ").split())
    previous = None
    while previous != name:
        previous, name = name, SUFFIXES.sub("", name).strip(" ,.")
    return name[:40] or previous[:40]


def main() -> None:
    if len(sys.argv) > 1:
        text = Path(sys.argv[1]).read_text(encoding="utf-8")
    else:  # the IEEE rejects requests without a browser-like User-Agent
        request = urllib.request.Request(URL, headers={"User-Agent": "Mozilla/5.0 net-toolkit"})
        with urllib.request.urlopen(request, timeout=60) as response:
            text = response.read().decode("utf-8")
    rows = {}
    for row in csv.DictReader(io.StringIO(text)):
        prefix = row["Assignment"].strip().upper()
        if re.fullmatch(r"[0-9A-F]{6}", prefix):
            rows[prefix] = short_name(row["Organization Name"])
    lines = "".join(f"{p}\t{rows[p]}\n" for p in sorted(rows))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with gzip.GzipFile(OUT, "wb", mtime=0) as fh:  # mtime=0: same input, same bytes
        fh.write(lines.encode("utf-8"))
    print(f"wrote {len(rows)} prefixes to {OUT} ({OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
