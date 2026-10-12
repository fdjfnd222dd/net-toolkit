"""Locate the bundled example files that every `--demo` runs on.

In a wheel (`pipx install .`) the repo's examples/ directory is packaged as
net_toolkit/examples; in a source checkout it sits at the repo root.
"""

from __future__ import annotations

from pathlib import Path

_HERE = Path(__file__).resolve().parent


def examples_dir() -> Path:
    packaged = _HERE / "examples"
    if packaged.is_dir():
        return packaged
    return _HERE.parents[1] / "examples"  # src/net_toolkit -> repo root


def example(*parts: str) -> Path:
    path = examples_dir().joinpath(*parts)
    if not path.exists():
        raise FileNotFoundError(f"bundled example missing: {path}")
    return path
