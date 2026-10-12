"""Allow `python -m net_toolkit`, handy when the `nt` script is not on PATH."""

from net_toolkit.cli import app

app(prog_name="nt")
