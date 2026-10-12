"""Shared Rich console and small rendering helpers used by every command."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

console = Console()
err_console = Console(stderr=True)


def kv_table(rows: list[tuple[str, str]], title: str | None = None) -> Table:
    """Two-column key/value table, used for single-object summaries."""
    table = Table(title=title, show_header=False, title_justify="left")
    table.add_column("field", style="bold cyan", no_wrap=True)
    table.add_column("value")
    for key, value in rows:
        table.add_row(key, value)
    return table
