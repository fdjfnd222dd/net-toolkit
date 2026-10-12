"""`nt` entrypoint. Each command lives in its own module and is registered here."""

from __future__ import annotations

import typer

from net_toolkit import __version__
from net_toolkit.commands import subnet_cmd

app = typer.Typer(
    name="nt",
    help="Networking utilities for lab work: subnetting, sweeps, backups, audits, pcaps.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)


def _version(value: bool) -> None:
    if value:
        typer.echo(f"nt {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", "-V", callback=_version, is_eager=True, help="Show version and exit."
    ),
) -> None:
    """Networking utilities for lab work."""


app.command("subnet")(subnet_cmd.subnet_command)


if __name__ == "__main__":  # pragma: no cover
    app()
