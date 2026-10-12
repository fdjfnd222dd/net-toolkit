import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

# Keep Rich output plain and wide so assertions don't depend on the terminal.
# CI runners set GITHUB_ACTIONS / FORCE_COLOR, which make Rich and Typer emit colour
# codes in the middle of the text; drop them before anything imports the CLI.
for var in ("FORCE_COLOR", "PY_COLORS", "GITHUB_ACTIONS", "TTY_COMPATIBLE"):
    os.environ.pop(var, None)
os.environ.setdefault("NO_COLOR", "1")
os.environ.setdefault("COLUMNS", "160")

REPO = Path(__file__).resolve().parents[1]
EXAMPLES = REPO / "examples"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()
