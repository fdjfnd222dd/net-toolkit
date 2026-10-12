import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

# Keep Rich output plain and wide so assertions don't depend on the terminal.
os.environ.setdefault("NO_COLOR", "1")
os.environ.setdefault("COLUMNS", "160")

REPO = Path(__file__).resolve().parents[1]
EXAMPLES = REPO / "examples"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()
