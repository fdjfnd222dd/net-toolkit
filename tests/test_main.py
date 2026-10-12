import subprocess
import sys


def test_python_dash_m():
    result = subprocess.run([sys.executable, "-m", "net_toolkit", "--version"],
                            capture_output=True, text=True, check=True)
    assert result.stdout.startswith("nt ")
