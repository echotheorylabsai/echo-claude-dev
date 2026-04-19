import subprocess
import sys
from pathlib import Path


def test_simulation_end_to_end_passes():
    plugin_root = Path(__file__).resolve().parents[1]
    simulator = plugin_root / "scripts" / "simulate_hooks.py"
    r = subprocess.run(
        [sys.executable, str(simulator)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert r.returncode == 0, f"simulation failed.\nSTDOUT:\n{r.stdout}\nSTDERR:\n{r.stderr}"
