"""Trust Desk (desk/): the reference build check and the Node test files run as part of the Python suite.

CI runs only pytest, and fails on any skipped test, so the desk's Node checks live here too.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DESK = ROOT / "desk"
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="Node is not installed")


def _node(*args: str, timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run([NODE, *args], cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                          timeout=timeout)


def test_network_build_is_current_and_valid():
    """The published files are exactly what the reference build makes from the HOCON, with no warnings."""
    done = _node("desk/tools/agentify/scripts/build_network.mjs", "desk/trust_desk.hocon",
                 "--manifest", "desk/agent-manifest.json", "--check")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "OK: these files are up to date" in done.stdout
    assert "WARNING" not in done.stdout.upper() and "warning" not in done.stderr.lower(), done.stdout


@pytest.mark.parametrize("name", sorted(p.name for p in (DESK / "tests").glob("*.test.mjs")))
def test_desk_node_file(name: str):
    done = _node("--test", f"desk/tests/{name}")
    assert done.returncode == 0, done.stdout[-6000:] + done.stderr[-2000:]
    assert "# fail 0" in done.stdout or "ℹ fail 0" in done.stdout, done.stdout[-2000:]
    assert "skipped 0" in done.stdout, "a desk Node test was skipped"
