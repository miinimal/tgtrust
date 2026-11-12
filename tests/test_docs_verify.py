"""The walk-through docs/VERIFY_IN_60_SECONDS.md must work as written.

Every fenced ```bash block whose first line is `# verify` is run (bash -e) from the root of a temporary
copy of the repository. The exit code must be 0 and every line of the ```text block that follows it
(lines containing `...` are elisions and are skipped) must appear in the output, as a substring of an
output line (trailing text after a quoted prefix is allowed, so changing values can be cut off).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "VERIFY_IN_60_SECONDS.md"

FENCE = re.compile(r"```(\w+)\n(.*?)```", re.S)


def _steps() -> list[tuple[str, list[str]]]:
    blocks = FENCE.findall(DOC.read_text())
    steps = []
    for i, (lang, body) in enumerate(blocks):
        if lang == "bash" and body.startswith("# verify\n"):
            expected: list[str] = []
            if i + 1 < len(blocks) and blocks[i + 1][0] == "text":
                expected = [ln.strip() for ln in blocks[i + 1][1].splitlines()
                            if ln.strip() and "..." not in ln]
            steps.append((body, expected))
    return steps


STEPS = _steps()


def test_doc_has_verified_steps():
    assert len(STEPS) >= 3
    assert all(expected for _, expected in STEPS), "every verified command needs quoted output"


@pytest.fixture(scope="module")
def repo_copy(tmp_path_factory) -> Path:
    dst = tmp_path_factory.mktemp("repo") / "tgtrust"
    shutil.copytree(ROOT, dst, ignore=shutil.ignore_patterns(
        ".git", ".venv", "venv", "__pycache__", "*.egg-info", ".pytest_cache", "node_modules"))
    return dst


@pytest.mark.parametrize("script,expected", STEPS, ids=[s.splitlines()[1][:40] for s, _ in STEPS])
def test_command_runs_and_output_matches(repo_copy, script, expected):
    env = dict(os.environ)
    env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")
    env.pop("PYTHONPATH", None)
    proc = subprocess.run(["bash", "-e", "-c", script], cwd=repo_copy, env=env,
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    lines = [ln.strip() for ln in proc.stdout.splitlines()]
    for want in expected:
        assert any(want in ln for ln in lines), f"quoted line not in output: {want!r}\n{proc.stdout}"
