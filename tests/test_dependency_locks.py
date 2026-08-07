from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_dependency_locks_and_release_commands_are_reproducible():
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "verify_dependency_locks.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
