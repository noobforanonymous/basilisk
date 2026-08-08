from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

from scripts import write_build_metadata


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


def test_desktop_sidecar_keeps_build_only_setuptools_out_of_runtime():
    tree = ast.parse((ROOT / "basilisk-backend.spec").read_text("utf-8"))
    analysis = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Analysis"
    )
    keyword_values = {
        keyword.arg: ast.literal_eval(keyword.value)
        for keyword in analysis.keywords
        if keyword.arg in {"hiddenimports", "excludes"}
    }

    assert "pkg_resources" not in keyword_values["hiddenimports"]
    assert "setuptools" not in keyword_values["hiddenimports"]
    assert "pkg_resources" in keyword_values["excludes"]
    assert "setuptools" in keyword_values["excludes"]


def test_linux_lifecycle_launches_the_packaged_electron_binary():
    script = (ROOT / "desktop" / "tests" / "linux-package-lifecycle.sh").read_text("utf-8")

    assert "command -v basilisk" not in script
    assert "readlink -f /usr/bin/basilisk" in script


def test_linux_community_metadata_is_explicitly_unsigned(monkeypatch):
    monkeypatch.delenv("BASILISK_HAS_WINDOWS_SIGNING", raising=False)
    monkeypatch.delenv("BASILISK_HAS_APPLE_SIGNING", raising=False)

    metadata = write_build_metadata.build_metadata("Linux")

    assert metadata["trust_model"] == "community-build"
    assert metadata["vendor_signed"] is False
    assert "unsigned" in metadata["warning"].lower()
