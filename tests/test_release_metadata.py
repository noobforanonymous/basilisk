"""Regression coverage for per-platform release metadata artifacts."""

from __future__ import annotations

import json

from scripts.generate_release_manifest import load_build_metadata
from scripts.render_release_notes import load_statuses


def test_release_metadata_loaders_accept_unique_platform_filenames(tmp_path):
    platforms = ("Windows", "Linux", "macOS")
    for platform in platforms:
        path = tmp_path / platform / f"basilisk-build-metadata-{platform}.json"
        path.parent.mkdir()
        path.write_text(json.dumps({"platform": platform}), encoding="utf-8")

    metadata = load_build_metadata(tmp_path)
    statuses = load_statuses(tmp_path)

    assert {item["platform"] for item in metadata} == set(platforms)
    assert set(statuses) == set(platforms)
