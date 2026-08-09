#!/usr/bin/env python3
"""Generate lightweight release metadata for Basilisk packaging workflows."""

from __future__ import annotations

import hashlib
import json
import os
import argparse
import re
import uuid
from urllib.parse import quote
from datetime import datetime, timezone
from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = ROOT / "build"
PYPROJECT = ROOT / "pyproject.toml"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iter_manifest_files() -> list[Path]:
    include_roots = [
        ROOT / "basilisk",
        ROOT / "desktop" / "src",
        ROOT / "native",
        ROOT / "pyproject.toml",
        ROOT / "requirements.txt",
        ROOT / "basilisk-backend.spec",
    ]
    files: list[Path] = []
    for item in include_roots:
        if item.is_file():
            files.append(item)
            continue
        if item.exists():
            for path in item.rglob("*"):
                if path.is_file() and "__pycache__" not in path.parts and "node_modules" not in path.parts:
                    files.append(path)
    return sorted(files)


def _locked_components() -> list[dict[str, str]]:
    components: list[dict[str, str]] = []
    for raw_line in (ROOT / "requirements.lock").read_text("utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "==" not in line:
            continue
        requirement = line.split("\\", 1)[0].split(";", 1)[0].strip()
        name, version = requirement.split("==", 1)
        normalized = re.sub(r"[-_.]+", "-", name).lower()
        components.append({
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{normalized}@{version}",
        })
    node_lock = ROOT / "desktop" / "package-lock.json"
    if node_lock.is_file():
        lock_data = json.loads(node_lock.read_text("utf-8"))
        for package_path, package in lock_data.get("packages", {}).items():
            if not package_path.startswith("node_modules/") or not isinstance(package, dict):
                continue
            name = package_path.removeprefix("node_modules/")
            version = str(package.get("version", ""))
            if not name or not version:
                continue
            components.append({
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:npm/{quote(name, safe='')}@{version}",
                "scope": "optional" if package.get("optional") else "required",
            })
    return sorted(components, key=lambda item: (item["name"].casefold(), item["version"]))


def build_sbom(pyproject: dict) -> dict:
    project = pyproject.get("project", {})
    lock_identity = "\n".join((
        sha256_file(ROOT / "requirements.lock"),
        sha256_file(ROOT / "desktop" / "package-lock.json"),
    ))
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, lock_identity)}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "Rot Hackers", "name": "Basilisk release manifest", "version": "2"}],
            "component": {
                "type": "application",
                "name": project.get("name", "basilisk-ai"),
                "version": project.get("version", "unknown"),
                "purl": f"pkg:pypi/{project.get('name', 'basilisk-ai')}@{project.get('version', 'unknown')}",
            },
            "properties": [
                {"name": "basilisk:python-lock-sha256", "value": sha256_file(ROOT / "requirements.lock")},
                {"name": "basilisk:desktop-lock-sha256", "value": sha256_file(ROOT / "desktop" / "package-lock.json")},
            ],
        },
        "components": _locked_components(),
    }


def build_provenance(pyproject: dict, assets: list[dict[str, str | int]]) -> dict:
    project = pyproject.get("project", {})
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {"name": item["path"], "digest": {"sha256": item["sha256"]}}
            for item in assets
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/regaan/basilisk/.github/workflows/build.yml@v2",
                "externalParameters": {
                    "ref": os.environ.get("GITHUB_REF", ""),
                    "version": project.get("version", "unknown"),
                },
                "internalParameters": {
                    "run_id": os.environ.get("GITHUB_RUN_ID", ""),
                    "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
                },
                "resolvedDependencies": [
                    {"uri": "git+https://github.com/regaan/basilisk", "digest": {"gitCommit": os.environ.get("GITHUB_SHA", "")}},
                    {"uri": "file:pyproject.toml", "digest": {"sha256": sha256_file(PYPROJECT)}},
                    {"uri": "file:requirements.lock", "digest": {"sha256": sha256_file(ROOT / "requirements.lock")}},
                    {"uri": "file:desktop/package-lock.json", "digest": {"sha256": sha256_file(ROOT / "desktop" / "package-lock.json")}},
                ],
            },
            "runDetails": {
                "builder": {"id": "https://github.com/actions/runner"},
                "metadata": {
                    "invocationId": os.environ.get("GITHUB_RUN_ID", "local"),
                    "startedOn": datetime.now(timezone.utc).isoformat(),
                },
            },
        },
    }


def iter_release_assets(artifact_root: Path | None) -> list[dict[str, str | int]]:
    if artifact_root is None or not artifact_root.exists():
        return []

    patterns = ("*.exe", "*.dmg", "*.AppImage", "*.pacman", "*.deb", "*.rpm", "*.zip", "*.tar.gz", "*.whl")
    assets: list[dict[str, str | int]] = []
    seen: set[Path] = set()
    for pattern in patterns:
        for path in artifact_root.rglob(pattern):
            if path.is_file() and path not in seen:
                seen.add(path)
                assets.append(
                    {
                        "path": str(path.relative_to(ROOT)),
                        "sha256": sha256_file(path),
                        "size": path.stat().st_size,
                    }
                )
    return sorted(assets, key=lambda item: str(item["path"]))


def load_build_metadata(build_metadata_root: Path | None) -> list[dict]:
    if build_metadata_root is None or not build_metadata_root.exists():
        return []
    data: list[dict] = []
    for path in sorted(build_metadata_root.rglob("basilisk-build-metadata-*.json")):
        data.append(json.loads(path.read_text("utf-8")))
    return data


def build_manifest(
    pyproject: dict,
    artifact_root: Path | None = None,
    build_metadata_root: Path | None = None,
) -> dict:
    project = pyproject.get("project", {})
    files = iter_manifest_files()
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "name": project.get("name", "basilisk-ai"),
        "version": project.get("version", "unknown"),
        "build_trust": load_build_metadata(build_metadata_root),
        "artifacts": iter_release_assets(artifact_root),
        "files": [
            {
                "path": str(path.relative_to(ROOT)),
                "sha256": sha256_file(path),
                "size": path.stat().st_size,
            }
            for path in files
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Basilisk release metadata")
    parser.add_argument(
        "--artifact-root",
        default="",
        help="Optional directory containing packaged release artifacts to hash into the manifest.",
    )
    parser.add_argument(
        "--build-metadata-root",
        default="",
        help="Optional directory containing per-platform build metadata JSON files.",
    )
    args = parser.parse_args()

    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    pyproject = tomllib.loads(PYPROJECT.read_text("utf-8"))
    artifact_root = (ROOT / args.artifact_root) if args.artifact_root else None
    build_metadata_root = (ROOT / args.build_metadata_root) if args.build_metadata_root else None

    manifest = build_manifest(
        pyproject,
        artifact_root=artifact_root,
        build_metadata_root=build_metadata_root,
    )
    sbom = build_sbom(pyproject)
    provenance = build_provenance(pyproject, manifest["artifacts"])

    (BUILD_DIR / "release-manifest.json").write_text(json.dumps(manifest, indent=2), "utf-8")
    (BUILD_DIR / "sbom.json").write_text(json.dumps(sbom, indent=2), "utf-8")
    (BUILD_DIR / "provenance.json").write_text(json.dumps(provenance, indent=2), "utf-8")
    print("Wrote build/release-manifest.json, build/sbom.json, build/provenance.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
