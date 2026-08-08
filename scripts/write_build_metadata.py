#!/usr/bin/env python3
"""Write build trust metadata for packaged Basilisk desktop artifacts."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path


def _bool_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def build_metadata(platform: str) -> dict:
    normalized = platform.lower()
    vendor_signed = False
    notarized = False
    warning = ""

    if normalized == "macos":
        vendor_signed = _bool_env("BASILISK_HAS_APPLE_SIGNING")
        notarized = _bool_env("BASILISK_HAS_APPLE_NOTARIZATION")
        warning = (
            ""
            if vendor_signed and notarized
            else "COMMUNITY BUILD: macOS artifact is not Apple Developer signed and notarized."
        )
    elif normalized == "windows":
        vendor_signed = _bool_env("BASILISK_HAS_WINDOWS_SIGNING")
        warning = (
            ""
            if vendor_signed
            else "COMMUNITY BUILD: Windows artifact is not Authenticode-signed and will trigger trust warnings."
        )
    else:
        warning = (
            "COMMUNITY BUILD: Linux packages are unsigned and include keyless CI provenance."
        )

    trust_model = "vendor-signed" if vendor_signed else "community-build"
    sigstore_mode = "ci-keyless" if _bool_env("GITHUB_ACTIONS") else "local"

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "platform": platform,
        "trust_model": trust_model,
        "display_label": "Vendor-Signed Build" if vendor_signed else "Community Build",
        "vendor_signed": vendor_signed,
        "notarized": notarized,
        "sigstore_release_signing": sigstore_mode,
        "warning": warning,
    }


def enforce_release_trust(metadata: dict) -> None:
    if not _bool_env("BASILISK_REQUIRE_VENDOR_TRUST"):
        return
    platform = str(metadata.get("platform", "")).lower()
    if platform == "windows" and not metadata.get("vendor_signed"):
        raise SystemExit("Release blocked: WINDOWS_SIGNING_CERT_BASE64 is required for tagged Windows builds")
    if platform == "macos" and not (metadata.get("vendor_signed") and metadata.get("notarized")):
        raise SystemExit("Release blocked: macOS Developer ID signing and notarization credentials are required")


def main() -> int:
    parser = argparse.ArgumentParser(description="Write Basilisk desktop build trust metadata")
    parser.add_argument("--platform", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--artifact-output", default="")
    parser.add_argument("--github-env", default="")
    args = parser.parse_args()

    metadata = build_metadata(args.platform)
    enforce_release_trust(metadata)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(metadata, indent=2), "utf-8")

    if args.artifact_output:
        artifact_output = Path(args.artifact_output)
        artifact_output.parent.mkdir(parents=True, exist_ok=True)
        artifact_output.write_text(json.dumps(metadata, indent=2), "utf-8")

    if args.github_env:
        env_path = Path(args.github_env)
        with env_path.open("a", encoding="utf-8") as handle:
            handle.write(f"BASILISK_RELEASE_TRUST={metadata['trust_model']}\n")
            handle.write(f"BASILISK_VENDOR_SIGNED={'true' if metadata['vendor_signed'] else 'false'}\n")
            handle.write(f"BASILISK_NOTARIZED={'true' if metadata['notarized'] else 'false'}\n")
            warning = str(metadata["warning"]).replace("\n", " ").strip()
            handle.write(f"BASILISK_BUILD_WARNING={warning}\n")

    print(f"Wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
