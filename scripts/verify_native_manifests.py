#!/usr/bin/env python3
"""Verify native manifest signatures and every listed library digest."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519


def verify(directory: Path, public_key: ed25519.Ed25519PublicKey) -> None:
    manifest = directory / "manifest.json"
    signature = directory / "manifest.sig"
    if not manifest.is_file() or not signature.is_file():
        raise SystemExit(f"Missing signed native manifest in {directory}")
    public_key.verify(base64.b64decode(signature.read_text("utf-8").strip()), manifest.read_bytes())
    payload = json.loads(manifest.read_text("utf-8"))
    libraries = payload.get("libraries", {})
    if not libraries:
        raise SystemExit(f"Native manifest contains no libraries: {manifest}")
    for name, metadata in libraries.items():
        library = directory / name
        if not library.is_file():
            raise SystemExit(f"Manifest library is missing: {library}")
        expected = metadata.get("sha256", "") if isinstance(metadata, dict) else str(metadata)
        actual = hashlib.sha256(library.read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(f"Native digest mismatch: {library}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directories", nargs="+", type=Path)
    parser.add_argument("--public-key", type=Path, default=Path("build/native-public.key"))
    args = parser.parse_args()
    key_hex = args.public_key.read_text("utf-8").strip()
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))
    for directory in args.directories:
        verify(directory, public_key)
        print(f"Verified signed native manifest: {directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

