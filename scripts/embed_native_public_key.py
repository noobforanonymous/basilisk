#!/usr/bin/env python3
"""Embed the CI-derived native-manifest verification key into the sidecar source."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


ASSIGNMENT = re.compile(
    r'^_TRUSTED_NATIVE_SIGNING_PUBLIC_KEY_HEX = "[0-9a-f]{64}"$',
    re.MULTILINE,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-key", default="build/native-public.key")
    parser.add_argument("--source", default="basilisk/native_bridge.py")
    args = parser.parse_args()

    public_key = Path(args.public_key).read_text("utf-8").strip().lower()
    if len(public_key) != 64 or any(char not in "0123456789abcdef" for char in public_key):
        raise SystemExit("Native manifest public key must be 32-byte lowercase hex")

    source = Path(args.source)
    content = source.read_text("utf-8")
    updated, count = ASSIGNMENT.subn(
        f'_TRUSTED_NATIVE_SIGNING_PUBLIC_KEY_HEX = "{public_key}"',
        content,
    )
    if count != 1:
        raise SystemExit("Could not locate exactly one native trust anchor assignment")
    source.write_text(updated, "utf-8")
    print(f"Embedded native manifest trust anchor in {source}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

