#!/usr/bin/env python3
"""Sign Basilisk native integrity manifests with Ed25519."""

from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


REPO_ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = REPO_ROOT / "build"


def _resolve_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (REPO_ROOT / path)


def load_private_key() -> ed25519.Ed25519PrivateKey:
    env_key = os.environ.get("BASILISK_NATIVE_SIGNING_KEY") or os.environ.get("BASILISK_RELEASE_SIGNING_KEY")
    if env_key:
        return ed25519.Ed25519PrivateKey.from_private_bytes(base64.b64decode(env_key))

    key_file = (
        os.environ.get("BASILISK_NATIVE_SIGNING_KEY_FILE")
        or os.environ.get("BASILISK_RELEASE_SIGNING_KEY_FILE")
    )
    key_path = _resolve_path(key_file or BUILD_DIR / "release-signing.key")
    if not key_path.exists():
        allow_ephemeral = os.environ.get("BASILISK_ALLOW_EPHEMERAL_NATIVE_SIGNING", "").lower()
        if allow_ephemeral not in {"1", "true", "yes"}:
            raise SystemExit(f"Missing signing key file: {key_path}")

        key_path.parent.mkdir(parents=True, exist_ok=True)
        private_key = ed25519.Ed25519PrivateKey.generate()
        key_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        try:
            key_path.chmod(0o600)
        except OSError:
            pass
        return private_key
    return ed25519.Ed25519PrivateKey.from_private_bytes(key_path.read_bytes())


def sign_manifest(path: Path, private_key: ed25519.Ed25519PrivateKey) -> Path:
    payload = path.read_bytes()
    signature = private_key.sign(payload)
    out = path.with_suffix(".sig")
    out.write_text(base64.b64encode(signature).decode("ascii"), "utf-8")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Sign Basilisk native manifests")
    parser.add_argument(
        "manifests",
        nargs="*",
        default=["basilisk/native_libs/manifest.json", "native/build/manifest.json"],
    )
    args = parser.parse_args()

    private_key = load_private_key()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()

    for item in args.manifests:
        path = _resolve_path(item)
        if not path.exists():
            raise SystemExit(f"Missing manifest: {path}")
        out = sign_manifest(path, private_key)
        print(f"Signed {path.relative_to(REPO_ROOT)} -> {out.relative_to(REPO_ROOT)}")

    (BUILD_DIR / "native-public.key").write_text(public_key, "utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
