from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from basilisk import native_bridge
from scripts import sign_native_manifests


def _clear_native_signing_environment(monkeypatch):
    for name in (
        "BASILISK_NATIVE_SIGNING_KEY",
        "BASILISK_RELEASE_SIGNING_KEY",
        "BASILISK_NATIVE_SIGNING_KEY_FILE",
        "BASILISK_RELEASE_SIGNING_KEY_FILE",
        "BASILISK_ALLOW_EPHEMERAL_NATIVE_SIGNING",
    ):
        monkeypatch.delenv(name, raising=False)


def test_ephemeral_native_signing_key_requires_explicit_opt_in(tmp_path, monkeypatch):
    _clear_native_signing_environment(monkeypatch)
    monkeypatch.setattr(sign_native_manifests, "BUILD_DIR", tmp_path / "build")

    with pytest.raises(SystemExit, match="Missing signing key file"):
        sign_native_manifests.load_private_key()


def test_ephemeral_native_signing_key_is_generated_for_community_build(tmp_path, monkeypatch):
    _clear_native_signing_environment(monkeypatch)
    build_dir = tmp_path / "build"
    monkeypatch.setattr(sign_native_manifests, "BUILD_DIR", build_dir)
    monkeypatch.setenv("BASILISK_ALLOW_EPHEMERAL_NATIVE_SIGNING", "true")

    generated = sign_native_manifests.load_private_key()
    stored = ed25519.Ed25519PrivateKey.from_private_bytes(
        (build_dir / "release-signing.key").read_bytes()
    )
    message = b"community-build-integrity"

    stored.public_key().verify(generated.sign(message), message)


def test_verify_library_integrity_accepts_matching_manifest(tmp_path):
    library = tmp_path / "libbasilisk_tokens.so"
    library.write_bytes(b"native-test")
    digest = hashlib.sha256(b"native-test").hexdigest()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps({"version": 1, "libraries": {library.name: {"sha256": digest}}}),
        encoding="utf-8",
    )
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key_hex = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    (tmp_path / "manifest.sig").write_text(
        base64.b64encode(private_key.sign(manifest_path.read_bytes())).decode("ascii"),
        encoding="utf-8",
    )

    assert native_bridge._verify_library_integrity(library, public_key_hex=public_key_hex) is True


def test_verify_library_integrity_rejects_mismatch(tmp_path):
    library = tmp_path / "libbasilisk_tokens.so"
    library.write_bytes(b"native-test")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps({"version": 1, "libraries": {library.name: {"sha256": "deadbeef"}}}),
        encoding="utf-8",
    )
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key_hex = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    (tmp_path / "manifest.sig").write_text(
        base64.b64encode(private_key.sign(manifest_path.read_bytes())).decode("ascii"),
        encoding="utf-8",
    )

    assert native_bridge._verify_library_integrity(library, public_key_hex=public_key_hex) is False


def test_verify_manifest_signature_rejects_tamper(tmp_path):
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({"version": 1, "libraries": {}}), encoding="utf-8")
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key_hex = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    (tmp_path / "manifest.sig").write_text(
        base64.b64encode(private_key.sign(manifest_path.read_bytes())).decode("ascii"),
        encoding="utf-8",
    )
    manifest_path.write_text(json.dumps({"version": 1, "libraries": {"oops": {}}}), encoding="utf-8")

    assert native_bridge._verify_manifest_signature(tmp_path, public_key_hex=public_key_hex) is False


def test_large_levenshtein_inputs_are_rejected():
    oversized = "a" * (native_bridge._MAX_NATIVE_TEXT_BYTES + 1)
    with pytest.raises(ValueError):
        native_bridge.levenshtein(oversized, "b")
