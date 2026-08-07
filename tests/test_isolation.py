"""Destination and scanner-isolation policy regressions."""

import os
import sys
from pathlib import Path

import pytest

from basilisk.runtime import destination_policy as policy_module
from basilisk.runtime.destination_policy import DestinationPolicy, DestinationPolicyError
from basilisk.runtime.isolation import (
    WorkerAuditPolicy,
    WorkerLimits,
    WorkerPolicyViolation,
    build_worker_audit_policy,
    spawn_restricted_scan,
)
from basilisk.runtime.scan_worker import _remove_cwd_from_import_path


def test_restricted_worker_does_not_probe_the_caller_directory_for_imports(
    monkeypatch,
    tmp_path,
):
    dependency_root = tmp_path.parent / "installed-packages"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "path", ["", str(tmp_path), str(dependency_root)])
    _remove_cwd_from_import_path()
    assert sys.path == [str(dependency_root)]


def test_worker_native_allowlist_resolves_only_named_root_library(tmp_path):
    native_root = tmp_path / "system32"
    native_root.mkdir()
    (native_root / "shell32.dll").write_bytes(b"test fixture")
    (native_root / "kernel32.dll").write_bytes(b"test fixture")
    policy = WorkerAuditPolicy(
        read_roots=(),
        write_roots=(),
        native_roots=(native_root,),
        native_library_names=("kernel32", "shell32"),
    )
    policy("ctypes.dlopen", ("shell32",))
    policy("ctypes.dlopen", ("SHELL32.DLL",))
    policy("ctypes.dlopen", ("kernel32",))
    with pytest.raises(WorkerPolicyViolation, match="native library"):
        policy("ctypes.dlopen", ("untrusted",))
    with pytest.raises(WorkerPolicyViolation, match="native library"):
        policy("ctypes.dlopen", (str(tmp_path / "shell32.dll"),))


async def test_public_https_destination_is_allowed(monkeypatch):
    monkeypatch.setattr(policy_module, "_resolve_addresses", lambda host, port: ["93.184.216.34"])
    policy = DestinationPolicy()
    assert await policy.validate("https://example.test/chat") == "https://example.test/chat"


async def test_approved_destination_pins_socket_ip_but_preserves_host_and_sni(monkeypatch):
    monkeypatch.setattr(
        policy_module,
        "_resolve_addresses",
        lambda host, port: ["2001:4860:4860::8888", "93.184.216.34"],
    )
    approved = await DestinationPolicy().approve("https://Example.Test:8443/chat?q=1")
    assert approved.connect_url == "https://93.184.216.34:8443/chat?q=1"
    assert approved.selected_address == "93.184.216.34"
    assert approved.host_header == "example.test:8443"
    assert approved.server_hostname == "example.test"
    assert approved.addresses == ("93.184.216.34", "2001:4860:4860::8888")


async def test_dns_rebinding_to_private_address_is_rejected_on_next_approval(monkeypatch):
    answers = iter((["93.184.216.34"], ["127.0.0.1"]))
    monkeypatch.setattr(
        policy_module,
        "_resolve_addresses",
        lambda host, port: next(answers),
    )
    policy = DestinationPolicy()
    first = await policy.approve("https://rebind.example.test/chat")
    assert first.selected_address == "93.184.216.34"
    with pytest.raises(DestinationPolicyError, match="blocked non-public"):
        await policy.approve("https://rebind.example.test/chat")


async def test_private_destination_is_blocked_by_default(monkeypatch):
    monkeypatch.setattr(policy_module, "_resolve_addresses", lambda host, port: ["127.0.0.1"])
    with pytest.raises(DestinationPolicyError, match="blocked non-public"):
        await DestinationPolicy(allow_insecure_http=True).validate("http://localhost:8000/chat")


async def test_isolated_lab_must_explicitly_allow_private_and_http(monkeypatch):
    monkeypatch.setattr(policy_module, "_resolve_addresses", lambda host, port: ["127.0.0.1"])
    policy = DestinationPolicy(allow_private=True, allow_insecure_http=True)
    assert await policy.validate("http://127.0.0.1:8000/chat")


async def test_destination_allowlist_is_enforced_before_dns(monkeypatch):
    monkeypatch.setattr(policy_module, "_resolve_addresses", lambda host, port: ["93.184.216.34"])
    policy = DestinationPolicy(allowed_hosts=("api.example.test",))
    with pytest.raises(DestinationPolicyError, match="allowlist"):
        await policy.validate("https://other.example.test/chat")


async def test_url_credentials_and_unsupported_schemes_are_rejected():
    with pytest.raises(DestinationPolicyError, match="credentials"):
        await DestinationPolicy().validate("https://user:pass@example.test/chat")
    with pytest.raises(DestinationPolicyError, match="scheme"):
        await DestinationPolicy().validate("file:///etc/passwd")


def test_worker_limits_are_explicit_for_every_scan_mode():
    limits = {mode: WorkerLimits.for_mode(mode) for mode in (
        "quick", "standard", "deep", "stealth", "chaos",
    )}
    assert limits["quick"].wall_seconds < limits["deep"].wall_seconds
    assert limits["standard"].memory_bytes <= limits["chaos"].memory_bytes
    assert all(item.cpu_seconds > 0 for item in limits.values())


def test_worker_supervisor_rejects_inline_credentials():
    with pytest.raises(ValueError, match="inline secret"):
        spawn_restricted_scan({"mode": "quick", "api_key": "nvapi-private"})


def test_worker_supervisor_passes_only_secret_references(monkeypatch):
    captured = {}

    class FakeProcess:
        pid = 1234

        def __init__(self, command, **kwargs):
            request = __import__("json").loads(
                __import__("pathlib").Path(command[-1]).read_text("utf-8")
            )
            captured.update({"command": command, "kwargs": kwargs, "request": request})

        def wait(self, timeout=None):
            return 0

    def fake_popen(command, **kwargs):
        return FakeProcess(command, **kwargs)

    monkeypatch.delenv("BASILISK_RESTRICTED_WORKER", raising=False)
    monkeypatch.setattr("basilisk.runtime.isolation.subprocess.Popen", fake_popen)
    result = spawn_restricted_scan({
        "target": "https://example.test/v1/chat/completions",
        "mode": "quick",
        "api_key": "@.secrets/provider-key",
        "auth": "",
        "attacker_api_key": "",
    })

    assert result == 0
    assert captured["kwargs"]["env"]["BASILISK_RESTRICTED_WORKER"] == "1"
    assert captured["request"]["arguments"]["api_key"] == "@.secrets/provider-key"
    assert "nvapi" not in str(captured["request"])


def test_worker_audit_policy_blocks_undeclared_files_and_processes(tmp_path):
    readable = tmp_path / "readable"
    writable = tmp_path / "writable"
    forbidden = tmp_path / "forbidden"
    readable.mkdir()
    writable.mkdir()
    forbidden.mkdir()
    policy = WorkerAuditPolicy(
        read_roots=(readable.resolve(),),
        write_roots=(writable.resolve(),),
    )

    policy("open", (readable / "input.txt", "r", 0))
    policy("open", (writable / "result.json", "w", os.O_WRONLY | os.O_CREAT))
    with pytest.raises(WorkerPolicyViolation, match="filesystem access denied"):
        policy("open", (forbidden / "private.txt", "r", 0))
    with pytest.raises(WorkerPolicyViolation, match="filesystem access denied"):
        policy("open", (forbidden / "result.txt", "w", os.O_WRONLY | os.O_CREAT))
    with pytest.raises(WorkerPolicyViolation, match="child process"):
        policy("subprocess.Popen", ("git", ["git", "status"], None, None))


def test_worker_policy_rejects_workspace_wide_output_directory(tmp_path, monkeypatch):
    request_path = tmp_path / "request.json"
    request_path.write_text("{}", encoding="utf-8")
    project_root = Path(__file__).resolve().parents[1]
    monkeypatch.chdir(project_root)
    with pytest.raises(ValueError, match="too broad"):
        build_worker_audit_policy({"output_dir": "."}, request_path)
