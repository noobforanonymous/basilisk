"""
Tests for Basilisk CLI commands.
"""

from __future__ import annotations

from click.testing import CliRunner

from basilisk.cli.encoding import configure_output_encoding
from basilisk.cli.main import cli


def test_windows_console_streams_are_reconfigured_for_unicode_output():
    class ReconfigurableStream:
        def __init__(self):
            self.options = None

        def reconfigure(self, **options):
            self.options = options

    stream = ReconfigurableStream()
    configure_output_encoding(platform="win32", streams=[stream])
    assert stream.options == {"encoding": "utf-8", "errors": "replace"}


class TestCLI:
    def setup_method(self):
        self.runner = CliRunner()

    def test_version_command(self):
        result = self.runner.invoke(cli, ["version"])
        assert result.exit_code == 0
        assert "Version:" in result.output

    def test_help_command(self):
        result = self.runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Basilisk" in result.output
        assert "scan" in result.output
        assert "recon" in result.output

    def test_scan_help(self):
        result = self.runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--target" in result.output
        assert "--provider" in result.output
        assert "--mode" in result.output
        assert "--execution-mode" in result.output

    def test_recon_help(self):
        result = self.runner.invoke(cli, ["recon", "--help"])
        assert result.exit_code == 0
        assert "--target" in result.output

    def test_replay_help(self):
        result = self.runner.invoke(cli, ["replay", "--help"])
        assert result.exit_code == 0

    def test_modules_command(self):
        result = self.runner.invoke(cli, ["modules"])
        # May fail if modules have import errors, but should not crash
        assert result.exit_code == 0

    def test_interactive_help(self):
        result = self.runner.invoke(cli, ["interactive", "--help"])
        assert result.exit_code == 0
        assert "--target" in result.output

    def test_sessions_help(self):
        result = self.runner.invoke(cli, ["sessions", "--help"])
        assert result.exit_code == 0

    def test_scan_requires_target(self):
        result = self.runner.invoke(cli, ["scan"])
        assert result.exit_code != 0

    def test_scan_cost_preview_exits_without_worker_or_credentials(self, monkeypatch):
        def forbidden_worker(_payload):
            raise AssertionError("cost preview must not spawn a scan worker")

        monkeypatch.setattr("basilisk.runtime.isolation.spawn_restricted_scan", forbidden_worker)
        result = self.runner.invoke(cli, [
            "scan", "-t", "https://example.test", "--cost-preview",
            "--mode", "quick", "--module", "injection.direct",
            "--probe-id", "INJ-001", "--skip-recon", "--no-evolve",
        ])
        assert result.exit_code == 0
        assert "Scan Cost Preview" in result.output
        assert "Hard request ceiling" in result.output
        assert "Provider cost estimate" in result.output
        assert "Unavailable until provider/model token rates are" in result.output

    def test_recon_requires_target(self):
        result = self.runner.invoke(cli, ["recon"])
        assert result.exit_code != 0

    def test_scan_rejects_inline_api_key(self):
        result = self.runner.invoke(
            cli,
            ["scan", "-t", "https://example.test", "--api-key", "sk-inline-secret"],
        )
        assert result.exit_code != 0
        assert "no longer accepts inline secret values" in result.output

    def test_scan_rejects_inline_attacker_api_key(self):
        result = self.runner.invoke(
            cli,
            ["scan", "-t", "https://example.test", "--attacker-api-key", "sk-inline-secret"],
        )
        assert result.exit_code != 0
        assert "no longer accepts inline secret values" in result.output

    def test_scan_propagates_runtime_exit_code(self, monkeypatch):
        async def fake_run_scan(**kwargs):
            return 7

        monkeypatch.setattr("basilisk.cli.scan.run_scan", fake_run_scan)
        result = self.runner.invoke(
            cli,
            ["scan", "-t", "https://example.test", "--no-evolve"],
        )
        assert result.exit_code == 7
