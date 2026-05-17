"""Unit tests for remote SSH deployment engine and CLI."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from wireghost.cli.deploy import app as deploy_app
from wireghost.deploy.engine import (
    DeployConfig,
    DeployResult,
    _build_remote_env,
    _scp_transfer,
    _ssh_opts,
    _ssh_target,
    build_bundle,
    check_ssh,
    deploy,
)

runner = CliRunner()


# ── Dataclass tests ──────────────────────────────────────────────────────


class TestDeployConfig:
    def test_defaults(self):
        cfg = DeployConfig(target_host="10.0.0.1")
        assert cfg.target_host == "10.0.0.1"
        assert cfg.ssh_user == "root"
        assert cfg.ssh_port == 22
        assert cfg.ssh_key is None
        assert cfg.ssh_password is None
        assert cfg.install_mode == "docker"
        assert cfg.with_msf is False
        assert cfg.web_host is None
        assert cfg.web_port == 443
        assert cfg.skip_compress is False
        assert cfg.bundle_path is None
        assert cfg.skip_health_check is False

    def test_custom(self):
        cfg = DeployConfig(
            target_host="192.168.1.100",
            ssh_user="admin",
            ssh_port=2222,
            ssh_key=Path("/home/user/.ssh/id_ed25519"),
            ssh_password="secret",
            install_mode="host",
            with_msf=True,
            web_host="portal.example.com",
            web_port=8443,
            skip_compress=True,
            bundle_path=Path("/tmp/bundle.tar.gz"),
            skip_health_check=True,
        )
        assert cfg.ssh_user == "admin"
        assert cfg.ssh_port == 2222
        assert cfg.ssh_key == Path("/home/user/.ssh/id_ed25519")
        assert cfg.ssh_password == "secret"
        assert cfg.install_mode == "host"
        assert cfg.with_msf is True
        assert cfg.web_host == "portal.example.com"
        assert cfg.web_port == 8443
        assert cfg.skip_compress is True
        assert cfg.bundle_path == Path("/tmp/bundle.tar.gz")
        assert cfg.skip_health_check is True


class TestDeployResult:
    def test_success(self):
        r = DeployResult(
            success=True,
            host="10.0.0.1",
            setup_url="https://10.0.0.1/setup",
            login_url="https://10.0.0.1/login",
            output="install complete",
            duration=45.2,
        )
        assert r.success is True
        assert r.host == "10.0.0.1"
        assert r.setup_url == "https://10.0.0.1/setup"
        assert r.login_url == "https://10.0.0.1/login"
        assert r.errors == []

    def test_failure(self):
        r = DeployResult(
            success=False,
            host="10.0.0.1",
            errors=["SSH connection failed", "SCP transfer failed"],
            duration=3.1,
        )
        assert r.success is False
        assert len(r.errors) == 2
        assert r.output == ""


# ── SSH helpers ───────────────────────────────────────────────────────────


class TestSshOpts:
    def test_default_opts(self):
        cfg = DeployConfig(target_host="10.0.0.1")
        opts = _ssh_opts(cfg)
        assert "-o" in opts
        assert "ConnectTimeout=10" in opts
        assert "StrictHostKeyChecking=accept-new" in opts
        assert "ServerAliveInterval=30" in opts
        assert "-p" in opts
        assert "22" in opts

    def test_custom_port(self):
        cfg = DeployConfig(target_host="10.0.0.1", ssh_port=2222)
        opts = _ssh_opts(cfg)
        idx = opts.index("-p")
        assert opts[idx + 1] == "2222"

    def test_with_key(self):
        cfg = DeployConfig(
            target_host="10.0.0.1",
            ssh_key=Path("/home/user/.ssh/id_rsa"),
        )
        opts = _ssh_opts(cfg)
        assert "-i" in opts
        assert "/home/user/.ssh/id_rsa" in opts

    def test_no_key_omits_i_flag(self):
        cfg = DeployConfig(target_host="10.0.0.1")
        opts = _ssh_opts(cfg)
        assert "-i" not in opts


class TestSshTarget:
    def test_builds_user_host(self):
        cfg = DeployConfig(target_host="10.0.0.1", ssh_user="admin")
        assert _ssh_target(cfg) == "admin@10.0.0.1"

    def test_default_root_user(self):
        cfg = DeployConfig(target_host="192.168.1.1")
        assert _ssh_target(cfg) == "root@192.168.1.1"


# ── check_ssh ─────────────────────────────────────────────────────────────


class TestCheckSsh:
    def test_success(self):
        cfg = DeployConfig(target_host="10.0.0.1")
        with patch("wireghost.deploy.engine._run_ssh") as mock_run:
            mock_run.return_value = (0, "SSH_OK\nUbuntu 24.04 LTS\n", "")
            assert check_ssh(cfg) is True
            mock_run.assert_called_once()

    def test_failure_bad_rc(self):
        cfg = DeployConfig(target_host="10.0.0.1")
        with patch("wireghost.deploy.engine._run_ssh") as mock_run:
            mock_run.return_value = (255, "", "Permission denied")
            assert check_ssh(cfg) is False

    def test_failure_no_ssh_ok_in_output(self):
        cfg = DeployConfig(target_host="10.0.0.1")
        with patch("wireghost.deploy.engine._run_ssh") as mock_run:
            mock_run.return_value = (0, "some garbage", "")
            assert check_ssh(cfg) is False

    def test_timeout_default(self):
        cfg = DeployConfig(target_host="10.0.0.1")
        with patch("wireghost.deploy.engine._run_ssh") as mock_run:
            mock_run.return_value = (0, "SSH_OK\n", "")
            check_ssh(cfg)
            assert mock_run.call_args[1]["timeout"] == 15


# ── build_bundle ──────────────────────────────────────────────────────────


class TestBuildBundle:
    def test_script_not_found(self):
        cfg = DeployConfig(target_host="10.0.0.1")
        with patch("pathlib.Path.is_file", return_value=False):
            with pytest.raises(FileNotFoundError, match="offline-export.sh"):
                build_bundle(cfg)

    def test_script_fails(self):
        cfg = DeployConfig(target_host="10.0.0.1")
        with patch("pathlib.Path.is_file", return_value=True), \
             patch("wireghost.deploy.engine._run_local") as mock_run:
            mock_run.return_value = (1, "", "build error")
            with pytest.raises(RuntimeError, match="Bundle build failed"):
                build_bundle(cfg)

    def test_parse_from_stdout(self, tmp_path):
        """Bundle path is parsed from 'Compressed archive created:' in stdout."""
        cfg = DeployConfig(target_host="10.0.0.1")
        bundle_file = tmp_path / "wireghost-offline-abc123.tar.gz"
        bundle_file.write_text("dummy")

        with patch("pathlib.Path.is_file", return_value=True), \
             patch("wireghost.deploy.engine._run_local") as mock_run, \
             patch("wireghost.deploy.engine.Path.__new__"):
            mock_run.return_value = (
                0,
                f"Compressed archive created: {bundle_file}\n",
                "",
            )
            # The parsed path is checked relative to project_root — let the
            # glob fallback in build_bundle() find our tmp_path file
            with patch.object(Path, "resolve", return_value=tmp_path):
                result = build_bundle(cfg, output_dir=tmp_path)
                assert result is not None

    def test_build_with_msf_flag(self):
        cfg = DeployConfig(target_host="10.0.0.1", with_msf=True)
        with patch("pathlib.Path.is_file", return_value=True), \
             patch("wireghost.deploy.engine._run_local") as mock_run:
            mock_run.return_value = (0, "Bundle: wireghost-offline-xxx\n", "")
            with patch("pathlib.Path.exists", return_value=True):
                build_bundle(cfg)
            # Verify --with-msf was passed to the script
            call_args = mock_run.call_args[0][0]
            assert "--with-msf" in call_args

    def test_build_with_skip_compress(self):
        cfg = DeployConfig(target_host="10.0.0.1", skip_compress=True)
        with patch("pathlib.Path.is_file", return_value=True), \
             patch("wireghost.deploy.engine._run_local") as mock_run:
            mock_run.return_value = (0, "Bundle: wireghost-offline-xxx\n", "")
            with patch("pathlib.Path.exists", return_value=True):
                build_bundle(cfg)
            call_args = mock_run.call_args[0][0]
            assert "--skip-compress" in call_args

    def test_build_timeout(self, tmp_path):
        cfg = DeployConfig(target_host="10.0.0.1")
        with patch("pathlib.Path.is_file", return_value=True), \
             patch("wireghost.deploy.engine._run_local") as mock_run:
            mock_run.return_value = (-1, "", "timed out")
            with pytest.raises(RuntimeError, match="Bundle build failed"):
                build_bundle(cfg, output_dir=tmp_path)


# ── _scp_transfer ─────────────────────────────────────────────────────────


class TestScpTransfer:
    def test_file_transfer_success(self):
        cfg = DeployConfig(target_host="10.0.0.1")
        local = Path("/tmp/bundle.tar.gz")
        with patch("wireghost.deploy.engine._run_local") as mock_run:
            mock_run.return_value = (0, "", "")
            assert _scp_transfer(cfg, local) is True
            cmd = mock_run.call_args[0][0]
            assert "scp" in cmd[0]
            assert "-C" in cmd  # compression flag
            assert str(local) in cmd

    def test_directory_transfer(self):
        cfg = DeployConfig(target_host="10.0.0.1")
        local = Path("/tmp/bundle_dir")
        with patch("wireghost.deploy.engine._run_local") as mock_run, \
             patch.object(Path, "is_dir", return_value=True):
            mock_run.return_value = (0, "", "")
            assert _scp_transfer(cfg, local) is True
            cmd = mock_run.call_args[0][0]
            assert "-r" in cmd  # recursive for dirs

    def test_transfer_failure(self):
        cfg = DeployConfig(target_host="10.0.0.1")
        local = Path("/tmp/bundle.tar.gz")
        with patch("wireghost.deploy.engine._run_local") as mock_run:
            mock_run.return_value = (1, "", "connection refused")
            assert _scp_transfer(cfg, local) is False

    def test_default_remote_dir(self):
        cfg = DeployConfig(target_host="10.0.0.1")
        local = Path("/tmp/bundle.tar.gz")
        with patch("wireghost.deploy.engine._run_local") as mock_run:
            mock_run.return_value = (0, "", "")
            _scp_transfer(cfg, local)
            cmd_str = " ".join(mock_run.call_args[0][0])
            assert ":/opt/" in cmd_str


# ── _build_remote_env ─────────────────────────────────────────────────────


class TestBuildRemoteEnv:
    def test_default_env(self):
        cfg = DeployConfig(target_host="10.0.0.1")
        env = _build_remote_env(cfg)
        assert "WIREGHOST_HOST='10.0.0.1'" in env
        assert "WIREGHOST_PORT='443'" in env
        assert "INSTALL_MODE" not in env  # docker mode doesn't set it

    def test_host_mode(self):
        cfg = DeployConfig(target_host="10.0.0.1", install_mode="host")
        env = _build_remote_env(cfg)
        assert "INSTALL_MODE='host'" in env

    def test_custom_web_host_and_port(self):
        cfg = DeployConfig(
            target_host="10.0.0.1",
            web_host="portal.example.com",
            web_port=8443,
        )
        env = _build_remote_env(cfg)
        assert "WIREGHOST_HOST='portal.example.com'" in env
        assert "WIREGHOST_PORT='8443'" in env


# ── deploy orchestrator ───────────────────────────────────────────────────


class TestDeployOrchestrator:
    def test_ssh_failure_returns_early(self):
        cfg = DeployConfig(target_host="10.0.0.1")
        with patch("wireghost.deploy.engine.check_ssh", return_value=False):
            result = deploy(cfg)
            assert result.success is False
            assert result.host == "10.0.0.1"
            assert "SSH connection failed" in result.errors

    def test_bundle_not_found(self):
        cfg = DeployConfig(
            target_host="10.0.0.1",
            bundle_path=Path("/nonexistent/bundle.tar.gz"),
        )
        with patch("wireghost.deploy.engine.check_ssh", return_value=True):
            result = deploy(cfg)
            assert result.success is False
            assert any("not found" in e for e in result.errors)

    def test_scp_failure_returns_early(self):
        cfg = DeployConfig(
            target_host="10.0.0.1",
            bundle_path=Path("/tmp/bundle.tar.gz"),
        )
        with patch("wireghost.deploy.engine.check_ssh", return_value=True), \
             patch.object(Path, "exists", return_value=True), \
             patch("wireghost.deploy.engine._scp_transfer", return_value=False):
            result = deploy(cfg)
            assert result.success is False
            assert any("SCP transfer failed" in e for e in result.errors)

    def test_full_deploy_success_tarball(self, tmp_path):
        """Full deployment flow with a .tar.gz bundle."""
        cfg = DeployConfig(
            target_host="10.0.0.1",
            bundle_path=tmp_path / "wireghost-offline-test.tar.gz",
        )
        cfg.bundle_path.write_text("dummy tarball")

        with patch("wireghost.deploy.engine.check_ssh", return_value=True), \
             patch("wireghost.deploy.engine._scp_transfer", return_value=True), \
             patch("wireghost.deploy.engine._run_ssh") as mock_ssh:
            # First call: installer (pass), second call: health check (pass)
            mock_ssh.side_effect = [
                (0, "Installation complete!\nPortal running", ""),
                (0, "wireghost-app running\nwireghost-db running\n", ""),
            ]

            result = deploy(cfg)

            assert result.success is True
            assert result.host == "10.0.0.1"
            assert result.setup_url == "https://10.0.0.1/setup"
            assert result.login_url == "https://10.0.0.1/login"
            assert result.duration > 0
            assert "Installation complete" in result.output

            # Verify remote install command included extract + install
            install_cmd = mock_ssh.call_args_list[0][0][1]
            assert "tar xzf" in install_cmd
            assert "sudo bash install.sh" in install_cmd

    def test_full_deploy_success_directory_bundle(self, tmp_path):
        """Full deployment with an uncompressed directory bundle."""
        cfg = DeployConfig(
            target_host="10.0.0.1",
            bundle_path=tmp_path / "wireghost-offline-test",
        )
        cfg.bundle_path.mkdir()

        with patch("wireghost.deploy.engine.check_ssh", return_value=True), \
             patch("wireghost.deploy.engine._scp_transfer", return_value=True), \
             patch("wireghost.deploy.engine._run_ssh") as mock_ssh:
            mock_ssh.side_effect = [
                (0, "Installation complete!", ""),
                (0, "all good", ""),
            ]

            result = deploy(cfg)
            assert result.success is True
            # Directory path should cd directly without tar extraction
            install_cmd = mock_ssh.call_args_list[0][0][1]
            assert "cd /opt/wireghost-offline-test" in install_cmd
            assert "tar xzf" not in install_cmd

    def test_full_deploy_installer_failure(self, tmp_path):
        cfg = DeployConfig(
            target_host="10.0.0.1",
            bundle_path=tmp_path / "wireghost-offline-test.tar.gz",
        )
        cfg.bundle_path.write_text("dummy")

        with patch("wireghost.deploy.engine.check_ssh", return_value=True), \
             patch("wireghost.deploy.engine._scp_transfer", return_value=True), \
             patch("wireghost.deploy.engine._run_ssh") as mock_ssh:
            mock_ssh.return_value = (1, "", "Docker daemon not running")

            result = deploy(cfg)
            assert result.success is False
            assert any("rc=1" in e for e in result.errors)

    def test_full_deploy_host_mode(self, tmp_path):
        cfg = DeployConfig(
            target_host="10.0.0.1",
            install_mode="host",
            bundle_path=tmp_path / "wireghost-offline-test.tar.gz",
        )
        cfg.bundle_path.write_text("dummy")

        with patch("wireghost.deploy.engine.check_ssh", return_value=True), \
             patch("wireghost.deploy.engine._scp_transfer", return_value=True), \
             patch("wireghost.deploy.engine._run_ssh") as mock_ssh:
            mock_ssh.side_effect = [
                (0, "OK", ""),
                (0, "OK", ""),
            ]

            deploy(cfg)
            install_cmd = mock_ssh.call_args_list[0][0][1]
            assert "--host" in install_cmd

    def test_full_deploy_with_msf_flag(self, tmp_path):
        cfg = DeployConfig(
            target_host="10.0.0.1",
            with_msf=True,
            bundle_path=tmp_path / "wireghost-offline-test.tar.gz",
        )
        cfg.bundle_path.write_text("dummy")

        with patch("wireghost.deploy.engine.check_ssh", return_value=True), \
             patch("wireghost.deploy.engine._scp_transfer", return_value=True), \
             patch("wireghost.deploy.engine._run_ssh") as mock_ssh:
            mock_ssh.side_effect = [
                (0, "OK", ""),
                (0, "OK", ""),
            ]

            deploy(cfg)
            install_cmd = mock_ssh.call_args_list[0][0][1]
            assert "--with-msf" in install_cmd

    def test_custom_web_host_in_urls(self, tmp_path):
        cfg = DeployConfig(
            target_host="10.0.0.1",
            web_host="portal.example.com",
            web_port=8443,
            bundle_path=tmp_path / "wireghost-offline-test.tar.gz",
        )
        cfg.bundle_path.write_text("dummy")

        with patch("wireghost.deploy.engine.check_ssh", return_value=True), \
             patch("wireghost.deploy.engine._scp_transfer", return_value=True), \
             patch("wireghost.deploy.engine._run_ssh") as mock_ssh:
            mock_ssh.side_effect = [
                (0, "OK", ""),
                (0, "OK", ""),
            ]

            result = deploy(cfg)
            # proto is 'http' when web_port != 443; non-standard port is appended
            assert result.setup_url == "http://portal.example.com:8443/setup"
            assert result.login_url == "http://portal.example.com:8443/login"

    def test_url_omits_default_ports(self, tmp_path):
        """80 and 443 should be omitted from URLs."""
        cfg = DeployConfig(
            target_host="10.0.0.1",
            web_host="myscan.example.com",
            web_port=443,
            bundle_path=tmp_path / "wireghost-offline-test.tar.gz",
        )
        cfg.bundle_path.write_text("dummy")

        with patch("wireghost.deploy.engine.check_ssh", return_value=True), \
             patch("wireghost.deploy.engine._scp_transfer", return_value=True), \
             patch("wireghost.deploy.engine._run_ssh") as mock_ssh:
            mock_ssh.side_effect = [
                (0, "OK", ""),
                (0, "OK", ""),
            ]

            result = deploy(cfg)
            assert ":443" not in result.setup_url

    def test_skip_health_check(self, tmp_path):
        cfg = DeployConfig(
            target_host="10.0.0.1",
            skip_health_check=True,
            bundle_path=tmp_path / "wireghost-offline-test.tar.gz",
        )
        cfg.bundle_path.write_text("dummy")

        with patch("wireghost.deploy.engine.check_ssh", return_value=True), \
             patch("wireghost.deploy.engine._scp_transfer", return_value=True), \
             patch("wireghost.deploy.engine._run_ssh") as mock_ssh:
            mock_ssh.return_value = (0, "OK", "")

            deploy(cfg)
            # Only one SSH call (installer) — no health check
            assert mock_ssh.call_count == 1

    def test_auto_builds_bundle_when_none_provided(self, tmp_path):
        """When bundle_path is None, build_bundle should be called."""
        cfg = DeployConfig(target_host="10.0.0.1")

        bundle = tmp_path / "wireghost-offline-auto.tar.gz"
        bundle.write_text("auto-built")

        with patch("wireghost.deploy.engine.check_ssh", return_value=True), \
             patch("wireghost.deploy.engine.build_bundle", return_value=bundle), \
             patch("wireghost.deploy.engine._scp_transfer", return_value=True), \
             patch("wireghost.deploy.engine._run_ssh") as mock_ssh:
            mock_ssh.side_effect = [
                (0, "OK", ""),
                (0, "OK", ""),
            ]

            result = deploy(cfg)
            assert result.success is True


# ── CLI tests ─────────────────────────────────────────────────────────────


class TestDeployCli:
    # Typer 0.23.0 with invoke_without_command=True requires options BEFORE
    # the TARGET argument. Pattern: deploy [OPTIONS] TARGET

    def test_help(self):
        result = runner.invoke(deploy_app, ["--help"])
        assert result.exit_code == 0
        assert "Deploy Wire_Ghost" in result.stdout
        assert "--check" in result.stdout

    def test_missing_target_shows_help(self):
        result = runner.invoke(deploy_app, [])
        assert result.exit_code != 0

    @patch("wireghost.cli.deploy.check_ssh")
    @patch("getpass.getpass", return_value="testpw")
    def test_check_mode_success(self, mock_getpass, mock_check):
        mock_check.return_value = True
        result = runner.invoke(deploy_app, ["--check", "--target", "10.0.0.1"])
        assert result.exit_code == 0
        mock_check.assert_called_once()

    @patch("wireghost.cli.deploy.check_ssh")
    @patch("getpass.getpass", return_value="testpw")
    def test_check_mode_failure(self, mock_getpass, mock_check):
        mock_check.return_value = False
        result = runner.invoke(deploy_app, ["--check", "--target", "10.0.0.1"])
        assert result.exit_code == 1
        mock_check.assert_called_once()

    def test_invalid_mode(self):
        result = runner.invoke(deploy_app, [
            "--mode", "kubernetes", "--check", "--target", "10.0.0.1",
        ])
        assert result.exit_code == 1

    def test_no_build_without_bundle(self):
        result = runner.invoke(deploy_app, [
            "--no-build", "--check", "--target", "10.0.0.1",
        ])
        assert result.exit_code == 1

    def test_custom_ssh_options(self):
        """Verify custom SSH options flow into DeployConfig."""
        with patch("wireghost.cli.deploy.check_ssh", return_value=True):
            result = runner.invoke(deploy_app, [
                "--check",
                "-u", "admin",
                "-P", "2222",
                "-i", "/home/user/.ssh/id_ed25519",
                "--web-host", "scan.example.com",
                "--web-port", "8080",
                "--target", "10.0.0.1",
            ])
            assert result.exit_code == 0

    @patch("wireghost.cli.deploy.deploy")
    @patch("wireghost.cli.deploy.check_ssh")
    def test_deploy_passes_config_to_engine(self, mock_check, mock_deploy):
        mock_check.return_value = True
        mock_deploy.return_value = DeployResult(
            success=True,
            host="10.0.0.1",
            setup_url="https://10.0.0.1/setup",
            login_url="https://10.0.0.1/login",
            duration=30.0,
            output="done",
        )

        with patch("getpass.getpass", return_value="testpw"):
            result = runner.invoke(deploy_app, [
                "--user", "deployer",
                "--mode", "host",
                "--with-msf",
                "--skip-health",
                "--target", "10.0.0.1",
            ])

        assert result.exit_code == 0
        mock_deploy.assert_called_once()
        cfg = mock_deploy.call_args[0][0]
        assert cfg.target_host == "10.0.0.1"
        assert cfg.ssh_user == "deployer"
        assert cfg.install_mode == "host"
        assert cfg.with_msf is True
        assert cfg.skip_health_check is True

    @patch("wireghost.cli.deploy.deploy")
    @patch("getpass.getpass", return_value="badpw")
    def test_deploy_failure_display(self, mock_getpass, mock_deploy):
        mock_deploy.return_value = DeployResult(
            success=False,
            host="10.0.0.1",
            errors=["SSH connection failed"],
            duration=2.0,
            output="Permission denied (publickey)",
        )

        result = runner.invoke(deploy_app, ["--target", "10.0.0.1"])

        assert result.exit_code == 0  # CLI succeeds even when deploy fails
        mock_deploy.assert_called_once()

    @patch("wireghost.cli.deploy.deploy")
    @patch("wireghost.cli.deploy.check_ssh")
    def test_bundle_option_passed(self, mock_check, mock_deploy):
        mock_check.return_value = True
        mock_deploy.return_value = DeployResult(
            success=True,
            host="10.0.0.1",
            setup_url="https://10.0.0.1/setup",
            login_url="https://10.0.0.1/login",
            duration=10.0,
        )

        with patch("getpass.getpass", return_value="testpw"):
            result = runner.invoke(deploy_app, [
                "--bundle", "/tmp/my-bundle.tar.gz",
                "--skip-health",
                "--target", "10.0.0.1",
            ])

        assert result.exit_code == 0
        cfg = mock_deploy.call_args[0][0]
        assert cfg.bundle_path == Path("/tmp/my-bundle.tar.gz")

    @patch("wireghost.cli.deploy.deploy")
    @patch("wireghost.cli.deploy.check_ssh")
    def test_skip_compress_flag_passed(self, mock_check, mock_deploy):
        mock_check.return_value = True
        mock_deploy.return_value = DeployResult(
            success=True, host="10.0.0.1",
            setup_url="https://10.0.0.1/setup",
            login_url="https://10.0.0.1/login",
            duration=5.0,
        )

        with patch("getpass.getpass", return_value="testpw"):
            result = runner.invoke(deploy_app, [
                "--skip-compress", "--skip-health", "--target", "10.0.0.1",
            ])
        assert result.exit_code == 0
        cfg = mock_deploy.call_args[0][0]
        assert cfg.skip_compress is True


# ── Dispatcher integration ────────────────────────────────────────────────


class TestDispatcherDeploy:
    """Verify the deploy app is mounted in the dispatcher."""

    def test_deploy_in_help(self):
        from wireghost.cli import dispatcher as disp
        result = runner.invoke(disp.app, ["--help"])
        assert result.exit_code == 0
        assert "deploy" in result.stdout

    def test_deploy_subcommand_help(self):
        from wireghost.cli import dispatcher as disp
        result = runner.invoke(disp.app, ["deploy", "--help"])
        assert result.exit_code == 0
        assert "--target" in result.stdout
