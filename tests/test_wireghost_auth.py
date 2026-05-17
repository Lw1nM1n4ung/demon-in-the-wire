"""Tests for wireghost auth commands."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
from typer.testing import CliRunner

from wireghost.cli.auth import app

runner = CliRunner()


class TestWhoami:
    def test_whoami_shows_user(self):
        mock_client = MagicMock()
        mock_client.whoami.return_value = {
            "username": "admin",
            "role": "owner",
            "email": "admin@example.com",
        }
        with patch("wireghost.cli.auth.get_client", return_value=mock_client):
            result = runner.invoke(app, ["whoami"])
            assert result.exit_code == 0
            assert "admin" in result.stdout
            assert "owner" in result.stdout

    def test_whoami_unauthorized(self):
        mock_client = MagicMock()
        mock_client.whoami.side_effect = RuntimeError("401")
        with patch("wireghost.cli.auth.get_client", return_value=mock_client):
            result = runner.invoke(app, ["whoami"])
            assert result.exit_code == 1


class TestLogin:
    def test_login_with_explicit_args(self):
        """Login with --portal, --username, --password avoids interactive prompts."""
        mock_client = MagicMock()
        mock_client.base_url = "https://portal.example.com"
        mock_client.login.return_value = {
            "user": {"username": "admin", "role": "owner"}
        }
        with patch("wireghost.cli.auth.get_client", return_value=mock_client):
            result = runner.invoke(app, [
                "login",
                "--portal", "https://portal.example.com",
                "--username", "admin",
                "--password", "hunter2",
            ])
        assert result.exit_code == 0
        assert "admin" in result.stdout
        assert "owner" in result.stdout
        mock_client.login.assert_called_once_with("admin", "hunter2", None)

    def test_login_failure_exits_1(self):
        mock_client = MagicMock()
        mock_client.login.side_effect = httpx.HTTPStatusError(
            "401", request=MagicMock(), response=MagicMock(status_code=401)
        )
        with patch("wireghost.cli.auth.get_client", return_value=mock_client):
            result = runner.invoke(app, [
                "login",
                "--portal", "https://portal.example.com",
                "--username", "admin",
                "--password", "wrong",
            ])
        assert result.exit_code == 1
        assert "Login failed" in result.stdout

    def test_login_prompts_for_missing_values(self):
        """When flags omitted, prompts for URL, username, and password."""
        mock_client = MagicMock()
        mock_client.base_url = ""
        mock_client.login.return_value = {
            "user": {"username": "demo", "role": "viewer"}
        }
        with patch("wireghost.cli.auth.get_client", return_value=mock_client), \
             patch("getpass.getpass", return_value="secret"):
            result = runner.invoke(app, ["login"], input="https://host:443\ndemo\n")
        assert result.exit_code == 0
        mock_client.login.assert_called_once_with("demo", "secret", None)


class TestLogout:
    def test_logout_clears_session(self):
        mock_client = MagicMock()
        with patch("wireghost.cli.auth.get_client", return_value=mock_client):
            result = runner.invoke(app, ["logout"])
            assert result.exit_code == 0
            mock_client.logout.assert_called_once()

    def test_logout_warns_on_exception(self):
        """Logout prints a warning (not error) when the server fails."""
        mock_client = MagicMock()
        mock_client.logout.side_effect = RuntimeError("Connection refused")
        with patch("wireghost.cli.auth.get_client", return_value=mock_client):
            result = runner.invoke(app, ["logout"])
        assert result.exit_code == 0  # non-fatal
        assert "Warning" in result.stdout
