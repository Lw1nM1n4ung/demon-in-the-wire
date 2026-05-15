"""Tests for wireghost auth commands."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

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


class TestLogout:
    def test_logout_clears_session(self):
        mock_client = MagicMock()
        with patch("wireghost.cli.auth.get_client", return_value=mock_client):
            result = runner.invoke(app, ["logout"])
            assert result.exit_code == 0
            mock_client.logout.assert_called_once()
