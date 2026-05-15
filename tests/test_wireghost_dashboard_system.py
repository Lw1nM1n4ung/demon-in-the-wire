"""Smoke tests for dashboard and system commands."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
from typer.testing import CliRunner

from wireghost.cli.dashboard import app as dashboard_app
from wireghost.cli.system import app as system_app

runner = CliRunner()


class TestDashboard:
    def test_stats(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"total_scans": 5}
        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp
        with patch("wireghost.cli.dashboard.get_client", return_value=mock_client):
            result = runner.invoke(dashboard_app, ["stats"])
            assert result.exit_code == 0


class TestSystem:
    def test_stats(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"cpu_percent": 12.5}
        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp
        with patch("wireghost.cli.system.get_client", return_value=mock_client):
            result = runner.invoke(system_app, ["stats"])
            assert result.exit_code == 0

    def test_tools(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"name": "nmap", "version": "7.95"}]
        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp
        with patch("wireghost.cli.system.get_client", return_value=mock_client):
            result = runner.invoke(system_app, ["tools"])
            assert result.exit_code == 0
