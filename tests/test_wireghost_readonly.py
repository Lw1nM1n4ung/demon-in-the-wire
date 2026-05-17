"""Smoke tests for read-only CLI commands."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest
from typer.testing import CliRunner

from wireghost.cli.scans import app as scans_app
from wireghost.cli.hosts import app as hosts_app
from wireghost.cli.findings import app as findings_app
from wireghost.cli.exploits import app as exploits_app

runner = CliRunner()


class TestScansList:
    def test_list_empty(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp
        with patch("wireghost.cli.scans.get_client", return_value=mock_client):
            result = runner.invoke(scans_app, ["list"])
            assert result.exit_code == 0


class TestHostsList:
    def test_list_empty(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp
        with patch("wireghost.cli.hosts.get_client", return_value=mock_client):
            result = runner.invoke(hosts_app, ["list"])
            assert result.exit_code == 0


class TestFindingsList:
    def test_list_empty(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp
        with patch("wireghost.cli.findings.get_client", return_value=mock_client):
            result = runner.invoke(findings_app, ["list"])
            assert result.exit_code == 0


class TestExploitsList:
    def test_list_empty(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp
        with patch("wireghost.cli.exploits.get_client", return_value=mock_client):
            result = runner.invoke(exploits_app, ["list"])
            assert result.exit_code == 0
