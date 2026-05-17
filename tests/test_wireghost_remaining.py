"""Smoke tests for remaining CLI commands."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
from typer.testing import CliRunner

from wireghost.cli.notifications import app as notify_app
from wireghost.cli.support import app as support_app

runner = CliRunner()


def _mock_200(data=None):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = 200
    resp.json.return_value = data or {}
    return resp


class TestNotify:
    def test_config(self):
        mock_client = MagicMock()
        mock_client.get.return_value = _mock_200()
        with patch("wireghost.cli.notifications.get_client", return_value=mock_client):
            result = runner.invoke(notify_app, ["config"])
            assert result.exit_code == 0


class TestSupport:
    def test_bundle(self):
        mock_client = MagicMock()
        mock_client.post.return_value = _mock_200({"path": "bundle.tar.gz"})
        with patch("wireghost.cli.support.get_client", return_value=mock_client):
            result = runner.invoke(support_app, [])
            assert result.exit_code == 0
