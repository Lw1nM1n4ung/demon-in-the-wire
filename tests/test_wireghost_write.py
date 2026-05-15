"""Smoke tests for write commands."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
from typer.testing import CliRunner

from wireghost.cli.policies import app as policies_app
from wireghost.cli.schedules import app as schedules_app
from wireghost.cli.users import app as users_app
from wireghost.cli.tokens import app as tokens_app
from wireghost.cli.sessions import app as sessions_app

runner = CliRunner()


def _mock_200(data=None):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = 200
    resp.json.return_value = data or []
    return resp


def _mock_client(mod):
    mock_client = MagicMock()
    mock_client.get.return_value = _mock_200()
    mock_client.post.return_value = _mock_200({"id": "fake-uuid"})
    return patch(mod, return_value=mock_client)


class TestPolicies:
    def test_list(self):
        with _mock_client("wireghost.cli.policies.get_client"):
            result = runner.invoke(policies_app, ["list"])
            assert result.exit_code == 0


class TestSchedules:
    def test_list(self):
        with _mock_client("wireghost.cli.schedules.get_client"):
            result = runner.invoke(schedules_app, ["list"])
            assert result.exit_code == 0


class TestUsers:
    def test_list(self):
        with _mock_client("wireghost.cli.users.get_client"):
            result = runner.invoke(users_app, ["list"])
            assert result.exit_code == 0


class TestTokens:
    def test_list(self):
        with _mock_client("wireghost.cli.tokens.get_client"):
            result = runner.invoke(tokens_app, ["list"])
            assert result.exit_code == 0


class TestSessions:
    def test_list(self):
        with _mock_client("wireghost.cli.sessions.get_client"):
            result = runner.invoke(sessions_app, ["list"])
            assert result.exit_code == 0
