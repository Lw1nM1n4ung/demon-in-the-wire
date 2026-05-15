# tests/test_wireghost_client.py
"""Tests for WireGhostClient."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from wireghost.cli.client import WireGhostClient, _config_dir


class TestConfigDir:
    def test_default_is_home_wireghost(self):
        with patch.dict(os.environ, {}, clear=True):
            d = _config_dir()
            assert d == Path.home() / ".wireghost"

    def test_env_override(self):
        with patch.dict(os.environ, {"WIREGHOST_CONFIG_DIR": "/tmp/wgtest"}):
            d = _config_dir()
            assert d == Path("/tmp/wgtest")


class TestTokenCache:
    def test_read_token_from_file(self):
        with tempfile.TemporaryDirectory() as td:
            token_file = Path(td) / ".token"
            token_file.write_text("wg_tok_test123")
            token_file.chmod(0o600)
            with patch.dict(os.environ, {"WIREGHOST_CONFIG_DIR": td}):
                client = WireGhostClient()
                assert client._token == "wg_tok_test123"

    def test_token_env_overrides_file(self):
        with tempfile.TemporaryDirectory() as td:
            token_file = Path(td) / ".token"
            token_file.write_text("wg_tok_file")
            with patch.dict(
                os.environ,
                {"WIREGHOST_CONFIG_DIR": td, "WIREGHOST_TOKEN": "wg_tok_env"},
            ):
                client = WireGhostClient()
                assert client._token == "wg_tok_env"


class TestAuthPrecedence:
    def test_constructor_token_highest(self):
        client = WireGhostClient(token="wg_tok_flag")
        assert client._token == "wg_tok_flag"

    def test_env_token_over_cached(self):
        with tempfile.TemporaryDirectory() as td:
            token_file = Path(td) / ".token"
            token_file.write_text("wg_tok_file")
            with patch.dict(
                os.environ,
                {"WIREGHOST_CONFIG_DIR": td, "WIREGHOST_TOKEN": "wg_tok_env"},
            ):
                client = WireGhostClient()
                assert client._token == "wg_tok_env"


class TestTLSBehavior:
    def test_localhost_skips_verify(self):
        client = WireGhostClient(base_url="https://localhost:18443")
        assert client._verify is False

    def test_remote_verifies(self):
        client = WireGhostClient(base_url="https://portal.example.com")
        assert client._verify is True

    def test_insecure_flag(self):
        client = WireGhostClient(base_url="https://portal.example.com", insecure=True)
        assert client._verify is False


class TestAttachAuth:
    def test_token_auth_header(self):
        client = WireGhostClient(token="wg_tok_abc")
        kwargs: dict = {}
        client._attach_auth(kwargs)
        assert kwargs["headers"]["Authorization"] == "Token wg_tok_abc"

    def test_session_cookie_fallback(self):
        client = WireGhostClient()
        client._cookies = {"sessionid": "abc123"}
        kwargs: dict = {}
        client._attach_auth(kwargs)
        assert kwargs["cookies"] == {"sessionid": "abc123"}
