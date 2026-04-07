"""Tests for wireghost.utils — network, process, fs."""

from __future__ import annotations

import pytest

from wireghost.utils.fs import build_output_tree
from wireghost.utils.network import extract_endpoint, is_valid_ipv4, safe_get
from wireghost.utils.process import ToolMissing, check_tools


# ---------- safe_get ----------


class TestSafeGet:
    def test_simple_key(self):
        assert safe_get({"a": 1}, ["a"]) == 1

    def test_nested_keys(self):
        assert safe_get({"a": {"b": {"c": 42}}}, ["a", "b", "c"]) == 42

    def test_missing_key_returns_default(self):
        assert safe_get({"a": 1}, ["b"]) == "N/A"

    def test_custom_default(self):
        assert safe_get({}, ["x"], default="none") == "none"

    def test_intermediate_not_dict(self):
        assert safe_get({"a": "string"}, ["a", "b"]) == "N/A"


# ---------- extract_endpoint ----------


class TestExtractEndpoint:
    def test_path_only(self):
        assert extract_endpoint("https://example.com/login") == "/login"

    def test_path_with_query(self):
        assert extract_endpoint("https://example.com/login?next=/dash") == "/login?next=/dash"

    def test_root_path(self):
        assert extract_endpoint("https://example.com") == "/"

    def test_just_path(self):
        assert extract_endpoint("http://10.0.0.1:8080/api/v1") == "/api/v1"


# ---------- is_valid_ipv4 ----------


class TestIsValidIpv4:
    def test_valid(self):
        assert is_valid_ipv4("10.0.0.1") is True
        assert is_valid_ipv4("192.168.1.255") is True
        assert is_valid_ipv4("0.0.0.0") is True

    def test_invalid(self):
        assert is_valid_ipv4("999.0.0.1") is False
        assert is_valid_ipv4("10.0.0") is False
        assert is_valid_ipv4("not-an-ip") is False
        assert is_valid_ipv4("") is False

    def test_ipv6_is_invalid(self):
        assert is_valid_ipv4("::1") is False


# ---------- check_tools ----------


class TestCheckTools:
    @pytest.mark.asyncio
    async def test_missing_tool_raises(self, monkeypatch):
        import shutil

        monkeypatch.setattr(shutil, "which", lambda _name: None)
        with pytest.raises(ToolMissing, match="nmap"):
            await check_tools(["nmap"])

    @pytest.mark.asyncio
    async def test_present_tool_passes(self, monkeypatch):
        import shutil

        monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/whatever")
        await check_tools(["nmap", "nuclei"])  # should not raise


# ---------- build_output_tree ----------


class TestBuildOutputTree:
    def test_creates_directories(self, tmp_path):
        tree = build_output_tree(tmp_path, "my_target")
        assert tree.base.is_dir()
        assert tree.live_host_dir.is_dir()
        assert tree.web_dir.is_dir()
        assert tree.reports_dir.is_dir()
        assert tree.ip_base.is_dir()

    def test_host_dirs(self, tmp_path):
        tree = build_output_tree(tmp_path, "scan1")
        hd = tree.host_dir("10.0.0.1")
        assert hd.is_dir()
        assert tree.host_nmap_xml_dir("10.0.0.1").is_dir()
        assert tree.host_web_dir("10.0.0.1").is_dir()
        assert tree.host_vuln_dir("10.0.0.1").is_dir()
