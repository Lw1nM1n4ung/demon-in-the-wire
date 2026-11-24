"""Regression tests for scanner command construction.

These flags were wrong in a way that silently produced zero results rather
than failing loudly, so they are pinned here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from wireghost.models.scan import Host
from wireghost.pipeline import nikto_scan, web_crawl


class _Result:
    returncode = 0
    stdout = ""


class _Tree:
    def __init__(self, tmp: Path):
        self.tmp = tmp

    def host_vuln_dir(self, ip):
        d = self.tmp / ip / "vuln"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def host_web_dir(self, ip):
        d = self.tmp / ip / "web"
        d.mkdir(parents=True, exist_ok=True)
        return d


class _Config:
    tool_timeout = 30
    skip_web_crawl = False


@pytest.mark.asyncio
async def test_nikto_command_has_no_removed_no404_flag(tmp_path, monkeypatch):
    captured = {}

    async def fake_run_tool(cmd, **kwargs):
        captured["cmd"] = cmd
        return _Result()

    monkeypatch.setattr(nikto_scan, "run_tool", fake_run_tool)
    monkeypatch.setattr(nikto_scan.shutil, "which", lambda _: "/usr/local/bin/nikto")

    host = Host(ip="10.0.0.1", web_endpoints=["http://10.0.0.1:80"])
    await nikto_scan.run_nikto(host, _Config(), _Tree(tmp_path))

    cmd = captured["cmd"]
    assert "-no404" not in cmd, "nikto 2.6.1 removed -no404; it prints usage instead"
    assert cmd[cmd.index("-Format") + 1] == "json"


@pytest.mark.asyncio
async def test_katana_kf_flag_receives_a_value(tmp_path, monkeypatch):
    captured = {}

    async def fake_run_tool(cmd, **kwargs):
        captured["cmd"] = cmd
        return _Result()

    monkeypatch.setattr(web_crawl, "run_tool", fake_run_tool)
    monkeypatch.setattr(web_crawl.shutil, "which", lambda _: "/usr/local/bin/katana")

    host = Host(ip="10.0.0.1", web_endpoints=["http://10.0.0.1:80"])
    await web_crawl.crawl_host(host, _Config(), _Tree(tmp_path))

    cmd = captured["cmd"]
    assert "-kf" in cmd
    assert cmd[cmd.index("-kf") + 1] == "all", "katana -kf requires a value"


def test_katana_finding_dedupes_query_variants_and_sets_port():
    from wireghost.pipeline.web_crawl import _crawl_finding

    host = Host(ip="10.0.0.1")
    urls = {
        "http://10.0.0.1:8080/app.js",
        "http://10.0.0.1:8080/app.js?v=1790057310715",
        "http://10.0.0.1:8080/admin",
    }
    finding = _crawl_finding(host, "http://10.0.0.1:8080/", urls)
    assert finding is not None
    # query-string duplicate collapsed, so 2 not 3
    assert "2 endpoint(s)" in finding.title
    assert finding.description.count("\n") == 1
    assert finding.port == "8080"


def test_katana_finding_caps_reported_urls():
    from wireghost.pipeline.web_crawl import _MAX_REPORTED_URLS, _crawl_finding

    host = Host(ip="10.0.0.1")
    urls = {f"http://10.0.0.1:8080/p{i}" for i in range(_MAX_REPORTED_URLS + 10)}
    finding = _crawl_finding(host, "http://10.0.0.1:8080/", urls)
    lines = finding.description.splitlines()
    assert len(lines) == _MAX_REPORTED_URLS + 1
    assert "and 10 more" in lines[-1]
    assert f"{_MAX_REPORTED_URLS + 10} endpoint(s)" in finding.title
