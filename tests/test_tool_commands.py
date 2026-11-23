"""Regression tests for external tool command flags."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from wireghost.models.scan import Host
from wireghost.pipeline import nikto_scan, portscan

IP = "10.0.0.1"


class _Tree:
    def __init__(self, directory):
        self.directory = directory

    def host_vuln_dir(self, ip):
        return self.directory

    def host_dir(self, ip):
        return self.directory


class _Config:
    tool_timeout = 3600
    port_range = "1-1000"


async def test_nikto_drops_explicit_timeout_flags(tmp_path):
    host = Host(ip=IP, web_endpoints=["http://10.0.0.1"])
    with (
        patch.object(nikto_scan.shutil, "which", return_value="/usr/bin/nikto"),
        patch.object(nikto_scan, "run_tool", new_callable=AsyncMock) as mock_run,
    ):
        mock_run.return_value = MagicMock(returncode=0)
        await nikto_scan.run_nikto(host, _Config(), _Tree(tmp_path))

    cmd = mock_run.call_args.args[0]
    assert "-timeout" not in cmd
    assert "-maxtime" not in cmd
    assert "-nointeractive" not in cmd


async def test_naabu_drops_rate_limit(tmp_path):
    with patch.object(portscan, "run_tool", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        await portscan._run_naabu(IP, _Config(), _Tree(tmp_path))

    cmd = mock_run.call_args.args[0]
    assert "-rate" not in cmd
