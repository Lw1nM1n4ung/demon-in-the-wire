"""Tests for port scanner fallback chain."""
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock
import pytest
from wireghost.models.scan import Host, Port
from wireghost.pipeline.portscan import scan_host


@pytest.fixture
def mock_config():
    cfg = MagicMock()
    cfg.tool_timeout = 300
    return cfg


@pytest.fixture
def mock_tree(tmp_path):
    tree = MagicMock()
    nmap_dir = tmp_path / "nmap" / "xml"
    nmap_dir.mkdir(parents=True)
    tree.host_nmap_xml_dir.return_value = nmap_dir
    tree.host_dir.return_value = tmp_path
    return tree


@pytest.fixture
def sem():
    return asyncio.Semaphore(5)


class TestFallbackChain:
    @pytest.mark.asyncio
    async def test_nmap_finds_ports_no_fallback(self, mock_config, mock_tree, sem):
        nmap_host = Host(ip="10.0.0.1", ports=[Port(number=80, state="open")])
        with (
            patch("wireghost.pipeline.portscan._run_nmap", new_callable=AsyncMock, return_value=nmap_host) as m_nmap,
            patch("wireghost.pipeline.portscan._run_naabu", new_callable=AsyncMock) as m_naabu,
            patch("wireghost.pipeline.portscan._run_masscan", new_callable=AsyncMock) as m_masscan,
        ):
            result = await scan_host("10.0.0.1", mock_config, mock_tree, sem)
            assert len(result.open_ports) == 1
            m_nmap.assert_awaited_once()
            m_naabu.assert_not_awaited()
            m_masscan.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_nmap_empty_falls_to_naabu(self, mock_config, mock_tree, sem):
        empty = Host(ip="10.0.0.1")
        naabu_host = Host(ip="10.0.0.1", ports=[Port(number=22, state="open")])
        with (
            patch("wireghost.pipeline.portscan._run_nmap", new_callable=AsyncMock, return_value=empty),
            patch("wireghost.pipeline.portscan._run_naabu", new_callable=AsyncMock, return_value=naabu_host) as m_naabu,
            patch("wireghost.pipeline.portscan._run_masscan", new_callable=AsyncMock) as m_masscan,
            patch("wireghost.pipeline.portscan._is_tool_available", return_value=True),
            patch("wireghost.pipeline.portscan._analyze_services", new_callable=AsyncMock, side_effect=lambda h, *a, **kw: h),
        ):
            result = await scan_host("10.0.0.1", mock_config, mock_tree, sem)
            assert len(result.open_ports) == 1
            assert result.open_ports[0].number == 22
            m_naabu.assert_awaited_once()
            m_masscan.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_nmap_naabu_empty_falls_to_masscan(self, mock_config, mock_tree, sem):
        empty = Host(ip="10.0.0.1")
        masscan_host = Host(ip="10.0.0.1", ports=[Port(number=443, state="open")])
        with (
            patch("wireghost.pipeline.portscan._run_nmap", new_callable=AsyncMock, return_value=empty),
            patch("wireghost.pipeline.portscan._run_naabu", new_callable=AsyncMock, return_value=empty),
            patch("wireghost.pipeline.portscan._run_masscan", new_callable=AsyncMock, return_value=masscan_host),
            patch("wireghost.pipeline.portscan._is_tool_available", return_value=True),
            patch("wireghost.pipeline.portscan._analyze_services", new_callable=AsyncMock, side_effect=lambda h, *a, **kw: h),
        ):
            result = await scan_host("10.0.0.1", mock_config, mock_tree, sem)
            assert len(result.open_ports) == 1
            assert result.open_ports[0].number == 443

    @pytest.mark.asyncio
    async def test_all_scanners_empty(self, mock_config, mock_tree, sem):
        empty = Host(ip="10.0.0.1")
        with (
            patch("wireghost.pipeline.portscan._run_nmap", new_callable=AsyncMock, return_value=empty),
            patch("wireghost.pipeline.portscan._run_naabu", new_callable=AsyncMock, return_value=empty),
            patch("wireghost.pipeline.portscan._run_masscan", new_callable=AsyncMock, return_value=empty),
            patch("wireghost.pipeline.portscan._is_tool_available", return_value=True),
        ):
            result = await scan_host("10.0.0.1", mock_config, mock_tree, sem)
            assert len(result.open_ports) == 0

    @pytest.mark.asyncio
    async def test_skip_unavailable_tools(self, mock_config, mock_tree, sem):
        empty = Host(ip="10.0.0.1")
        with (
            patch("wireghost.pipeline.portscan._run_nmap", new_callable=AsyncMock, return_value=empty),
            patch("wireghost.pipeline.portscan._run_naabu", new_callable=AsyncMock) as m_naabu,
            patch("wireghost.pipeline.portscan._run_masscan", new_callable=AsyncMock) as m_masscan,
            patch("wireghost.pipeline.portscan._is_tool_available", return_value=False),
        ):
            result = await scan_host("10.0.0.1", mock_config, mock_tree, sem)
            m_naabu.assert_not_awaited()
            m_masscan.assert_not_awaited()
