"""Phase 2 -- Port scanning with fallback chain: nmap -> naabu -> masscan."""
from __future__ import annotations
import asyncio
import logging
import shutil
from typing import TYPE_CHECKING

from wireghost.models.scan import Host
from wireghost.parsers.nmap import parse_nmap_xml
from wireghost.parsers.naabu import parse_naabu_json
from wireghost.parsers.masscan import parse_masscan_xml
from wireghost.utils.process import run_tool

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.utils.fs import OutputTree

log = logging.getLogger("wireghost")


def _is_tool_available(name: str) -> bool:
    return shutil.which(name) is not None


async def _run_nmap(ip: str, config: ScanConfig, tree: OutputTree) -> Host:
    nmap_dir = tree.host_nmap_xml_dir(ip)
    out_base = str(nmap_dir / "portscan")
    xml_path = nmap_dir / "portscan.xml"
    result = await run_tool(
        ["nmap", "--open", "-p-", "-sV", "-sC", "-O", "-Pn", "-oA", out_base, ip],
        timeout=int(config.nmap_timeout or config.tool_timeout),
        label=f"nmap:{ip}",
    )
    if result.returncode != 0:
        return Host(ip=ip)
    hosts = parse_nmap_xml(xml_path)
    return hosts[0] if hosts else Host(ip=ip)


async def _run_naabu(ip: str, config: ScanConfig, tree: OutputTree) -> Host:
    out_dir = tree.host_dir(ip)
    json_path = out_dir / "naabu_scan.json"
    result = await run_tool(
        ["naabu", "-host", ip, "-json", "-o", str(json_path), "-Pn", "-rate", "1000"],
        timeout=int(config.tool_timeout),
        label=f"naabu:{ip}",
    )
    if result.returncode != 0:
        return Host(ip=ip)
    hosts = parse_naabu_json(json_path)
    return hosts[0] if hosts else Host(ip=ip)


async def _run_masscan(ip: str, config: ScanConfig, tree: OutputTree) -> Host:
    out_dir = tree.host_dir(ip)
    xml_path = out_dir / "masscan_scan.xml"
    result = await run_tool(
        ["masscan", ip, "-p0-65535", "--rate", "5000", "--banners", "-oX", str(xml_path)],
        timeout=int(config.tool_timeout),
        label=f"masscan:{ip}",
    )
    if result.returncode != 0:
        return Host(ip=ip)
    hosts = parse_masscan_xml(xml_path)
    return hosts[0] if hosts else Host(ip=ip)


_SCANNERS: list[tuple[str, str, str]] = [
    ("nmap", "_run_nmap", "nmap"),
    ("naabu", "_run_naabu", "naabu"),
    ("masscan", "_run_masscan", "masscan"),
]


async def scan_host(
    ip: str,
    config: ScanConfig,
    tree: OutputTree,
    sem: asyncio.Semaphore,
) -> Host:
    """Scan a host with fallback chain: nmap -> naabu -> masscan.

    Tries each scanner in order. Returns as soon as one finds open ports.
    Scanners not installed are silently skipped (except nmap which is required).
    """
    import wireghost.pipeline.portscan as _mod

    async with sem:
        for name, fn_name, tool_bin in _SCANNERS:
            if name != "nmap" and not _is_tool_available(tool_bin):
                log.debug("Skipping %s for %s (not installed)", name, ip)
                continue

            log.info("Trying %s for %s", name, ip)
            scanner_fn = getattr(_mod, fn_name)
            host = await scanner_fn(ip, config, tree)

            if host.open_ports:
                log.info("%s found %d open port(s) on %s", name, len(host.open_ports), ip)
                return host

            log.info("%s found no open ports on %s, trying next scanner", name, ip)

        log.warning("All scanners found no open ports on %s", ip)
        return Host(ip=ip, status="up")
