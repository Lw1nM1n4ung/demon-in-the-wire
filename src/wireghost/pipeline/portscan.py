"""Phase 2 -- Full port scan per host via nmap."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from wireghost.models.scan import Host
from wireghost.parsers.nmap import parse_nmap_xml
from wireghost.utils.process import run_tool

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.utils.fs import OutputTree

log = logging.getLogger("wireghost")


async def scan_host(
    ip: str,
    config: ScanConfig,
    tree: OutputTree,
    sem: asyncio.Semaphore,
) -> Host:
    """Run a full TCP port scan on *ip* and return a populated Host.

    The semaphore *sem* limits concurrency across parallel invocations.
    """
    async with sem:
        nmap_dir = tree.host_nmap_xml_dir(ip)
        out_base = str(nmap_dir / "portscan")
        xml_path = nmap_dir / "portscan.xml"

        result = await run_tool(
            [
                "nmap",
                "--open",
                "-p-",
                "-Pn",
                "-oA",
                out_base,
                ip,
            ],
            timeout=int(config.tool_timeout),
            label=f"nmap port scan {ip}",
        )

        if result.returncode != 0:
            log.warning("Port scan failed for %s (rc=%d)", ip, result.returncode)
            return Host(ip=ip, status="up")

        hosts = parse_nmap_xml(xml_path)
        if hosts:
            host = hosts[0]
            log.info(
                "Port scan %s: %d open port(s)",
                ip,
                len(host.open_ports),
            )
            return host

        log.info("Port scan %s: no results parsed", ip)
        return Host(ip=ip, status="up")
