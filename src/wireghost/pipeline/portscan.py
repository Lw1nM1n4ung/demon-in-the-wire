"""Phase 2 -- Port scanning with fallback chain: nmap -> naabu -> masscan."""
from __future__ import annotations
import asyncio
import logging
import shutil
from typing import TYPE_CHECKING

from wireghost.models.scan import Host, Service
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
    cmd = ["nmap", "--open", "-p-", "-sC"]
    if config.version_detect:
        cmd.append("-sV")
    if config.os_detect:
        cmd.append("-O")
    cmd.extend(["-Pn", "-oA", out_base, ip])
    result = await run_tool(
        cmd,
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


async def _enrich_services(
    host: Host, config: ScanConfig, tree: OutputTree,
) -> Host:
    """Run targeted nmap -sV on ports found by naabu/masscan to identify services.

    Only called when a non-nmap scanner found ports (Port.service is None).
    Scans only the known-open ports, so it completes in seconds.
    """
    ports_without_service = [p for p in host.open_ports if p.service is None]
    if not ports_without_service:
        return host

    port_csv = ",".join(str(p.number) for p in ports_without_service)
    log.info(
        "[%s] Enriching %d port(s) with nmap -sV: %s",
        host.ip, len(ports_without_service), port_csv,
    )

    nmap_dir = tree.host_nmap_xml_dir(host.ip)
    xml_path = nmap_dir / "service_enrich.xml"

    cmd = ["nmap", "-sV", "-sC", "-Pn", "-p", port_csv]
    if config.os_detect:
        cmd.append("-O")
    cmd.extend(["-oX", str(xml_path), host.ip])

    result = await run_tool(
        cmd,
        timeout=min(300, int(config.nmap_timeout or config.tool_timeout)),
        label=f"nmap-enrich:{host.ip}",
    )

    if result.returncode != 0:
        log.warning("[%s] nmap enrichment failed (rc=%d) — using port heuristics", host.ip, result.returncode)
        return host

    enriched_hosts = parse_nmap_xml(xml_path)
    if not enriched_hosts:
        return host

    enriched = enriched_hosts[0]
    svc_map: dict[int, Service] = {}
    for p in enriched.ports:
        if p.service and p.service.name:
            svc_map[p.number] = p.service

    for p in host.ports:
        if p.service is None and p.number in svc_map:
            p.service = svc_map[p.number]

    if not host.os and enriched.os:
        host.os = enriched.os

    enriched_count = sum(1 for p in host.open_ports if p.service is not None)
    log.info(
        "[%s] Service enrichment: %d/%d port(s) now have service info",
        host.ip, enriched_count, len(host.open_ports),
    )
    return host


async def scan_host(
    ip: str,
    config: ScanConfig,
    tree: OutputTree,
    sem: asyncio.Semaphore,
) -> Host:
    """Scan a host with fallback chain: nmap -> naabu -> masscan.

    Tries each scanner in order. Returns as soon as one finds open ports.
    When a non-nmap scanner finds ports, runs targeted nmap -sV to
    identify services on the discovered ports.
    """
    import wireghost.pipeline.portscan as _mod

    async with sem:
        scanner_used = ""
        for name, fn_name, tool_bin in _SCANNERS:
            if name != "nmap" and not _is_tool_available(tool_bin):
                log.debug("Skipping %s for %s (not installed)", name, ip)
                continue

            log.info("Trying %s for %s", name, ip)
            scanner_fn = getattr(_mod, fn_name)
            host = await scanner_fn(ip, config, tree)

            if host.open_ports:
                log.info("%s found %d open port(s) on %s", name, len(host.open_ports), ip)
                scanner_used = name
                break

            log.info("%s found no open ports on %s, trying next scanner", name, ip)
        else:
            log.warning("All scanners found no open ports on %s", ip)
            return Host(ip=ip, status="up")

        if scanner_used != "nmap" and host.open_ports:
            host = await _enrich_services(host, config, tree)

        return host
