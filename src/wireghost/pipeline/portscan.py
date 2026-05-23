"""Phase 3 -- Port discovery (nmap → naabu → masscan) + targeted service analysis.

Port discovery only finds which ports are open — fast SYN scan, no service
probing.  Once ports are known, service analysis runs ``nmap -sV -sC -O``
targeted at only the discovered ports, which completes in seconds instead
of the 30-90 minutes a full -sV on 65535 ports would take.

Service detection is then augmented by **fingerprintx** (Praetorian) as a
second source of truth.  fingerprintx sends protocol-specific probes and
matches responses against signatures, identifying services regardless of
port number.  It fills in ports where nmap -sV was uncertain — nmap's
identifications are trusted when present; fingerprintx augments, never
overrides.  This means every downstream phase (service_enum, MSF module
selection, vulnscan targeting, web detection) benefits from corrected
service names.

Splitting the two steps means the fallback chain is symmetric (all three
tools just find ports) and service analysis always happens regardless of
which tool won the chain.
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tempfile
from pathlib import Path
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
    """Port discovery only — fast SYN scan, no service/OS/script overhead."""
    nmap_dir = tree.host_nmap_xml_dir(ip)
    out_base = str(nmap_dir / "portscan")
    xml_path = nmap_dir / "portscan.xml"
    cmd = ["nmap", "--open", "-p-", "-Pn", "-oA", out_base, ip]
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
        ["masscan", ip, "-p0-65535", "--banners", "-oX", str(xml_path)],
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


async def _analyze_services(
    host: Host, config: ScanConfig, tree: OutputTree,
) -> Host:
    """Run targeted ``nmap -sV -sC -O`` on discovered open ports.

    Always called after port discovery regardless of which tool found the
    ports.  Scans only the known-open ports, so service identification
    completes in seconds instead of the 30-90 minutes a full -sV on all
    65535 ports would take.
    """
    if not host.open_ports:
        return host

    port_csv = ",".join(str(p.number) for p in host.open_ports)
    log.info(
        "[%s] Service analysis on %d port(s): %s",
        host.ip, len(host.open_ports), port_csv,
    )

    nmap_dir = tree.host_nmap_xml_dir(host.ip)
    xml_path = nmap_dir / "service_analysis.xml"

    cmd = ["nmap", "-sV", "-sC", "-Pn", "-p", port_csv]
    if config.os_detect:
        cmd.append("-O")
    cmd.extend(["-oX", str(xml_path), host.ip])

    result = await run_tool(
        cmd,
        timeout=min(300, int(config.nmap_timeout or config.tool_timeout)),
        label=f"nmap-svc:{host.ip}",
    )

    if result.returncode != 0:
        log.warning("[%s] Service analysis failed (rc=%d)", host.ip, result.returncode)
        return host

    analyzed_hosts = parse_nmap_xml(xml_path)
    if not analyzed_hosts:
        return host

    analyzed = analyzed_hosts[0]
    svc_map: dict[int, Service] = {}
    for p in analyzed.ports:
        if p.service and p.service.name:
            svc_map[p.number] = p.service

    for p in host.ports:
        if p.number in svc_map:
            p.service = svc_map[p.number]
            p.service_source = 'nmap'

    if analyzed.os:
        host.os = analyzed.os

    svc_count = sum(1 for p in host.open_ports if p.service is not None)
    log.info(
        "[%s] Service analysis: %d/%d port(s) identified",
        host.ip, svc_count, len(host.open_ports),
    )
    return host


async def _run_fingerprintx(
    host_ip: str,
    ports: list[Port],
    timeout: int,
) -> dict[int, dict[str, str]]:
    """Run fingerprintx against all open *ports* on *host_ip*.

    fingerprintx sends protocol-specific probes and matches responses against
    signature fingerprints. It identifies services regardless of port number,
    making it a reliable second source of truth alongside nmap -sV.

    Returns ``{port_number: {protocol, transport, version}}``, or an empty
    dict when the tool is not installed, produces no output, or exits non-zero.
    """
    if not shutil.which("fingerprintx"):
        return {}
    if not ports:
        return {}

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", prefix="fpx_", delete=False,
    ) as fh:
        for port in ports:
            fh.write(f"{host_ip}:{port.number}\n")
        targets_path = fh.name

    try:
        result = await run_tool(
            ["fingerprintx", "-l", targets_path, "--json"],
            timeout=timeout,
            label=f"fingerprintx {host_ip}",
        )
        if result.returncode != 0:
            log.debug(
                "[%s] fingerprintx exited rc=%d: %s",
                host_ip, result.returncode, (result.stderr or "")[:200],
            )
            return {}

        output = result.stdout.strip()
        if not output:
            return {}

        parsed: dict[int, dict[str, str]] = {}
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            port_num = int(data.get("port", 0))
            if port_num:
                parsed[port_num] = {
                    "protocol": data.get("protocol", "").lower(),
                    "transport": data.get("transport", ""),
                    "version": data.get("version", ""),
                }
        return parsed
    finally:
        Path(targets_path).unlink(missing_ok=True)


def _merge_fpx_results(
    host: Host, fpx_results: dict[int, dict[str, str]],
) -> int:
    """Merge fingerprintx results into ``Port.service`` where nmap was uncertain.

    Only fills in ports where nmap -sV did NOT produce a service name.
    nmap's identifications are trusted when present — fingerprintx augments,
    never overrides.

    Returns the number of ports augmented.
    """
    augmented = 0
    for port in host.open_ports:
        fpx = fpx_results.get(port.number)
        if not fpx:
            continue
        proto = fpx["protocol"]
        if not proto:
            continue
        # Trust nmap when it identified something
        if port.service and port.service.name:
            continue
        fpx_version = fpx.get("version", "")
        fpx_product = ""
        # Extract product from combined version string (e.g. "Apache/2.4.7")
        if fpx_version:
            for sep in ("/", " "):
                if sep in fpx_version:
                    parts = fpx_version.split(sep, 1)
                    fpx_product = parts[0].strip()
                    fpx_version = parts[1].strip() if len(parts) > 1 else ""
                    break
        port.service = Service(
            name=proto,
            product=fpx_product,
            version=fpx_version,
        )
        port.service_source = 'fingerprintx'
        augmented += 1
        log.debug(
            "[%s] fingerprintx augmented port %d: %s",
            host.ip, port.number, proto,
        )
    return augmented


async def scan_host(
    ip: str,
    config: ScanConfig,
    tree: OutputTree,
    sem: asyncio.Semaphore,
) -> Host:
    """Port discovery (nmap → naabu → masscan) + targeted service analysis.

    Phase 3a: Find open ports. Tries each scanner in order, returns as
    soon as one finds ports. All three tools only discover ports — no
    service/OS/script overhead.

    Phase 3b: Run ``nmap -sV -sC -O`` targeted at only the discovered
    ports. Completes in seconds since it only probes known-open ports.
    Always runs regardless of which tool found the ports.
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
                host = await _analyze_services(host, config, tree)

                # fingerprintx: second source of truth for service detection.
                # Augments ports where nmap -sV was uncertain — runs on all
                # open ports so downstream phases (service_enum, MSF, vulnscan,
                # web detection) all benefit from corrected service names.
                if (
                    not config.skip_fingerprintx
                    and shutil.which("fingerprintx")
                    and host.open_ports
                ):
                    fpx_timeout = min(30, int(config.tool_timeout))
                    fpx_results = await _run_fingerprintx(
                        host.ip, host.open_ports, fpx_timeout,
                    )
                    if fpx_results:
                        augmented = _merge_fpx_results(host, fpx_results)
                        if augmented:
                            log.info(
                                "[%s] fingerprintx augmented %d port(s) "
                                "nmap could not identify",
                                host.ip, augmented,
                            )

                return host

            log.info("%s found no open ports on %s, trying next scanner", name, ip)

        log.warning("All scanners found no open ports on %s", ip)
        return Host(ip=ip, status="up")
