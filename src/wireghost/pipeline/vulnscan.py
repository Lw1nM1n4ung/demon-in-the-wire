"""Phase 4 -- Vulnerability scanning via nuclei and nmap --script=vuln."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from wireghost.models.finding import Finding
from wireghost.models.scan import Host
from wireghost.parsers.nmap import parse_nmap_vuln_xml
from wireghost.parsers.nuclei import parse_nuclei_json
from wireghost.utils.process import run_tool

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.utils.fs import OutputTree

log = logging.getLogger("wireghost")


async def run_nuclei(
    host: Host,
    config: ScanConfig,
    tree: OutputTree,
) -> list[Finding]:
    """Run nuclei against each web endpoint on *host*."""
    if not host.web_endpoints:
        return []

    vuln_dir = tree.host_vuln_dir(host.ip)
    targets_file = vuln_dir / "nuclei_targets.txt"
    targets_file.write_text(
        "\n".join(host.web_endpoints) + "\n", encoding="utf-8"
    )

    output_file = vuln_dir / "nuclei.json"

    result = await run_tool(
        [
            "nuclei",
            "-l", str(targets_file),
            "-jsonl",
            "-o", str(output_file),
            "-silent",
        ],
        timeout=int(config.tool_timeout),
        label=f"nuclei {host.ip}",
    )

    if result.returncode != 0:
        log.warning("Nuclei failed for %s (rc=%d)", host.ip, result.returncode)

    findings = parse_nuclei_json(output_file)
    log.info("Nuclei %s: %d finding(s)", host.ip, len(findings))
    return findings


async def run_nmap_vuln(
    host: Host,
    config: ScanConfig,
    tree: OutputTree,
) -> list[Finding]:
    """Run nmap --script=vuln against open ports on *host*."""
    open_ports = host.open_ports
    if not open_ports:
        return []

    vuln_dir = tree.host_vuln_dir(host.ip)
    out_base = str(vuln_dir / "nmap_vuln")
    xml_path = vuln_dir / "nmap_vuln.xml"

    port_csv = ",".join(str(p.number) for p in open_ports)

    result = await run_tool(
        [
            "nmap",
            "--script=vuln",
            "-p", port_csv,
            "-Pn",
            "-oX", str(xml_path),
            host.ip,
        ],
        timeout=int(config.tool_timeout),
        label=f"nmap vuln {host.ip}",
    )

    if result.returncode != 0:
        log.warning("Nmap vuln failed for %s (rc=%d)", host.ip, result.returncode)

    findings = parse_nmap_vuln_xml(xml_path)
    log.info("Nmap vuln %s: %d finding(s)", host.ip, len(findings))
    return findings


async def scan_host_vulns(
    host: Host,
    config: ScanConfig,
    tree: OutputTree,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """Run nuclei and nmap vuln scans concurrently for a single host.

    *sem* limits how many hosts are scanned in parallel.
    """
    async with sem:
        tasks: list[asyncio.Task[list[Finding]]] = []

        if not config.skip_nuclei:
            tasks.append(asyncio.create_task(run_nuclei(host, config, tree)))

        if not config.skip_vuln:
            tasks.append(asyncio.create_task(run_nmap_vuln(host, config, tree)))

        if not tasks:
            return []

        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[Finding] = []
        for result in results:
            if isinstance(result, BaseException):
                log.error("Vuln scan error for %s: %s", host.ip, result)
            else:
                findings.extend(result)

        log.info(
            "Vuln scan %s: %d total finding(s)",
            host.ip,
            len(findings),
        )
        return findings
