"""Phase 4 -- Vulnerability scanning via nuclei, nmap --script=vuln, and searchsploit."""

from __future__ import annotations

import asyncio
import logging
import shutil
from typing import TYPE_CHECKING

from wireghost.models.finding import Finding
from wireghost.models.scan import Host
from wireghost.parsers.nmap import parse_nmap_vuln_xml
from wireghost.parsers.nuclei import parse_nuclei_json
from wireghost.parsers.searchsploit import parse_searchsploit_json
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
            "-as",
            "-jsonl",
            "-o", str(output_file),
            "-rl", "150",
            "-c", "25",
            "-timeout", "10",
            "-stats",
            "-severity", "critical,high,medium,low",
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
            "--script=vuln,auth,default",
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


def _collect_versions(host: Host) -> list[tuple[str, str]]:
    """Collect search terms for searchsploit with associated port.

    Returns list of (search_term, port_number) tuples.
    Skips generic names like OS names.
    """
    terms: list[tuple[str, str]] = []
    seen: set[str] = set()

    _SKIP = {"linux", "ubuntu", "debian", "windows", "http", "https", "tcp", "udp"}

    # From nmap -sV (Service.product + Service.version → port)
    for port in host.open_ports:
        if port.service and port.service.product:
            name = port.service.product
            if name.lower() in _SKIP:
                continue
            port_str = str(port.number)
            if port.service.version:
                key = f"{name} {port.service.version}"
                if key not in seen:
                    seen.add(key)
                    terms.append((key, port_str))
            if name not in seen:
                seen.add(name)
                terms.append((name, port_str))

    # From httpx tech-detect (WebTech) — with version
    for tech in host.technologies:
        if tech.name and tech.name.lower() not in _SKIP and tech.version:
            key = f"{tech.name} {tech.version}"
            # Try to find port from URL
            port_str = ""
            if tech.url:
                import re
                m = re.search(r':(\d+)', tech.url)
                if m:
                    port_str = m.group(1)
            if key not in seen:
                seen.add(key)
                terms.append((key, port_str))

    return sorted(terms)


async def run_searchsploit(
    host: Host,
    config: ScanConfig,
    tree: OutputTree,
) -> list[Finding]:
    """Run searchsploit with version-aware searches."""
    if not shutil.which("searchsploit"):
        return []

    vuln_dir = tree.host_vuln_dir(host.ip)
    all_findings: list[Finding] = []
    seen_edb: set[str] = set()

    # Method 1: searchsploit --nmap (basic, uses nmap XML with -sV data)
    nmap_xml = tree.host_nmap_xml_dir(host.ip) / "portscan.xml"
    if nmap_xml.exists():
        result = await run_tool(
            ["searchsploit", "-v", "--nmap", str(nmap_xml), "-j"],
            timeout=int(config.tool_timeout),
            label=f"searchsploit:nmap {host.ip}",
        )
        output = result.stdout.strip()
        if output:
            json_out = vuln_dir / "searchsploit_nmap.json"
            json_out.write_text(output, encoding="utf-8")
            findings = parse_searchsploit_json(json_out, host_ip=host.ip)
            for f in findings:
                if f.template_id not in seen_edb:
                    seen_edb.add(f.template_id)
                    all_findings.append(f)

    # Method 2: Per-version searches (more targeted, with port mapping)
    import json as json_mod
    version_tuples = _collect_versions(host)
    combined_exploits: list[dict] = []
    # Track which port each exploit came from
    exploit_ports: dict[str, str] = {}  # EDB-ID → port

    for software, port_str in version_tuples:
        result = await run_tool(
            ["searchsploit", "-j", software],
            timeout=30,
            label=f"searchsploit:{software}",
        )
        output = result.stdout.strip()
        if not output:
            continue
        try:
            data = json_mod.loads(output)
            for entry in data.get("RESULTS_EXPLOIT", []):
                edb = str(entry.get("EDB-ID", ""))
                if edb and edb not in exploit_ports:
                    exploit_ports[edb] = port_str
                combined_exploits.append(entry)
        except (json_mod.JSONDecodeError, Exception):
            pass

    # Save ALL accumulated results as one JSON file
    if combined_exploits:
        combined = {"RESULTS_EXPLOIT": combined_exploits, "RESULTS_SHELLCODE": []}
        json_path = vuln_dir / "searchsploit_all.json"
        json_path.write_text(json_mod.dumps(combined), encoding="utf-8")
        findings = parse_searchsploit_json(json_path, host_ip=host.ip)
        # Set port on each finding based on which service matched
        for f in findings:
            edb = f.template_id.replace("EDB-", "")
            if edb in exploit_ports:
                f.port = exploit_ports[edb]
        for f in findings:
            if f.template_id not in seen_edb:
                seen_edb.add(f.template_id)
                all_findings.append(f)

    log.info("Searchsploit %s: %d exploit(s) from %d version(s)", host.ip, len(all_findings), len(versions))
    return all_findings


async def run_openvas(
    host: Host,
    config: ScanConfig,
    tree: OutputTree,
) -> list[Finding]:
    """Run OpenVAS scan via scannerctl (if enabled and available)."""
    if config.skip_openvas:
        return []

    from wireghost.pipeline.openvas_client import scan_host_scannerctl
    vuln_dir = tree.host_vuln_dir(host.ip)
    result_path = await scan_host_scannerctl(
        ip=host.ip,
        output_dir=vuln_dir,
        timeout=config.tool_timeout,
    )
    if result_path is None:
        return []

    # Try parsing as OpenVAS XML first, fall back to text parsing
    from wireghost.parsers.openvas import parse_openvas_xml
    xml_path = vuln_dir / f"openvas_report_{host.ip}.xml"
    if xml_path.exists():
        findings = parse_openvas_xml(xml_path, host.ip)
    else:
        findings = parse_openvas_xml(result_path, host.ip)

    log.info("OpenVAS %s: %d finding(s)", host.ip, len(findings))
    return findings


async def scan_host_vulns(
    host: Host,
    config: ScanConfig,
    tree: OutputTree,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """Run nuclei, nmap vuln, and searchsploit concurrently for a single host.

    *sem* limits how many hosts are scanned in parallel.
    """
    async with sem:
        tasks: list[asyncio.Task[list[Finding]]] = []

        if not config.skip_nuclei:
            tasks.append(asyncio.create_task(run_nuclei(host, config, tree)))

        if not config.skip_vuln:
            tasks.append(asyncio.create_task(run_nmap_vuln(host, config, tree)))

        # Searchsploit: auto-find exploits for detected services (if installed)
        tasks.append(asyncio.create_task(run_searchsploit(host, config, tree)))

        # OpenVAS: full vulnerability assessment (if enabled)
        if not config.skip_openvas:
            tasks.append(asyncio.create_task(run_openvas(host, config, tree)))

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
