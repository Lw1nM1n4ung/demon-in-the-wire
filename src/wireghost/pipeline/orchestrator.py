"""Pipeline orchestrator -- runs all scan phases in order."""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from datetime import datetime
from typing import Callable

from wireghost.config import ScanConfig
from wireghost.models.finding import Finding
from wireghost.models.report import ScanReport
from wireghost.models.scan import Host
from wireghost.pipeline.cms_scan import scan_cms
from wireghost.pipeline.discovery import discover_hosts
from wireghost.pipeline.ldap_enum import enumerate_ldap
from wireghost.pipeline.msf_scan import scan_msf
from wireghost.pipeline.nfs_enum import enumerate_nfs
from wireghost.pipeline.portscan import scan_host
from wireghost.pipeline.service_enum import enumerate_services
from wireghost.pipeline.netexec_enum import enumerate_netexec
from wireghost.pipeline.smb_enum import enumerate_smb
from wireghost.pipeline.snmp_enum import enumerate_snmp
from wireghost.pipeline.tls_audit import audit_tls
from wireghost.pipeline.vulnscan import scan_host_vulns
from wireghost.pipeline.web_crawl import crawl_host
from wireghost.pipeline.webdetect import probe_host
from wireghost.pipeline.webscreenshot import screenshot_host
from wireghost.utils.fs import build_output_tree
from wireghost.utils.log import setup_logging
from wireghost.utils.process import check_tools

log = logging.getLogger("wireghost")

# Ordered list of pipeline phases.  The overall "current phase" is the
# earliest phase where at least one host is still working.
PHASE_ORDER = [
    "discovery",
    "portscan",
    "webdetect",
    "webcrawl",
    "enumeration",
    "reports",
]


def _dedup_findings(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings across tools based on host:port:vuln identity."""
    seen: set[str] = set()
    deduped: list[Finding] = []
    for f in findings:
        if f.cve:
            key = f"{f.host}:{f.port}:{f.cve}"
        else:
            title_norm = f.title.lower()
            for prefix in ("nmap: ", "msf ", "nxc: "):
                title_norm = title_norm.removeprefix(prefix)
            key = f"{f.host}:{f.port}:{title_norm[:60]}"
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


async def run_pipeline(
    config: ScanConfig,
    on_progress: Callable[[str, int, int], None] | None = None,
    on_discovery_complete: Callable[[list[str], dict[str, tuple[str, str]]], None] | None = None,
    on_host_complete: Callable[[Host, list[Finding]], None] | None = None,
) -> ScanReport:
    """Execute the full Wire_Ghost scanning pipeline.

    If *on_progress* is provided it is called at phase boundaries as
    ``on_progress(phase, done, total)`` where *phase* is one of the
    keys in :data:`PHASE_ORDER` (``discovery`` → ``portscan`` →
    ``webdetect`` → ``webcrawl`` → ``enumeration`` → ``reports`` →
    ``completed``).

    If *on_discovery_complete* is provided it is called right after
    host discovery with the list of live IPs and the MAC/vendor map.

    If *on_host_complete* is provided it is called after each host
    finishes its full pipeline with the populated Host and its Findings.
    """
    scan_start = datetime.now()

    # Set up logging and output tree
    setup_logging(output_dir=str(config.output_dir), verbose=config.verbose)
    target_name = config.target.replace("/", "_").replace(":", "_")
    tree = build_output_tree(config.output_dir, target_name)

    log.info("Starting Wire_Ghost scan against %s", config.target)

    # --- Phase 1: Tool check ---
    required_tools = ["nmap", "fping"]
    if not config.skip_nuclei:
        required_tools.append("nuclei")
    await check_tools(required_tools)
    log.info("All required tools found")

    # Log availability of optional fallback scanners
    import shutil
    for tool in ("naabu", "masscan", "sslscan", "showmount", "snmpget", "snmpwalk", "katana", "ldapsearch", "msfconsole"):
        if shutil.which(tool):
            log.info("Optional scanner available: %s", tool)
        else:
            log.info("Optional scanner not found: %s (fallback skipped if needed)", tool)

    # --- Phase 2: Discovery ---
    log.info("Phase 2: Host discovery")
    if on_progress:
        on_progress("discovery", 0, 0)
    live_ips, mac_vendor_map = await discover_hosts(config, tree, on_progress=on_progress)

    if on_discovery_complete:
        on_discovery_complete(live_ips, mac_vendor_map)

    if not live_ips:
        log.warning("No live hosts discovered -- nothing to scan")
        report = ScanReport(
            target=config.target,
            scan_start=scan_start,
            scan_end=datetime.now(),
        )
        return report

    # --- Per-host phase tracking ---
    total_hosts = len(live_ips)
    _phase_counts: dict[str, int] = defaultdict(int)
    _phase_lock = asyncio.Lock()

    def _get_current_phase() -> str:
        for ph in PHASE_ORDER:
            if _phase_counts[ph] < total_hosts:
                return ph
        return "completed"

    async def _advance_phase(phase: str) -> None:
        """Mark one host as having completed *phase*; update progress."""
        async with _phase_lock:
            _phase_counts[phase] += 1
            current = _get_current_phase()
            if on_progress:
                on_progress(current, _phase_counts[current], total_hosts)

    # --- Per-host pipeline (1 host = 1 full pipeline, all in parallel) ---
    log.info(
        "Launching per-host pipelines: %d host(s), parallelism=%d",
        total_hosts, config.parallelism,
    )
    if on_progress:
        on_progress("portscan", 0, total_hosts)
    sem = asyncio.Semaphore(config.parallelism)

    async def _host_pipeline(ip: str) -> tuple[Host, list[Finding]]:
        """Run the full scan pipeline for a single host."""
        # Phase 3a: Port scan (with fallback chain) + service detection
        host = await scan_host(ip, config, tree, sem)
        await _advance_phase("portscan")

        # Enrich with ARP data from discovery phase
        mac, vendor = mac_vendor_map.get(ip, ("", ""))
        if mac:
            host.mac_address = mac
        if vendor:
            host.vendor = vendor

        if not host.open_ports:
            log.info("[%s] No open ports — skipping web/vuln phases", ip)
            # Mark all remaining phases done for this host
            for ph in ("webdetect", "webcrawl", "enumeration"):
                await _advance_phase(ph)
            snmp_findings = await enumerate_snmp(host, config, tree, sem)
            return host, snmp_findings

        # Phase 3b: Web detection
        await probe_host(host, config, tree, sem)
        await _advance_phase("webdetect")

        # Phase 3c: Web crawl (sequential — nuclei needs the URLs)
        crawl_findings = await crawl_host(host, config, tree, sem)
        await _advance_phase("webcrawl")

        # Phases 3d: All enumeration + vuln scan + screenshot + MSF in parallel
        svc_task = (
            enumerate_services(host, config, tree, sem)
            if config.service_enum
            else asyncio.sleep(0, result=[])
        )
        results = await asyncio.gather(
            scan_cms(host, config, tree, sem),
            svc_task,
            enumerate_smb(host, config, tree, sem),
            enumerate_netexec(host, config, tree, sem),
            audit_tls(host, config, tree, sem),
            enumerate_snmp(host, config, tree, sem),
            enumerate_nfs(host, config, tree, sem),
            enumerate_ldap(host, config, tree, sem),
            scan_host_vulns(host, config, tree, sem),
            screenshot_host(host, config, tree, sem),
            scan_msf(host, config, tree, sem),
            return_exceptions=True,
        )
        await _advance_phase("enumeration")

        task_names = [
            "cms", "service_enum", "smb", "netexec", "tls",
            "snmp", "nfs", "ldap", "vulnscan", "screenshot", "msf",
        ]
        findings: list[Finding] = list(crawl_findings)
        for name, result in zip(task_names, results):
            if isinstance(result, Exception):
                log.error("[%s] %s scanner failed", ip, name, exc_info=result)
                continue
            if isinstance(result, list):
                findings.extend(result)

        findings = _dedup_findings(findings)

        log.info(
            "[%s] Pipeline done: %d port(s), %d endpoint(s), %d finding(s)",
            ip, len(host.open_ports), len(host.web_endpoints), len(findings),
        )
        return host, findings

    results = await asyncio.gather(
        *[_host_pipeline(ip) for ip in live_ips],
        return_exceptions=True,
    )

    hosts: list[Host] = []
    all_findings: list[Finding] = []
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            log.error("Host pipeline failed for %s", live_ips[i], exc_info=r)
            continue
        host, findings = r
        hosts.append(host)
        all_findings.extend(findings)
        if on_host_complete:
            on_host_complete(host, findings)

    scan_end = datetime.now()
    report = ScanReport(
        target=config.target,
        hosts=hosts,
        findings=all_findings,
        scan_start=scan_start,
        scan_end=scan_end,
    )

    log.info(
        "Scan complete: %d host(s), %d open port(s), %d finding(s)",
        len(report.hosts),
        report.total_open_ports,
        len(report.findings),
    )

    # --- Phase 4: Report generation ---
    if on_progress:
        on_progress("reports", 0, 0)
    _generate_reports(config, report, tree)

    return report


def _generate_reports(config: ScanConfig, report: ScanReport, tree: object) -> None:
    """Try to generate reports; log a warning if the report engine is unavailable."""
    try:
        from wireghost.reports import ReportEngine  # type: ignore[attr-defined]
    except ImportError:
        log.warning(
            "Report engine not available -- skipping report generation. "
            "Install report renderers to enable this feature."
        )
        return

    engine = ReportEngine(config, tree)
    engine.generate(report)
