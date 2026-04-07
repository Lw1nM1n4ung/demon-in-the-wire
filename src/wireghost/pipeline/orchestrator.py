"""Pipeline orchestrator -- runs all scan phases in order."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime

from wireghost.config import ScanConfig
from wireghost.models.finding import Finding
from wireghost.models.report import ScanReport
from wireghost.models.scan import Host
from wireghost.pipeline.discovery import discover_hosts
from wireghost.pipeline.portscan import scan_host
from wireghost.pipeline.vulnscan import scan_host_vulns
from wireghost.pipeline.webdetect import probe_host
from wireghost.utils.fs import build_output_tree
from wireghost.utils.log import setup_logging
from wireghost.utils.process import check_tools

log = logging.getLogger("wireghost")


async def run_pipeline(config: ScanConfig) -> ScanReport:
    """Execute the full Wire_Ghost scanning pipeline.

    Phases:
        1. Tool verification
        2. Host discovery (nmap + fping)
        3. Port scanning (parallel per host)
        4. Web detection (parallel per host)
        5. Vulnerability scanning (parallel per host, nuclei + nmap concurrent)
        6. Report generation
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
    for tool in ("naabu", "masscan"):
        if shutil.which(tool):
            log.info("Optional scanner available: %s", tool)
        else:
            log.info("Optional scanner not found: %s (fallback skipped if needed)", tool)

    # --- Phase 2: Discovery ---
    log.info("Phase 2: Host discovery")
    live_ips = await discover_hosts(config, tree)

    if not live_ips:
        log.warning("No live hosts discovered -- nothing to scan")
        report = ScanReport(
            target=config.target,
            scan_start=scan_start,
            scan_end=datetime.now(),
        )
        return report

    # --- Phase 3: Port scanning ---
    log.info("Phase 3: Port scanning %d host(s)", len(live_ips))
    sem = asyncio.Semaphore(config.parallelism)
    host_tasks = [scan_host(ip, config, tree, sem) for ip in live_ips]
    hosts: list[Host] = await asyncio.gather(*host_tasks)

    # --- Phase 4: Web detection ---
    log.info("Phase 4: Web detection")
    web_tasks = [probe_host(h, config, tree, sem) for h in hosts]
    await asyncio.gather(*web_tasks)

    # --- Phase 5: Vulnerability scanning ---
    log.info("Phase 5: Vulnerability scanning")
    vuln_tasks = [scan_host_vulns(h, config, tree, sem) for h in hosts]
    all_findings_lists: list[list[Finding]] = await asyncio.gather(*vuln_tasks)

    all_findings: list[Finding] = []
    for findings in all_findings_lists:
        all_findings.extend(findings)

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

    # --- Phase 6: Report generation ---
    _generate_reports(config, report, tree)

    return report


def _generate_reports(config: ScanConfig, report: ScanReport, tree: object) -> None:
    """Try to generate reports; log a warning if the report engine is unavailable."""
    try:
        from wireghost.reports import ReportEngine  # type: ignore[attr-defined]

        engine = ReportEngine(config, tree)
        engine.generate(report)
    except (ImportError, AttributeError):
        log.warning(
            "Report engine not available -- skipping report generation. "
            "Install report renderers to enable this feature."
        )
