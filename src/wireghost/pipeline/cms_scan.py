"""CMS-specific scanning -- auto-triggered by technology detection."""
from __future__ import annotations

import asyncio
import logging
import shutil
from pathlib import Path
from typing import TYPE_CHECKING

from wireghost.models.finding import Finding
from wireghost.parsers.wpscan import parse_wpscan_json
from wireghost.utils.process import run_tool

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.models.scan import Host
    from wireghost.utils.fs import OutputTree

log = logging.getLogger("wireghost")


async def _run_wpscan(url: str, host_ip: str, config: ScanConfig, tree: OutputTree) -> list[Finding]:
    """Run WPScan against a WordPress URL."""
    vuln_dir = tree.host_vuln_dir(host_ip)
    json_out = vuln_dir / "wpscan.json"

    result = await run_tool(
        [
            "wpscan", "--url", url,
            "--enumerate", "ap,at,u",
            "--plugins-detection", "mixed",
            "--format", "json",
            "--no-banner",
            "-o", str(json_out),
        ],
        timeout=int(config.tool_timeout),
        label=f"wpscan {host_ip}",
    )

    if not json_out.exists():
        # WPScan might output to stdout instead
        if result.stdout and result.stdout.strip().startswith("{"):
            json_out.write_text(result.stdout, encoding="utf-8")

    findings = parse_wpscan_json(json_out, host_ip=host_ip)
    log.info("WPScan %s: %d finding(s)", host_ip, len(findings))
    return findings


async def scan_cms(
    host: Host, config: ScanConfig, tree: OutputTree, sem: asyncio.Semaphore,
) -> list[Finding]:
    """Run CMS-specific scanners based on detected technologies.

    Currently supports: WordPress (via WPScan).
    Future: JoomScan for Joomla, droopescan for Drupal.
    """
    async with sem:
        findings: list[Finding] = []

        # Check for WordPress in detected technologies
        wp_urls: list[str] = []
        for tech in host.technologies:
            if tech.name.lower() in ("wordpress", "wp", "wordpress.org"):
                if tech.url and tech.url not in wp_urls:
                    wp_urls.append(tech.url)

        # Also check web endpoints for /wp-login.php or /wp-admin patterns
        for ep in host.web_endpoints:
            if any(wp in ep.lower() for wp in ("/wp-", "wordpress")):
                base = ep.split("/wp-")[0] if "/wp-" in ep else ep
                if base not in wp_urls:
                    wp_urls.append(base)

        if wp_urls and shutil.which("wpscan"):
            for url in wp_urls:
                log.info("WordPress detected at %s -- running WPScan", url)
                findings.extend(await _run_wpscan(url, host.ip, config, tree))
        elif wp_urls:
            log.info("WordPress detected but wpscan not installed -- skipping CMS scan")

        return findings
