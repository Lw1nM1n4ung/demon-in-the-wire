"""TLS/SSL audit via sslscan — cipher, cert, and protocol weakness detection."""

from __future__ import annotations

import asyncio
import logging
import shutil
from typing import TYPE_CHECKING

from wireghost.models.finding import Finding
from wireghost.models.scan import Host
from wireghost.parsers.sslscan import parse_sslscan
from wireghost.utils.process import run_tool

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.utils.fs import OutputTree

log = logging.getLogger("wireghost")

_TLS_SERVICE_KEYWORDS = ("ssl", "https", "tls", "imaps", "pop3s", "smtps", "ldaps")
_TLS_FALLBACK_PORTS = {443, 8443, 993, 995, 636, 465, 990, 992, 994}


def _get_tls_ports(host: Host) -> list:
    """Return ports likely running TLS — route by service name, fall back to port number."""
    tls_ports = []
    for port in host.open_ports:
        svc = port.service_name.lower()
        if any(kw in svc for kw in _TLS_SERVICE_KEYWORDS):
            tls_ports.append(port)
        elif not svc and port.number in _TLS_FALLBACK_PORTS:
            tls_ports.append(port)
    return tls_ports


async def audit_tls(
    host: Host, config: ScanConfig, tree: OutputTree, sem: asyncio.Semaphore,
) -> list[Finding]:
    """Run sslscan on every TLS port detected on *host*."""
    if config.skip_tls_audit:
        return []
    if not shutil.which("sslscan"):
        log.info("[%s] sslscan not found — skipping TLS audit", host.ip)
        return []

    tls_ports = _get_tls_ports(host)
    if not tls_ports:
        return []

    log.info("[%s] TLS audit on %d port(s)", host.ip, len(tls_ports))
    findings: list[Finding] = []

    for port in tls_ports:
        async with sem:
            xml_path = tree.host_vuln_dir(host.ip) / f"sslscan_{port.number}.xml"
            result = await run_tool(
                ["sslscan", f"--xml={xml_path}", f"{host.ip}:{port.number}"],
                timeout=int(config.tool_timeout),
                label=f"sslscan {host.ip}:{port.number}",
            )
            if xml_path.exists():
                findings.extend(parse_sslscan(xml_path, host.ip, port.number))
            elif result.returncode != 0:
                log.warning("[%s] sslscan failed on port %d (rc=%d) with no XML output",
                            host.ip, port.number, result.returncode)

    log.info("[%s] TLS audit: %d finding(s)", host.ip, len(findings))
    return findings
