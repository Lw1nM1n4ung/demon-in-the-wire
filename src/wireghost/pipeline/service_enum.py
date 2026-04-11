"""Service-specific enumeration — targeted nmap scripts per detected service."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from wireghost.models.finding import Finding
from wireghost.parsers.nmap import parse_nmap_vuln_xml
from wireghost.utils.process import run_tool

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.models.scan import Host
    from wireghost.utils.fs import OutputTree

log = logging.getLogger("wireghost")

# Service name (from nmap -sV) → targeted NSE scripts
SERVICE_SCRIPTS: dict[str, str] = {
    "ssh": "ssh-auth-methods",
    "ftp": "ftp-anon,ftp-bounce",
    "microsoft-ds": "smb-enum-shares,smb-enum-users,smb-security-mode",
    "netbios-ssn": "smb-enum-shares,smb-enum-users",
    "mysql": "mysql-info,mysql-enum,mysql-empty-password",
    "ms-sql-s": "ms-sql-info,ms-sql-empty-password",
    "postgresql": "pgsql-brute",
    "mongodb": "mongodb-info,mongodb-databases",
    "redis": "redis-info",
    "ldap": "ldap-rootdse,ldap-search",
    "snmp": "snmp-info,snmp-sysdescr",
    "ms-wbt-server": "rdp-enum-encryption,rdp-vuln-ms12-020",
    "vnc": "vnc-info",
    "domain": "dns-zone-transfer",
    "smtp": "smtp-enum-users,smtp-open-relay,smtp-commands",
    "nfs": "nfs-ls,nfs-showmount,nfs-statfs",
    "telnet": "telnet-encryption",
    "docker": "docker-version",
    "http": "",  # skip — already handled by nuclei + httpx
    "https": "",  # skip
    "http-proxy": "",  # skip
}


async def enumerate_services(
    host: Host,
    config: ScanConfig,
    tree: OutputTree,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """Run targeted nmap NSE scripts per detected service.

    For each open port with a known service, runs service-specific
    enumeration scripts (auth checks, info gathering, misconfig detection).
    """
    async with sem:
        if not host.open_ports:
            return []

        # Group ports by their script set to minimize nmap invocations
        script_groups: dict[str, list[int]] = {}
        for port in host.open_ports:
            svc_name = port.service.name if port.service else ""
            if not svc_name:
                continue
            scripts = SERVICE_SCRIPTS.get(svc_name, "")
            if not scripts:
                continue
            if scripts not in script_groups:
                script_groups[scripts] = []
            script_groups[scripts].append(port.number)

        if not script_groups:
            return []

        vuln_dir = tree.host_vuln_dir(host.ip)
        all_findings: list[Finding] = []

        for scripts, ports in script_groups.items():
            port_csv = ",".join(str(p) for p in ports)
            xml_out = vuln_dir / f"svc_enum_{ports[0]}.xml"

            result = await run_tool(
                [
                    "nmap",
                    f"--script={scripts}",
                    "-p", port_csv,
                    "-Pn",
                    "-oX", str(xml_out),
                    host.ip,
                ],
                timeout=int(config.tool_timeout),
                label=f"svc-enum:{host.ip}:{port_csv}",
            )

            if xml_out.exists():
                findings = parse_nmap_vuln_xml(xml_out)
                all_findings.extend(findings)

        log.info(
            "Service enum %s: %d finding(s) from %d service group(s)",
            host.ip, len(all_findings), len(script_groups),
        )
        return all_findings
