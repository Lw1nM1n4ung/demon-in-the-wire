"""SNMP enumeration — blind community string probe + snmpwalk."""

from __future__ import annotations

import asyncio
import logging
import shutil
from typing import TYPE_CHECKING

from wireghost.models.finding import Finding
from wireghost.models.scan import Host
from wireghost.models.severity import Severity
from wireghost.parsers.snmpwalk import extract_system_info, parse_snmpwalk
from wireghost.utils.process import run_tool

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.utils.fs import OutputTree

log = logging.getLogger("wireghost")

_DEFAULT_COMMUNITIES = ["public", "private", "community", "manager", "cisco", "admin"]


async def _probe_communities(ip: str) -> str | None:
    """Try common SNMP community strings with snmpget (3s timeout each)."""
    for community in _DEFAULT_COMMUNITIES:
        result = await run_tool(
            [
                "snmpget",
                "-v2c",
                "-c",
                community,
                "-t",
                "3",
                "-r",
                "0",
                ip,
                ".1.3.6.1.2.1.1.1.0",
            ],
            timeout=5,
            label=f"snmpget probe {ip} ({community})",
        )
        if result.returncode == 0 and "Timeout" not in result.stderr:
            return community
    return None


def _build_findings(
    host_ip: str,
    community: str,
    walk_stdout: str,
) -> list[Finding]:
    """Build Finding objects from SNMP probe + walk results."""
    findings: list[Finding] = []

    findings.append(
        Finding(
            source="snmp_enum",
            host=host_ip,
            port="161",
            protocol="udp",
            severity=Severity.HIGH,
            title=f"SNMP default community string: '{community}'",
            description=(
                f"SNMP agent on {host_ip} accepts the community string '{community}'. "
                "An attacker can enumerate system information, network interfaces, "
                "routing tables, and installed software."
            ),
        )
    )

    if walk_stdout:
        oid_map = parse_snmpwalk(walk_stdout)
        sys_info = extract_system_info(oid_map)
        if sys_info:
            info_lines = [f"{k}: {v}" for k, v in sys_info.items()]
            findings.append(
                Finding(
                    source="snmp_enum",
                    host=host_ip,
                    port="161",
                    protocol="udp",
                    severity=Severity.INFO,
                    title="SNMP system information exposed",
                    description="\n".join(info_lines),
                )
            )

    return findings


async def enumerate_snmp(
    host: Host,
    config: ScanConfig,
    tree: OutputTree
) -> list[Finding]:
    """Blind SNMP probe on *host* followed by full walk if community found."""
    if config.skip_snmp_enum:
        return []
    if not shutil.which("snmpget"):
        log.info("[%s] snmpget not found — skipping SNMP enum", host.ip)
        return []

    working_community = await _probe_communities(host.ip)
    if not working_community:
        return []

    log.info("[%s] SNMP community '%s' accepted — running snmpwalk", host.ip, working_community)

    walk_stdout = ""
    if shutil.which("snmpwalk"):
        out_path = tree.host_vuln_dir(host.ip) / "snmpwalk.txt"
        result = await run_tool(
            ["snmpwalk", "-v2c", "-c", working_community, "-OQn", host.ip],
            timeout=min(60, int(config.tool_timeout)),
            label=f"snmpwalk {host.ip}",
        )
        if result.returncode == 0:
            walk_stdout = result.stdout
            out_path.write_text(walk_stdout, encoding="utf-8")

    findings = _build_findings(host.ip, working_community, walk_stdout)
    log.info("[%s] SNMP enum: %d finding(s)", host.ip, len(findings))
    return findings
