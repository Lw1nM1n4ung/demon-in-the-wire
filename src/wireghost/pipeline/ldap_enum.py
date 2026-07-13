"""LDAP deep enumeration via ldapsearch — rootDSE and naming contexts."""

from __future__ import annotations

import asyncio
import logging
import shutil
from typing import TYPE_CHECKING

from wireghost.models.finding import Finding
from wireghost.models.scan import Host
from wireghost.models.severity import Severity
from wireghost.utils.process import run_tool

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.utils.fs import OutputTree

log = logging.getLogger("wireghost")

_LDAP_SERVICE_KEYWORDS = ("ldap",)
_LDAP_FALLBACK_PORTS = {389, 636, 3268, 3269}


def _get_ldap_ports(host: Host) -> list:
    """Return ports running LDAP — service name first, port fallback."""
    ldap_ports = []
    for port in host.open_ports:
        svc = port.service_name.lower()
        if any(kw in svc for kw in _LDAP_SERVICE_KEYWORDS):
            ldap_ports.append(port)
        elif not svc and port.number in _LDAP_FALLBACK_PORTS:
            ldap_ports.append(port)
    return ldap_ports


def _parse_rootdse(stdout: str) -> dict[str, list[str]]:
    """Extract key attributes from ldapsearch rootDSE output."""
    attrs: dict[str, list[str]] = {}
    current_attr = ""
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("dn:"):
            continue
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            current_attr = key
            attrs.setdefault(key, []).append(val)
        elif current_attr and line.startswith(" "):
            attrs.setdefault(current_attr, []).append(line.strip())
    return attrs


async def enumerate_ldap(
    host: Host,
    config: ScanConfig,
    tree: OutputTree
) -> list[Finding]:
    """Run ldapsearch rootDSE query on LDAP ports."""
    if config.skip_ldap_enum:
        return []
    if not shutil.which("ldapsearch"):
        log.info("[%s] ldapsearch not found — skipping LDAP enum", host.ip)
        return []

    ldap_ports = _get_ldap_ports(host)
    if not ldap_ports:
        return []

    findings: list[Finding] = []

    for port in ldap_ports:
        svc_lower = port.service_name.lower()
        is_ssl = "ssl" in svc_lower or "ldaps" in svc_lower or svc_lower == "ldapssl"
        scheme = "ldaps" if is_ssl else "ldap"
        uri = f"{scheme}://{host.ip}:{port.number}"

        log.info("[%s] LDAP rootDSE query on %s", host.ip, uri)

        out_path = tree.host_vuln_dir(host.ip) / f"ldapsearch_rootdse_{port.number}.txt"
        result = await run_tool(
            [
                "ldapsearch",
                "-x",
                "-H",
                uri,
                "-b",
                "",
                "-s",
                "base",
                "+",
                "*",
            ],
            timeout=15,
            label=f"ldapsearch rootDSE {host.ip}:{port.number}",
        )

        if result.returncode != 0:
            log.debug(
                "[%s] ldapsearch on port %d exited rc=%d: %s",
                host.ip,
                port.number,
                result.returncode,
                (result.stderr or "")[:200],
            )
            continue

        out_path.write_text(result.stdout, encoding="utf-8")
        attrs = _parse_rootdse(result.stdout)

        # Anonymous bind succeeded — this is a finding
        findings.append(
            Finding(
                source="ldap_enum",
                host=host.ip,
                port=str(port.number),
                protocol="tcp",
                severity=Severity.HIGH,
                title="LDAP anonymous bind allowed",
                description=f"LDAP server at {uri} accepts anonymous bind, exposing directory structure.",
            )
        )

        # Naming contexts
        naming_contexts = attrs.get("namingContexts", [])
        if naming_contexts:
            findings.append(
                Finding(
                    source="ldap_enum",
                    host=host.ip,
                    port=str(port.number),
                    protocol="tcp",
                    severity=Severity.MEDIUM,
                    title=f"LDAP naming contexts exposed ({len(naming_contexts)})",
                    description="Naming contexts:\n" + "\n".join(naming_contexts),
                )
            )

        # Domain functional level
        for key in (
            "domainFunctionality",
            "forestFunctionality",
            "domainControllerFunctionality",
        ):
            vals = attrs.get(key, [])
            if vals:
                findings.append(
                    Finding(
                        source="ldap_enum",
                        host=host.ip,
                        port=str(port.number),
                        protocol="tcp",
                        severity=Severity.INFO,
                        title=f"LDAP {key}: {vals[0]}",
                        description=f"{key} = {vals[0]}",
                    )
                )

    log.info("[%s] LDAP enum: %d finding(s)", host.ip, len(findings))
    return findings
