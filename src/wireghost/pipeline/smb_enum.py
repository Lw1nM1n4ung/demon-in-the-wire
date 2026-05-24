"""SMB/NetBIOS enumeration via enum4linux."""

from __future__ import annotations

import asyncio
import logging
import shutil
from typing import TYPE_CHECKING

from wireghost.models.finding import Finding
from wireghost.parsers.enum4linux import parse_enum4linux_output
from wireghost.utils.process import run_tool

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.models.scan import Host
    from wireghost.utils.fs import OutputTree

log = logging.getLogger("wireghost")

_SMB_SERVICE_NAMES = {"microsoft-ds", "netbios-ssn", "smb"}
_SMB_FALLBACK_PORTS = {139, 445}


def _has_smb(host: Host) -> bool:
    for port in host.open_ports:
        svc = port.service_name
        if svc in _SMB_SERVICE_NAMES:
            return True
        if not svc and port.number in _SMB_FALLBACK_PORTS:
            return True
    return False


async def enumerate_smb(
    host: Host,
    config: ScanConfig,
    tree: OutputTree,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """Run enum4linux against a host if it has SMB services detected."""
    async with sem:
        if config.skip_enum4linux:
            return []

        smb_open = _has_smb(host)
        if not smb_open:
            return []

        if not shutil.which("enum4linux"):
            log.info("[%s] enum4linux not installed — skipping SMB enumeration", host.ip)
            return []

        vuln_dir = tree.host_vuln_dir(host.ip)
        out_file = vuln_dir / "enum4linux.txt"

        result = await run_tool(
            ["enum4linux", "-a", host.ip],
            timeout=int(config.tool_timeout),
            label=f"enum4linux {host.ip}",
        )

        output = (result.stdout or "") + (result.stderr or "")
        if output.strip():
            out_file.write_text(output, encoding="utf-8")

        findings = parse_enum4linux_output(output, host_ip=host.ip)
        log.info("[%s] enum4linux: %d finding(s)", host.ip, len(findings))
        return findings
