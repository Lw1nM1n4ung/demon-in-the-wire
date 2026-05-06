"""NFS enumeration via showmount — list exported shares."""

from __future__ import annotations

import asyncio
import logging
import shutil
from typing import TYPE_CHECKING

from wireghost.models.finding import Finding
from wireghost.models.scan import Host
from wireghost.parsers.showmount import parse_showmount
from wireghost.utils.process import run_tool

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.utils.fs import OutputTree

log = logging.getLogger("wireghost")

_NFS_SERVICE_KEYWORDS = ("nfs", "rpcbind", "mountd", "nlockmgr")
_NFS_FALLBACK_PORTS = {2049, 111}


def _has_nfs(host: Host) -> bool:
    """Check if any open port looks like NFS — service name first, port number fallback."""
    for port in host.open_ports:
        svc = port.service_name.lower()
        if any(kw in svc for kw in _NFS_SERVICE_KEYWORDS):
            return True
        if not svc and port.number in _NFS_FALLBACK_PORTS:
            return True
    return False


async def enumerate_nfs(
    host: Host, config: ScanConfig, tree: OutputTree, sem: asyncio.Semaphore,
) -> list[Finding]:
    """Run showmount -e if NFS-related services are detected on *host*."""
    if config.skip_nfs_enum:
        return []
    if not shutil.which("showmount"):
        log.info("[%s] showmount not found — skipping NFS enum", host.ip)
        return []
    if not _has_nfs(host):
        return []

    async with sem:
        log.info("[%s] NFS enum via showmount", host.ip)
        result = await run_tool(
            ["showmount", "-e", host.ip],
            timeout=15,
            label=f"showmount -e {host.ip}",
        )
        if result.returncode != 0:
            return []

        out_path = tree.host_vuln_dir(host.ip) / "showmount.txt"
        out_path.write_text(result.stdout, encoding="utf-8")

        findings = parse_showmount(result.stdout, host.ip)
        log.info("[%s] NFS enum: %d finding(s)", host.ip, len(findings))
        return findings
