"""Phase 1 -- Host discovery via nmap ping-sweep and fping."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from wireghost.utils.network import is_valid_ipv4
from wireghost.utils.process import run_tool

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.utils.fs import OutputTree

log = logging.getLogger("wireghost")

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


async def discover_hosts(config: ScanConfig, tree: OutputTree) -> list[str]:
    """Run nmap -sn and fping against *config.target*, merge and return live IPs.

    The merged, deduplicated, sorted list is also written to
    ``<tree.live_host_dir>/live.txt``.
    """
    target = config.target
    timeout = int(config.tool_timeout)

    live_ips: set[str] = set()

    # --- nmap ping sweep ---
    nmap_result = await run_tool(
        ["nmap", "-sn", target],
        timeout=timeout,
        label=f"nmap -sn {target}",
    )
    if nmap_result.returncode == 0:
        for ip in _IPV4_RE.findall(nmap_result.stdout):
            if is_valid_ipv4(ip):
                live_ips.add(ip)

    # --- fping ---
    fping_result = await run_tool(
        ["fping", "-a", "-g", target],
        timeout=timeout,
        label=f"fping -a -g {target}",
    )
    # fping returns 0 when all hosts reply, 1 when some are unreachable
    if fping_result.returncode in (0, 1):
        for ip in _IPV4_RE.findall(fping_result.stdout):
            if is_valid_ipv4(ip):
                live_ips.add(ip)

    sorted_ips = sorted(live_ips, key=lambda ip: tuple(int(o) for o in ip.split(".")))

    # Persist to disk
    live_txt = tree.live_host_dir / "live.txt"
    live_txt.write_text("\n".join(sorted_ips) + "\n" if sorted_ips else "", encoding="utf-8")

    log.info("Discovery found %d live host(s)", len(sorted_ips))
    return sorted_ips
