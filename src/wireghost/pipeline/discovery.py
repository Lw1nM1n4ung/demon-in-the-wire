"""Phase 1 -- Host discovery via nmap ping-sweep, fping, and ARP scanning.

Large CIDRs (/16 or bigger) are auto-partitioned into /24 subnets
and scanned in parallel batches for faster discovery.

When arp-scan and/or netdiscover are available, Layer 2 ARP scanning
runs alongside ICMP probes to catch firewall-silent hosts and collect
MAC address + vendor data.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import shutil
from typing import TYPE_CHECKING

from wireghost.utils.network import is_valid_ipv4
from wireghost.utils.process import run_tool

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.utils.fs import OutputTree

log = logging.getLogger("wireghost")

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Subnets with more than 512 IPs (prefix < /24) get partitioned
_PARTITION_THRESHOLD = 23


def _range_to_cidrs(target: str) -> list[ipaddress.IPv4Network] | None:
    """Convert dash-range notation like '10.0.0.0-10.0.3.255' into CIDRs.

    Returns None when *target* isn't a dash-range (caller falls back to
    single-target handling). Uses ipaddress.summarize_address_range so
    the result is the minimum set of CIDRs that exactly covers the range —
    a /22 if aligned, else a cluster of smaller blocks.
    """
    if "-" not in target:
        return None
    try:
        start_s, end_s = target.split("-", 1)
        start = ipaddress.IPv4Address(start_s.strip())
        end = ipaddress.IPv4Address(end_s.strip())
        if end < start:
            return None
        return list(ipaddress.summarize_address_range(start, end))
    except (ValueError, ipaddress.AddressValueError):
        return None


def _partition_target(target: str) -> list[str]:
    """Split anything wider than a /24 into /24 subnets for parallel scanning.

    - /16 → 256 /24 subnets
    - /20 → 16 /24 subnets
    - /24 or smaller (/25, /26, …, single IP) → returned as-is
    - Dash ranges (10.0.0.0-10.0.3.255) → summarized to CIDRs, then each
      CIDR wider than /24 is further split. A 1024-host range becomes
      4 /24s just like /22 would.
    - Hostnames → returned as-is
    """
    # Dash range → expand to CIDRs first, then feed each CIDR through the
    # same /24-split path so range and CIDR inputs converge on one code path.
    cidrs = _range_to_cidrs(target)
    if cidrs is not None:
        out: list[str] = []
        for net in cidrs:
            if net.prefixlen <= _PARTITION_THRESHOLD:
                out.extend(str(s) for s in net.subnets(new_prefix=24))
            else:
                out.append(str(net))
        log.info("Partitioning range %s into %d /24 subnet(s)", target, len(out))
        return out

    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.prefixlen <= _PARTITION_THRESHOLD:
            subnets = list(net.subnets(new_prefix=24))
            log.info(
                "Partitioning /%d target into %d /24 subnets",
                net.prefixlen,
                len(subnets),
            )
            return [str(s) for s in subnets]
        return [target]
    except ValueError:
        # Not a valid CIDR — hostname or single IP
        return [target]


async def _arp_scan_subnet(
    subnet: str,
    timeout: int,
    live_ips: set[str],
    mac_vendor: dict[str, tuple[str, str]],
    has_arpscan: bool,
    has_netdiscover: bool,
) -> None:
    """Run arp-scan and/or netdiscover on a subnet, collect MAC/vendor."""
    from wireghost.parsers.arpscan import parse_arpscan
    from wireghost.parsers.netdiscover import parse_netdiscover

    if has_arpscan:
        arp_result = await run_tool(
            ["arp-scan", "--plain", subnet],
            timeout=timeout,
            label=f"arp-scan {subnet}",
        )
        if arp_result.returncode == 0:
            for ip, mac, vendor in parse_arpscan(arp_result.stdout):
                if is_valid_ipv4(ip):
                    live_ips.add(ip)
                    mac_vendor[ip] = (mac, vendor)

    if has_netdiscover:
        nd_result = await run_tool(
            ["netdiscover", "-P", "-N", "-r", subnet, "-c", "3"],
            timeout=timeout,
            label=f"netdiscover -r {subnet}",
        )
        if nd_result.returncode == 0:
            for ip, mac, vendor in parse_netdiscover(nd_result.stdout):
                if is_valid_ipv4(ip):
                    live_ips.add(ip)
                    if ip not in mac_vendor:
                        mac_vendor[ip] = (mac, vendor)


async def _scan_subnet(
    subnet: str,
    timeout: int,
    live_ips: set[str],
    mac_vendor: dict[str, tuple[str, str]],
    semaphore: asyncio.Semaphore,
    index: int,
    total: int,
    run_arp: bool,
    has_arpscan: bool,
    has_netdiscover: bool,
) -> None:
    """Scan a single subnet with nmap + fping + optional ARP tools."""
    async with semaphore:
        if total > 1:
            log.info("Scanning subnet %d/%d: %s", index, total, subnet)

        # nmap ping sweep
        nmap_result = await run_tool(
            ["nmap", "-sn", subnet],
            timeout=timeout,
            label=f"nmap -sn {subnet}",
        )
        if nmap_result.returncode == 0:
            for ip in _IPV4_RE.findall(nmap_result.stdout):
                if is_valid_ipv4(ip):
                    live_ips.add(ip)

        # fping
        fping_result = await run_tool(
            ["fping", "-a", "-g", subnet],
            timeout=timeout,
            label=f"fping -a -g {subnet}",
        )
        if fping_result.returncode in (0, 1):
            for ip in _IPV4_RE.findall(fping_result.stdout):
                if is_valid_ipv4(ip):
                    live_ips.add(ip)

        # ARP scanning (Layer 2) — supplements ICMP with MAC/vendor data
        if run_arp and (has_arpscan or has_netdiscover):
            await _arp_scan_subnet(
                subnet, timeout, live_ips, mac_vendor,
                has_arpscan, has_netdiscover,
            )


async def discover_hosts(
    config: ScanConfig, tree: OutputTree,
) -> tuple[list[str], dict[str, tuple[str, str]]]:
    """Run nmap -sn, fping, and ARP tools against *config.target*.

    Large CIDRs (>/24) are automatically partitioned into /24 subnets
    and scanned concurrently (limited by config.parallelism).

    Returns
    -------
    tuple[list[str], dict[str, tuple[str, str]]]
        Sorted list of live IPs and a dict mapping ip → (mac_address, vendor).
    """
    target = config.target
    timeout = int(config.tool_timeout)

    # Partition large targets into /24 subnets
    subnets = _partition_target(target)
    total = len(subnets)

    if total > 1:
        log.info(
            "Target %s partitioned into %d /24 subnets (parallelism=%d)",
            target,
            total,
            config.parallelism,
        )

    # Check ARP tool availability
    has_arpscan = shutil.which("arp-scan") is not None
    has_netdiscover = shutil.which("netdiscover") is not None
    run_arp = not config.skip_arp_scan and (has_arpscan or has_netdiscover)

    if config.skip_arp_scan:
        log.info("ARP scanning disabled (skip_arp_scan=True)")
    elif not has_arpscan and not has_netdiscover:
        log.info("ARP tools not found (arp-scan, netdiscover) — skipping Layer 2 discovery")
    else:
        tools = []
        if has_arpscan:
            tools.append("arp-scan")
        if has_netdiscover:
            tools.append("netdiscover")
        log.info("ARP scanning enabled: %s", ", ".join(tools))

    live_ips: set[str] = set()
    mac_vendor: dict[str, tuple[str, str]] = {}

    # Cap discovery parallelism for large targets — scanning 256 /24 subnets
    # with 10 concurrent nmap+fping processes overwhelms the scanner and network.
    discovery_parallelism = config.parallelism
    if total >= 256:
        discovery_parallelism = min(discovery_parallelism, 2)
        if discovery_parallelism < config.parallelism:
            log.info(
                "Large target (>= /16) — capping discovery parallelism to %d",
                discovery_parallelism,
            )

    semaphore = asyncio.Semaphore(discovery_parallelism)

    # Scan all subnets concurrently (semaphore-limited)
    tasks = [
        _scan_subnet(
            subnet, timeout, live_ips, mac_vendor, semaphore,
            i + 1, total, run_arp, has_arpscan, has_netdiscover,
        )
        for i, subnet in enumerate(subnets)
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for i, result in enumerate(results):
        if isinstance(result, BaseException):
            log.error("Subnet scan %s failed: %s", subnets[i], result, exc_info=result)

    # Compute the "error / unreachable" set: every IP in the input CIDR(s)
    # that did NOT answer either nmap or fping. Only makes sense when the
    # input was a CIDR — hostnames and single IPs contribute no expansion.
    candidate_ips: set[str] = set()
    for subnet in subnets:
        try:
            net = ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            continue  # hostname or opaque single-IP string — not expandable
        # .hosts() skips the network + broadcast addrs on /≤30. For /31 and
        # /32 it yields both IPs or the single IP respectively.
        for ip in net.hosts():
            candidate_ips.add(str(ip))
    unreachable_ips = candidate_ips - live_ips

    _ip_sort_key = lambda ip: tuple(int(o) for o in ip.split(".")) if ip.count(".") == 3 else (0,)
    sorted_unreachable = sorted(unreachable_ips, key=_ip_sort_key)

    # Always persist the unreachable list as a diagnostic — operators can
    # eyeball which IPs were silently dropped by ICMP filters. No cost if
    # the input was a hostname (empty file).
    unreachable_txt = tree.live_host_dir / "unreachable.txt"
    unreachable_txt.write_text(
        ("\n".join(sorted_unreachable) + "\n") if sorted_unreachable else "",
        encoding="utf-8",
    )

    # Persist ARP results for diagnostics
    if mac_vendor:
        arp_txt = tree.live_host_dir / "arp_results.txt"
        lines = []
        for ip in sorted(mac_vendor, key=_ip_sort_key):
            mac, vendor = mac_vendor[ip]
            lines.append(f"{ip}\t{mac}\t{vendor}")
        arp_txt.write_text("\n".join(lines) + "\n", encoding="utf-8")
        log.info("ARP discovery: %d host(s) with MAC/vendor data", len(mac_vendor))

    # The returned list (feeds the rest of the pipeline) depends on the
    # scan_unresponsive flag. Default behaviour is unchanged — only alive
    # hosts proceed to portscan.
    if config.scan_unresponsive and unreachable_ips:
        log.warning(
            "scan_unresponsive=True — including %d ICMP-silent IP(s) in the scan "
            "(total scan targets: %d)",
            len(unreachable_ips),
            len(live_ips) + len(unreachable_ips),
        )
        effective_ips: set[str] = live_ips | unreachable_ips
    else:
        if unreachable_ips:
            log.info(
                "Discovery: %d unreachable IP(s) recorded to unreachable.txt "
                "(not scanned; set scan_unresponsive=True to include them)",
                len(unreachable_ips),
            )
        effective_ips = live_ips

    sorted_ips = sorted(effective_ips, key=_ip_sort_key)

    # Persist to disk
    live_txt = tree.live_host_dir / "live.txt"
    live_txt.write_text(
        "\n".join(sorted_ips) + "\n" if sorted_ips else "",
        encoding="utf-8",
    )

    log.info("Discovery found %d live host(s) across %d subnet(s)", len(sorted_ips), total)
    return sorted_ips, mac_vendor
