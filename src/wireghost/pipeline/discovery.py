"""Phase 1 -- Host discovery via nmap ping-sweep, fping, and ARP scanning.

Large CIDRs (wider than /24) are auto-partitioned into /24 subnets and
scanned concurrently (parallelism controlled by config.parallelism).

Within each subnet, nmap, fping, and ARP tools run in parallel via
asyncio.gather to minimize wall-clock time.

When arp-scan and/or netdiscover are available, Layer 2 ARP scanning
runs alongside ICMP probes to catch firewall-silent hosts and collect
MAC address + vendor data.

Enhanced discovery (enabled by default) adds:
  - TCP SYN ping to 17 high-value ports (SSH, SMB, RDP, databases, etc.)
    beyond nmap's default 80+443 — catches hosts that drop probes to
    80/443 but respond on other ports.
  - UDP ping to 5 common UDP services (DNS, NTP, NetBIOS, SNMP, IKE)
    — catches hosts behind TCP/ICMP-filtering firewalls.

Passive DNS sweep (enabled by default) runs nmap -sL -R to resolve
PTR records across the target range without sending a single packet.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import shutil
from typing import TYPE_CHECKING, Any, Callable

from wireghost.utils.network import is_valid_ipv4
from wireghost.utils.process import run_tool

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.utils.fs import OutputTree

log = logging.getLogger("wireghost")

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# fping stderr: "ICMP Host Unreachable from <gateway> for ICMP Echo sent to <target>"
# These are hosts that exist (the gateway knows about them) but are firewalled
# against ICMP — they may still have open TCP ports.  Always include them.
_FPING_UNREACHABLE_RE = re.compile(
    r"ICMP Host Unreachable from [\d.]+ for ICMP Echo sent to (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
)

# Subnets with more than 512 IPs (prefix < /24) get partitioned
_PARTITION_THRESHOLD = 23

# TCP ports probed during enhanced discovery (nmap -PS<ports>).
# These are high-value ports whose mere presence indicates a live host —
# SSH, SMB, RDP, databases, web alternates, WinRM.
_TCP_DISCOVERY_PORTS = "22,25,53,111,135,139,445,1433,3306,3389,5432,5985,6379,8080,8443,9090,9200"

# UDP ports probed during enhanced discovery (nmap -PU<ports>).
# UDP ping bypasses firewalls that drop TCP SYN and ICMP but allow UDP
# (common in enterprise environments for DNS, NTP, SNMP).
_UDP_DISCOVERY_PORTS = "53,123,137,161,500"


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

    - Multiple targets separated by commas or whitespace → each processed independently
    - /16 → 256 /24 subnets
    - /20 → 16 /24 subnets
    - /24 or smaller (/25, /26, …, single IP) → returned as-is
    - Dash ranges (10.0.0.0-10.0.3.255) → summarized to CIDRs, then each
      CIDR wider than /24 is further split. A 1024-host range becomes
      4 /24s just like /22 would.
    - Hostnames → returned as-is
    """
    # Multi-target support: split on commas and/or whitespace
    if re.search(r"[,\s]", target) and "/" in target:
        parts = re.split(r"[,\s]+", target.strip())
        parts = [p for p in parts if p]
        if len(parts) > 1:
            all_subnets: list[str] = []
            for part in parts:
                all_subnets.extend(_partition_target(part))
            # Dedup while preserving order
            seen: set[str] = set()
            deduped = []
            for s in all_subnets:
                if s not in seen:
                    seen.add(s)
                    deduped.append(s)
            log.info(
                "Multi-target: %d part(s) → %d unique /24 subnet(s)",
                len(parts),
                len(deduped),
            )
            return deduped

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
    fping_unreachable: set[str],
    semaphore: asyncio.Semaphore,
    index: int,
    total: int,
    run_arp: bool,
    has_arpscan: bool,
    has_netdiscover: bool,
    enhanced: bool = True,
) -> tuple[set[str], dict[str, tuple[str, str]]]:
    """Scan a single subnet — nmap, fping, and ARP tools run in parallel.

    Returns (new_ips, new_mac) — the delta of IPs and MAC entries
    discovered by THIS subnet scan, computed inside the semaphore so
    concurrent subnet scans don't inflate the per-subnet delta.
    """
    async with semaphore:
        before_ips = set(live_ips)
        before_mac_keys = set(mac_vendor.keys())

        if total > 1:
            log.info("Scanning subnet %d/%d: %s", index, total, subnet)

        async def _run_nmap() -> None:
            if enhanced:
                nmap_args = [
                    "nmap",
                    "-sn",
                    "-PS" + _TCP_DISCOVERY_PORTS,
                    "-PU" + _UDP_DISCOVERY_PORTS,
                    subnet,
                ]
            else:
                nmap_args = ["nmap", "-sn", subnet]

            result = await run_tool(
                nmap_args,
                timeout=timeout,
                label=f"nmap -sn {subnet}",
            )
            if result.returncode == 0:
                for ip in _IPV4_RE.findall(result.stdout):
                    if is_valid_ipv4(ip):
                        live_ips.add(ip)

        async def _run_fping() -> None:
            result = await run_tool(
                ["fping", "-a", "-g", subnet],
                timeout=timeout,
                label=f"fping -a -g {subnet}",
            )
            if result.returncode in (0, 1):
                for ip in _IPV4_RE.findall(result.stdout):
                    if is_valid_ipv4(ip):
                        live_ips.add(ip)
            # ICMP Host Unreachable → host exists but blocks ICMP (firewall/WAF).
            # These are NOT the same as silent/unresponsive — the gateway knows
            # about them.  Always include them in the scan.
            if result.stderr:
                for ip in _FPING_UNREACHABLE_RE.findall(result.stderr):
                    if is_valid_ipv4(ip):
                        fping_unreachable.add(ip)

        tasks = [
            _run_nmap(),
            _run_fping(),
        ]
        if run_arp and (has_arpscan or has_netdiscover):
            tasks.append(
                _arp_scan_subnet(
                    subnet,
                    timeout,
                    live_ips,
                    mac_vendor,
                    has_arpscan,
                    has_netdiscover,
                )
            )

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, BaseException):
                log.error("Discovery tool failed for %s: %s", subnet, result)

        # Compute the delta INSIDE the semaphore — concurrent subnet scans
        # have not yet modified live_ips/mac_vendor, so each subnet only
        # reports its own discoveries.
        new_ips = live_ips - before_ips
        new_mac = {ip: mac_vendor[ip] for ip in mac_vendor if ip not in before_mac_keys}

    return new_ips, new_mac


async def _dns_sweep_subnet(
    subnet: str,
    timeout: int,
    semaphore: asyncio.Semaphore,
) -> dict[str, str]:
    """Run ``nmap -sL -R`` on a single subnet, returning ip→hostname dict.

    Designed to be fanned out per /24 so DNS PTR lookups run in parallel
    across subnets instead of sequentially across the entire target range.
    """
    async with semaphore:
        result = await run_tool(
            ["nmap", "-sL", "-R", subnet],
            timeout=min(timeout, 120),
            label=f"nmap -sL -R {subnet}",
        )
        if result.returncode != 0:
            return {}

        hostnames: dict[str, str] = {}
        _PTR_LINE = re.compile(
            r"^Nmap scan report for (.+?) \((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)$"
        )
        for line in result.stdout.splitlines():
            m = _PTR_LINE.match(line.strip())
            if m:
                hostname, ip = m.group(1), m.group(2)
                hostnames[ip] = hostname

        return hostnames


async def discover_hosts(
    config: ScanConfig,
    tree: OutputTree,
    on_progress: "Callable[[str, int, int], None] | None" = None,
    on_subnet_complete: "Callable[[list[str], dict[str, tuple[str, str]]], None] | None" = None,
) -> tuple[list[str], dict[str, tuple[str, str]]]:
    """Run nmap -sn, fping, ARP tools, and passive DNS against *config.target*.

    Large CIDRs (>/24) are automatically partitioned into /24 subnets
    and scanned concurrently (limited by config.parallelism).

    If *on_progress* is provided it is called as
    ``on_progress('discovery', subnets_done, total_subnets)``
    after each subnet scan completes.

    If *on_subnet_complete* is provided it is called after each subnet
    scan with the list of newly discovered IPs and any MAC/vendor updates,
    so the caller can persist hosts incrementally rather than waiting for
    every subnet to finish.

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

    enhanced = config.enhanced_discovery
    if enhanced:
        log.info(
            "Enhanced discovery: TCP ports=%s UDP ports=%s",
            _TCP_DISCOVERY_PORTS,
            _UDP_DISCOVERY_PORTS,
        )

    live_ips: set[str] = set()
    mac_vendor: dict[str, tuple[str, str]] = {}
    fping_unreachable: set[str] = set()

    # Discovery is I/O-bound (waiting on nmap/fping timeouts) — use a
    # dedicated high-concurrency semaphore so large CIDRs (/16 → 256 /24s)
    # scan at maximum parallelism regardless of the main pipeline setting.
    discovery_parallelism = max(config.parallelism, 256)
    semaphore = asyncio.Semaphore(discovery_parallelism)
    log.info("Discovery parallelism: %d (pipeline: %d)", discovery_parallelism, config.parallelism)

    # Scan all subnets concurrently (semaphore-limited).
    # Active discovery + passive DNS sweep all fanned out per /24 subnet
    # so DNS PTR lookups run in parallel rather than sequentially.
    coros: list[Any] = []
    subnets_done = 0

    async def _tracked_scan_subnet(subnet: str, idx: int) -> None:
        nonlocal subnets_done
        new_ips, new_mac = await _scan_subnet(
            subnet,
            timeout,
            live_ips,
            mac_vendor,
            fping_unreachable,
            semaphore,
            idx,
            total,
            run_arp,
            has_arpscan,
            has_netdiscover,
            enhanced=enhanced,
        )
        subnets_done += 1
        if on_subnet_complete and (new_ips or new_mac):
            on_subnet_complete(list(new_ips), new_mac)
        if on_progress:
            on_progress("discovery", subnets_done, total)

    for i, subnet in enumerate(subnets):
        coros.append(_tracked_scan_subnet(subnet, i + 1))
        if not config.skip_passive_dns:
            coros.append(_dns_sweep_subnet(subnet, timeout, semaphore))

    results = await asyncio.gather(*coros, return_exceptions=True)

    # Collect DNS sweep results from the gather output. DNS coros are
    # interleaved with scan coros (scan, dns, scan, dns, …) so we
    # iterate all results and pick out the dict ones.
    dns_hostnames: dict[str, str] = {}
    scan_idx = 0
    for result in results:
        if isinstance(result, dict):
            dns_hostnames.update(result)
        elif isinstance(result, BaseException):
            if scan_idx < len(subnets):
                log.error("Subnet scan %s failed: %s", subnets[scan_idx], result, exc_info=result)
            scan_idx += 1
        else:
            scan_idx += 1

    # Persist merged DNS sweep results
    if dns_hostnames:
        dns_file = tree.live_host_dir / "dns_sweep.txt"
        dns_file.write_text(
            "\n".join(f"{ip}\t{dns_hostnames[ip]}" for ip in sorted(dns_hostnames)) + "\n",
            encoding="utf-8",
        )
        log.info("Passive DNS sweep: %d PTR record(s) found", len(dns_hostnames))
    elif not config.skip_passive_dns:
        log.info("Passive DNS sweep: no PTR records found")

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
    _ip_sort_key = lambda ip: tuple(int(o) for o in ip.split(".")) if ip.count(".") == 3 else (0,)

    # fping ICMP Host Unreachable: hosts the gateway knows about but that
    # drop ICMP (firewall / WAF).  These exist — always scan them.
    if fping_unreachable:
        # Dedup against live_ips (some may have also responded to nmap or ARP).
        new_fpx_unreachable = fping_unreachable - live_ips
        if new_fpx_unreachable:
            sorted_fpx = sorted(new_fpx_unreachable, key=_ip_sort_key)
            fpx_txt = tree.live_host_dir / "fping_unreachable.txt"
            fpx_txt.write_text(
                "\n".join(sorted_fpx) + "\n",
                encoding="utf-8",
            )
            log.info(
                "fping unreachable: %d firewalled host(s) added to scan targets",
                len(new_fpx_unreachable),
            )
            live_ips |= new_fpx_unreachable
        else:
            log.info(
                "fping unreachable: %d IP(s) already captured by other tools",
                len(fping_unreachable),
            )

    unreachable_ips = candidate_ips - live_ips
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
