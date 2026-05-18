"""Phase 3 -- Web service detection via HTTP/HTTPS probing.

Port filtering is verification-driven: port numbers and nmap labels are NEVER
trusted as positive indicators of a web service.  Anyone can run SSH on 8080
or nginx on 2222.  The only reliable test is an actual HTTP request.

Nmap IS trusted for one narrow thing: confidently identifying protocols that
are NOT HTTP (SSH, MySQL, SMTP, SMB, etc.).  These are protocol-level
fingerprints that nmap gets right reliably.  If nmap says a port is ssh,
we skip it -- not because "ssh isn't web" but because nmap's ssh fingerprint
is definitive.

Everything else -- unknown services, uncertain detections, ports nmap couldn't
identify -- gets probed.  The HTTP HEAD request IS the verification.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import ssl
from typing import TYPE_CHECKING

import aiohttp

from wireghost.models.scan import Host, Port, WebTech
from wireghost.utils.process import run_tool

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.utils.fs import OutputTree

log = logging.getLogger("wireghost")

_PROBE_TIMEOUT = aiohttp.ClientTimeout(total=5)

# ── Web candidate filter ────────────────────────────────────────────────────

# Protocols nmap fingerprints with high confidence.  If nmap says a port is
# one of these, it almost certainly is -- so we skip HTTP probing.  Every
# other port (uncertain, unknown, or even tagged "http" by nmap) gets probed
# because port numbers and service labels are NOT trusted as positive signals.
# The HTTP HEAD request IS the verification.
_NON_WEB_PROTOCOLS: frozenset[str] = frozenset({
    "ssh", "smtp", "domain", "snmp", "ldap", "ldaps", "smb",
    "netbios-ssn", "microsoft-ds", "mysql", "postgresql", "redis",
    "mongodb", "ftp", "ftp-data", "telnet", "ms-sql-s", "ms-sql-m",
    "oracle-tns", "oracle", "rdp", "ms-wbt-server", "vnc", "nfs",
    "nfs-oracle", "rpcbind", "mountd", "nlockmgr", "pop3", "pop3s",
    "imap", "imaps", "ntp", "dhcp", "dhcpv6", "tftp", "sip", "sips",
    "rtsp", "rsync", "ipp", "ipp-ssl", "cups", "jetdirect",
    "docker", "docker-tls", "kubernetes", "kubelet",
})


def _should_probe(port: Port) -> tuple[bool, str]:
    """Return (should_probe, reason) for a port.

    Only ONE rule: if nmap confidently identifies a non-web protocol, skip it.
    Everything else -- including ports nmap calls "http", common web ports,
    and ports nmap couldn't identify at all -- gets probed.  The HTTP request
    itself is the only verification that matters.
    """
    svc = port.service_name.lower() if port.service_name else ""

    if svc in _NON_WEB_PROTOCOLS:
        return False, f"non-web protocol {svc}"

    if svc:
        return True, f"service={svc} (probe to verify)"
    return True, "unknown service (probe to verify)"


async def _try_url(session: aiohttp.ClientSession, url: str) -> bool:
    """Return True if the URL responds to a HEAD request."""
    try:
        async with session.head(url, timeout=_PROBE_TIMEOUT, ssl=False) as resp:
            return resp.status < 600  # any HTTP response counts
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
        return False


async def _detect_technologies(
    host: Host, tree: OutputTree, timeout: float,
) -> None:
    """Run httpx -tech-detect on web endpoints to identify technologies."""
    if not host.web_endpoints or not shutil.which("httpx"):
        return

    web_dir = tree.host_web_dir(host.ip)
    endpoints_file = web_dir / "endpoints.txt"
    # endpoints.txt should already exist from probe_host
    if not endpoints_file.exists():
        endpoints_file.write_text("\n".join(host.web_endpoints) + "\n")

    tech_json = web_dir / "tech_detect.json"

    await run_tool(
        ["httpx", "-l", str(endpoints_file), "-tech-detect", "-sc", "-title", "-server", "-favicon", "-jarm", "-json", "-o", str(tech_json), "-silent"],
        timeout=int(timeout),
        label=f"httpx tech {host.ip}",
    )

    if not tech_json.exists():
        return

    # Parse httpx JSON output (one JSON object per line)
    for line in tech_json.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        url = item.get("url", "")
        techs = item.get("tech", [])
        if isinstance(techs, list):
            for tech in techs:
                # httpx tech format: "TechName" or "TechName:version"
                if ":" in tech:
                    name, version = tech.split(":", 1)
                else:
                    name, version = tech, ""
                host.technologies.append(WebTech(name=name.strip(), version=version.strip(), url=url))

        # Parse additional fields from httpx enrichment flags
        status_code = item.get("status_code", 0)
        title = item.get("title", "")
        server = item.get("webserver", "")
        favicon_hash = item.get("favicon", {}).get("hash", "") if isinstance(item.get("favicon"), dict) else ""
        jarm = item.get("jarm", "")

        if server:
            host.technologies.append(WebTech(name="Server", version=server, url=url))
        if title:
            host.web_titles[url] = title

    log.info("Tech detect %s: %d technologies found", host.ip, len(host.technologies))


async def probe_host(
    host: Host,
    config: ScanConfig,
    tree: OutputTree,
    sem: asyncio.Semaphore,
) -> None:
    """Probe open ports on *host* for HTTP and HTTPS endpoints.

    Ports are filtered through ``_should_probe`` which skips only ports
    where nmap has confidently identified a non-web protocol.  Everything
    else gets probed — the HTTP request itself is the verification.

    Discovered URLs are appended to ``host.web_endpoints`` and written to
    disk under the host web directory and the global web directory.
    """
    async with sem:
        # ── Filter ports to web candidates ──
        candidates: list[Port] = []
        skipped: list[str] = []
        for port in host.open_ports:
            ok, reason = _should_probe(port)
            if ok:
                candidates.append(port)
            else:
                skipped.append(f"{port.number}/{port.protocol} ({reason})")

        if skipped:
            log.info(
                "Web detect %s: skipping %d non-web port(s) -- %s",
                host.ip, len(skipped), "; ".join(skipped[:5]),
            )

        if not candidates:
            log.info("Web detect %s: no web candidates among %d open port(s)", host.ip, len(host.open_ports))
            return

        endpoints: list[str] = []

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(ssl=ssl_ctx)
        async with aiohttp.ClientSession(connector=connector) as session:
            for port in candidates:
                # Try HTTP first
                http_url = f"http://{host.ip}:{port.number}"
                if await _try_url(session, http_url):
                    endpoints.append(http_url)
                    continue

                # Then HTTPS
                https_url = f"https://{host.ip}:{port.number}"
                if await _try_url(session, https_url):
                    endpoints.append(https_url)

        host.web_endpoints = endpoints

        if endpoints:
            log.info("Web detect %s: %d endpoint(s) from %d candidate(s)", host.ip, len(endpoints), len(candidates))

            # Write per-host file
            web_file = tree.host_web_dir(host.ip) / "endpoints.txt"
            web_file.write_text(
                "\n".join(endpoints) + "\n", encoding="utf-8"
            )

            # Append to global web file
            global_file = tree.web_dir / "all_endpoints.txt"
            with open(global_file, "a", encoding="utf-8") as fh:
                for url in endpoints:
                    fh.write(url + "\n")
        else:
            log.info("Web detect %s: no web endpoints responded among %d candidate(s)", host.ip, len(candidates))

        # Run httpx tech detection on discovered endpoints
        await _detect_technologies(host, tree, config.tool_timeout)
