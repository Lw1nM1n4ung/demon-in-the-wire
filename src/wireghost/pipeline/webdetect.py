"""Phase 3 -- Web service detection via HTTP/HTTPS probing."""

from __future__ import annotations

import asyncio
import logging
import ssl
from typing import TYPE_CHECKING

import aiohttp

from wireghost.models.scan import Host

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.utils.fs import OutputTree

log = logging.getLogger("wireghost")

# Ports commonly associated with HTTP/HTTPS
_COMMON_HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 9090, 3000, 5000}
_PROBE_TIMEOUT = aiohttp.ClientTimeout(total=5)


async def _try_url(session: aiohttp.ClientSession, url: str) -> bool:
    """Return True if the URL responds to a HEAD request."""
    try:
        async with session.head(url, timeout=_PROBE_TIMEOUT, ssl=False) as resp:
            return resp.status < 600  # any HTTP response counts
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
        return False


async def probe_host(
    host: Host,
    config: ScanConfig,
    tree: OutputTree,
    sem: asyncio.Semaphore,
) -> None:
    """Probe each open port on *host* for HTTP and HTTPS endpoints.

    Discovered URLs are appended to ``host.web_endpoints`` and written
    to disk under the host web directory and the global web directory.
    """
    async with sem:
        endpoints: list[str] = []

        # Build candidate ports from open ports
        candidate_ports = [p.number for p in host.open_ports]

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(ssl=ssl_ctx)
        async with aiohttp.ClientSession(connector=connector) as session:
            for port_num in candidate_ports:
                # Try HTTP first
                http_url = f"http://{host.ip}:{port_num}"
                if await _try_url(session, http_url):
                    endpoints.append(http_url)
                    continue

                # Then HTTPS
                https_url = f"https://{host.ip}:{port_num}"
                if await _try_url(session, https_url):
                    endpoints.append(https_url)

        host.web_endpoints = endpoints

        if endpoints:
            log.info("Web detect %s: %d endpoint(s)", host.ip, len(endpoints))

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
            log.info("Web detect %s: no web endpoints", host.ip)
