"""Web crawling via katana — spider endpoints before nuclei."""

from __future__ import annotations

import logging
import re
import shutil
from urllib.parse import urlparse
from typing import TYPE_CHECKING

from wireghost.models.finding import Finding
from wireghost.models.scan import Host
from wireghost.models.severity import Severity
from wireghost.utils.process import run_tool

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.utils.fs import OutputTree

log = logging.getLogger("wireghost")


def _safe_filename(url: str) -> str:
    """Convert a URL to a safe filename fragment."""
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", url)[:80]


async def crawl_host(host: Host, config: ScanConfig, tree: OutputTree) -> list[Finding]:
    """Spider all web endpoints on *host* with katana.

    Discovered URLs are appended to host.web_endpoints so nuclei
    (which runs after this) scans them automatically.
    Must be called BEFORE the parallel asyncio.gather in the orchestrator.
    """
    if config.skip_web_crawl:
        return []
    if not shutil.which("katana"):
        log.info("[%s] katana not found — skipping web crawl", host.ip)
        return []
    if not host.web_endpoints:
        return []

    log.info("[%s] Web crawl on %d endpoint(s)", host.ip, len(host.web_endpoints))
    new_urls: set[str] = set()
    per_endpoint: dict[str, set[str]] = {}
    existing = set(host.web_endpoints)

    for endpoint in list(host.web_endpoints):
        out_path = tree.host_web_dir(host.ip) / f"katana_{_safe_filename(endpoint)}.txt"
        result = await run_tool(
            [
                "katana",
                "-u",
                endpoint,
                "-d",
                "3",
                "-jc",
                # katana's -kf takes a value; passing -ef straight after it made
                # katana read "-ef" as the value and abort, so crawl found nothing.
                "-kf",
                "all",
                "-ef",
                "css,png,jpg,gif,svg,woff,woff2,ico,ttf,eot",
                "-silent",
                "-nc",
            ],
            timeout=min(120, int(config.tool_timeout)),
            label=f"katana {endpoint}",
        )
        if result.returncode == 0 and result.stdout.strip():
            out_path.write_text(result.stdout, encoding="utf-8")
            found_here = per_endpoint.setdefault(endpoint, set())
            for line in result.stdout.strip().splitlines():
                url = line.strip()
                if url and url not in existing and url not in new_urls:
                    new_urls.add(url)
                    found_here.add(url)

    host.web_endpoints.extend(sorted(new_urls))
    log.info("[%s] katana discovered %d new URL(s)", host.ip, len(new_urls))

    findings: list[Finding] = []
    for endpoint, discovered in per_endpoint.items():
        finding = _crawl_finding(host, endpoint, discovered)
        if finding:
            findings.append(finding)
    return findings

def _dedupe_urls(urls: set[str]) -> list[str]:
    """Drop query-string duplicates.

    A crawler emits both /app.js and /app.js?v=1790057310715; listing both
    turns the report into a wall of near-identical URLs.
    """
    seen: set[str] = set()
    out: list[str] = []
    for url in sorted(urls):
        key = url.split("?", 1)[0]
        if key in seen:
            continue
        seen.add(key)
        out.append(url)
    return out


# How many URLs to quote in the finding itself; the crawl file keeps them all.
_MAX_REPORTED_URLS = 25


def _crawl_finding(host: Host, endpoint: str, discovered: set[str]) -> Finding | None:
    listed = _dedupe_urls(discovered)
    if not listed:
        return None

    lines = listed[:_MAX_REPORTED_URLS]
    if len(listed) > _MAX_REPORTED_URLS:
        lines.append(
            f"... and {len(listed) - _MAX_REPORTED_URLS} more "
            f"(full list: ips/{host.ip}/web/katana_*.txt)"
        )

    parsed = urlparse(endpoint)
    return Finding(
        source="katana",
        host=host.ip,
        port=str(parsed.port or ("443" if parsed.scheme == "https" else "80")),
        protocol="tcp",
        severity=Severity.INFO,
        title=f"Web crawl discovered {len(listed)} endpoint(s)",
        description="\n".join(lines),
        endpoint=parsed.path or "/",
        full_url=endpoint,
    )
