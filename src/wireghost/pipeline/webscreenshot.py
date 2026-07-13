"""Pipeline phase -- web endpoint screenshots via gowitness."""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
import ssl
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import aiohttp

from wireghost.models.scan import Host, Screenshot
from wireghost.utils.process import run_tool

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.utils.fs import OutputTree

log = logging.getLogger("wireghost")


def _safe_filename(url: str) -> str:
    """Convert a URL into a filesystem-safe PNG name."""
    p = urlparse(url)
    host = p.hostname or "unknown"
    port = p.port or (443 if p.scheme == "https" else 80)
    return f"{p.scheme}_{host}_{port}.png"


async def screenshot_host(
    host: Host,
    config: ScanConfig,
    tree: OutputTree
) -> None:
    """Capture screenshots of all web endpoints on *host* using gowitness."""
    if config.skip_screenshots:
        return
    if not shutil.which("gowitness"):
        log.warning("gowitness not found — skipping screenshots for %s", host.ip)
        return
    if not host.web_endpoints:
        return

    out_dir = tree.host_screenshots_dir(host.ip)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as url_file:
        url_file.write("\n".join(host.web_endpoints))
        url_path = url_file.name

    try:
        await run_tool(
            [
                "gowitness",
                "scan",
                "file",
                "-f",
                url_path,
                "--screenshot-path",
                str(out_dir),
                "--timeout",
                "10",
                "--delay",
                "2",
                "--chrome-window-x",
                "1280",
                "--chrome-window-y",
                "720",
                "--screenshot-format",
                "png",
            ],
            timeout=int(config.tool_timeout),
            label=f"gowitness:{host.ip}",
        )
    except Exception:
        log.warning("[%s] gowitness failed — skipping screenshots", host.ip, exc_info=True)
        return
    finally:
        Path(url_path).unlink(missing_ok=True)

    # Fetch real HTTP status codes for the screenshot URLs
    ss_urls = [u for u in host.web_endpoints if u.startswith("http")]
    status_map = await _fetch_status_codes(ss_urls)

    for png in out_dir.glob("*.png"):
        matched_url = _match_url(png.name, host.web_endpoints)
        url = matched_url or png.stem
        host.screenshots.append(
            Screenshot(
                url=url,
                filename=str(png.relative_to(tree.base)),
                title=host.web_titles.get(url, ""),
                status_code=status_map.get(url, 0),
            )
        )

    for sc in host.screenshots:
        src = tree.base / sc.filename
        dst = out_dir / _safe_filename(sc.url)
        if src.exists() and src != dst and not dst.exists():
            src.rename(dst)
            sc.filename = str(dst.relative_to(tree.base))

    if host.screenshots:
        log.info("[%s] Captured %d screenshot(s)", host.ip, len(host.screenshots))


def _match_url(png_name: str, urls: list[str]) -> str | None:
    """Best-effort match a gowitness PNG filename back to a source URL."""
    stem = png_name.removesuffix(".png").lower()
    for url in urls:
        normalized = re.sub(r"[/:]+", "-", url.lower()).strip("-")
        if normalized in stem or stem in normalized:
            return url
    return urls[0] if urls else None


async def _fetch_status_codes(urls: list[str]) -> dict[str, int]:
    """Fetch HTTP status codes for *urls* with concurrent HEAD requests."""
    if not urls:
        return {}
    status_map: dict[str, int] = {}
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    connector = aiohttp.TCPConnector(ssl=ssl_context)
    timeout = aiohttp.ClientTimeout(total=8)

    async def _head(session: aiohttp.ClientSession, url: str) -> None:
        try:
            async with session.head(url, allow_redirects=True, timeout=timeout) as resp:
                status_map[url] = resp.status
        except Exception:
            pass

    try:
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            await asyncio.gather(*(_head(session, u) for u in urls), return_exceptions=True)
    except Exception:
        pass

    return status_map
