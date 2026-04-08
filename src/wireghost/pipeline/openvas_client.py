"""OpenVAS scanner via scannerctl CLI — runs NASL vulnerability tests directly."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from pathlib import Path

from wireghost.utils.process import run_tool

log = logging.getLogger("wireghost")

_FEED_PATHS = [
    Path("/var/lib/openvas/plugins"),
    Path.home() / "openvas-feeds" / "nasl",
    Path("/opt/openvas/plugins"),
]


def _find_feed_path() -> Path | None:
    """Find the NASL feed directory."""
    for p in _FEED_PATHS:
        if p.is_dir() and any(p.glob("*.nasl")):
            return p
    return None


async def scan_host_scannerctl(
    ip: str,
    output_dir: Path,
    feed_path: Path | None = None,
    timeout: float = 3600,
) -> Path | None:
    """Run OpenVAS vulnerability scan via scannerctl CLI.

    Returns path to results file or None if scan fails.
    """
    if not shutil.which("scannerctl"):
        log.debug("scannerctl not found — skipping OpenVAS scan for %s", ip)
        return None

    feed = feed_path or _find_feed_path()
    if not feed:
        log.info("No NASL feed found — skipping OpenVAS scan for %s", ip)
        return None

    # Create scan config JSON
    scan_config = {
        "target": {
            "hosts": [ip],
            "ports": [{"protocol": "tcp", "range": [{"start": 1, "end": 65535}]}],
        },
        "vts": [{"oid": "1.3.6.1.4.1.25623.1.0"}],
    }

    config_path = output_dir / f"scannerctl_config_{ip}.json"
    config_path.write_text(json.dumps(scan_config), encoding="utf-8")

    result_path = output_dir / f"scannerctl_results_{ip}.txt"

    log.info("scannerctl: scanning %s with feed %s", ip, feed)

    result = await run_tool(
        [
            "scannerctl", "execute", "scan",
            str(feed),
            str(config_path),
            "-t", ip,
        ],
        timeout=int(timeout),
        label=f"scannerctl {ip}",
    )

    # Save output
    output = (result.stdout or "") + (result.stderr or "")
    if output.strip():
        result_path.write_text(output, encoding="utf-8")
        log.info("scannerctl: results saved for %s", ip)
        return result_path

    if result.returncode != 0:
        log.warning("scannerctl failed for %s (rc=%d)", ip, result.returncode)

    return None
