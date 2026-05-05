"""Nikto web server scanner — runs against each web endpoint on a host."""

from __future__ import annotations

import logging
import shutil
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from wireghost.models.finding import Finding
from wireghost.parsers.nikto import parse_nikto_json
from wireghost.utils.process import run_tool

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.models.scan import Host
    from wireghost.utils.fs import OutputTree

log = logging.getLogger("wireghost")


async def run_nikto(
    host: Host,
    config: ScanConfig,
    tree: OutputTree,
) -> list[Finding]:
    """Run Nikto against each web endpoint on *host*.

    Endpoints are scanned sequentially (Nikto is IO-heavy).
    Findings are deduped by template_id + endpoint across endpoints.
    """
    if not host.web_endpoints:
        return []

    if not shutil.which("nikto"):
        log.warning("nikto not installed, skipping for %s", host.ip)
        return []

    vuln_dir = tree.host_vuln_dir(host.ip)
    all_findings: list[Finding] = []
    seen: set[str] = set()

    for idx, url in enumerate(host.web_endpoints):
        parsed = urlparse(url)
        port = str(parsed.port or ("443" if parsed.scheme == "https" else "80"))
        out_file = vuln_dir / f"nikto_{idx}.json"

        cmd = [
            "nikto",
            "-h", url,
            "-o", str(out_file),
            "-Format", "json",
            "-timeout", "15",
            "-maxtime", "1200s",
            "-nointeractive",
            "-no404",
            "-Tuning", "1234589ab",
        ]

        await run_tool(
            cmd,
            timeout=int(config.tool_timeout),
            label=f"nikto {host.ip}:{port}",
        )

        if out_file.exists():
            findings = parse_nikto_json(out_file)
            for f in findings:
                if not f.host:
                    f.host = host.ip
                if not f.port:
                    f.port = port
                dedup_key = f"{f.template_id}:{f.endpoint}"
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    all_findings.append(f)

    log.info("Nikto %s: %d finding(s)", host.ip, len(all_findings))
    return all_findings
