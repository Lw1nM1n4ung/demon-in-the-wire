"""OpenVAS CLI client — runs full scans via gvm-cli subprocess commands."""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

from wireghost.utils.process import run_tool

log = logging.getLogger("wireghost")

# Well-known OpenVAS/GVM UUIDs
FULL_AND_DEEP_CONFIG = "708f25c4-7489-11df-8094-002264764cea"  # Full and deep
FULL_AND_FAST_CONFIG = "daba56c8-73ec-11df-a475-002264764cea"  # Full and fast
OPENVAS_SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"
IANA_TCP_UDP_PORTLIST = "4a4717fe-57d2-11e1-9a26-406186ea4fc5"
XML_REPORT_FORMAT = "a994b278-1f62-11e1-96ac-406186ea4fc5"


def _extract_id(xml_text: str) -> str | None:
    """Extract the id attribute from a GMP XML response."""
    match = re.search(r'id="([a-f0-9-]+)"', xml_text)
    return match.group(1) if match else None


def _extract_status(xml_text: str) -> str:
    """Extract task status from get_tasks response."""
    try:
        root = ET.fromstring(xml_text)
        status = root.find(".//status")
        return status.text.strip() if status is not None and status.text else ""
    except ET.ParseError:
        return ""


def _extract_progress(xml_text: str) -> str:
    """Extract scan progress percentage."""
    try:
        root = ET.fromstring(xml_text)
        progress = root.find(".//progress")
        if progress is not None and progress.text:
            return progress.text.strip().split("\n")[0]
    except ET.ParseError:
        pass
    return "?"


def _gvm_cli_available() -> bool:
    return shutil.which("gvm-cli") is not None


async def _gvm_cmd(
    socket_path: str, username: str, password: str,
    xml_cmd: str, timeout: int = 120,
) -> str:
    """Run a gvm-cli command and return stdout."""
    result = await run_tool(
        [
            "gvm-cli",
            "--gmp-username", username,
            "--gmp-password", password,
            "socket",
            "--socketpath", socket_path,
            "--xml", xml_cmd,
        ],
        timeout=timeout,
        label="gvm-cli",
    )
    return result.stdout


async def scan_host_openvas(
    ip: str,
    output_dir: Path,
    socket_path: str = "/run/gvmd/gvmd.sock",
    username: str = "admin",
    password: str = "admin",
    timeout: float = 3600,
) -> Path | None:
    """Run a full OpenVAS scan on a host via gvm-cli.

    Workflow:
        1. Create target
        2. Create task (Full and deep scan config)
        3. Start task → get report_id
        4. Poll until done
        5. Get report XML
        6. Save and return path

    Returns None if gvm-cli not available or scan fails.
    """
    if not _gvm_cli_available():
        log.debug("gvm-cli not found — skipping OpenVAS for %s", ip)
        return None

    import datetime
    ts = datetime.datetime.now().strftime("%Y%m%d%H%M%S")

    # 1. Create target
    log.info("OpenVAS: creating target for %s", ip)
    resp = await _gvm_cmd(
        socket_path, username, password,
        f'<create_target>'
        f'<name>wireghost-{ip}-{ts}</name>'
        f'<hosts>{ip}</hosts>'
        f'<port_list id="{IANA_TCP_UDP_PORTLIST}"/>'
        f'</create_target>',
    )
    target_id = _extract_id(resp)
    if not target_id:
        log.error("OpenVAS: failed to create target for %s: %s", ip, resp[:200])
        return None
    log.info("OpenVAS: target created %s", target_id)

    # 2. Create task (Full and deep = most thorough scan)
    resp = await _gvm_cmd(
        socket_path, username, password,
        f'<create_task>'
        f'<name>wireghost-scan-{ip}-{ts}</name>'
        f'<config id="{FULL_AND_DEEP_CONFIG}"/>'
        f'<target id="{target_id}"/>'
        f'<scanner id="{OPENVAS_SCANNER_ID}"/>'
        f'</create_task>',
    )
    task_id = _extract_id(resp)
    if not task_id:
        log.error("OpenVAS: failed to create task for %s: %s", ip, resp[:200])
        return None
    log.info("OpenVAS: task created %s", task_id)

    # 3. Start task
    resp = await _gvm_cmd(
        socket_path, username, password,
        f'<start_task task_id="{task_id}"/>',
    )
    # Report ID is in <report_id> element
    report_match = re.search(r'<report_id>([a-f0-9-]+)</report_id>', resp)
    report_id = report_match.group(1) if report_match else None
    if not report_id:
        log.error("OpenVAS: failed to start task for %s: %s", ip, resp[:200])
        return None
    log.info("OpenVAS: scan started for %s (report=%s)", ip, report_id)

    # 4. Poll until done
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = await _gvm_cmd(
            socket_path, username, password,
            f'<get_tasks task_id="{task_id}"/>',
            timeout=30,
        )
        status = _extract_status(resp)
        if status in ("Done", "Stopped"):
            log.info("OpenVAS: scan complete for %s (status=%s)", ip, status)
            break
        progress = _extract_progress(resp)
        log.info("OpenVAS: %s scanning... %s%%", ip, progress)
        await asyncio.sleep(15)
    else:
        log.warning("OpenVAS: scan timed out for %s, stopping task", ip)
        await _gvm_cmd(
            socket_path, username, password,
            f'<stop_task task_id="{task_id}"/>',
        )

    # 5. Get report XML
    resp = await _gvm_cmd(
        socket_path, username, password,
        f'<get_reports report_id="{report_id}" '
        f'report_format_id="{XML_REPORT_FORMAT}" '
        f'ignore_pagination="1" details="1"/>',
        timeout=120,
    )

    # 6. Save XML
    xml_path = output_dir / f"openvas_report_{ip}.xml"
    xml_path.write_text(resp, encoding="utf-8")
    log.info("OpenVAS: report saved to %s (%d bytes)", xml_path, len(resp))
    return xml_path
