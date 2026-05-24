"""Network enumeration via NetExec (nxc) — SMB, FTP, RDP, MSSQL."""

from __future__ import annotations

import asyncio
import logging
import shutil
from pathlib import Path
from typing import TYPE_CHECKING

from wireghost.models.finding import Finding
from wireghost.parsers.netexec import parse_netexec_output
from wireghost.utils.process import run_tool

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.models.scan import Host
    from wireghost.utils.fs import OutputTree

log = logging.getLogger("wireghost")

_SERVICE_PROTOS: dict[str, str] = {
    "microsoft-ds": "smb",
    "netbios-ssn": "smb",
    "ftp": "ftp",
    "ms-wbt-server": "rdp",
    "ms-sql-s": "mssql",
}

_PORT_FALLBACK: dict[int, str] = {
    139: "smb",
    445: "smb",
    21: "ftp",
    3389: "rdp",
    1433: "mssql",
}


async def enumerate_netexec(
    host: Host,
    config: ScanConfig,
    tree: OutputTree,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """Run nxc against a host for each supported protocol with open ports."""
    async with sem:
        if config.skip_netexec:
            return []

        if not shutil.which("nxc"):
            log.info("[%s] nxc not installed — skipping NetExec enumeration", host.ip)
            return []

        protos: set[str] = set()
        for p in host.open_ports:
            svc = p.service_name
            proto = _SERVICE_PROTOS.get(svc)
            if proto:
                protos.add(proto)
            elif not svc and p.number in _PORT_FALLBACK:
                protos.add(_PORT_FALLBACK[p.number])

        if not protos:
            return []

        vuln_dir = tree.host_vuln_dir(host.ip)
        all_findings: list[Finding] = []
        seen_ids: set[str] = set()

        for proto in sorted(protos):
            findings = await _run_proto(proto, host.ip, config, vuln_dir)
            for f in findings:
                if f.template_id and f.template_id in seen_ids:
                    continue
                if f.template_id:
                    seen_ids.add(f.template_id)
                all_findings.append(f)

        log.info("[%s] netexec: %d finding(s)", host.ip, len(all_findings))
        return all_findings


async def _run_proto(
    proto: str,
    ip: str,
    config: ScanConfig,
    vuln_dir: Path,
) -> list[Finding]:
    """Run nxc commands for a single protocol and parse the output."""
    findings: list[Finding] = []
    timeout = min(int(config.tool_timeout), 120)

    if proto == "smb":
        result = await run_tool(
            [
                "nxc",
                "smb",
                ip,
                "-u",
                "",
                "-p",
                "",
                "--no-bruteforce",
                "--shares",
                "--users",
                "--pass-pol",
                "--timeout",
                "30",
            ],
            timeout=timeout,
            label=f"nxc smb {ip}",
        )
        output = (result.stdout or "") + (result.stderr or "")
        if output.strip():
            (vuln_dir / "nxc_smb.txt").write_text(output, encoding="utf-8")
        findings.extend(parse_netexec_output(output, host_ip=ip, protocol="smb"))

        result = await run_tool(
            [
                "nxc",
                "smb",
                ip,
                "-u",
                "",
                "-p",
                "",
                "--no-bruteforce",
                "-M",
                "ms17-010",
                "--timeout",
                "30",
            ],
            timeout=timeout,
            label=f"nxc smb ms17-010 {ip}",
        )
        output = (result.stdout or "") + (result.stderr or "")
        if output.strip():
            (vuln_dir / "nxc_smb_ms17010.txt").write_text(output, encoding="utf-8")
        findings.extend(parse_netexec_output(output, host_ip=ip, protocol="smb"))

    elif proto == "ftp":
        result = await run_tool(
            ["nxc", "ftp", ip, "--no-bruteforce", "--timeout", "30"],
            timeout=timeout,
            label=f"nxc ftp {ip}",
        )
        output = (result.stdout or "") + (result.stderr or "")
        if output.strip():
            (vuln_dir / "nxc_ftp.txt").write_text(output, encoding="utf-8")
        findings.extend(parse_netexec_output(output, host_ip=ip, protocol="ftp"))

    elif proto == "rdp":
        result = await run_tool(
            ["nxc", "rdp", ip, "--no-bruteforce", "--timeout", "30"],
            timeout=timeout,
            label=f"nxc rdp {ip}",
        )
        output = (result.stdout or "") + (result.stderr or "")
        if output.strip():
            (vuln_dir / "nxc_rdp.txt").write_text(output, encoding="utf-8")
        findings.extend(parse_netexec_output(output, host_ip=ip, protocol="rdp"))

    elif proto == "mssql":
        result = await run_tool(
            ["nxc", "mssql", ip, "--no-bruteforce", "--timeout", "30"],
            timeout=timeout,
            label=f"nxc mssql {ip}",
        )
        output = (result.stdout or "") + (result.stderr or "")
        if output.strip():
            (vuln_dir / "nxc_mssql.txt").write_text(output, encoding="utf-8")
        findings.extend(parse_netexec_output(output, host_ip=ip, protocol="mssql"))

    return findings
