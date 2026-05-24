"""Metasploit auxiliary/scanner module execution — service-routed per host."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from wireghost.models.finding import Finding
from wireghost.models.severity import Severity
from wireghost.parsers.msf import parse_msf_output
from wireghost.utils.process import run_tool

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.models.scan import Host
    from wireghost.utils.fs import OutputTree

log = logging.getLogger("wireghost")


# ---------------------------------------------------------------------------
# Module descriptor
# ---------------------------------------------------------------------------


@dataclass
class MsfModule:
    path: str
    severity: Severity
    options: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Static service → module map (curated, high-value scanners)
# ---------------------------------------------------------------------------

_SERVICE_MODULES: dict[str, list[MsfModule]] = {
    "ssh": [
        MsfModule("auxiliary/scanner/ssh/ssh_version", Severity.INFO),
        MsfModule(
            "auxiliary/scanner/ssh/ssh_enumusers",
            Severity.MEDIUM,
            {
                "USER_FILE": "/opt/metasploit-framework/data/wordlists/unix_users.txt",
                "THRESHOLD": "10",
            },
        ),
    ],
    "microsoft-ds": [
        MsfModule("auxiliary/scanner/smb/smb_version", Severity.INFO),
        MsfModule("auxiliary/scanner/smb/smb_ms17_010", Severity.CRITICAL),
        MsfModule(
            "auxiliary/scanner/smb/smb_login",
            Severity.HIGH,
            {
                "BLANK_PASSWORDS": "true",
                "USER_AS_PASS": "false",
            },
        ),
    ],
    "netbios-ssn": [
        MsfModule("auxiliary/scanner/smb/smb_version", Severity.INFO),
        MsfModule("auxiliary/scanner/smb/smb_ms17_010", Severity.CRITICAL),
    ],
    "ftp": [
        MsfModule("auxiliary/scanner/ftp/ftp_version", Severity.INFO),
        MsfModule("auxiliary/scanner/ftp/anonymous", Severity.HIGH),
    ],
    "http": [
        MsfModule("auxiliary/scanner/http/http_version", Severity.INFO),
        MsfModule(
            "auxiliary/scanner/http/tomcat_mgr_login",
            Severity.CRITICAL,
            {
                "BLANK_PASSWORDS": "true",
                "STOP_ON_SUCCESS": "true",
                "HttpUsername": "tomcat",
                "HttpPassword": "tomcat",
            },
        ),
        MsfModule("auxiliary/scanner/http/jboss_vulnscan", Severity.HIGH),
        MsfModule("auxiliary/scanner/http/jenkins_enum", Severity.MEDIUM),
    ],
    "https": [
        MsfModule("auxiliary/scanner/http/http_version", Severity.INFO),
        MsfModule(
            "auxiliary/scanner/http/tomcat_mgr_login",
            Severity.CRITICAL,
            {
                "BLANK_PASSWORDS": "true",
                "STOP_ON_SUCCESS": "true",
                "SSL": "true",
                "HttpUsername": "tomcat",
                "HttpPassword": "tomcat",
            },
        ),
    ],
    "http-proxy": [
        MsfModule("auxiliary/scanner/http/http_version", Severity.INFO),
    ],
    "mysql": [
        MsfModule("auxiliary/scanner/mysql/mysql_version", Severity.INFO),
        MsfModule(
            "auxiliary/scanner/mysql/mysql_login",
            Severity.HIGH,
            {"BLANK_PASSWORDS": "true", "USERNAME": "root"},
        ),
    ],
    "postgresql": [
        MsfModule("auxiliary/scanner/postgres/postgres_version", Severity.INFO),
        MsfModule(
            "auxiliary/scanner/postgres/postgres_login",
            Severity.HIGH,
            {"BLANK_PASSWORDS": "true", "USERNAME": "postgres"},
        ),
    ],
    "ms-sql-s": [
        MsfModule("auxiliary/scanner/mssql/mssql_ping", Severity.INFO),
        MsfModule(
            "auxiliary/scanner/mssql/mssql_login",
            Severity.HIGH,
            {"BLANK_PASSWORDS": "true", "USERNAME": "sa"},
        ),
    ],
    "ms-wbt-server": [
        MsfModule("auxiliary/scanner/rdp/rdp_scanner", Severity.INFO),
        MsfModule("auxiliary/scanner/rdp/cve_2019_0708_bluekeep", Severity.CRITICAL),
    ],
    "vnc": [
        MsfModule("auxiliary/scanner/vnc/vnc_none_auth", Severity.CRITICAL),
    ],
    "telnet": [
        MsfModule("auxiliary/scanner/telnet/telnet_version", Severity.INFO),
    ],
    "redis": [
        MsfModule("auxiliary/scanner/redis/redis_server", Severity.HIGH),
    ],
    "mongodb": [
        MsfModule(
            "auxiliary/scanner/mongodb/mongodb_login", Severity.HIGH, {"BLANK_PASSWORDS": "true"}
        ),
    ],
    "smtp": [
        MsfModule("auxiliary/scanner/smtp/smtp_version", Severity.INFO),
        MsfModule("auxiliary/scanner/smtp/smtp_enum", Severity.MEDIUM),
    ],
    "ldap": [
        MsfModule(
            "auxiliary/scanner/ldap/ldap_search",
            Severity.MEDIUM,
            {"BASE_DN": "", "ANONYMOUS_LOGIN": "true"},
        ),
    ],
    "nfs": [
        MsfModule("auxiliary/scanner/nfs/nfsmount", Severity.HIGH),
    ],
    "domain": [
        MsfModule("auxiliary/scanner/dns/dns_amp", Severity.MEDIUM),
    ],
    "imap": [
        MsfModule("auxiliary/scanner/imap/imap_version", Severity.INFO),
    ],
    "pop3": [
        MsfModule("auxiliary/scanner/pop3/pop3_version", Severity.INFO),
    ],
    "snmp": [
        MsfModule("auxiliary/scanner/snmp/snmp_enum", Severity.HIGH),
    ],
}


# ---------------------------------------------------------------------------
# Dynamic metadata lookup — supplements the static map
# ---------------------------------------------------------------------------

_MSF_BLOCKLIST: set[str] = {
    "auxiliary/scanner/http/dir_scanner",
    "auxiliary/scanner/http/brute_dirs",
    "auxiliary/scanner/http/files_dir",
    "auxiliary/scanner/ssh/ssh_login",
    "auxiliary/scanner/http/http_login",
    "auxiliary/scanner/smb/smb_lookupsid",
    "auxiliary/scanner/http/apache_mod_cgi_bash_env",
    "auxiliary/scanner/http/crawler",
    "auxiliary/scanner/http/dir_listing",
}

_MSF_SEVERITY_MAP: dict[str, Severity] = {
    "excellent": Severity.CRITICAL,
    "great": Severity.HIGH,
    "good": Severity.MEDIUM,
    "normal": Severity.LOW,
    "low": Severity.INFO,
    "manual": Severity.INFO,
}


def _lookup_metadata_modules(
    service_names: set[str],
    metadata_path: str,
) -> list[MsfModule]:
    """Query MSF metadata for scanner modules matching detected services."""
    meta_file = Path(metadata_path)
    if not meta_file.exists():
        return []

    try:
        metadata = json.loads(meta_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("Failed to load MSF metadata from %s: %s", meta_file, exc)
        return []

    modules: list[MsfModule] = []
    seen_paths: set[str] = set()

    for _key, mod in metadata.items():
        fullname = mod.get("fullname", "")
        if not fullname.startswith("auxiliary/scanner/"):
            continue
        if fullname in _MSF_BLOCKLIST or fullname in seen_paths:
            continue

        mod_services = set(mod.get("autofilter_services", []))
        if not mod_services & service_names:
            continue

        rank_name = mod.get("rank_name", "normal")
        severity = _MSF_SEVERITY_MAP.get(rank_name, Severity.INFO)

        matched = mod_services & service_names
        seen_paths.add(fullname)
        modules.append(
            MsfModule(
                path=fullname,
                severity=severity,
                options={"_rport": str(mod.get("rport", "")), "_services": ",".join(matched)},
            )
        )

    return modules


# ---------------------------------------------------------------------------
# Module selection (static + dynamic, deduplicated)
# ---------------------------------------------------------------------------


def _select_modules(
    host: Host,
    config: ScanConfig,
) -> list[tuple[MsfModule, int]]:
    """Return (module, port_number) pairs for this host."""
    selected: list[tuple[MsfModule, int]] = []
    seen_keys: set[str] = set()
    service_names: set[str] = set()

    for port in host.open_ports:
        svc = port.service_name
        if not svc:
            continue
        service_names.add(svc)

        for mod in _SERVICE_MODULES.get(svc, []):
            key = f"{mod.path}:{port.number}"
            if key not in seen_keys:
                seen_keys.add(key)
                selected.append((mod, port.number))

    dynamic = _lookup_metadata_modules(service_names, config.msf_metadata_path)
    for mod in dynamic:
        mod_services = (
            set(mod.options.get("_services", "").split(","))
            if mod.options.get("_services")
            else service_names
        )
        for port in host.open_ports:
            svc = port.service_name
            if not svc or svc not in mod_services:
                continue
            key = f"{mod.path}:{port.number}"
            if key not in seen_keys:
                seen_keys.add(key)
                selected.append((mod, port.number))
                break

    return selected


# ---------------------------------------------------------------------------
# RC script generation
# ---------------------------------------------------------------------------


def _build_rc_script(
    host_ip: str,
    modules: list[tuple[MsfModule, int]],
    spool_path: Path,
) -> str:
    """Generate an MSF resource script for a single host."""
    lines: list[str] = [
        f"spool {spool_path}",
        "setg THREADS 5",
        "setg ConnectTimeout 10",
        "",
    ]
    for mod, port_num in modules:
        lines.append(f"# ===MODULE:{mod.path}:{port_num}===")
        lines.append(f"use {mod.path}")
        lines.append(f"set RHOSTS {host_ip}")
        lines.append(f"set RPORT {port_num}")
        for opt_key, opt_val in mod.options.items():
            if opt_key.startswith("_"):
                continue
            if opt_val:
                lines.append(f"set {opt_key} {opt_val}")
        lines.append("run")
        lines.append("# ===END_MODULE===")
        lines.append("")

    lines.append("spool off")
    lines.append("exit")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def scan_msf(
    host: Host,
    config: ScanConfig,
    tree: OutputTree,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """Run Metasploit auxiliary/scanner modules against a host."""
    if config.skip_msf_scan:
        return []
    if not shutil.which("msfconsole"):
        log.info("[%s] msfconsole not found — skipping MSF scan", host.ip)
        return []
    if not host.open_ports:
        return []

    modules = _select_modules(host, config)
    if not modules:
        return []

    async with sem:
        vuln_dir = tree.host_vuln_dir(host.ip)
        spool_path = vuln_dir / "msf_spool.txt"
        rc_path = vuln_dir / "msf_scan.rc"

        rc_content = _build_rc_script(host.ip, modules, spool_path)
        rc_path.write_text(rc_content, encoding="utf-8")

        log.info(
            "[%s] MSF scan: %d module(s) across %d port(s)",
            host.ip,
            len(modules),
            len({p for _, p in modules}),
        )

        result = await run_tool(
            ["msfconsole", "-q", "-r", str(rc_path)],
            timeout=min(600, int(config.tool_timeout)),
            label=f"msfconsole {host.ip}",
        )

        if result.returncode != 0:
            log.warning("[%s] msfconsole exited with rc=%d", host.ip, result.returncode)

        output = ""
        if spool_path.exists():
            output = spool_path.read_text(encoding="utf-8", errors="replace")
        elif result.stdout:
            output = result.stdout

        if not output.strip():
            if result.returncode != 0:
                log.warning(
                    "[%s] msfconsole produced no output (rc=%d)", host.ip, result.returncode
                )
            return []

        findings = parse_msf_output(output, host.ip)
        log.info("[%s] MSF scan: %d finding(s)", host.ip, len(findings))
        return findings
