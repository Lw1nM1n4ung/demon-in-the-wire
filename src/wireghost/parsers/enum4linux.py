"""Parser for enum4linux text output — extracts SMB/NetBIOS enumeration findings."""

from __future__ import annotations

import re

from wireghost.models.finding import Finding
from wireghost.models.severity import SEVERITY_ORDER, Severity


def parse_enum4linux_output(output: str, host_ip: str = "") -> list[Finding]:
    """Parse enum4linux stdout into Finding objects.

    enum4linux outputs structured text with ``======`` section headers.
    We extract: null sessions, users, shares, groups, password policy, OS info.
    """
    if not output or not output.strip():
        return []

    findings: list[Finding] = []

    _parse_null_session(output, host_ip, findings)
    _parse_os_info(output, host_ip, findings)
    _parse_users(output, host_ip, findings)
    _parse_shares(output, host_ip, findings)
    _parse_groups(output, host_ip, findings)
    _parse_password_policy(output, host_ip, findings)

    return findings


def _parse_null_session(output: str, host: str, findings: list[Finding]) -> None:
    if re.search(r"Attempting to make a null session", output, re.I):
        if re.search(r"\[E\].*Could(n.t| not) (establish|connect|create)", output, re.I):
            return
        if re.search(r"\[\+\].*Server allows sessions using username", output, re.I) or \
           re.search(r"\[\+\].*Got a positive name list", output, re.I):
            findings.append(Finding(
                source="enum4linux",
                host=host,
                port="445",
                protocol="tcp",
                severity=Severity.HIGH,
                title="SMB Null Session Allowed",
                description="The target allows anonymous (null) SMB sessions, "
                            "enabling unauthenticated enumeration of users, shares, and system info.",
                tags=["smb", "null-session", "misconfiguration"],
            ))


def _parse_os_info(output: str, host: str, findings: list[Finding]) -> None:
    m = re.search(
        r"OS information on\s+\S+.*?\n(.*?)(?=\n=====|\n\[[\+E\*\]].*Enumerating|\Z)",
        output, re.S | re.I,
    )
    if not m:
        return
    block = m.group(1)
    os_line = re.search(r"OS=\[([^\]]+)\]", block)
    sv_line = re.search(r"server=\[([^\]]+)\]", block, re.I)
    if os_line:
        os_str = os_line.group(1).strip()
        sv_str = sv_line.group(1).strip() if sv_line else ""
        desc = f"Detected OS: {os_str}"
        if sv_str:
            desc += f"\nSamba/Server version: {sv_str}"
        findings.append(Finding(
            source="enum4linux",
            host=host,
            port="445",
            protocol="tcp",
            severity=Severity.INFO,
            title=f"SMB OS Detection: {os_str}",
            description=desc,
            tags=["smb", "os-detection"],
        ))


def _parse_users(output: str, host: str, findings: list[Finding]) -> None:
    users: list[str] = []
    for m in re.finditer(r"user:\[([^\]]+)\]", output):
        u = m.group(1).strip()
        if u and u not in users:
            users.append(u)

    if not users:
        return

    findings.append(Finding(
        source="enum4linux",
        host=host,
        port="445",
        protocol="tcp",
        severity=Severity.MEDIUM,
        title=f"SMB User Enumeration — {len(users)} user(s) found",
        description="Enumerated users via RID cycling / querydispinfo:\n" +
                    "\n".join(f"  - {u}" for u in users),
        tags=["smb", "user-enumeration"],
    ))


def _parse_shares(output: str, host: str, findings: list[Finding]) -> None:
    shares: list[dict[str, str]] = []
    for m in re.finditer(
        r"^\s*(//\S+|\\\\[^\s]+)\s+(Mapping:\s*(\S+))?\s*(Type:\s*(\S+))?",
        output, re.M,
    ):
        name = m.group(1).strip()
        mapping = m.group(3) or ""
        share_type = m.group(5) or ""
        shares.append({"name": name, "mapping": mapping, "type": share_type})

    share_names = re.findall(r"\[\+\]\s+(\S+)\s+Mapping:\s*OK", output)
    for sn in share_names:
        if not any(sn in s["name"] for s in shares):
            shares.append({"name": sn, "mapping": "OK", "type": ""})

    if not shares:
        return

    accessible = [s for s in shares if s.get("mapping", "").upper() == "OK"]
    sev = Severity.MEDIUM if accessible else Severity.LOW

    desc_lines = [f"  {s['name']}  (Mapping: {s['mapping']}, Type: {s['type']})" for s in shares]
    findings.append(Finding(
        source="enum4linux",
        host=host,
        port="445",
        protocol="tcp",
        severity=sev,
        title=f"SMB Share Enumeration — {len(shares)} share(s) found",
        description="Enumerated network shares:\n" + "\n".join(desc_lines),
        tags=["smb", "share-enumeration"],
    ))


def _parse_groups(output: str, host: str, findings: list[Finding]) -> None:
    groups: list[str] = []
    for m in re.finditer(r"group:\[([^\]]+)\]", output):
        g = m.group(1).strip()
        if g and g not in groups:
            groups.append(g)

    if not groups:
        return

    findings.append(Finding(
        source="enum4linux",
        host=host,
        port="445",
        protocol="tcp",
        severity=Severity.LOW,
        title=f"SMB Group Enumeration — {len(groups)} group(s) found",
        description="Enumerated groups:\n" + "\n".join(f"  - {g}" for g in groups),
        tags=["smb", "group-enumeration"],
    ))


def _parse_password_policy(output: str, host: str, findings: list[Finding]) -> None:
    m = re.search(
        r"Password Info for Domain.*?\n(.*?)(?=\n=====|\n\[\*\]|\Z)",
        output, re.S | re.I,
    )
    if not m:
        m = re.search(
            r"password policy.*?\n(.*?)(?=\n=====|\n\[\*\]|\Z)",
            output, re.S | re.I,
        )
    if not m:
        return

    block = m.group(1)
    policies: dict[str, str] = {}
    for line in block.splitlines():
        kv = re.match(r"\s*\[\+\]\s*(.*?):\s*(.*)", line)
        if kv:
            policies[kv.group(1).strip()] = kv.group(2).strip()

    if not policies:
        return

    min_len = policies.get("Minimum password length", "")
    sev = Severity.INFO
    if min_len and min_len.isdigit() and int(min_len) < 8:
        sev = Severity.MEDIUM

    lockout = policies.get("Account Lockout Threshold", "")
    if lockout and lockout.lower() in ("none", "0"):
        if SEVERITY_ORDER.get(Severity.MEDIUM, 99) < SEVERITY_ORDER.get(sev, 99):
            sev = Severity.MEDIUM

    desc_lines = [f"  {k}: {v}" for k, v in policies.items()]
    findings.append(Finding(
        source="enum4linux",
        host=host,
        port="445",
        protocol="tcp",
        severity=sev,
        title="SMB Password Policy Enumeration",
        description="Retrieved domain password policy:\n" + "\n".join(desc_lines),
        tags=["smb", "password-policy"],
    ))
