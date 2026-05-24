"""Parser for NetExec (nxc) text output — extracts network enumeration findings."""

from __future__ import annotations

import re

from wireghost.models.finding import Finding
from wireghost.models.severity import Severity


def parse_netexec_output(output: str, host_ip: str = "", protocol: str = "smb") -> list[Finding]:
    """Parse nxc stdout into Finding objects.

    NetExec outputs lines in the format:
        PROTO  IP  PORT  HOSTNAME  [STATUS]  MESSAGE
    where STATUS is [*]=info, [+]=success, [-]=fail, [!]=warn.
    """
    if not output or not output.strip():
        return []

    findings: list[Finding] = []
    dispatch = {
        "smb": _parse_smb,
        "ftp": _parse_ftp,
        "rdp": _parse_rdp,
        "mssql": _parse_mssql,
    }
    parser = dispatch.get(protocol)
    if parser:
        parser(output, host_ip, findings)

    return findings


def _parse_smb(output: str, host: str, findings: list[Finding]) -> None:
    _parse_smb_info(output, host, findings)
    _parse_smb_signing(output, host, findings)
    _parse_smbv1(output, host, findings)
    _parse_smb_null_session(output, host, findings)
    _parse_smb_shares(output, host, findings)
    _parse_smb_ms17010(output, host, findings)


def _parse_smb_info(output: str, host: str, findings: list[Finding]) -> None:
    m = re.search(
        r"\[\*\]\s+(Windows\s+[\d.]+\s+Build\s+\d+[^\(]*)"
        r"\s*\(name:([^)]*)\)\s*\(domain:([^)]*)\)",
        output,
    )
    if m:
        os_info = m.group(1).strip()
        name = m.group(2).strip()
        domain = m.group(3).strip()
        findings.append(
            Finding(
                source="netexec",
                host=host,
                port="445",
                protocol="tcp",
                severity=Severity.INFO,
                title=f"SMB OS Detection: {os_info}",
                description=f"Host: {name}, Domain: {domain}, OS: {os_info}",
                template_id="NXC-SMB-OSINFO",
                tags=["smb", "os-detection"],
            )
        )


def _parse_smb_signing(output: str, host: str, findings: list[Finding]) -> None:
    m = re.search(r"\(signing:(False|True)\)", output)
    if m and m.group(1) == "False":
        findings.append(
            Finding(
                source="netexec",
                host=host,
                port="445",
                protocol="tcp",
                severity=Severity.MEDIUM,
                title="SMB Signing Disabled",
                description="SMB message signing is not required, making the host "
                "susceptible to relay attacks (e.g. ntlmrelayx).",
                template_id="NXC-SMB-SIGNING",
                tags=["smb", "signing", "relay"],
            )
        )


def _parse_smbv1(output: str, host: str, findings: list[Finding]) -> None:
    m = re.search(r"\(SMBv1:(False|True)\)", output)
    if m and m.group(1) == "True":
        findings.append(
            Finding(
                source="netexec",
                host=host,
                port="445",
                protocol="tcp",
                severity=Severity.HIGH,
                title="SMBv1 Enabled",
                description="SMBv1 is enabled on this host. SMBv1 is deprecated and "
                "vulnerable to multiple exploits including EternalBlue (MS17-010).",
                template_id="NXC-SMBV1",
                tags=["smb", "smbv1", "deprecated"],
            )
        )


def _parse_smb_null_session(output: str, host: str, findings: list[Finding]) -> None:
    if re.search(r"\[\+\].*\\.*:\s*\(Guest\)", output) or re.search(
        r"\[\+\].*\\.*:\s*$", output, re.MULTILINE
    ):
        findings.append(
            Finding(
                source="netexec",
                host=host,
                port="445",
                protocol="tcp",
                severity=Severity.HIGH,
                title="SMB Null/Guest Session Allowed",
                description="The target accepts null or guest SMB sessions, "
                "enabling unauthenticated enumeration.",
                template_id="NXC-NULL-SESSION",
                tags=["smb", "null-session", "misconfiguration"],
            )
        )


def _parse_smb_shares(output: str, host: str, findings: list[Finding]) -> None:
    share_lines = re.findall(
        r"SMB\s+\S+\s+\d+\s+\S+\s+(\S+)\s+(READ(?:,WRITE)?|WRITE)\s*(.*)",
        output,
    )
    accessible = []
    for share_name, perms, _remark in share_lines:
        if share_name in ("Share", "-----", "Permissions"):
            continue
        accessible.append(f"{share_name} ({perms})")

    if accessible:
        findings.append(
            Finding(
                source="netexec",
                host=host,
                port="445",
                protocol="tcp",
                severity=Severity.MEDIUM,
                title=f"SMB Accessible Shares ({len(accessible)})",
                description="Shares accessible via null/guest session: " + ", ".join(accessible),
                template_id="NXC-SMB-SHARES",
                tags=["smb", "shares", "enumeration"],
            )
        )


def _parse_smb_ms17010(output: str, host: str, findings: list[Finding]) -> None:
    if re.search(
        r"VULNERABLE.*MS17-010|MS17-010.*VULNERABLE|\[\+\]\s*MS17-010", output, re.I
    ) and not re.search(r"\bnot\s+vulnerable\b", output, re.I):
        findings.append(
            Finding(
                source="netexec",
                host=host,
                port="445",
                protocol="tcp",
                severity=Severity.CRITICAL,
                title="MS17-010 (EternalBlue) — Remote Code Execution",
                description="Host is vulnerable to MS17-010 (EternalBlue). "
                "This allows unauthenticated remote code execution via SMBv1.",
                template_id="NXC-MS17-010",
                cve="CVE-2017-0144",
                cvss="9.8",
                tags=["smb", "ms17-010", "eternalblue", "rce"],
            )
        )


def _parse_ftp(output: str, host: str, findings: list[Finding]) -> None:
    if re.search(r"\[\+\].*Anonymous", output, re.I):
        findings.append(
            Finding(
                source="netexec",
                host=host,
                port="21",
                protocol="tcp",
                severity=Severity.MEDIUM,
                title="FTP Anonymous Login Allowed",
                description="The FTP server allows anonymous login, potentially "
                "exposing files to unauthenticated users.",
                template_id="NXC-FTP-ANON",
                tags=["ftp", "anonymous", "misconfiguration"],
            )
        )

    m = re.search(r"\[\*\]\s*Banner:\s*(.+)", output)
    if m:
        banner = m.group(1).strip()
        findings.append(
            Finding(
                source="netexec",
                host=host,
                port="21",
                protocol="tcp",
                severity=Severity.INFO,
                title=f"FTP Banner: {banner}",
                description=f"FTP service banner: {banner}",
                template_id="NXC-FTP-BANNER",
                tags=["ftp", "banner"],
            )
        )


def _parse_rdp(output: str, host: str, findings: list[Finding]) -> None:
    if re.search(r"nla:\s*False", output, re.I):
        findings.append(
            Finding(
                source="netexec",
                host=host,
                port="3389",
                protocol="tcp",
                severity=Severity.MEDIUM,
                title="RDP Network Level Authentication Disabled",
                description="NLA is disabled on the RDP service. Without NLA, "
                "the attack surface increases (credential brute-force, "
                "BlueKeep-style exploits).",
                template_id="NXC-RDP-NLA",
                tags=["rdp", "nla", "misconfiguration"],
            )
        )

    if re.search(r"GUEST\s+account\s+is\s+enabled", output, re.I):
        findings.append(
            Finding(
                source="netexec",
                host=host,
                port="3389",
                protocol="tcp",
                severity=Severity.MEDIUM,
                title="RDP Guest Account Enabled",
                description="The Guest account is enabled on the RDP service.",
                template_id="NXC-RDP-GUEST",
                tags=["rdp", "guest", "misconfiguration"],
            )
        )


def _parse_mssql(output: str, host: str, findings: list[Finding]) -> None:
    m = re.search(
        r"\[\*\]\s+(Windows\s+[\d.]+\s+Build\s+\d+)\s*\(name:([^)]*)\)",
        output,
    )
    if m:
        os_info = m.group(1).strip()
        name = m.group(2).strip()
        findings.append(
            Finding(
                source="netexec",
                host=host,
                port="1433",
                protocol="tcp",
                severity=Severity.INFO,
                title=f"MSSQL Host: {name} ({os_info})",
                description=f"MSSQL service detected on {name}, OS: {os_info}",
                template_id="NXC-MSSQL-INFO",
                tags=["mssql", "enumeration"],
            )
        )

    if re.search(r"\[\+\]", output) and not re.search(r"\[-\].*Login failed", output, re.I):
        findings.append(
            Finding(
                source="netexec",
                host=host,
                port="1433",
                protocol="tcp",
                severity=Severity.HIGH,
                title="MSSQL Anonymous/Default Login Succeeded",
                description="MSSQL accepted an anonymous or default-credential login.",
                template_id="NXC-MSSQL-AUTH",
                tags=["mssql", "authentication", "misconfiguration"],
            )
        )
