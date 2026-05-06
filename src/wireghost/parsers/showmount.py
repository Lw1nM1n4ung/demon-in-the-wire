"""Parse showmount -e output into Finding objects."""

from __future__ import annotations

from wireghost.models.finding import Finding
from wireghost.models.severity import Severity


def parse_showmount(stdout: str, host_ip: str) -> list[Finding]:
    """Parse showmount -e output.

    Expected format:
        Export list for 10.0.0.1:
        /home    *
        /backups 10.0.0.0/24
    """
    findings: list[Finding] = []

    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line.startswith("/"):
            continue

        parts = line.split()
        export_path = parts[0]
        allowed = " ".join(parts[1:]) if len(parts) > 1 else ""

        world_open = allowed in ("*", "(everyone)", "")
        severity = Severity.HIGH if world_open else Severity.MEDIUM

        findings.append(Finding(
            source="nfs_enum",
            host=host_ip,
            port="2049",
            protocol="tcp",
            severity=severity,
            title=f"NFS export: {export_path} ({allowed or '*'})",
            description=f"NFS share {export_path} is exported to {allowed or 'everyone'}",
        ))

    return findings
