"""Finding data model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from wireghost.models.severity import Severity


@dataclass
class Finding:
    source: Literal[
        "nmap_vuln",
        "nuclei",
        "nuclei_external",
        "nettacker",
        "searchsploit",
        "service_enum",
        "wpscan",
        "enum4linux",
        "nikto",
        "netexec",
        "sslscan",
        "snmp_enum",
        "nfs_enum",
        "ldap_enum",
        "katana",
        "msf_scan",
        "getsploit",
        "nvd",
    ]
    host: str
    port: str
    protocol: str
    severity: Severity
    title: str
    description: str
    endpoint: str = "/"
    full_url: str = ""
    template_id: str = ""
    script_id: str = ""
    matched_at: str = ""
    raw_output: str = ""
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    request: str = ""  # HTTP request sent
    response: str = ""  # HTTP response received
    curl_command: str = ""  # curl to reproduce
    cvss: str = ""  # CVSS score/metrics
    cwe: str = ""  # CWE ID
    cve: str = ""  # CVE ID

    def __post_init__(self) -> None:
        # Callers that rebuild findings from the database (report
        # regeneration) pass severity as a plain string, which broke every
        # ``severity.value`` consumer.  Normalise once, here.
        if not isinstance(self.severity, Severity):
            try:
                self.severity = Severity(str(self.severity).lower())
            except ValueError:
                self.severity = Severity.UNKNOWN
