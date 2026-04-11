"""Finding data model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from wireghost.models.severity import Severity


@dataclass
class Finding:
    source: Literal["nmap_vuln", "nuclei", "nettacker", "searchsploit", "openvas", "service_enum"]
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
    request: str = ""       # HTTP request sent
    response: str = ""      # HTTP response received
    curl_command: str = ""  # curl to reproduce
    cvss: str = ""          # CVSS score/metrics
    cwe: str = ""           # CWE ID
    cve: str = ""           # CVE ID
