"""Finding data model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from wireghost.models.severity import Severity


@dataclass
class Finding:
    source: Literal["nmap_vuln", "nuclei", "nettacker", "searchsploit"]
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
