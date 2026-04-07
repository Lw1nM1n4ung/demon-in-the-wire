"""ScanReport aggregate model."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from wireghost.models.finding import Finding
from wireghost.models.scan import Host
from wireghost.models.severity import Severity


@dataclass
class ScanReport:
    target: str
    hosts: list[Host] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    scan_start: datetime = field(default_factory=datetime.now)
    scan_end: datetime | None = None

    def severity_stats(self) -> dict[Severity, int]:
        """Count findings per severity level."""
        counts: dict[Severity, int] = defaultdict(int)
        for f in self.findings:
            counts[f.severity] += 1
        return dict(counts)

    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        """Group findings by their severity."""
        groups: dict[Severity, list[Finding]] = defaultdict(list)
        for f in self.findings:
            groups[f.severity].append(f)
        return dict(groups)

    def findings_by_host(self) -> dict[str, list[Finding]]:
        """Group findings by host IP."""
        groups: dict[str, list[Finding]] = defaultdict(list)
        for f in self.findings:
            groups[f.host].append(f)
        return dict(groups)

    @property
    def total_open_ports(self) -> int:
        return sum(len(h.open_ports) for h in self.hosts)
