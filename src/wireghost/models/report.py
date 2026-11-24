"""ScanReport aggregate model."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime

from wireghost.models.finding import Finding
from wireghost.models.scan import Host
from wireghost.models.severity import Severity
from wireghost.utils.text import xml_safe


def _clean_value(value):
    """Recursively strip XML-illegal characters from report data."""
    if isinstance(value, str):
        return xml_safe(value)
    if isinstance(value, list):
        return [_clean_value(v) for v in value]
    if isinstance(value, dict):
        return {k: _clean_value(v) for k, v in value.items()}
    if is_dataclass(value) and not isinstance(value, type):
        _clean_dataclass(value)
    return value


def _clean_dataclass(obj) -> None:
    for f in fields(obj):
        setattr(obj, f.name, _clean_value(getattr(obj, f.name)))


@dataclass
class ScanReport:
    target: str
    hosts: list[Host] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    scan_start: datetime = field(default_factory=datetime.now)
    scan_end: datetime | None = None

    def __post_init__(self) -> None:
        self.sanitize()

    def sanitize(self) -> None:
        """Strip XML-illegal characters from everything a report renders.

        Report text ends up in XML-backed formats (DOCX/XLSX) that reject
        control characters, and scanner output is full of them.  Cleaning here
        — and again at render time, since hosts/findings are appended to by
        the pipeline — means every renderer and the CLI get usable strings.
        """
        self.target = xml_safe(self.target)
        for finding in self.findings:
            _clean_dataclass(finding)
        for host in self.hosts:
            _clean_dataclass(host)

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
