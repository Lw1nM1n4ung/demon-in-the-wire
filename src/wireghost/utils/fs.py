"""Filesystem / output-tree utilities."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class OutputTree:
    """Directory layout for a scan run."""

    base: Path
    live_host_dir: Path
    web_dir: Path
    reports_dir: Path
    ip_base: Path

    def host_dir(self, ip: str) -> Path:
        """Per-host base directory."""
        d = self.ip_base / ip
        d.mkdir(parents=True, exist_ok=True)
        return d

    def host_nmap_xml_dir(self, ip: str) -> Path:
        d = self.host_dir(ip) / "nmap_xml"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def host_web_dir(self, ip: str) -> Path:
        d = self.host_dir(ip) / "web"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def host_vuln_dir(self, ip: str) -> Path:
        d = self.host_dir(ip) / "vuln"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def host_screenshots_dir(self, ip: str) -> Path:
        d = self.host_dir(ip) / "web" / "screenshots"
        d.mkdir(parents=True, exist_ok=True)
        return d


def build_output_tree(output_dir: str | Path, target_name: str) -> OutputTree:
    """Create the full output directory tree and return an :class:`OutputTree`.

    Layout::

        <output_dir>/
            <target_name>/
                live_hosts/
                web/
                reports/
                ips/
    """
    base = Path(output_dir).resolve() / target_name
    live_host_dir = base / "live_hosts"
    web_dir = base / "web"
    reports_dir = base / "reports"
    ip_base = base / "ips"

    for d in (base, live_host_dir, web_dir, reports_dir, ip_base):
        d.mkdir(parents=True, exist_ok=True)

    return OutputTree(
        base=base,
        live_host_dir=live_host_dir,
        web_dir=web_dir,
        reports_dir=reports_dir,
        ip_base=ip_base,
    )
