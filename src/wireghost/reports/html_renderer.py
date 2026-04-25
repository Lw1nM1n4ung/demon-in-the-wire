"""Static HTML report renderer."""

from __future__ import annotations

import base64
import logging
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from jinja2 import Environment, FileSystemLoader

from wireghost.models.severity import SEVERITY_ORDER, Severity

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.models.report import ScanReport

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

log = logging.getLogger("wireghost")


def _screenshot_b64(reports_dir: Path, host_ip: str, filename: str) -> str:
    """Read a screenshot PNG and return a base64 data URI, or empty string."""
    png = reports_dir.parent / "ips" / host_ip / "web" / "screenshots" / filename
    if not png.is_file():
        return ""
    try:
        data = png.read_bytes()
        return f"data:image/png;base64,{base64.b64encode(data).decode()}"
    except OSError:
        log.debug("Could not read screenshot %s", png)
        return ""


class HtmlRenderer:
    """Render a ScanReport as a self-contained static HTML page."""

    def render(
        self,
        report: ScanReport,
        config: ScanConfig,
        reports_dir: Path,
    ) -> Path:
        env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=True,
        )
        env.filters["screenshot_b64"] = lambda fname, ip: _screenshot_b64(
            reports_dir, ip, fname
        )
        template = env.get_template("static_report.html.j2")

        stats = report.severity_stats()
        crit_high = stats.get(Severity.CRITICAL, 0) + stats.get(
            Severity.HIGH, 0
        )

        # Sort findings by severity order (critical first)
        sorted_findings = sorted(
            report.findings,
            key=lambda f: SEVERITY_ORDER.get(f.severity, 99),
        )

        recommendations = _build_recommendations(report, stats)

        html = template.render(
            title=config.report_title,
            date=(report.scan_start or datetime.now()).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            target=report.target,
            crit_high=crit_high,
            hosts_count=len(report.hosts),
            open_ports=report.total_open_ports,
            total_findings=len(report.findings),
            critical=stats.get(Severity.CRITICAL, 0),
            high=stats.get(Severity.HIGH, 0),
            medium=stats.get(Severity.MEDIUM, 0),
            findings=sorted_findings,
            hosts=report.hosts,
            recommendations=recommendations,
        )

        out = reports_dir / "summary.html"
        out.write_text(html, encoding="utf-8")
        return out


def _build_recommendations(
    report: ScanReport,
    stats: dict[Severity, int],
) -> list[str]:
    recs: list[str] = []
    crit_high = stats.get(Severity.CRITICAL, 0) + stats.get(
        Severity.HIGH, 0
    )

    if crit_high > 0:
        recs.append(
            f"IMMEDIATE ACTION: Address {crit_high} critical/high severity vulnerabilities"
        )

    ports_seen = {f.port for f in report.findings}
    if ports_seen & {"80", "443", "8080", "8443"}:
        recs.append(
            "WEB SERVICES: Implement WAF, update web applications, and configure security headers"
        )
    if ports_seen & {"22", "21", "23"}:
        recs.append(
            "REMOTE ACCESS: Harden SSH/FTP/Telnet configurations and use key-based authentication"
        )

    recs.extend(
        [
            "NETWORK SECURITY: Implement network segmentation and firewall rules",
            "MONITORING: Deploy SIEM and intrusion detection systems",
            "PATCHING: Establish regular patch management process",
            "ACCESS CONTROL: Implement principle of least privilege",
            "TESTING: Conduct regular security assessments and penetration tests",
        ]
    )
    return recs
