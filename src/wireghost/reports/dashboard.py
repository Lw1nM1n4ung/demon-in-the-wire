"""Interactive dashboard renderer."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from jinja2 import Environment, FileSystemLoader

from wireghost.models.severity import SEVERITY_ORDER, Severity

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.models.report import ScanReport

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
_ASSETS_DIR = _TEMPLATE_DIR / "assets"


class DashboardRenderer:
    """Render a ScanReport as a self-contained interactive HTML dashboard."""

    def render(
        self,
        report: ScanReport,
        config: ScanConfig,
        reports_dir: Path,
    ) -> Path:
        # Read CSS and JS assets to embed inline
        css = (_ASSETS_DIR / "style.css").read_text(encoding="utf-8")
        js = (_ASSETS_DIR / "dashboard.js").read_text(encoding="utf-8")

        env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=False,  # we embed raw CSS / JS / JSON
        )
        template = env.get_template("dashboard.html.j2")

        stats = report.severity_stats()

        # Sort findings by severity
        sorted_findings = sorted(
            report.findings,
            key=lambda f: SEVERITY_ORDER.get(f.severity, 99),
        )

        # Build JSON blob for client-side JS
        scan_data = _build_scan_json(report, stats)

        # Prepare template-friendly finding dicts
        findings_dicts = [
            {
                "severity": f.severity.value,
                "source": f.source,
                "host": f.host,
                "port": f.port,
                "title": f.title,
            }
            for f in sorted_findings
        ]

        # Prepare host data for template
        hosts_dicts = []
        for h in report.hosts:
            hosts_dicts.append(
                {
                    "ip": h.ip,
                    "hostname": h.hostname,
                    "open_ports": [
                        {
                            "number": p.number,
                            "protocol": p.protocol,
                            "service": {
                                "name": p.service.name if p.service else "",
                                "product": p.service.product
                                if p.service
                                else "",
                                "version": p.service.version
                                if p.service
                                else "",
                            },
                        }
                        for p in h.open_ports
                    ],
                }
            )

        html = template.render(
            title=config.report_title,
            date=(report.scan_start or datetime.now()).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            target=report.target,
            hosts_count=len(report.hosts),
            open_ports=report.total_open_ports,
            total_findings=len(report.findings),
            critical=stats.get(Severity.CRITICAL, 0),
            high=stats.get(Severity.HIGH, 0),
            medium=stats.get(Severity.MEDIUM, 0),
            findings=findings_dicts,
            hosts=hosts_dicts,
            css=css,
            js=js,
            scan_json=json.dumps(scan_data),
        )

        out = reports_dir / "dashboard.html"
        out.write_text(html, encoding="utf-8")
        return out


def _build_scan_json(
    report: ScanReport,
    stats: dict[Severity, int],
) -> dict:
    """Build a JSON-serializable dict for the client-side JS."""
    return {
        "target": report.target,
        "hosts_count": len(report.hosts),
        "open_ports": report.total_open_ports,
        "total_findings": len(report.findings),
        "severity_stats": {
            sev.value: count for sev, count in stats.items()
        },
        "findings": [
            {
                "severity": f.severity.value,
                "source": f.source,
                "host": f.host,
                "port": f.port,
                "title": f.title,
            }
            for f in report.findings
        ],
    }
