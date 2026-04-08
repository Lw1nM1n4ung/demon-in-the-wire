"""Interactive dashboard renderer."""

from __future__ import annotations

import json
from collections import defaultdict
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

        # Compute risk level
        risk_level = _compute_risk_level(stats)

        # Compute source counts
        source_counts = _compute_source_counts(report)

        # Deduplicate technologies across all hosts
        technologies = _collect_technologies(report)

        # Unique source names for the filter dropdown
        sources = sorted(source_counts.keys())

        # Build JSON blob for client-side JS
        scan_data = _build_scan_json(report, stats, source_counts)

        # Prepare template-friendly finding dicts with HTML-escaped evidence
        from html import escape as html_escape

        findings_dicts = [
            {
                "severity": f.severity.value,
                "source": f.source,
                "host": html_escape(f.host),
                "port": html_escape(f.port),
                "title": html_escape(f.title),
                "description": html_escape(f.description),
                "request": html_escape(f.request),
                "response": html_escape(f.response),
                "curl_command": html_escape(f.curl_command),
                "cvss": html_escape(f.cvss),
                "cwe": html_escape(f.cwe),
                "cve": html_escape(f.cve),
                "references": [html_escape(r) for r in f.references],
                "template_id": html_escape(f.template_id),
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
                    "technologies": [
                        {
                            "name": t.name,
                            "version": t.version,
                        }
                        for t in getattr(h, "technologies", [])
                    ],
                }
            )

        # Prepare technology dicts for template
        tech_dicts = [
            {"name": t.name, "version": t.version}
            for t in technologies
        ]

        # Separate known exploits (searchsploit findings)
        exploits = [f for f in findings_dicts if f["source"] == "searchsploit"]

        html = template.render(
            title=config.report_title,
            date=(report.scan_start or datetime.now()).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            target=report.target,
            hosts_count=len(report.hosts),
            open_ports=report.total_open_ports,
            total_findings=len(report.findings),
            tech_count=len(technologies),
            critical=stats.get(Severity.CRITICAL, 0),
            high=stats.get(Severity.HIGH, 0),
            medium=stats.get(Severity.MEDIUM, 0),
            risk_level=risk_level,
            findings=findings_dicts,
            exploits=exploits,
            hosts=hosts_dicts,
            technologies=tech_dicts,
            sources=sources,
            css=css,
            js=js,
            scan_json=json.dumps(scan_data),
        )

        out = reports_dir / "dashboard.html"
        out.write_text(html, encoding="utf-8")
        return out


def _compute_risk_level(stats: dict[Severity, int]) -> str:
    """Determine overall risk level from severity stats."""
    if stats.get(Severity.CRITICAL, 0) > 0:
        return "CRITICAL"
    if stats.get(Severity.HIGH, 0) > 0:
        return "HIGH"
    if stats.get(Severity.MEDIUM, 0) > 0:
        return "MEDIUM"
    return "LOW"


def _compute_source_counts(report: ScanReport) -> dict[str, int]:
    """Count findings per source."""
    counts: dict[str, int] = defaultdict(int)
    for f in report.findings:
        counts[f.source] += 1
    return dict(counts)


def _collect_technologies(report: ScanReport) -> list:
    """Collect and deduplicate technologies from all hosts."""
    seen: set[tuple[str, str]] = set()
    techs = []
    for h in report.hosts:
        for t in getattr(h, "technologies", []):
            key = (t.name, t.version)
            if key not in seen:
                seen.add(key)
                techs.append(t)
    return techs


def _build_scan_json(
    report: ScanReport,
    stats: dict[Severity, int],
    source_counts: dict[str, int],
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
        "source_counts": source_counts,
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
