"""DOCX report renderer."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import RGBColor

from wireghost.models.severity import (
    SEVERITY_COLORS,
    SEVERITY_ORDER,
    Severity,
)

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.models.report import ScanReport


def _docx_color(sev: Severity) -> RGBColor:
    """Convert a Severity to a python-docx RGBColor."""
    r, g, b = SEVERITY_COLORS.get(sev, (128, 128, 128))
    return RGBColor(r, g, b)


_SEVERITY_WALK = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


class DocxRenderer:
    """Render a ScanReport as a Microsoft Word document."""

    def render(
        self,
        report: ScanReport,
        config: ScanConfig,
        reports_dir: Path,
    ) -> Path:
        doc = Document()

        self._title_page(doc, config, report)
        self._executive_summary(doc, report)
        self._vuln_breakdown(doc, report)
        self._detailed_findings(doc, report)
        self._recommendations(doc, report)

        out = reports_dir / "security_report.docx"
        doc.save(str(out))
        return out

    # ------------------------------------------------------------------ #
    # Sections
    # ------------------------------------------------------------------ #

    def _title_page(
        self, doc: Document, config: ScanConfig, report: ScanReport
    ) -> None:
        title = doc.add_heading(config.report_title, level=0)
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER

        now = report.scan_start or datetime.now()
        doc.add_paragraph(
            f"Generated on: {now.strftime('%Y-%m-%d at %H:%M:%S')}"
        )
        doc.add_paragraph(f"Target: {report.target}")
        doc.add_page_break()

    def _executive_summary(self, doc: Document, report: ScanReport) -> None:
        doc.add_heading("Executive Summary", level=1)

        stats = report.severity_stats()
        crit_high = stats.get(Severity.CRITICAL, 0) + stats.get(
            Severity.HIGH, 0
        )

        risk_para = doc.add_paragraph()
        risk_para.add_run("Overall Risk Assessment:\n").bold = True

        if crit_high > 0:
            run = risk_para.add_run(
                f"HIGH RISK - {crit_high} critical/high vulnerabilities found\n"
            )
            run.font.color.rgb = _docx_color(Severity.CRITICAL)
        elif stats.get(Severity.MEDIUM, 0) > 0:
            run = risk_para.add_run(
                f"MEDIUM RISK - {stats[Severity.MEDIUM]} medium vulnerabilities found\n"
            )
            run.font.color.rgb = _docx_color(Severity.MEDIUM)
        else:
            run = risk_para.add_run(
                "LOW RISK - No critical or high severity vulnerabilities found\n"
            )
            run.font.color.rgb = _docx_color(Severity.INFO)

        # Stats table
        stats_table = doc.add_table(rows=6, cols=2)
        stats_table.style = "Light Grid Accent 1"

        rows_data = [
            ("Hosts Scanned", str(len(report.hosts))),
            ("Open Ports", str(report.total_open_ports)),
            ("Total Vulnerabilities", str(len(report.findings))),
            ("Critical Findings", str(stats.get(Severity.CRITICAL, 0))),
            ("High Findings", str(stats.get(Severity.HIGH, 0))),
            ("Medium Findings", str(stats.get(Severity.MEDIUM, 0))),
        ]

        for idx, (label, value) in enumerate(rows_data):
            stats_table.cell(idx, 0).text = label
            stats_table.cell(idx, 1).text = value

        doc.add_paragraph()

    def _vuln_breakdown(self, doc: Document, report: ScanReport) -> None:
        doc.add_heading("Vulnerability Breakdown", level=2)

        nmap_vulns = [f for f in report.findings if f.source == "nmap_vuln"]
        nuclei_vulns = [f for f in report.findings if f.source == "nuclei"]

        source_table = doc.add_table(rows=3, cols=4)
        source_table.style = "Light Grid Accent 2"

        headers = source_table.rows[0].cells
        headers[0].text = "Source"
        headers[1].text = "Total"
        headers[2].text = "Critical/High"
        headers[3].text = "Medium/Low"

        for row_idx, (label, vulns) in enumerate(
            [("Nmap Scans", nmap_vulns), ("Nuclei Scans", nuclei_vulns)],
            start=1,
        ):
            cells = source_table.rows[row_idx].cells
            cells[0].text = label
            cells[1].text = str(len(vulns))
            ch = sum(
                1
                for v in vulns
                if v.severity in (Severity.CRITICAL, Severity.HIGH)
            )
            ml = sum(
                1
                for v in vulns
                if v.severity in (Severity.MEDIUM, Severity.LOW)
            )
            cells[2].text = str(ch)
            cells[3].text = str(ml)

        doc.add_page_break()

    def _detailed_findings(self, doc: Document, report: ScanReport) -> None:
        if not report.findings:
            return

        doc.add_heading("Detailed Vulnerability Findings", level=1)

        by_sev = report.findings_by_severity()

        for sev in _SEVERITY_WALK:
            findings = by_sev.get(sev, [])
            if not findings:
                continue

            doc.add_heading(f"{sev.value.upper()} Severity Findings", level=2)

            for i, finding in enumerate(findings, 1):
                doc.add_heading(f"{i}. {finding.title}", level=3)

                # Severity badge
                badge_para = doc.add_paragraph()
                badge_run = badge_para.add_run(
                    f"SEVERITY: {sev.value.upper()} | TYPE: {finding.source.upper()}"
                )
                badge_run.bold = True
                badge_run.font.color.rgb = _docx_color(sev)

                # Detail table
                detail_table = doc.add_table(rows=0, cols=2)
                detail_table.style = "Light Grid Accent 2"

                def _add(label: str, value: str) -> None:
                    if value and value != "N/A":
                        row = detail_table.add_row().cells
                        row[0].text = label
                        row[1].text = value

                _add("Host", finding.host)
                _add("Endpoint", finding.endpoint or "/")
                if finding.port:
                    _add(
                        "Port",
                        f"{finding.port}/{finding.protocol}",
                    )
                _add("Template ID", finding.template_id)
                _add("Description", finding.description)
                _add("Raw Output", finding.raw_output)

                doc.add_paragraph()

    def _recommendations(self, doc: Document, report: ScanReport) -> None:
        doc.add_page_break()
        doc.add_heading("Security Recommendations", level=1)

        recs: list[str] = []
        stats = report.severity_stats()
        crit_high = stats.get(Severity.CRITICAL, 0) + stats.get(
            Severity.HIGH, 0
        )

        if crit_high > 0:
            recs.append(
                f"IMMEDIATE ACTION: Address {crit_high} critical/high severity vulnerabilities"
            )

        # Dynamic recommendations based on findings
        ports_seen = {f.port for f in report.findings}
        if ports_seen & {"80", "443", "8080", "8443"}:
            recs.append(
                "WEB SERVICES: Implement WAF, update web applications, and configure security headers"
            )
        if ports_seen & {"22", "21", "23"}:
            recs.append(
                "REMOTE ACCESS: Harden SSH/FTP/Telnet configurations and use key-based authentication"
            )

        # Static general recommendations
        recs.extend(
            [
                "NETWORK SECURITY: Implement network segmentation and firewall rules",
                "MONITORING: Deploy SIEM and intrusion detection systems",
                "PATCHING: Establish regular patch management process",
                "ACCESS CONTROL: Implement principle of least privilege",
                "TESTING: Conduct regular security assessments and penetration tests",
            ]
        )

        for rec in recs:
            doc.add_paragraph(rec, style="List Bullet")
