"""DOCX report renderer — professional VA report format."""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.opc.constants import RELATIONSHIP_TYPE as RT
from docx.shared import Emu, Inches, Pt, RGBColor
from lxml import etree

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.models.finding import Finding
    from wireghost.models.report import ScanReport
    from wireghost.models.scan import Host

log = logging.getLogger("wireghost")


def _make_anchor_image(
    part, image_path: str, width: int, height: int,
    pos_h_from: str, pos_h_offset: int,
    pos_v_from: str, pos_v_offset: int,
) -> etree._Element:
    """Create a wp:anchor element for a floating image, matching reference doc format."""
    # Add image relationship
    rel_id = part.relate_to(
        part.package.get_or_add_image_part(image_path),
        RT.IMAGE,
    )

    nsmap = {
        'wp': 'http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing',
        'r': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships',
        'a': 'http://schemas.openxmlformats.org/drawingml/2006/main',
        'pic': 'http://schemas.openxmlformats.org/drawingml/2006/picture',
    }

    anchor_xml = (
        '<wp:anchor distT="0" distB="0" distL="114300" distR="114300" '
        'simplePos="0" relativeHeight="0" behindDoc="0" locked="0" '
        'layoutInCell="1" allowOverlap="1" '
        'xmlns:wp="{wp}" xmlns:r="{r}" xmlns:a="{a}" xmlns:pic="{pic}">'
        '  <wp:simplePos x="0" y="0"/>'
        '  <wp:positionH relativeFrom="{pos_h_from}">'
        '    <wp:posOffset>{pos_h_offset}</wp:posOffset>'
        '  </wp:positionH>'
        '  <wp:positionV relativeFrom="{pos_v_from}">'
        '    <wp:posOffset>{pos_v_offset}</wp:posOffset>'
        '  </wp:positionV>'
        '  <wp:extent cx="{cx}" cy="{cy}"/>'
        '  <wp:wrapNone/>'
        '  <wp:docPr id="1" name="Picture"/>'
        '  <a:graphic>'
        '    <a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
        '      <pic:pic>'
        '        <pic:nvPicPr>'
        '          <pic:cNvPr id="0" name="Picture"/>'
        '          <pic:cNvPicPr/>'
        '        </pic:nvPicPr>'
        '        <pic:blipFill>'
        '          <a:blip r:embed="{rel_id}"/>'
        '          <a:stretch><a:fillRect/></a:stretch>'
        '        </pic:blipFill>'
        '        <pic:spPr>'
        '          <a:xfrm>'
        '            <a:off x="0" y="0"/>'
        '            <a:ext cx="{cx}" cy="{cy}"/>'
        '          </a:xfrm>'
        '          <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>'
        '        </pic:spPr>'
        '      </pic:pic>'
        '    </a:graphicData>'
        '  </a:graphic>'
        '</wp:anchor>'
    ).format(
        cx=width, cy=height,
        pos_h_from=pos_h_from, pos_h_offset=pos_h_offset,
        pos_v_from=pos_v_from, pos_v_offset=pos_v_offset,
        rel_id=rel_id,
        **nsmap,
    )

    return etree.fromstring(anchor_xml)

# Brand color from reference document
_GREEN = RGBColor(0x00, 0x6D, 0x38)
_RED = RGBColor(0xFF, 0x00, 0x00)
_BLACK = RGBColor(0x00, 0x00, 0x00)


def _apply_styles(doc: Document) -> None:
    """Set document-wide font and heading styles to match reference."""
    # Normal: Calibri 11pt black
    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(11)
    normal.font.color.rgb = _BLACK

    # Heading 1: 14pt bold #006D38
    h1 = doc.styles["Heading 1"]
    h1.font.name = "Calibri"
    h1.font.size = Pt(14)
    h1.font.bold = True
    h1.font.color.rgb = _GREEN

    # Heading 2: 13pt bold #006D38
    h2 = doc.styles["Heading 2"]
    h2.font.name = "Calibri"
    h2.font.size = Pt(13)
    h2.font.bold = True
    h2.font.color.rgb = _GREEN

    # Heading 3: 12pt bold #006D38
    h3 = doc.styles["Heading 3"]
    h3.font.name = "Calibri"
    h3.font.size = Pt(12)
    h3.font.bold = True
    h3.font.color.rgb = _GREEN


_DISCLAIMER = (
    "Nothing contained in this document shall be construed as conferring "
    "by implication, estoppels, or otherwise, any license or right to any "
    "copyright, patent or trademark of the authors or any third party. "
    "The document is provided on an 'AS IS' basis.\n\n"
    "The findings in this report reflect the conditions found during the "
    "assessment period (vulnerability / exploit reported to the date of "
    "the report and cannot guarantee any future compliance). Security is "
    "a continuous process and new vulnerabilities may be discovered after "
    "this assessment."
)


def _group_hosts_by_subnet(hosts: list[Host]) -> dict[str, list[Host]]:
    """Group hosts by their /24 subnet prefix."""
    subnets: dict[str, list[Host]] = defaultdict(list)
    for h in hosts:
        parts = h.ip.rsplit(".", 1)
        subnet = f"{parts[0]}.0/24" if len(parts) == 2 else h.ip
        subnets[subnet].append(h)
    return dict(sorted(subnets.items()))


def _group_findings_by_host(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Group findings by host IP."""
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        grouped[f.host].append(f)
    return dict(sorted(grouped.items()))


class DocxRenderer:
    """Render a ScanReport as a professional VA report (DOCX)."""

    def render(
        self,
        report: ScanReport,
        config: ScanConfig,
        reports_dir: Path,
    ) -> Path:
        doc = Document()
        _apply_styles(doc)

        logo, header_logo = self._resolve_logos(config)

        self._cover_page(doc, config, report, logo)
        self._executive_summary(doc, config, report)
        self._target_subnets(doc, report)
        self._live_hosts(doc, report)
        self._open_ports(doc, report)
        self._web_screenshots(doc, report, reports_dir)
        self._identified_issues(doc, report)

        self._add_header_logos(doc, logo, header_logo)

        out = reports_dir / "security_report.docx"
        doc.save(str(out))
        return out

    @staticmethod
    def _resolve_logos(config: ScanConfig) -> tuple[Path | None, Path | None]:
        """Resolve logo paths. Custom from config/env, or built-in defaults."""
        assets = Path(__file__).parent / "assets"
        default_logo = assets / "logo.png"
        default_header = assets / "logo_header.png"

        # Custom logo overrides both
        custom = getattr(config, "logo_path", None)
        if custom and Path(custom).is_file():
            return Path(custom), Path(custom)

        # Use built-in defaults
        logo = default_logo if default_logo.is_file() else None
        header = default_header if default_header.is_file() else None
        return logo, header

    @staticmethod
    def _add_header_logos(
        doc: Document, logo: Path | None, header_logo: Path | None,
    ) -> None:
        """Add floating logos to page header matching reference positioning."""
        if not logo and not header_logo:
            return
        section = doc.sections[0]
        section.different_first_page_header_footer = True  # cover page: no header
        header = section.header
        header.is_linked_to_previous = False
        hp = header.paragraphs[0] if header.paragraphs else header.add_paragraph()

        # LEFT: main logo (logo.png, 0.92x0.52in) at margin left
        if logo:
            anchor = _make_anchor_image(
                header.part, str(logo),
                width=Emu(838200), height=Emu(472440),      # 0.92 x 0.52 in
                pos_h_from="margin", pos_h_offset=-695960,   # left side
                pos_v_from="paragraph", pos_v_offset=-291465,
            )
            run = hp.add_run()
            run._element.append(anchor)

        # RIGHT: secondary logo (logo_header.png, 1.03x0.58in) at column right
        if header_logo:
            anchor = _make_anchor_image(
                header.part, str(header_logo),
                width=Emu(945515), height=Emu(531495),     # 1.03 x 0.58 in
                pos_h_from="column", pos_h_offset=5763260,  # right side
                pos_v_from="paragraph", pos_v_offset=-296545,
            )
            run = hp.add_run()
            run._element.append(anchor)

    # ------------------------------------------------------------------ #

    def _cover_page(
        self, doc: Document, config: ScanConfig, report: ScanReport,
        logo: Path | None = None,
    ) -> None:
        # Cover logo (floating, ~2.5 x 1.41 inches, centered on margin)
        if logo:
            logo_para = doc.add_paragraph()
            anchor = _make_anchor_image(
                doc.part, str(logo),
                width=Emu(2286000), height=Emu(1288415),  # 2.50 x 1.41 in
                pos_h_from="margin", pos_h_offset=1840230,  # centered (exact from reference)
                pos_v_from="margin", pos_v_offset=0,
            )
            run = logo_para.add_run()
            run._element.append(anchor)

        doc.add_paragraph()

        title = doc.add_paragraph()
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = title.add_run(report.target)
        run.bold = True
        run.font.size = Pt(22)

        subtitle = doc.add_paragraph()
        subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = subtitle.add_run("Vulnerability Assessment Report")
        run.bold = True
        run.font.size = Pt(22)

        doc.add_paragraph()

        # Disclaimer
        doc.add_paragraph()
        disc_title = doc.add_paragraph()
        disc_run = disc_title.add_run("DISCLAIMER")
        disc_run.bold = True
        disc_run.font.size = Pt(14)
        disc_run.font.color.rgb = _RED
        doc.add_paragraph(_DISCLAIMER)

        doc.add_paragraph()

        # Prepared / Reviewed / Approved / Date
        now = report.scan_start or datetime.now()
        meta = doc.add_paragraph()
        meta.add_run("Prepared By: ").bold = True
        meta.add_run(getattr(config, "prepared_by", "Security Team"))
        meta.add_run("\n")
        meta.add_run("Reviewed By: ").bold = True
        meta.add_run(getattr(config, "reviewed_by", ""))
        meta.add_run("\n")
        meta.add_run("Approved By: ").bold = True
        meta.add_run(getattr(config, "approved_by", ""))
        meta.add_run("\n")
        meta.add_run("Date: ").bold = True
        meta.add_run(now.strftime("%d %b %Y"))

        doc.add_page_break()

    def _executive_summary(
        self, doc: Document, config: ScanConfig, report: ScanReport
    ) -> None:
        doc.add_heading("Executive Summary", level=1)
        doc.add_paragraph(
            f"A comprehensive Vulnerability Assessment was conducted on "
            f"{report.target} to identify existing vulnerabilities, "
            f"misconfigurations and known threats."
        )

        stats = report.severity_stats()
        from wireghost.models.severity import Severity

        summary = doc.add_paragraph()
        summary.add_run("Assessment Results:\n").bold = True
        summary.add_run(f"  Hosts Scanned: {len(report.hosts)}\n")
        summary.add_run(f"  Open Ports: {report.total_open_ports}\n")
        summary.add_run(f"  Total Findings: {len(report.findings)}\n")
        summary.add_run(f"  Critical: {stats.get(Severity.CRITICAL, 0)}\n")
        summary.add_run(f"  High: {stats.get(Severity.HIGH, 0)}\n")
        summary.add_run(f"  Medium: {stats.get(Severity.MEDIUM, 0)}\n")
        summary.add_run(f"  Low: {stats.get(Severity.LOW, 0)}\n")
        summary.add_run(f"  Info: {stats.get(Severity.INFO, 0)}\n")

    def _target_subnets(self, doc: Document, report: ScanReport) -> None:
        doc.add_heading("Target Subnets", level=1)
        doc.add_paragraph(
            "Vulnerability Assessment was conducted on the following targets."
        )

        subnets = _group_hosts_by_subnet(report.hosts)
        table = doc.add_table(rows=1, cols=2)
        table.style = "Light Grid Accent 1"
        table.rows[0].cells[0].text = "Subnets"
        table.rows[0].cells[1].text = "Zone"

        if subnets:
            for subnet, hosts in subnets.items():
                row = table.add_row().cells
                row[0].text = subnet
                row[1].text = report.target
        else:
            row = table.add_row().cells
            row[0].text = report.target
            row[1].text = "0"

    def _live_hosts(self, doc: Document, report: ScanReport) -> None:
        doc.add_heading("3. Identified Live Hosts", level=1)
        doc.add_paragraph("The following IPs are alive in the subnets.")

        subnets = _group_hosts_by_subnet(report.hosts)

        table = doc.add_table(rows=1, cols=2)
        table.style = "Light Grid Accent 1"
        table.rows[0].cells[0].text = "Subnets"
        table.rows[0].cells[1].text = "Hosts"

        for subnet, hosts in subnets.items():
            first = True
            for h in sorted(hosts, key=lambda x: tuple(int(p) for p in x.ip.split("."))):
                row = table.add_row().cells
                row[0].text = subnet if first else ""
                row[1].text = h.ip
                first = False

        if not subnets:
            row = table.add_row().cells
            row[0].text = report.target
            row[1].text = "No Live Host"

    def _open_ports(self, doc: Document, report: ScanReport) -> None:
        doc.add_heading("4. Open Ports", level=1)

        subnets = _group_hosts_by_subnet(report.hosts)
        section_num = 4
        sub_num = 1

        for subnet, hosts in subnets.items():
            doc.add_heading(
                f"{section_num}.{sub_num}. Summarized open ports on {subnet} subnet.",
                level=2,
            )

            table = doc.add_table(rows=1, cols=2)
            table.style = "Light Grid Accent 1"
            table.rows[0].cells[0].text = "Hosts"
            table.rows[0].cells[1].text = "Ports"

            for h in sorted(hosts, key=lambda x: tuple(int(p) for p in x.ip.split("."))):
                ports_str = ",".join(
                    f"{p.number}/{p.protocol}" for p in h.open_ports
                )
                row = table.add_row().cells
                row[0].text = h.ip
                row[1].text = ports_str or ""

            sub_num += 1

    def _web_screenshots(
        self, doc: Document, report: ScanReport, reports_dir: Path,
    ) -> None:
        hosts_with_ss = [
            h for h in report.hosts if getattr(h, "screenshots", None)
        ]
        if not hosts_with_ss:
            return

        doc.add_heading("5. Web Screenshots", level=1)
        doc.add_paragraph(
            "Screenshots of discovered web services captured during the assessment."
        )

        for h in hosts_with_ss:
            doc.add_heading(h.ip, level=2)
            for sc in h.screenshots:
                png = (
                    reports_dir.parent
                    / "ips"
                    / h.ip
                    / "web"
                    / "screenshots"
                    / sc.filename
                )
                if not png.is_file():
                    continue
                caption = sc.url
                if sc.title:
                    caption += f" — {sc.title}"
                doc.add_paragraph(caption)
                try:
                    doc.add_picture(str(png), width=Inches(5.5))
                except Exception:
                    log.debug("Could not embed screenshot %s", png)

    def _identified_issues(self, doc: Document, report: ScanReport) -> None:
        if not report.findings:
            return

        findings_by_host = _group_findings_by_host(report.findings)

        # Group hosts into subnets for section numbering
        host_to_subnet: dict[str, str] = {}
        for h in report.hosts:
            parts = h.ip.rsplit(".", 1)
            host_to_subnet[h.ip] = f"{parts[0]}.0/24" if len(parts) == 2 else h.ip

        # Group findings by subnet
        findings_by_subnet: dict[str, list[Finding]] = defaultdict(list)
        for host_ip, host_findings in findings_by_host.items():
            subnet = host_to_subnet.get(host_ip, host_ip)
            findings_by_subnet[subnet].extend(host_findings)

        section_num = 6
        for subnet in sorted(findings_by_subnet.keys()):
            subnet_findings = findings_by_subnet[subnet]
            doc.add_heading(
                f"{section_num}. Identified issues on {subnet} subnet.",
                level=1,
            )

            for idx, finding in enumerate(subnet_findings, 1):
                # Heading: section.idx. Title
                doc.add_heading(
                    f"{section_num}.{idx}. {finding.title}",
                    level=2,
                )

                # IP (bold)
                ip_para = doc.add_paragraph()
                ip_para.add_run(f"IP: {finding.host}").bold = True

                # Port (bold)
                if finding.port:
                    port_para = doc.add_paragraph()
                    port_para.add_run(f"Port: {finding.port}").bold = True

                # URL (bold, if web endpoint)
                url_text = ""
                if finding.full_url:
                    url_text = finding.full_url
                elif finding.matched_at:
                    url_text = finding.matched_at
                elif finding.endpoint and finding.endpoint != "/":
                    protocol = finding.protocol or "http"
                    port = finding.port or "80"
                    url_text = f"{protocol}://{finding.host}:{port}{finding.endpoint}"
                if url_text:
                    url_para = doc.add_paragraph()
                    url_para.add_run(f"URL: {url_text}").bold = True

                # Vulnerability Summary
                doc.add_heading("Vulnerability Summary", level=3)
                desc = finding.description or finding.raw_output or finding.title
                doc.add_paragraph(desc)

                if finding.source == "nuclei_external":
                    fp_para = doc.add_paragraph()
                    fp_run = fp_para.add_run(
                        "Note: This finding was generated from an external nuclei template "
                        "and may be a false positive. Manual verification is recommended."
                    )
                    fp_run.italic = True
                    fp_run.font.color.rgb = RGBColor(0xF5, 0x9E, 0x0B)

                # CVE/CWE/CVSS
                if finding.cve:
                    cve_para = doc.add_paragraph()
                    cve_para.add_run("CVE: ").bold = True
                    cve_para.add_run(finding.cve)
                if finding.cwe:
                    cwe_para = doc.add_paragraph()
                    cwe_para.add_run("CWE: ").bold = True
                    cwe_para.add_run(finding.cwe)
                if finding.cvss:
                    cvss_para = doc.add_paragraph()
                    cvss_para.add_run("CVSS: ").bold = True
                    cvss_para.add_run(finding.cvss)

                # Curl command to reproduce
                if finding.curl_command:
                    doc.add_heading("Reproduce", level=3)
                    curl_para = doc.add_paragraph()
                    curl_run = curl_para.add_run(finding.curl_command[:500])
                    curl_run.font.size = Pt(9)

                # Evidence (request/response) - truncated
                if finding.request:
                    doc.add_heading("Evidence", level=3)
                    req_text = finding.request[:500]
                    if len(finding.request) > 500:
                        req_text += "\n[TRUNCATED]"
                    req_para = doc.add_paragraph()
                    req_run = req_para.add_run(req_text)
                    req_run.font.size = Pt(8)

            section_num += 1

        doc.add_paragraph()
        end_para = doc.add_paragraph("END OF DOCUMENT")
        end_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
