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

from wireghost.models.severity import SEVERITY_COLORS, Severity

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.models.finding import Finding
    from wireghost.models.report import ScanReport
    from wireghost.models.scan import Host

log = logging.getLogger("wireghost")

_SEVERITY_RGB: dict[Severity, RGBColor] = {
    sev: RGBColor(*rgb) for sev, rgb in SEVERITY_COLORS.items()
}


# Global counter for unique drawing object IDs within a single document.
# Reset per render call via DocxRenderer.reset_doc_pr_id().
_doc_pr_id_counter: int = 0


def _next_doc_pr_id() -> int:
    """Return a unique ID for wp:docPr and pic:cNvPr elements."""
    global _doc_pr_id_counter
    _doc_pr_id_counter += 1
    return _doc_pr_id_counter


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

    doc_pr_id = _next_doc_pr_id()

    anchor_xml = (
        '<wp:anchor distT="0" distB="0" distL="114300" distR="114300" '
        'simplePos="0" relativeHeight="0" behindDoc="0" locked="0" '
        'layoutInCell="1" allowOverlap="1" '
        'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"'
        ' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
        ' xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"'
        ' xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">'
        '  <wp:simplePos x="0" y="0"/>'
        '  <wp:positionH relativeFrom="{pos_h_from}">'
        '    <wp:posOffset>{pos_h_offset}</wp:posOffset>'
        '  </wp:positionH>'
        '  <wp:positionV relativeFrom="{pos_v_from}">'
        '    <wp:posOffset>{pos_v_offset}</wp:posOffset>'
        '  </wp:positionV>'
        '  <wp:extent cx="{cx}" cy="{cy}"/>'
        '  <wp:wrapNone/>'
        '  <wp:docPr id="{doc_pr_id}" name="Picture"/>'
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
        doc_pr_id=doc_pr_id,
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
    "assessment period (vulnerability / exploit reported as of the date of "
    "the report and cannot guarantee any future compliance). Security is "
    "a continuous process and new vulnerabilities may be discovered after "
    "this assessment."
)


def _ip_key(ip: str) -> tuple[int, ...]:
    """Sort key that orders IP addresses numerically (10.0.0.5 before 10.0.0.50)."""
    return tuple(int(octet) for octet in ip.split("."))


def _group_hosts_by_subnet(hosts: list[Host]) -> dict[str, list[Host]]:
    """Group hosts by their /24 subnet prefix."""
    subnets: dict[str, list[Host]] = defaultdict(list)
    for h in hosts:
        parts = h.ip.rsplit(".", 1)
        subnet = f"{parts[0]}.0/24" if len(parts) == 2 else h.ip
        subnets[subnet].append(h)
    return dict(sorted(subnets.items(), key=lambda kv: _ip_key(kv[0].split("/")[0])))


def _group_findings_by_host(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Group findings by host IP, sorted by severity within each host."""
    from wireghost.models.severity import SEVERITY_ORDER

    grouped: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        grouped[f.host].append(f)
    for host_findings in grouped.values():
        host_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    return dict(sorted(grouped.items(), key=lambda kv: _ip_key(kv[0])))


class DocxRenderer:
    """Render a ScanReport as a professional VA report (DOCX)."""

    @staticmethod
    def _reset_doc_pr_counter() -> None:
        """Reset the global drawing-object ID counter for a new document."""
        global _doc_pr_id_counter
        _doc_pr_id_counter = 0

    def render(
        self,
        report: ScanReport,
        config: ScanConfig,
        reports_dir: Path,
    ) -> Path:
        self._reset_doc_pr_counter()
        doc = Document()
        _apply_styles(doc)

        logo, header_logo = self._resolve_logos(config)

        # Dynamic section numbering — counter shared across all section methods.
        # Sections 1 (Exec Summary) and 2 (Target Subnets) are unnumbered;
        # numbering becomes visible starting at section 3 (Live Hosts).
        self._section = 0

        self._cover_page(doc, config, report, logo)
        self._executive_summary(doc, config, report)
        doc.add_page_break()
        self._target_subnets(doc, report)
        doc.add_page_break()
        self._live_hosts(doc, report)
        doc.add_page_break()
        self._open_ports(doc, report)
        doc.add_page_break()
        self._web_screenshots(doc, report, reports_dir)
        self._identified_issues(doc, report, reports_dir)

        end_para = doc.add_paragraph("END OF DOCUMENT")
        end_para.alignment = WD_ALIGN_PARAGRAPH.CENTER

        # Set document metadata before saving
        self._set_metadata(doc, config, report)

        self._add_header_logos(doc, logo, header_logo)

        out = reports_dir / "security_report.docx"
        doc.save(str(out))

        # Clean up problematic auto-generated parts that can prevent
        # opening in strict OOXML validators (Word, Google Docs).
        self._clean_zip(out)

        return out

    def _next_section(self) -> int:
        self._section += 1
        return self._section

    @staticmethod
    def _resolve_logos(config: ScanConfig) -> tuple[Path | None, Path | None]:
        """Resolve logo paths. Custom from config/env, or built-in defaults."""
        assets = Path(__file__).parent / "assets"
        default_logo = assets / "logo.png"
        default_header = assets / "logo_header.png"

        # Custom logo: use as cover logo; keep built-in header logo if available
        custom = getattr(config, "logo_path", None)
        if custom and Path(custom).is_file():
            header = default_header if default_header.is_file() else None
            return Path(custom), header

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

    @staticmethod
    def _set_metadata(doc: Document, config: ScanConfig, report: ScanReport) -> None:
        """Set proper document metadata (creator, title, dates)."""
        now = datetime.now()
        core = doc.core_properties
        core.creator = getattr(config, "prepared_by", "WireGhost") or "WireGhost"
        core.title = f"VA Report — {report.target}"
        core.description = (
            f"Vulnerability Assessment Report for {report.target}. "
            f"{len(report.hosts)} hosts, {len(report.findings)} findings."
        )
        core.created = now
        core.modified = now
        core.last_modified_by = getattr(config, "prepared_by", "WireGhost") or "WireGhost"

    @staticmethod
    def _clean_zip(path: Path) -> None:
        """Remove problematic auto-generated parts that can prevent opening."""
        import io
        import re
        import zipfile

        removals = {
            "customXml/item1.xml",
            "customXml/_rels/item1.xml.rels",
            "customXml/itemProps1.xml",
            "docProps/thumbnail.jpeg",
        }

        buf = io.BytesIO()
        with zipfile.ZipFile(str(path), "r") as zin:
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout:
                for item in zin.infolist():
                    if item.filename in removals:
                        continue
                    data = zin.read(item.filename)

                    if item.filename == "[Content_Types].xml":
                        content = data.decode("utf-8")
                        for rm in removals:
                            content = re.sub(
                                r'<Override\s+PartName="/' + re.escape(rm) + r'"[^>]*/?>',
                                "",
                                content,
                            )
                        data = content.encode("utf-8")

                    elif item.filename == "_rels/.rels":
                        content = data.decode("utf-8")
                        content = re.sub(
                            r'<Relationship[^>]*Type="[^"]*thumbnail[^"]*"[^>]*/>',
                            "",
                            content,
                        )
                        data = content.encode("utf-8")

                    elif item.filename == "word/_rels/document.xml.rels":
                        content = data.decode("utf-8")
                        content = re.sub(
                            r'<Relationship[^>]*Type="[^"]*customXml[^"]*"[^>]*/>',
                            "",
                            content,
                        )
                        data = content.encode("utf-8")

                    zout.writestr(item, data)

        path.write_bytes(buf.getvalue())

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
        self._next_section()  # section 1 (unnumbered)
        doc.add_heading("Executive Summary", level=1)
        doc.add_paragraph(
            f"A comprehensive Vulnerability Assessment was conducted on "
            f"{report.target} to identify existing vulnerabilities, "
            f"misconfigurations and known threats."
        )

        stats = report.severity_stats()

        # Severity-distribution table
        sev_table = doc.add_table(rows=1, cols=3)
        sev_table.style = "Light Grid Accent 1"
        hdr = sev_table.rows[0].cells
        hdr[0].text = "Severity"
        hdr[1].text = "Count"
        hdr[2].text = "Description"

        severity_rows = [
            (Severity.CRITICAL, "Critical", "Immediate threat; requires urgent remediation"),
            (Severity.HIGH, "High", "Significant risk; prioritize for resolution"),
            (Severity.MEDIUM, "Medium", "Moderate risk; address in regular patch cycle"),
            (Severity.LOW, "Low", "Minor risk; address as resources permit"),
            (Severity.INFO, "Info", "Informational; no action required"),
        ]
        for sev, label, desc in severity_rows:
            count = stats.get(sev, 0)
            if count > 0:
                row = sev_table.add_row().cells
                # Colored severity label
                sev_para = row[0].paragraphs[0]
                sev_para.clear()
                sev_run = sev_para.add_run(label)
                sev_run.font.color.rgb = _SEVERITY_RGB.get(sev, _BLACK)
                sev_run.bold = True
                row[1].text = str(count)
                row[2].text = desc

        doc.add_paragraph()
        summary = doc.add_paragraph()
        summary.add_run("Assessment Results:\n").bold = True
        summary.add_run(f"  Hosts Scanned: {len(report.hosts)}\n")
        summary.add_run(f"  Open Ports: {report.total_open_ports}\n")
        summary.add_run(f"  Total Findings: {len(report.findings)}\n")

    def _target_subnets(self, doc: Document, report: ScanReport) -> None:
        self._next_section()  # section 2 (unnumbered)
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
        sec = self._next_section()
        doc.add_heading(f"{sec}. Identified Live Hosts", level=1)
        doc.add_paragraph("The following IPs are alive in the subnets.")

        subnets = _group_hosts_by_subnet(report.hosts)

        table = doc.add_table(rows=1, cols=2)
        table.style = "Light Grid Accent 1"
        table.rows[0].cells[0].text = "Subnets"
        table.rows[0].cells[1].text = "Hosts"

        for subnet, hosts in subnets.items():
            first = True
            for h in sorted(hosts, key=lambda x: _ip_key(x.ip)):
                row = table.add_row().cells
                row[0].text = subnet if first else ""
                row[1].text = h.ip
                first = False

        if not subnets:
            row = table.add_row().cells
            row[0].text = report.target
            row[1].text = "No Live Host"

    def _open_ports(self, doc: Document, report: ScanReport) -> None:
        sec = self._next_section()
        doc.add_heading(f"{sec}. Open Ports", level=1)

        subnets = _group_hosts_by_subnet(report.hosts)
        sub_num = 1

        for subnet, hosts in subnets.items():
            doc.add_heading(
                f"{sec}.{sub_num}. Summarized open ports on {subnet} subnet.",
                level=2,
            )

            table = doc.add_table(rows=1, cols=2)
            table.style = "Light Grid Accent 1"
            table.rows[0].cells[0].text = "Hosts"
            table.rows[0].cells[1].text = "Ports"

            for h in sorted(hosts, key=lambda x: _ip_key(x.ip)):
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
        # Only show screenshots for hosts that have NO findings — hosts with both
        # get screenshots embedded inline within _identified_issues instead.
        hosts_with_findings = {f.host for f in report.findings}
        hosts_with_ss = [
            h for h in report.hosts
            if getattr(h, "screenshots", None) and h.ip not in hosts_with_findings
        ]
        if not hosts_with_ss:
            return

        sec = self._next_section()
        doc.add_heading(f"{sec}. Web Screenshots", level=1)
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

    def _identified_issues(
        self, doc: Document, report: ScanReport, reports_dir: Path,
    ) -> None:
        if not report.findings:
            return

        findings_by_host = _group_findings_by_host(report.findings)
        host_map: dict[str, Host] = {h.ip: h for h in report.hosts}

        host_to_subnet: dict[str, str] = {}
        for h in report.hosts:
            parts = h.ip.rsplit(".", 1)
            host_to_subnet[h.ip] = f"{parts[0]}.0/24" if len(parts) == 2 else h.ip

        findings_by_subnet: dict[str, list[Finding]] = defaultdict(list)
        for host_ip, host_findings in findings_by_host.items():
            subnet = host_to_subnet.get(host_ip, host_ip)
            findings_by_subnet[subnet].extend(host_findings)

        shown_ss: set[str] = set()

        for subnet in sorted(findings_by_subnet.keys(), key=lambda s: _ip_key(s.split("/")[0])):
            sec = self._next_section()
            subnet_findings = findings_by_subnet[subnet]
            doc.add_heading(
                f"{sec}. Identified issues on {subnet} subnet.",
                level=1,
            )

            for idx, finding in enumerate(subnet_findings, 1):
                sev_label = finding.severity.name.upper() if hasattr(finding.severity, 'name') else str(finding.severity)
                sev_color = _SEVERITY_RGB.get(finding.severity, _BLACK)

                # Multi-run heading with colored severity label
                h = doc.add_heading("", level=2)
                h.clear()
                run_num = h.add_run(f"{sec}.{idx}. [")
                run_num.font.color.rgb = _GREEN
                run_sev = h.add_run(sev_label)
                run_sev.font.color.rgb = sev_color
                run_sev.bold = True
                run_tail = h.add_run(f"] {finding.title}")
                run_tail.font.color.rgb = _GREEN

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
                    scheme = finding.protocol if finding.protocol in ("http", "https") else ""
                    if not scheme:
                        scheme = "https" if str(finding.port) == "443" else "http"
                    port = finding.port or ""
                    if port:
                        url_text = f"{scheme}://{finding.host}:{port}{finding.endpoint}"
                    else:
                        url_text = f"{scheme}://{finding.host}{finding.endpoint}"
                if url_text:
                    url_para = doc.add_paragraph()
                    url_para.add_run(f"URL: {url_text}").bold = True

                # Embed web screenshots inline with first finding for this host
                if finding.host not in shown_ss:
                    shown_ss.add(finding.host)
                    host = host_map.get(finding.host)
                    if host and getattr(host, "screenshots", None):
                        ss_dir = reports_dir.parent / "ips" / finding.host / "web" / "screenshots"
                        for sc in host.screenshots:
                            png = ss_dir / sc.filename
                            if not png.is_file():
                                continue
                            caption = sc.url
                            if sc.title:
                                caption += f" — {sc.title}"
                            ss_para = doc.add_paragraph()
                            ss_para.add_run(f"Web Screenshot: {caption}").bold = True
                            try:
                                doc.add_picture(str(png), width=Inches(5.5))
                            except Exception:
                                log.debug("Could not embed screenshot %s", png)

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

                # Evidence (request/response) — truncated, small font
                if finding.request:
                    doc.add_heading("Evidence", level=3)
                    req_text = finding.request[:500]
                    if len(finding.request) > 500:
                        req_text += "\n[TRUNCATED]"
                    req_para = doc.add_paragraph()
                    req_run = req_para.add_run(req_text)
                    req_run.font.size = Pt(8)
