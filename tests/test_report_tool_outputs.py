"""Integration tests: tool-by-tool section in every report format."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from docx import Document
from openpyxl import load_workbook

from wireghost.models.finding import Finding
from wireghost.models.report import ScanReport
from wireghost.models.scan import Host, Port, Service
from wireghost.models.severity import Severity
from wireghost.reports.dashboard import DashboardRenderer
from wireghost.reports.docx_renderer import DocxRenderer
from wireghost.reports.html_renderer import HtmlRenderer
from wireghost.reports.xlsx_renderer import XlsxRenderer

IP = "10.0.0.1"
MARKER = "FULL_RAW_MARKER_12345"


def _config():
    return SimpleNamespace(report_title="Test Report", prepared_by="QA", logo_path=None)


def _report() -> ScanReport:
    host = Host(ip=IP, ports=[Port(number=22, service=Service(name="ssh"))])
    findings = [
        Finding(
            source="nuclei_external",
            host=IP,
            port="22",
            protocol="tcp",
            severity=Severity.LOW,
            title="SSH finding",
            description="desc",
        ),
    ]
    return ScanReport(target=f"{IP}/32", hosts=[host], findings=findings)


def _tree(tmp_path: Path) -> tuple[Path, str]:
    reports = tmp_path / "reports"
    reports.mkdir()
    vuln = tmp_path / "ips" / IP / "vuln"
    vuln.mkdir(parents=True)
    raw = MARKER + "\n" + ("A" * 70_000)
    (vuln / "nuclei.json").write_text(raw, encoding="utf-8")
    return reports, raw


def test_html_contains_tool_section_and_full_raw(tmp_path):
    reports, raw = _tree(tmp_path)
    out = HtmlRenderer().render(_report(), _config(), reports)
    html = out.read_text(encoding="utf-8")
    assert "Tool-by-Tool Results" in html
    assert "Nuclei" in html
    assert MARKER in html
    assert raw[-100:] in html


def test_dashboard_contains_tool_section_and_full_raw(tmp_path):
    reports, raw = _tree(tmp_path)
    out = DashboardRenderer().render(_report(), _config(), reports)
    html = out.read_text(encoding="utf-8")
    assert "Tool-by-Tool Results" in html
    assert MARKER in html
    assert raw[-100:] in html


def test_docx_contains_tool_section_and_full_raw(tmp_path):
    reports, raw = _tree(tmp_path)
    out = DocxRenderer().render(_report(), _config(), reports)
    doc = Document(str(out))
    texts = [p.text for p in doc.paragraphs]
    assert any("Tool-by-Tool Results" in t for t in texts)
    joined = "\n".join(texts)
    assert MARKER in joined
    assert raw[-100:] in joined


def test_xlsx_has_tool_sheets_with_chunked_full_raw(tmp_path):
    reports, raw = _tree(tmp_path)
    out = XlsxRenderer().render(_report(), _config(), reports)
    wb = load_workbook(str(out))
    assert "Tool Summary" in wb.sheetnames
    assert "Tool Raw Output" in wb.sheetnames

    summary = wb["Tool Summary"]
    rows = list(summary.iter_rows(values_only=True))
    assert any(row[0] == "Nuclei" for row in rows)

    raw_sheet = wb["Tool Raw Output"]
    chunks = [row for row in raw_sheet.iter_rows(values_only=True) if row[0] == "Nuclei"]
    text = "".join(row[5] for row in chunks)
    assert text == raw
    assert all(len(row[5]) <= 32_000 for row in chunks)


def test_engine_renders_every_requested_format(tmp_path):
    """The engine is what the worker calls; it swallows per-format errors, so
    assert all four bundles actually come back."""
    from wireghost.config import ScanConfig
    from wireghost.reports.engine import ReportEngine

    reports, _ = _tree(tmp_path)
    config = ScanConfig.load(
        target=f"{IP}/32",
        report_formats=["html", "dashboard", "docx", "xlsx"],
        output_dir=str(tmp_path),
    )
    paths = ReportEngine(config, reports).generate(_report())
    assert len(paths) == 4
    assert {p.suffix for p in paths} == {".html", ".docx", ".xlsx"}
    for path in paths:
        assert path.stat().st_size > 0


DIRTY = "[+] \x1b[32mGREEN\x1b[0m\x00\x07 text"


def test_docx_survives_control_chars_in_finding_text(tmp_path):
    """nxc/enum4linux findings carry ANSI escapes and NULs; Word rejects them."""
    reports, _ = _tree(tmp_path)
    report = _report()
    report.findings[0].description = DIRTY
    report.findings[0].raw_output = DIRTY
    report.findings[0].title = "t" + DIRTY
    out = DocxRenderer().render(report, _config(), reports)
    doc = Document(str(out))
    joined = "\n".join(p.text for p in doc.paragraphs)
    for ch in ("\x00", "\x07", "\x1b"):
        assert ch not in joined
    assert "GREEN" in joined


def test_xlsx_survives_control_chars_in_finding_text(tmp_path):
    reports, _ = _tree(tmp_path)
    report = _report()
    report.findings[0].description = DIRTY
    report.findings[0].raw_output = DIRTY
    out = XlsxRenderer().render(report, _config(), reports)
    assert out.exists()
