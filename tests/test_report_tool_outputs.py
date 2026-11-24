"""Integration tests: tool-by-tool section in every report format."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from docx import Document
from openpyxl import load_workbook

from wireghost.models.finding import Finding
from wireghost.models.report import ScanReport
from wireghost.models.scan import Host, Port, Screenshot, Service, WebTech
from wireghost.models.severity import Severity
from wireghost.reports.dashboard import DashboardRenderer
from wireghost.reports.docx_renderer import DocxRenderer
from wireghost.reports.html_renderer import HtmlRenderer
from wireghost.reports.tool_output import collect_tool_outputs
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


def test_severity_enum_survives_sanitize():
    """Severity is a str Enum; sanitizing must not degrade it to a plain str."""
    report = _report()
    assert report.findings[0].severity is Severity.LOW
    assert report.severity_stats() == {Severity.LOW: 1}
    report.sanitize()
    assert report.findings[0].severity is Severity.LOW
    assert report.severity_stats() == {Severity.LOW: 1}


def test_scan_window_accepts_aware_timestamps(tmp_path):
    """The portal stores tz-aware datetimes; file mtimes are naive."""
    from datetime import datetime, timedelta, timezone

    reports, _ = _tree(tmp_path)
    (tmp_path / "ips" / IP / "vuln" / "nuclei.json").write_text("x", encoding="utf-8")
    report = _report()
    report.scan_start = datetime.now(timezone.utc) - timedelta(minutes=5)
    report.scan_end = None
    outputs = {t["source"]: t for t in collect_tool_outputs(report, reports)}
    assert len(outputs["nuclei"]["files"]) == 1


def test_dashboard_renders_with_aware_timestamps(tmp_path):
    from datetime import datetime, timedelta, timezone

    reports, _ = _tree(tmp_path)
    report = _report()
    report.scan_start = datetime.now(timezone.utc) - timedelta(minutes=5)
    report.scan_end = datetime.now(timezone.utc)
    out = DashboardRenderer().render(report, _config(), reports)
    assert out.exists() and out.stat().st_size > 0


def test_finding_accepts_string_severity_from_db():
    """Report regeneration rebuilds findings from DB strings."""
    f = Finding(
        source="nuclei",
        host=IP,
        port="22",
        protocol="tcp",
        severity="high",
        title="t",
        description="d",
    )
    assert f.severity is Severity.HIGH
    report = ScanReport(target=f"{IP}/32", hosts=[Host(ip=IP)], findings=[f])
    assert report.severity_stats() == {Severity.HIGH: 1}


def test_docx_raw_text_is_budgeted_to_stay_openable(tmp_path):
    """Word refuses ~100 MB document.xml; the DOCX must stay small."""
    from wireghost.reports import docx_renderer

    reports, _ = _tree(tmp_path)
    big = "A" * 5_000_000
    (tmp_path / "ips" / IP / "vuln" / "nuclei.json").write_text(big, encoding="utf-8")

    original = docx_renderer._DOCX_RAW_BUDGET
    docx_renderer._DOCX_RAW_BUDGET = 200_000
    try:
        out = DocxRenderer().render(_report(), _config(), reports)
    finally:
        docx_renderer._DOCX_RAW_BUDGET = original

    import zipfile

    with zipfile.ZipFile(out) as zf:
        size = zf.getinfo("word/document.xml").file_size
    assert size < 2_000_000, f"document.xml too large for Word: {size}"

    text = "\n".join(p.text for p in Document(str(out)).paragraphs)
    assert "truncated" in text
    assert "Full text" in text or "full text" in text


def _web_report() -> ScanReport:
    host = Host(
        ip=IP,
        ports=[Port(number=443, service=Service(name="https"))],
        web_endpoints=["https://10.0.0.1/"],
        web_titles={"https://10.0.0.1/": "Intranet Portal"},
        technologies=[WebTech(name="nginx", version="1.24", url="https://10.0.0.1/")],
    )
    return ScanReport(target=f"{IP}/32", hosts=[host], findings=[])


def test_html_summary_includes_web_services_and_technologies(tmp_path):
    reports, _ = _tree(tmp_path)
    out = HtmlRenderer().render(_web_report(), _config(), reports)
    html = out.read_text(encoding="utf-8")
    assert "Web Services" in html
    assert "Intranet Portal" in html
    assert "https://10.0.0.1/" in html
    assert "Detected Technologies" in html
    assert "nginx" in html


def test_docx_includes_web_services_and_technologies(tmp_path):
    reports, _ = _tree(tmp_path)
    out = DocxRenderer().render(_web_report(), _config(), reports)
    text = "\n".join(p.text for p in Document(str(out)).paragraphs)
    table_text = "\n".join(
        cell.text for t in Document(str(out)).tables for row in t.rows for cell in row.cells
    )
    joined = text + "\n" + table_text
    assert "Web Services" in joined
    assert "Intranet Portal" in joined
    assert "Detected Technologies" in joined
    assert "nginx" in joined


PNG_1PX = bytes.fromhex(
    "89504e470d0a1a0a0000000d494844520000000800000008080200000"
    "04b6d29dc0000001449444154789c633c2127c7800d3061151db41200d"
    "0ca01143e63a8990000000049454e44ae426082"
)


def _shot_report() -> ScanReport:
    host = Host(
        ip=IP,
        web_titles={"https://10.0.0.1/": "Intranet Portal"},
        screenshots=[
            # The portal stores the path relative to the scan dir, not a bare name.
            Screenshot(
                url="https://10.0.0.1/",
                filename=f"ips/{IP}/web/screenshots/shot.png",
                title="Intranet Portal",
                status_code=200,
            )
        ],
    )
    return ScanReport(target=f"{IP}/32", hosts=[host], findings=[])


def _tree_with_shot(tmp_path: Path) -> Path:
    reports = tmp_path / "reports"
    reports.mkdir()
    shots = tmp_path / "ips" / IP / "web" / "screenshots"
    shots.mkdir(parents=True)
    (shots / "shot.png").write_bytes(PNG_1PX)
    return reports


def test_html_web_services_include_screenshot(tmp_path):
    reports = _tree_with_shot(tmp_path)
    out = HtmlRenderer().render(_shot_report(), _config(), reports)
    html = out.read_text(encoding="utf-8")
    assert "Web Services" in html
    assert "data:image/png;base64," in html
    assert "Intranet Portal" in html


def test_docx_web_services_include_screenshot(tmp_path):
    reports = _tree_with_shot(tmp_path)
    out = DocxRenderer().render(_shot_report(), _config(), reports)
    doc = Document(str(out))
    text = "\n".join(p.text for p in doc.paragraphs)
    assert "Web Service Screenshots" in text
    assert "https://10.0.0.1/" in text
    assert len(doc.inline_shapes) >= 1, "screenshot image not embedded"
