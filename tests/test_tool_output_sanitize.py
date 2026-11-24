"""Raw tool output can contain bytes XML cannot store (ANSI colour codes,
NULs, binary garbage). Excel/Word writers raise on those, which would abort
the whole report bundle for any scan that enumerated a Windows host."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from openpyxl import load_workbook

from wireghost.models.report import ScanReport
from wireghost.models.scan import Host
from wireghost.reports.docx_renderer import DocxRenderer
from wireghost.reports.tool_output import collect_tool_outputs
from wireghost.reports.xlsx_renderer import XlsxRenderer

IP = "10.0.0.5"
DIRTY = "[+] \x1b[32mGREEN\x1b[0m found\x00 null\x07 bell\x0c formfeed"


def _config():
    return SimpleNamespace(report_title="T", prepared_by="QA", logo_path=None)


def _tree(tmp_path: Path) -> Path:
    reports = tmp_path / "reports"
    reports.mkdir()
    vuln = tmp_path / "ips" / IP / "vuln"
    vuln.mkdir(parents=True)
    (vuln / "enum4linux.txt").write_text(DIRTY, encoding="utf-8")
    return reports


def _report() -> ScanReport:
    return ScanReport(target=f"{IP}/32", hosts=[Host(ip=IP)], findings=[])


def test_collector_strips_xml_illegal_control_chars(tmp_path):
    reports = _tree(tmp_path)
    outputs = {t["source"]: t for t in collect_tool_outputs(_report(), reports)}
    text = outputs["enum4linux"]["files"][0]["text"]
    assert "GREEN" in text
    assert "found" in text
    for ch in ("\x00", "\x07", "\x0c", "\x1b"):
        assert ch not in text


def test_xlsx_renders_with_dirty_raw_output(tmp_path):
    reports = _tree(tmp_path)
    out = XlsxRenderer().render(_report(), _config(), reports)
    wb = load_workbook(str(out))
    assert "Tool Raw Output" in wb.sheetnames
    wb.close()


def test_docx_renders_with_dirty_raw_output(tmp_path):
    reports = _tree(tmp_path)
    out = DocxRenderer().render(_report(), _config(), reports)
    assert out.exists()


@pytest.mark.parametrize("bad", ["\x00", "\x08", "\x0b", "\x1b", "\x1f"])
def test_no_xml_illegal_chars_survive(tmp_path, bad):
    reports = _tree(tmp_path)
    (tmp_path / "ips" / IP / "vuln" / "enum4linux.txt").write_text(f"a{bad}b", encoding="utf-8")
    outputs = {t["source"]: t for t in collect_tool_outputs(_report(), reports)}
    text = outputs["enum4linux"]["files"][0]["text"]
    assert bad not in text
    assert text == "ab"
