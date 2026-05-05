"""Tests for wireghost.reports.engine — ReportEngine dispatch."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from wireghost.config import ScanConfig
from wireghost.reports.engine import ReportEngine


def _make_engine(tmp_path: Path, formats: list[str]) -> ReportEngine:
    cfg = ScanConfig(report_formats=formats)
    return ReportEngine(cfg, tmp_path)


def _mock_report() -> MagicMock:
    return MagicMock(name="ScanReport")


def _mock_renderer(tmp_path: Path, filename: str = "report") -> MagicMock:
    mock_mod = MagicMock()
    renderer_instance = MagicMock()
    renderer_instance.render.return_value = tmp_path / filename
    for cls_name in ("HtmlRenderer", "DocxRenderer", "XlsxRenderer", "DashboardRenderer"):
        setattr(mock_mod, cls_name, MagicMock(return_value=renderer_instance))
    return mock_mod


class TestReportEngineDispatch:
    def test_creates_reports_dir(self, tmp_path):
        reports_dir = tmp_path / "reports"
        cfg = ScanConfig(report_formats=["html"])
        ReportEngine(cfg, reports_dir)
        assert reports_dir.is_dir()

    @patch("importlib.import_module")
    def test_dispatches_html(self, mock_import, tmp_path):
        mock_import.return_value = _mock_renderer(tmp_path)
        engine = _make_engine(tmp_path, ["html"])
        paths = engine.generate(_mock_report())
        mock_import.assert_called_with("wireghost.reports.html_renderer")
        assert len(paths) == 1

    @patch("importlib.import_module")
    def test_dispatches_docx(self, mock_import, tmp_path):
        mock_import.return_value = _mock_renderer(tmp_path)
        engine = _make_engine(tmp_path, ["docx"])
        paths = engine.generate(_mock_report())
        mock_import.assert_called_with("wireghost.reports.docx_renderer")
        assert len(paths) == 1

    @patch("importlib.import_module")
    def test_dispatches_xlsx(self, mock_import, tmp_path):
        mock_import.return_value = _mock_renderer(tmp_path)
        engine = _make_engine(tmp_path, ["xlsx"])
        paths = engine.generate(_mock_report())
        mock_import.assert_called_with("wireghost.reports.xlsx_renderer")
        assert len(paths) == 1

    @patch("importlib.import_module")
    def test_dispatches_dashboard(self, mock_import, tmp_path):
        mock_import.return_value = _mock_renderer(tmp_path)
        engine = _make_engine(tmp_path, ["dashboard"])
        paths = engine.generate(_mock_report())
        mock_import.assert_called_with("wireghost.reports.dashboard")
        assert len(paths) == 1

    @patch("importlib.import_module")
    def test_multiple_formats(self, mock_import, tmp_path):
        mock_import.return_value = _mock_renderer(tmp_path)
        engine = _make_engine(tmp_path, ["html", "docx"])
        paths = engine.generate(_mock_report())
        assert len(paths) == 2

    def test_unknown_format_skipped(self, tmp_path):
        engine = _make_engine(tmp_path, ["pdf"])
        paths = engine.generate(_mock_report())
        assert paths == []

    def test_empty_formats(self, tmp_path):
        engine = _make_engine(tmp_path, [])
        paths = engine.generate(_mock_report())
        assert paths == []

    @patch("importlib.import_module")
    def test_renderer_exception_handled(self, mock_import, tmp_path):
        mock_import.side_effect = ImportError("no module")
        engine = _make_engine(tmp_path, ["html"])
        paths = engine.generate(_mock_report())
        assert paths == []

    def test_format_case_insensitive(self, tmp_path):
        engine = _make_engine(tmp_path, ["PDF"])
        paths = engine.generate(_mock_report())
        assert paths == []

    @patch("importlib.import_module")
    def test_format_whitespace_stripped(self, mock_import, tmp_path):
        mock_import.return_value = _mock_renderer(tmp_path)
        engine = _make_engine(tmp_path, ["  html  "])
        paths = engine.generate(_mock_report())
        assert len(paths) == 1

    def test_accepts_path_directly(self, tmp_path):
        reports_dir = tmp_path / "my_reports"
        cfg = ScanConfig(report_formats=[])
        ReportEngine(cfg, reports_dir)
        assert reports_dir.is_dir()
