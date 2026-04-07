"""Report engine -- dispatches to format-specific renderers."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.models.report import ScanReport
    from wireghost.utils.fs import OutputTree

log = logging.getLogger("wireghost")


class ReportEngine:
    """Generates reports in one or more formats.

    The *tree_or_dir* parameter accepts either an :class:`OutputTree`
    (from the pipeline orchestrator) or a plain :class:`Path` (from the CLI
    ``report`` sub-command).  When a ``Path`` is supplied the engine uses it
    directly as the reports directory.
    """

    def __init__(self, config: ScanConfig, tree_or_dir: OutputTree | Path) -> None:
        self.config = config

        # Resolve reports_dir from either an OutputTree or a plain Path.
        if isinstance(tree_or_dir, Path):
            self._reports_dir = tree_or_dir
        else:
            self._reports_dir = tree_or_dir.reports_dir  # type: ignore[union-attr]

        self._reports_dir.mkdir(parents=True, exist_ok=True)

    # --------------------------------------------------------------------- #
    # Public API
    # --------------------------------------------------------------------- #

    def generate(self, report: ScanReport) -> list[Path]:
        """Run every renderer requested by *config.report_formats*.

        Returns a list of file paths that were successfully created.
        """
        created: list[Path] = []

        _DISPATCH: dict[str, tuple[str, str]] = {
            "docx": ("wireghost.reports.docx_renderer", "DocxRenderer"),
            "xlsx": ("wireghost.reports.xlsx_renderer", "XlsxRenderer"),
            "html": ("wireghost.reports.html_renderer", "HtmlRenderer"),
            "dashboard": ("wireghost.reports.dashboard", "DashboardRenderer"),
        }

        for fmt in self.config.report_formats:
            fmt_lower = fmt.strip().lower()
            entry = _DISPATCH.get(fmt_lower)
            if entry is None:
                log.warning("Unknown report format %r -- skipping", fmt)
                continue

            module_path, class_name = entry
            try:
                import importlib

                mod = importlib.import_module(module_path)
                renderer_cls = getattr(mod, class_name)
                renderer = renderer_cls()
                path = renderer.render(report, self.config, self._reports_dir)
                created.append(path)
                log.info("Created %s report: %s", fmt_lower, path)
            except Exception:
                log.exception("Failed to generate %s report", fmt_lower)

        return created
