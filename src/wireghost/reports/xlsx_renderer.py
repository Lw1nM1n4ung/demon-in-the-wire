"""XLSX report renderer -- host / port summary spreadsheet."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from openpyxl import Workbook

if TYPE_CHECKING:
    from wireghost.config import ScanConfig
    from wireghost.models.report import ScanReport


class XlsxRenderer:
    """Render a ScanReport as an Excel workbook with two sheets."""

    def render(
        self,
        report: ScanReport,
        config: ScanConfig,
        reports_dir: Path,
    ) -> Path:
        wb = Workbook()

        # --- Sheet 1: summary ------------------------------------------
        ws_summary = wb.active
        ws_summary.title = "Hosts and Ports"
        ws_summary.append(["Host", "Open Ports"])

        # --- Sheet 2: detail -------------------------------------------
        ws_detail = wb.create_sheet("Detailed Ports")
        ws_detail.append(["Host", "Port", "Protocol", "State", "Service"])

        for host in report.hosts:
            # Summary row: comma-separated open ports
            open_ports_str = ",".join(
                f"{p.number}/{p.protocol}" for p in host.open_ports
            )
            ws_summary.append([host.ip, open_ports_str])

            # Detail rows: every port (open, filtered, etc.)
            for port in host.ports:
                svc_name = port.service.name if port.service else ""
                ws_detail.append(
                    [host.ip, port.number, port.protocol, port.state, svc_name]
                )

        out = reports_dir / "ports_summary.xlsx"
        wb.save(str(out))
        return out
