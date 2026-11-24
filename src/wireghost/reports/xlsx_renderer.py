"""XLSX report renderer -- host / port summary spreadsheet."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from openpyxl import Workbook

from wireghost.reports.tool_output import collect_tool_outputs

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
        report.sanitize()
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
            open_ports_str = ",".join(f"{p.number}/{p.protocol}" for p in host.open_ports)
            ws_summary.append([host.ip, open_ports_str])

            # Detail rows: every port (open, filtered, etc.)
            for port in host.ports:
                svc_name = port.service.name if port.service else ""
                ws_detail.append([host.ip, port.number, port.protocol, port.state, svc_name])

        # --- Sheet 3: tool summary -------------------------------------
        tool_outputs = collect_tool_outputs(report, reports_dir)
        ws_tool = wb.create_sheet("Tool Summary")
        ws_tool.append(
            [
                "Tool",
                "Status",
                "Findings",
                "Critical",
                "High",
                "Medium",
                "Low",
                "Info",
                "Hosts",
                "Files",
                "Command",
            ]
        )
        for tool in tool_outputs:
            counts = tool["severity_counts"]
            ws_tool.append(
                [
                    tool["label"],
                    tool["status"],
                    tool["finding_count"],
                    counts["critical"],
                    counts["high"],
                    counts["medium"],
                    counts["low"],
                    counts["info"],
                    ", ".join(tool["hosts"]),
                    len(tool["files"]),
                    tool["command"],
                ]
            )

        # --- Sheet 4: full raw output (chunked for Excel's 32k cell cap) ---
        ws_raw = wb.create_sheet("Tool Raw Output")
        ws_raw.append(["Tool", "Host", "File", "Path", "Chunk", "Text"])
        chunk_size = 32_000
        for tool in tool_outputs:
            for raw in tool["files"]:
                if raw["binary"]:
                    ws_raw.append(
                        [tool["label"], raw["host"], raw["name"], raw["path"], 1, "(binary file)"]
                    )
                    continue
                text = raw["text"]
                for idx, start in enumerate(range(0, len(text), chunk_size), 1):
                    ws_raw.append(
                        [
                            tool["label"],
                            raw["host"],
                            raw["name"],
                            raw["path"],
                            idx,
                            text[start : start + chunk_size],
                        ]
                    )

        out = reports_dir / "ports_summary.xlsx"
        wb.save(str(out))
        return out
