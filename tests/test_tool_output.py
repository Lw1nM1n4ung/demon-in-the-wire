"""Tests for the report tool-output collector."""

from __future__ import annotations

from pathlib import Path

from wireghost.models.finding import Finding
from wireghost.models.report import ScanReport
from wireghost.models.scan import Host, Port, Service
from wireghost.models.severity import Severity
from wireghost.reports.tool_output import TOOL_SPECS, collect_tool_outputs


def _report(ip: str = "10.0.0.1") -> ScanReport:
    host = Host(
        ip=ip,
        ports=[Port(number=22, service=Service(name="ssh")), Port(number=3306)],
    )
    findings = [
        Finding(
            source="nuclei_external",
            host=ip,
            port="22",
            protocol="tcp",
            severity=Severity.LOW,
            title="SSH weak cipher",
            description="",
        ),
        Finding(
            source="msf_scan",
            host=ip,
            port="22",
            protocol="tcp",
            severity=Severity.INFO,
            title="MSF module check",
            description="",
        ),
    ]
    return ScanReport(target=f"{ip}/32", hosts=[host], findings=findings)


def _tree(tmp_path: Path) -> tuple[Path, Path]:
    reports = tmp_path / "reports"
    reports.mkdir()
    ips = tmp_path / "ips" / "10.0.0.1"
    (ips / "vuln").mkdir(parents=True)
    (ips / "nmap_xml").mkdir()
    return reports, ips


def test_all_tools_are_reported(tmp_path):
    reports, _ = _tree(tmp_path)
    outputs = collect_tool_outputs(_report(), reports)
    assert len(outputs) == len(TOOL_SPECS)
    assert any(t["source"] == "nikto" and t["status"] == "no output" for t in outputs)


def test_nuclei_external_findings_normalized(tmp_path):
    reports, _ = _tree(tmp_path)
    outputs = {t["source"]: t for t in collect_tool_outputs(_report(), reports)}
    assert outputs["nuclei"]["finding_count"] == 1
    assert outputs["nuclei"]["severity_counts"]["low"] == 1


def test_full_raw_text_retained_without_truncation(tmp_path):
    reports, ips = _tree(tmp_path)
    big = "line\\n" * 20_000  # 100 KB
    (ips / "vuln" / "nuclei.json").write_text(big, encoding="utf-8")
    outputs = {t["source"]: t for t in collect_tool_outputs(_report(), reports)}
    nuclei_files = outputs["nuclei"]["files"]
    assert len(nuclei_files) == 1
    assert len(nuclei_files[0]["text"]) == len(big)
    assert nuclei_files[0]["host"] == "10.0.0.1"


def test_files_grouped_per_host(tmp_path):
    reports, ips = _tree(tmp_path)
    (ips / "nmap_xml" / "portscan.xml").write_text("<nmaprun/>", encoding="utf-8")
    outputs = {t["source"]: t for t in collect_tool_outputs(_report(), reports)}
    assert outputs["nmap"]["status"] == "ran"
    assert outputs["nmap"]["files"][0]["name"] == "portscan.xml"
    assert outputs["nmap"]["hosts"] == ["10.0.0.1"]


def test_missing_ips_tree_does_not_crash(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    outputs = collect_tool_outputs(_report(), reports)
    assert all(t["files"] == [] for t in outputs)
