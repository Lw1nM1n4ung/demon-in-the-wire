"""Tests for wireghost.models — severity, scan, finding, report."""

from __future__ import annotations

from datetime import datetime

from wireghost.models.finding import Finding
from wireghost.models.report import ScanReport
from wireghost.models.scan import Host, Port, Service
from wireghost.models.severity import (
    SEVERITY_COLORS,
    SEVERITY_HEX,
    SEVERITY_ORDER,
    Severity,
    categorize_nmap_vuln,
)


# ---------- Severity ordering ----------


class TestSeverityOrder:
    def test_critical_is_highest(self):
        assert SEVERITY_ORDER[Severity.CRITICAL] < SEVERITY_ORDER[Severity.HIGH]

    def test_full_order(self):
        ordered = sorted(Severity, key=lambda s: SEVERITY_ORDER[s])
        assert ordered == [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
            Severity.UNKNOWN,
        ]


# ---------- Colors ----------


class TestSeverityColors:
    def test_all_severities_have_color(self):
        for sev in Severity:
            assert sev in SEVERITY_COLORS
            assert sev in SEVERITY_HEX

    def test_hex_format(self):
        for sev, hexval in SEVERITY_HEX.items():
            assert hexval.startswith("#")
            assert len(hexval) == 7  # #RRGGBB


# ---------- categorize_nmap_vuln ----------


class TestCategorizeNmapVuln:
    def test_critical_shellshock(self):
        assert categorize_nmap_vuln("http-shellshock", "VULNERABLE") == Severity.CRITICAL

    def test_critical_heartbleed(self):
        assert categorize_nmap_vuln("ssl-heartbleed", "VULNERABLE") == Severity.CRITICAL

    def test_critical_ms17_010(self):
        assert categorize_nmap_vuln("smb-vuln-ms17-010", "VULNERABLE") == Severity.CRITICAL

    def test_high_vuln(self):
        assert categorize_nmap_vuln("http-vuln-cve2021-41773", "VULNERABLE") == Severity.HIGH

    def test_high_rce(self):
        assert categorize_nmap_vuln("some-script", "remote code execution possible") == Severity.HIGH

    def test_high_sqli(self):
        assert categorize_nmap_vuln("http-sql-injection", "sqli detected") == Severity.HIGH

    def test_medium_enum(self):
        assert categorize_nmap_vuln("http-enum", "/admin: admin panel") == Severity.MEDIUM

    def test_medium_weak(self):
        assert categorize_nmap_vuln("ssl-cert", "weak cipher detected") == Severity.MEDIUM

    def test_medium_default(self):
        assert categorize_nmap_vuln("http-default-accounts", "found default creds") == Severity.MEDIUM

    def test_info_plain(self):
        assert categorize_nmap_vuln("http-title", "Welcome to nginx") == Severity.INFO


# ---------- Host.open_ports ----------


class TestHostOpenPorts:
    def test_filters_open_only(self):
        host = Host(
            ip="10.0.0.1",
            ports=[
                Port(number=22, state="open"),
                Port(number=80, state="open"),
                Port(number=3306, state="filtered"),
                Port(number=8080, state="closed"),
            ],
        )
        opens = host.open_ports
        assert len(opens) == 2
        assert all(p.state == "open" for p in opens)

    def test_empty_ports(self):
        host = Host(ip="10.0.0.2")
        assert host.open_ports == []


# ---------- ScanReport ----------


def _make_finding(host: str, severity: Severity, title: str = "f") -> Finding:
    return Finding(
        source="nmap_vuln",
        host=host,
        port="80",
        protocol="tcp",
        severity=severity,
        title=title,
        description="test",
    )


class TestScanReport:
    def test_severity_stats(self):
        report = ScanReport(
            target="10.0.0.0/24",
            findings=[
                _make_finding("10.0.0.1", Severity.CRITICAL),
                _make_finding("10.0.0.1", Severity.HIGH),
                _make_finding("10.0.0.2", Severity.HIGH),
                _make_finding("10.0.0.2", Severity.INFO),
            ],
            scan_start=datetime(2023, 11, 14, 12, 0),
        )
        stats = report.severity_stats()
        assert stats[Severity.CRITICAL] == 1
        assert stats[Severity.HIGH] == 2
        assert stats[Severity.INFO] == 1
        assert Severity.MEDIUM not in stats

    def test_findings_by_host(self):
        report = ScanReport(
            target="10.0.0.0/24",
            findings=[
                _make_finding("10.0.0.1", Severity.CRITICAL),
                _make_finding("10.0.0.1", Severity.HIGH),
                _make_finding("10.0.0.2", Severity.MEDIUM),
            ],
            scan_start=datetime(2023, 11, 14, 12, 0),
        )
        by_host = report.findings_by_host()
        assert len(by_host["10.0.0.1"]) == 2
        assert len(by_host["10.0.0.2"]) == 1

    def test_total_open_ports(self):
        report = ScanReport(
            target="10.0.0.0/24",
            hosts=[
                Host(
                    ip="10.0.0.1",
                    ports=[
                        Port(number=22, state="open"),
                        Port(number=3306, state="filtered"),
                    ],
                ),
                Host(
                    ip="10.0.0.2",
                    ports=[
                        Port(number=80, state="open"),
                        Port(number=443, state="open"),
                    ],
                ),
            ],
            scan_start=datetime(2023, 11, 14, 12, 0),
        )
        assert report.total_open_ports == 3

    def test_findings_by_severity(self):
        report = ScanReport(
            target="10.0.0.0/24",
            findings=[
                _make_finding("10.0.0.1", Severity.HIGH),
                _make_finding("10.0.0.1", Severity.HIGH),
                _make_finding("10.0.0.2", Severity.LOW),
            ],
            scan_start=datetime(2023, 11, 14, 12, 0),
        )
        by_sev = report.findings_by_severity()
        assert len(by_sev[Severity.HIGH]) == 2
        assert len(by_sev[Severity.LOW]) == 1
        assert Severity.CRITICAL not in by_sev

    def test_empty_findings(self):
        report = ScanReport(
            target="10.0.0.0/24",
            scan_start=datetime(2023, 11, 14, 12, 0),
        )
        assert report.severity_stats() == {}
        assert report.findings_by_host() == {}
        assert report.total_open_ports == 0


# ---------- Finding defaults ----------


class TestFinding:
    def test_default_fields(self):
        f = Finding(
            source="nuclei",
            host="10.0.0.1",
            port="80",
            protocol="tcp",
            severity=Severity.HIGH,
            title="Test",
            description="desc",
        )
        assert f.references == []
        assert f.tags == []
        assert f.curl_command == ""
        assert f.cve == ""
        assert f.cvss == ""
        assert f.cwe == ""

    def test_references_is_list(self):
        f = Finding(
            source="nuclei",
            host="10.0.0.1",
            port="80",
            protocol="tcp",
            severity=Severity.HIGH,
            title="Test",
            description="desc",
            references=["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773"],
        )
        assert isinstance(f.references, list)
        assert len(f.references) == 1

    def test_independent_default_lists(self):
        f1 = Finding(
            source="nuclei", host="a", port="80", protocol="tcp",
            severity=Severity.INFO, title="t1", description="d",
        )
        f2 = Finding(
            source="nuclei", host="b", port="80", protocol="tcp",
            severity=Severity.INFO, title="t2", description="d",
        )
        f1.tags.append("added")
        assert "added" not in f2.tags


# ---------- Service model ----------


class TestService:
    def test_service_defaults(self):
        svc = Service(name="http")
        assert svc.product == ""
        assert svc.version == ""

    def test_service_with_product(self):
        svc = Service(name="ssh", product="OpenSSH", version="8.9")
        assert svc.product == "OpenSSH"
        assert svc.version == "8.9"
