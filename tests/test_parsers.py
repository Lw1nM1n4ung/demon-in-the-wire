"""Tests for wireghost.parsers — nmap + nuclei + naabu + masscan + searchsploit."""

from __future__ import annotations

from pathlib import Path

from wireghost.models.severity import Severity
from wireghost.parsers.nmap import (
    extract_open_ports,
    generate_vuln_command,
    parse_nmap_vuln_xml,
    parse_nmap_xml,
)
from wireghost.parsers.nuclei import parse_nuclei_json
from wireghost.parsers.naabu import parse_naabu_json
from wireghost.parsers.masscan import parse_masscan_xml


# ================================================================
# Nmap parser tests
# ================================================================


class TestParseNmapXml:
    def test_parse_nmap_xml(self, nmap_port_scan_xml: Path):
        hosts = parse_nmap_xml(nmap_port_scan_xml)
        assert len(hosts) == 1

        host = hosts[0]
        assert host.ip == "10.0.0.1"
        assert host.hostname == "test-host.local"
        assert host.status == "up"

        # 4 total ports, 3 open
        assert len(host.ports) == 4
        open_ports = host.open_ports
        assert len(open_ports) == 3
        open_numbers = sorted(p.number for p in open_ports)
        assert open_numbers == [22, 80, 443]

        # 3306 is filtered
        filtered = [p for p in host.ports if p.number == 3306]
        assert len(filtered) == 1
        assert filtered[0].state == "filtered"

    def test_parse_nmap_xml_missing_file(self, tmp_path: Path):
        result = parse_nmap_xml(tmp_path / "nonexistent.xml")
        assert result == []


class TestParseNmapVulnXml:
    def test_parse_nmap_vuln_xml(self, nmap_vuln_scan_xml: Path):
        findings = parse_nmap_vuln_xml(nmap_vuln_scan_xml)
        # ssh-auth-methods is filtered (info-only script, not a vuln)
        assert len(findings) == 2

        by_title = {f.title: f for f in findings}

        # http-enum -> MEDIUM (matches "enum" keyword)
        f_enum = by_title["Nmap: http-enum"]
        assert f_enum.severity == Severity.MEDIUM
        assert f_enum.source == "nmap_vuln"
        assert f_enum.host == "10.0.0.1"

        # http-vuln-cve2021-41773 -> HIGH (matches "vuln" keyword)
        f_cve = by_title["Nmap: http-vuln-cve2021-41773"]
        assert f_cve.severity == Severity.HIGH


class TestExtractOpenPorts:
    def test_extract_open_ports(self, nmap_port_scan_xml: Path):
        pairs = extract_open_ports(nmap_port_scan_xml)
        assert len(pairs) == 3
        port_numbers = sorted(p for _, p in pairs)
        assert port_numbers == [22, 80, 443]
        # All from the same host.
        assert all(ip == "10.0.0.1" for ip, _ in pairs)
        # 3306 (filtered) must not appear.
        assert 3306 not in port_numbers


class TestGenerateVulnCommand:
    def test_generate_vuln_command(self, nmap_port_scan_xml: Path, tmp_path: Path):
        cmd = generate_vuln_command(nmap_port_scan_xml, tmp_path / "vuln.xml")
        assert cmd is not None
        assert "nmap" in cmd
        assert "--script=vuln" in cmd
        assert "22,80,443" in cmd
        assert "10.0.0.1" in cmd

    def test_generate_vuln_command_no_file(self, tmp_path: Path):
        result = generate_vuln_command(tmp_path / "nope.xml", tmp_path / "out.xml")
        assert result is None


# ================================================================
# Nuclei parser tests
# ================================================================


class TestParseNucleiArray:
    def test_parse_nuclei_array(self, nuclei_array_json: Path):
        findings = parse_nuclei_json(nuclei_array_json)
        assert len(findings) == 3

        by_template = {f.template_id: f for f in findings}

        # tech-detect -> INFO
        f_tech = by_template["tech-detect"]
        assert f_tech.severity == Severity.INFO
        assert f_tech.title == "Technology Detection - nginx"
        assert f_tech.source == "nuclei"

        # CVE-2021-41773 -> CRITICAL
        f_cve = by_template["CVE-2021-41773"]
        assert f_cve.severity == Severity.CRITICAL
        assert f_cve.title == "Apache HTTP Server 2.4.49 - Path Traversal"

        # ssl-weak-cipher -> MEDIUM
        f_ssl = by_template["ssl-weak-cipher"]
        assert f_ssl.severity == Severity.MEDIUM
        assert f_ssl.title == "SSL Weak Cipher Suites Detected"


class TestParseNucleiJsonl:
    def test_parse_nuclei_jsonl(self, nuclei_jsonl_json: Path):
        findings = parse_nuclei_json(nuclei_jsonl_json)
        assert len(findings) == 2

        by_template = {f.template_id: f for f in findings}

        # tech-detect -> INFO
        f_tech = by_template["tech-detect"]
        assert f_tech.severity == Severity.INFO

        # xss-reflected -> HIGH
        f_xss = by_template["xss-reflected"]
        assert f_xss.severity == Severity.HIGH
        assert f_xss.title == "Reflected XSS"
        assert "/search" in f_xss.endpoint


class TestParseNucleiMissingFile:
    def test_parse_nuclei_missing_file(self, tmp_path: Path):
        result = parse_nuclei_json(tmp_path / "nonexistent.json")
        assert result == []


class TestParseNucleiEmpty:
    def test_parse_nuclei_empty(self, tmp_path: Path):
        empty = tmp_path / "empty.json"
        empty.write_text("")
        result = parse_nuclei_json(empty)
        assert result == []


# ================================================================
# Naabu parser tests
# ================================================================


class TestParseNaabuJson:
    def test_parses_hosts_and_ports(self):
        fixture = Path(__file__).parent / "fixtures" / "naabu_output.json"
        hosts = parse_naabu_json(fixture)
        assert len(hosts) == 1
        assert hosts[0].ip == "10.0.0.1"
        assert len(hosts[0].open_ports) == 3
        ports = sorted(p.number for p in hosts[0].open_ports)
        assert ports == [22, 80, 443]

    def test_all_ports_are_open(self):
        fixture = Path(__file__).parent / "fixtures" / "naabu_output.json"
        hosts = parse_naabu_json(fixture)
        for port in hosts[0].ports:
            assert port.state == "open"
            assert port.protocol == "tcp"

    def test_missing_file_returns_empty(self):
        assert parse_naabu_json(Path("/nonexistent.json")) == []

    def test_empty_file_returns_empty(self, tmp_path):
        empty = tmp_path / "empty.json"
        empty.write_text("")
        assert parse_naabu_json(empty) == []

    def test_multiple_hosts(self, tmp_path):
        data = '{"ip":"10.0.0.1","port":22,"protocol":"tcp"}\n{"ip":"10.0.0.2","port":80,"protocol":"tcp"}\n'
        f = tmp_path / "multi.json"
        f.write_text(data)
        hosts = parse_naabu_json(f)
        assert len(hosts) == 2
        ips = sorted(h.ip for h in hosts)
        assert ips == ["10.0.0.1", "10.0.0.2"]


# ================================================================
# Masscan parser tests
# ================================================================


class TestParseMasscanXml:
    def test_parses_hosts_and_ports(self):
        fixture = Path(__file__).parent / "fixtures" / "masscan_output.xml"
        hosts = parse_masscan_xml(fixture)
        assert len(hosts) == 1
        assert hosts[0].ip == "10.0.0.1"
        assert len(hosts[0].open_ports) == 3
        ports = sorted(p.number for p in hosts[0].open_ports)
        assert ports == [22, 80, 443]

    def test_all_ports_open_tcp(self):
        fixture = Path(__file__).parent / "fixtures" / "masscan_output.xml"
        hosts = parse_masscan_xml(fixture)
        for port in hosts[0].ports:
            assert port.state == "open"
            assert port.protocol == "tcp"

    def test_missing_file_returns_empty(self):
        assert parse_masscan_xml(Path("/nonexistent.xml")) == []

    def test_no_service_info(self):
        fixture = Path(__file__).parent / "fixtures" / "masscan_output.xml"
        hosts = parse_masscan_xml(fixture)
        for port in hosts[0].ports:
            assert port.service is None


# ------------------------------------------------------------------ #
# searchsploit
# ------------------------------------------------------------------ #
from wireghost.parsers.searchsploit import parse_searchsploit_json


class TestParseSearchsploitJson:
    def test_parses_exploits(self):
        fixture = Path(__file__).parent / "fixtures" / "searchsploit_output.json"
        findings = parse_searchsploit_json(fixture, host_ip="10.0.0.1")
        assert len(findings) == 3
        assert findings[0].source == "searchsploit"
        assert findings[0].host == "10.0.0.1"
        assert "Apache 2.4.49" in findings[0].title

    def test_severity_classification(self):
        fixture = Path(__file__).parent / "fixtures" / "searchsploit_output.json"
        findings = parse_searchsploit_json(fixture)
        titles = {f.title: f.severity for f in findings}
        # "Remote Code Execution" -> CRITICAL
        assert titles["Exploit: Apache 2.4.49 - Path Traversal & Remote Code Execution"] == Severity.CRITICAL
        # "Remote" type -> HIGH
        assert titles["Exploit: OpenSSH 8.9 - Remote Code Execution"] == Severity.CRITICAL
        # "Denial of Service" -> MEDIUM
        assert titles["Exploit: MySQL 5.7 - Denial of Service"] == Severity.MEDIUM

    def test_cve_references(self):
        fixture = Path(__file__).parent / "fixtures" / "searchsploit_output.json"
        findings = parse_searchsploit_json(fixture)
        apache = findings[0]
        assert any("CVE-2021-41773" in r for r in apache.references)
        assert any("exploit-db.com" in r for r in apache.references)

    def test_edb_id_in_template_id(self):
        fixture = Path(__file__).parent / "fixtures" / "searchsploit_output.json"
        findings = parse_searchsploit_json(fixture)
        assert findings[0].template_id == "EDB-50383"

    def test_missing_file_returns_empty(self):
        assert parse_searchsploit_json(Path("/nonexistent.json")) == []

    def test_empty_file_returns_empty(self, tmp_path):
        empty = tmp_path / "empty.json"
        empty.write_text("")
        assert parse_searchsploit_json(empty) == []

    def test_deduplicates_by_edb_id(self, tmp_path):
        import json
        data = {"RESULTS_EXPLOIT": [
            {"Title": "Dup Exploit", "EDB-ID": "11111", "Type": "remote", "Platform": "linux", "Codes": "", "Path": "", "Date_Published": ""},
            {"Title": "Dup Exploit Again", "EDB-ID": "11111", "Type": "remote", "Platform": "linux", "Codes": "", "Path": "", "Date_Published": ""},
        ], "RESULTS_SHELLCODE": []}
        f = tmp_path / "dup.json"
        f.write_text(json.dumps(data))
        findings = parse_searchsploit_json(f)
        assert len(findings) == 1


