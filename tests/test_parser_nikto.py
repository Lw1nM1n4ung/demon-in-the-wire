"""Tests for wireghost.parsers.nikto."""

from __future__ import annotations

import json
from pathlib import Path

from wireghost.models.severity import Severity
from wireghost.parsers.nikto import parse_nikto_json

FIXTURE_DIR = Path(__file__).parent / "fixtures"


class TestParseNiktoJson:
    def test_parses_vulnerabilities(self):
        findings = parse_nikto_json(FIXTURE_DIR / "nikto_output.json")
        assert len(findings) == 5

    def test_all_sources_nikto(self):
        findings = parse_nikto_json(FIXTURE_DIR / "nikto_output.json")
        assert all(f.source == "nikto" for f in findings)

    def test_host_ip_set(self):
        findings = parse_nikto_json(FIXTURE_DIR / "nikto_output.json")
        assert all(f.host == "10.0.0.1" for f in findings)

    def test_port_set(self):
        findings = parse_nikto_json(FIXTURE_DIR / "nikto_output.json")
        assert all(f.port == "80" for f in findings)

    def test_severity_low_for_header_leak(self):
        findings = parse_nikto_json(FIXTURE_DIR / "nikto_output.json")
        etag = [f for f in findings if "ETags" in f.title]
        assert len(etag) == 1
        assert etag[0].severity == Severity.LOW

    def test_severity_medium_for_directory_listing(self):
        findings = parse_nikto_json(FIXTURE_DIR / "nikto_output.json")
        dirlist = [f for f in findings if "Directory listing" in f.title]
        assert len(dirlist) == 1
        assert dirlist[0].severity == Severity.MEDIUM

    def test_severity_critical_for_rce(self):
        findings = parse_nikto_json(FIXTURE_DIR / "nikto_output.json")
        rce = [f for f in findings if "Remote code execution" in f.title]
        assert len(rce) == 1
        assert rce[0].severity == Severity.CRITICAL

    def test_severity_medium_for_clickjack(self):
        findings = parse_nikto_json(FIXTURE_DIR / "nikto_output.json")
        click = [f for f in findings if "clickjacking" in f.title]
        assert len(click) == 1
        assert click[0].severity == Severity.MEDIUM

    def test_template_id_format(self):
        findings = parse_nikto_json(FIXTURE_DIR / "nikto_output.json")
        for f in findings:
            assert f.template_id.startswith("NIKTO-")

    def test_endpoint_set(self):
        findings = parse_nikto_json(FIXTURE_DIR / "nikto_output.json")
        endpoints = {f.endpoint for f in findings}
        assert "/icons/" in endpoints
        assert "/cgi-bin/test.cgi" in endpoints

    def test_curl_command_generated(self):
        findings = parse_nikto_json(FIXTURE_DIR / "nikto_output.json")
        for f in findings:
            assert "curl" in f.curl_command

    def test_references_parsed(self):
        findings = parse_nikto_json(FIXTURE_DIR / "nikto_output.json")
        etag = [f for f in findings if "ETags" in f.title][0]
        assert "OSVDB-3092" in etag.references

    def test_deduplicates_same_id_and_endpoint(self, tmp_path):
        data = [{
            "ip": "10.0.0.1", "port": "80",
            "vulnerabilities": [
                {"id": "11111", "msg": "Dup finding", "url": "/"},
                {"id": "11111", "msg": "Dup finding again", "url": "/"},
            ],
        }]
        f = tmp_path / "dup.json"
        f.write_text(json.dumps(data))
        findings = parse_nikto_json(f)
        assert len(findings) == 1

    def test_missing_file_returns_empty(self):
        assert parse_nikto_json(Path("/nonexistent.json")) == []

    def test_empty_file_returns_empty(self, tmp_path):
        empty = tmp_path / "empty.json"
        empty.write_text("")
        assert parse_nikto_json(empty) == []

    def test_malformed_json_returns_empty(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("{not valid json")
        assert parse_nikto_json(f) == []

    def test_single_host_object_not_array(self, tmp_path):
        data = {
            "ip": "10.0.0.2", "port": "443",
            "vulnerabilities": [
                {"id": "22222", "msg": "Test finding", "url": "/test"},
            ],
        }
        f = tmp_path / "single.json"
        f.write_text(json.dumps(data))
        findings = parse_nikto_json(f)
        assert len(findings) == 1
        assert findings[0].host == "10.0.0.2"
        assert findings[0].port == "443"
        assert findings[0].protocol == "https"
