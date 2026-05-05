"""Tests for wireghost.parsers.wpscan."""

from __future__ import annotations

import json
from pathlib import Path

from wireghost.models.severity import Severity
from wireghost.parsers.wpscan import parse_wpscan_json

FIXTURE_DIR = Path(__file__).parent / "fixtures"


class TestParseWpscanJson:
    def test_parses_wordpress_version(self):
        findings = parse_wpscan_json(FIXTURE_DIR / "wpscan_output.json", host_ip="10.0.0.1")
        ver = [f for f in findings if "WordPress Version" in f.title]
        assert len(ver) == 1
        assert "6.2.1" in ver[0].title
        assert ver[0].severity == Severity.INFO

    def test_version_vulnerability(self):
        findings = parse_wpscan_json(FIXTURE_DIR / "wpscan_output.json", host_ip="10.0.0.1")
        vuln = [f for f in findings if "Authenticated XSS" in f.title]
        assert len(vuln) == 1
        assert vuln[0].severity == Severity.HIGH
        assert "CVE-2023-38000" in vuln[0].cve

    def test_parses_plugins(self):
        findings = parse_wpscan_json(FIXTURE_DIR / "wpscan_output.json", host_ip="10.0.0.1")
        plugins = [f for f in findings if "WP Plugin:" in f.title]
        assert len(plugins) == 2
        names = {f.title for f in plugins}
        assert any("contact-form-7" in n for n in names)
        assert any("akismet" in n for n in names)

    def test_plugin_version_in_title(self):
        findings = parse_wpscan_json(FIXTURE_DIR / "wpscan_output.json", host_ip="10.0.0.1")
        cf7 = [f for f in findings if "contact-form-7" in f.title and "WP Plugin:" in f.title]
        assert len(cf7) == 1
        assert "5.7.1" in cf7[0].title

    def test_plugin_vulnerability(self):
        findings = parse_wpscan_json(FIXTURE_DIR / "wpscan_output.json", host_ip="10.0.0.1")
        vuln = [f for f in findings if "Open Redirect" in f.title]
        assert len(vuln) == 1
        assert vuln[0].severity == Severity.HIGH

    def test_parses_themes(self):
        findings = parse_wpscan_json(FIXTURE_DIR / "wpscan_output.json", host_ip="10.0.0.1")
        themes = [f for f in findings if "WP Theme:" in f.title]
        assert len(themes) == 1
        assert "twentytwentythree" in themes[0].title

    def test_parses_users(self):
        findings = parse_wpscan_json(FIXTURE_DIR / "wpscan_output.json", host_ip="10.0.0.1")
        users = [f for f in findings if "WP User:" in f.title]
        assert len(users) == 2
        usernames = {f.title for f in users}
        assert "WP User: admin" in usernames
        assert "WP User: editor" in usernames
        assert all(u.severity == Severity.MEDIUM for u in users)

    def test_interesting_findings(self):
        findings = parse_wpscan_json(FIXTURE_DIR / "wpscan_output.json", host_ip="10.0.0.1")
        interesting = [f for f in findings if "XML-RPC" in f.title]
        assert len(interesting) == 1
        assert interesting[0].severity == Severity.LOW

    def test_all_sources_wpscan(self):
        findings = parse_wpscan_json(FIXTURE_DIR / "wpscan_output.json", host_ip="10.0.0.1")
        assert all(f.source == "wpscan" for f in findings)

    def test_host_ip_set(self):
        findings = parse_wpscan_json(FIXTURE_DIR / "wpscan_output.json", host_ip="10.0.0.1")
        assert all(f.host == "10.0.0.1" for f in findings)

    def test_full_url_contains_target(self):
        findings = parse_wpscan_json(FIXTURE_DIR / "wpscan_output.json", host_ip="10.0.0.1")
        ver = [f for f in findings if "WordPress Version" in f.title]
        assert "http://10.0.0.1/" in ver[0].full_url

    def test_cve_references_in_vuln(self):
        findings = parse_wpscan_json(FIXTURE_DIR / "wpscan_output.json", host_ip="10.0.0.1")
        vuln = [f for f in findings if "Authenticated XSS" in f.title][0]
        assert "CVE-2023-38000" in vuln.cve

    def test_missing_file_returns_empty(self):
        assert parse_wpscan_json(Path("/nonexistent.json")) == []

    def test_empty_file_returns_empty(self, tmp_path):
        empty = tmp_path / "empty.json"
        empty.write_text("")
        assert parse_wpscan_json(empty) == []

    def test_malformed_json_returns_empty(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("{not valid")
        assert parse_wpscan_json(f) == []

    def test_no_vulns_clean_scan(self, tmp_path):
        data = {
            "target_url": "http://10.0.0.2/",
            "version": {"number": "6.4"},
            "plugins": {},
            "themes": {},
            "users": {},
            "interesting_findings": [],
        }
        f = tmp_path / "clean.json"
        f.write_text(json.dumps(data))
        findings = parse_wpscan_json(f, host_ip="10.0.0.2")
        vulns = [fi for fi in findings if fi.severity in (Severity.HIGH, Severity.CRITICAL)]
        assert len(vulns) == 0

    def test_non_dict_returns_empty(self, tmp_path):
        f = tmp_path / "list.json"
        f.write_text(json.dumps([1, 2, 3]))
        assert parse_wpscan_json(f) == []

    def test_default_host_ip_empty(self):
        findings = parse_wpscan_json(FIXTURE_DIR / "wpscan_output.json")
        assert all(f.host == "" for f in findings)
