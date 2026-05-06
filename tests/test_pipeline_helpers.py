"""Tests for miscellaneous pipeline helper functions across multiple modules."""

from __future__ import annotations

from unittest.mock import patch

from wireghost.models.finding import Finding
from wireghost.models.scan import Host, Port, Service, WebTech
from wireghost.models.severity import Severity
from wireghost.pipeline.snmp_enum import _build_findings, _DEFAULT_COMMUNITIES
from wireghost.pipeline.web_crawl import _safe_filename as crawl_safe_filename
from wireghost.pipeline.webscreenshot import (
    _match_url,
    _safe_filename as screenshot_safe_filename,
)
from wireghost.utils.installer import _get_arch


# ================================================================
# SNMP: _build_findings
# ================================================================


class TestSnmpBuildFindings:
    def test_community_string_finding(self):
        findings = _build_findings("10.0.0.1", "public", "")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "public" in findings[0].title
        assert findings[0].source == "snmp_enum"
        assert findings[0].port == "161"
        assert findings[0].protocol == "udp"

    def test_with_walk_output(self):
        walk = ".1.3.6.1.2.1.1.1.0 = STRING: Linux host 5.4.0\n"
        findings = _build_findings("10.0.0.1", "public", walk)
        assert len(findings) == 2
        assert findings[1].severity == Severity.INFO
        assert "system information" in findings[1].title.lower()

    def test_empty_walk_single_finding(self):
        findings = _build_findings("10.0.0.1", "private", "")
        assert len(findings) == 1
        assert "private" in findings[0].title

    def test_host_ip_in_description(self):
        findings = _build_findings("192.168.1.1", "community", "")
        assert "192.168.1.1" in findings[0].description


class TestSnmpDefaultCommunities:
    def test_public_in_list(self):
        assert "public" in _DEFAULT_COMMUNITIES

    def test_private_in_list(self):
        assert "private" in _DEFAULT_COMMUNITIES

    def test_at_least_5_communities(self):
        assert len(_DEFAULT_COMMUNITIES) >= 5


# ================================================================
# web_crawl: _safe_filename
# ================================================================


class TestCrawlSafeFilename:
    def test_url_sanitized(self):
        result = crawl_safe_filename("http://10.0.0.1:8080/admin")
        assert "/" not in result
        assert ":" not in result

    def test_max_length(self):
        long_url = "http://10.0.0.1/" + "a" * 200
        result = crawl_safe_filename(long_url)
        assert len(result) <= 80

    def test_preserves_alphanumeric(self):
        result = crawl_safe_filename("http_test_file.txt")
        assert "http_test_file.txt" == result

    def test_special_chars_replaced(self):
        result = crawl_safe_filename("https://host/path?q=1&r=2")
        assert "?" not in result
        assert "&" not in result


# ================================================================
# webscreenshot: _safe_filename
# ================================================================


class TestScreenshotSafeFilename:
    def test_http_url(self):
        result = screenshot_safe_filename("http://10.0.0.1:8080")
        assert result == "http_10.0.0.1_8080.png"

    def test_https_default_port(self):
        result = screenshot_safe_filename("https://10.0.0.1")
        assert result == "https_10.0.0.1_443.png"

    def test_http_default_port(self):
        result = screenshot_safe_filename("http://10.0.0.1")
        assert result == "http_10.0.0.1_80.png"

    def test_ends_with_png(self):
        result = screenshot_safe_filename("http://host:9999")
        assert result.endswith(".png")


# ================================================================
# webscreenshot: _match_url
# ================================================================


class TestMatchUrl:
    def test_exact_match(self):
        urls = ["http://10.0.0.1:80", "https://10.0.0.1:443"]
        png = "http-10.0.0.1-80.png"
        result = _match_url(png, urls)
        assert result == "http://10.0.0.1:80"

    def test_fallback_to_first(self):
        urls = ["http://10.0.0.1:80"]
        result = _match_url("totally_unrelated_name.png", urls)
        assert result == "http://10.0.0.1:80"

    def test_empty_urls(self):
        result = _match_url("test.png", [])
        assert result is None

    def test_normalized_comparison(self):
        urls = ["https://10.0.0.1:443/admin"]
        result = _match_url("https-10.0.0.1-443-admin.png", urls)
        assert result == urls[0]


# ================================================================
# installer: _get_arch
# ================================================================


class TestGetArch:
    def test_x86_64(self):
        with patch("platform.machine", return_value="x86_64"):
            assert _get_arch() == "amd64"

    def test_amd64(self):
        with patch("platform.machine", return_value="amd64"):
            assert _get_arch() == "amd64"

    def test_aarch64(self):
        with patch("platform.machine", return_value="aarch64"):
            assert _get_arch() == "arm64"

    def test_arm64(self):
        with patch("platform.machine", return_value="arm64"):
            assert _get_arch() == "arm64"

    def test_unknown_passthrough(self):
        with patch("platform.machine", return_value="riscv64"):
            assert _get_arch() == "riscv64"


# ================================================================
# CMS scan: WordPress URL detection logic
# ================================================================


class TestWordPressDetection:
    def _detect_wp_urls(self, technologies: list[WebTech], endpoints: list[str]) -> list[str]:
        """Extract WordPress URL detection logic from scan_cms."""
        wp_urls: list[str] = []
        for tech in technologies:
            if tech.name.lower() in ("wordpress", "wp", "wordpress.org"):
                if tech.url and tech.url not in wp_urls:
                    wp_urls.append(tech.url)
        for ep in endpoints:
            if any(wp in ep.lower() for wp in ("/wp-", "wordpress")):
                base = ep.split("/wp-")[0] if "/wp-" in ep else ep
                if base not in wp_urls:
                    wp_urls.append(base)
        return wp_urls

    def test_wordpress_in_tech(self):
        techs = [WebTech(name="WordPress", version="6.4", url="http://10.0.0.1:80")]
        urls = self._detect_wp_urls(techs, [])
        assert urls == ["http://10.0.0.1:80"]

    def test_wp_in_tech(self):
        techs = [WebTech(name="WP", version="", url="http://10.0.0.1")]
        urls = self._detect_wp_urls(techs, [])
        assert len(urls) == 1

    def test_wp_login_endpoint(self):
        urls = self._detect_wp_urls([], ["http://10.0.0.1/wp-login.php"])
        assert urls == ["http://10.0.0.1"]

    def test_wp_admin_endpoint(self):
        urls = self._detect_wp_urls([], ["http://10.0.0.1/wp-admin/"])
        assert urls == ["http://10.0.0.1"]

    def test_dedup_tech_and_endpoint(self):
        techs = [WebTech(name="WordPress", version="6.4", url="http://10.0.0.1")]
        urls = self._detect_wp_urls(techs, ["http://10.0.0.1/wp-login.php"])
        assert len(urls) == 1

    def test_no_wordpress_detected(self):
        techs = [WebTech(name="nginx", version="1.24", url="http://10.0.0.1")]
        urls = self._detect_wp_urls(techs, ["http://10.0.0.1/admin"])
        assert urls == []

    def test_wordpress_org_variant(self):
        techs = [WebTech(name="WordPress.org", version="", url="http://10.0.0.1")]
        urls = self._detect_wp_urls(techs, [])
        assert len(urls) == 1

    def test_case_insensitive(self):
        urls = self._detect_wp_urls([], ["http://10.0.0.1/WP-ADMIN/"])
        assert len(urls) == 1


# ================================================================
# orchestrator: _dedup_findings (comprehensive edge cases)
# ================================================================

from wireghost.pipeline.orchestrator import _dedup_findings


class TestDedupFindingsExtended:
    def _f(self, host="10.0.0.1", port="80", title="vuln", source="nuclei", cve="") -> Finding:
        return Finding(
            source=source, host=host, port=port, protocol="tcp",
            severity=Severity.HIGH, title=title, description="d", cve=cve,
        )

    def test_same_cve_different_sources_deduped(self):
        findings = [
            self._f(source="nmap_vuln", cve="CVE-2021-1234"),
            self._f(source="msf_scan", cve="CVE-2021-1234"),
        ]
        result = _dedup_findings(findings)
        assert len(result) == 1
        assert result[0].source == "nmap_vuln"

    def test_different_cves_kept(self):
        findings = [
            self._f(cve="CVE-2021-1234"),
            self._f(cve="CVE-2021-5678"),
        ]
        result = _dedup_findings(findings)
        assert len(result) == 2

    def test_title_prefix_stripping(self):
        findings = [
            self._f(source="nmap_vuln", title="nmap: SMB vuln detected"),
            self._f(source="msf_scan", title="MSF smb vuln detected"),
        ]
        result = _dedup_findings(findings)
        assert len(result) == 1

    def test_nxc_prefix_stripped(self):
        findings = [
            self._f(source="netexec", title="nxc: SMB signing disabled"),
            self._f(source="nmap_vuln", title="SMB signing disabled"),
        ]
        result = _dedup_findings(findings)
        assert len(result) == 1

    def test_different_hosts_not_deduped(self):
        findings = [
            self._f(host="10.0.0.1", title="same vuln"),
            self._f(host="10.0.0.2", title="same vuln"),
        ]
        result = _dedup_findings(findings)
        assert len(result) == 2

    def test_different_ports_not_deduped(self):
        findings = [
            self._f(port="80", title="same vuln"),
            self._f(port="443", title="same vuln"),
        ]
        result = _dedup_findings(findings)
        assert len(result) == 2

    def test_empty_list(self):
        assert _dedup_findings([]) == []

    def test_long_title_truncated_for_key(self):
        long_title = "A" * 100
        findings = [
            self._f(title=long_title),
            self._f(title=long_title + " extra suffix"),
        ]
        result = _dedup_findings(findings)
        assert len(result) == 1

    def test_first_finding_wins(self):
        findings = [
            self._f(source="nuclei", title="test vuln"),
            self._f(source="msf_scan", title="test vuln"),
        ]
        result = _dedup_findings(findings)
        assert result[0].source == "nuclei"
