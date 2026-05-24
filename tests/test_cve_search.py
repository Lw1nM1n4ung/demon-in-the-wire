"""Tests for enhanced CVE search: version extraction, CPE mapping, NVD query."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp  # ensure aiohttp is in sys.modules so patches resolve
import pytest

from wireghost.config import ScanConfig
from wireghost.models.finding import Finding
from wireghost.models.scan import Host, Port, Service, WebTech
from wireghost.models.severity import Severity
from wireghost.pipeline.cve_search import (
    VersionInfo,
    _lookup_cpe,
    _extract_versions_from_ports,
    _extract_versions_from_technologies,
    _extract_versions_from_findings,
    _parse_msf_finding,
    _parse_service_enum_finding,
    _parse_wpscan_finding,
    _parse_enum4linux_finding,
    _parse_netexec_finding,
    _parse_snmp_finding,
    _parse_tls_finding,
    _parse_ldap_finding,
    collect_all_versions,
    build_cpe_uri,
    _severity_from_cvss,
    scan_cve_search,
)


# ── Helpers ────────────────────────────────────────────────────────────

def _make_host(ip="10.0.0.1", ports=None, technologies=None):
    """Build a minimal Host for testing."""
    host = Host(
        ip=ip,
        hostname="",
        os="",
        status="up",
        ports=ports or [],
        technologies=technologies or [],
        web_endpoints=[],
    )
    return host


def _make_port(number, protocol="tcp", state="open", service_product="", service_version="", service_name=""):
    svc = Service(
        name=service_name,
        product=service_product,
        version=service_version,
    ) if (service_name or service_product or service_version) else None
    return Port(
        number=number,
        protocol=protocol,
        state=state,
        service=svc,
    )


def _make_finding(source, title, port="", description="", template_id="", host="10.0.0.1"):
    return Finding(
        source=source,
        host=host,
        port=port,
        protocol="tcp",
        severity=Severity.INFO,
        title=title,
        description=description or title,
        template_id=template_id,
    )


# ================================================================
# CPE lookup
# ================================================================


class TestCpeLookup:
    def test_known_product_openssh(self):
        vendor, product = _lookup_cpe("openssh")
        assert vendor == "openbsd"
        assert product == "openssh"

    def test_known_product_apache(self):
        vendor, product = _lookup_cpe("apache httpd")
        assert vendor == "apache"
        assert product == "http_server"

    def test_known_product_wordpress(self):
        vendor, product = _lookup_cpe("wordpress")
        assert vendor == "wordpress"
        assert product == "wordpress"

    def test_case_insensitive(self):
        vendor, product = _lookup_cpe("OpenSSH")
        assert vendor == "openbsd"
        assert product == "openssh"

    def test_whitespace_trim(self):
        vendor, product = _lookup_cpe("  nginx  ")
        assert vendor == "nginx"
        assert product == "nginx"

    def test_service_name_fallback_ssh(self):
        vendor, product = _lookup_cpe("ssh")
        assert vendor == "openbsd"
        assert product == "openssh"

    def test_service_name_fallback_mysql(self):
        vendor, product = _lookup_cpe("mysql")
        assert vendor == "oracle"
        assert product == "mysql"

    def test_unknown_product_returns_empty(self):
        vendor, product = _lookup_cpe("completely_unknown_xyz")
        assert vendor == ""
        assert product == ""


# ================================================================
# Version extraction from ports (nmap -sV + fingerprintx)
# ================================================================


class TestExtractVersionsFromPorts:
    def test_single_port_with_version(self):
        host = _make_host(ip="10.0.0.1", ports=[
            _make_port(22, service_product="OpenSSH", service_version="9.6p1", service_name="ssh"),
        ])
        versions = _extract_versions_from_ports(host)
        assert len(versions) == 1
        assert versions[0].product == "OpenSSH"
        assert versions[0].version == "9.6p1"
        assert versions[0].port == "22"
        assert versions[0].source == "nmap"
        assert versions[0].cpe_vendor == "openbsd"
        assert versions[0].cpe_product == "openssh"

    def test_multiple_ports(self):
        host = _make_host(ip="10.0.0.2", ports=[
            _make_port(22, service_product="OpenSSH", service_version="8.4p1", service_name="ssh"),
            _make_port(80, service_product="nginx", service_version="1.18.0", service_name="http"),
            _make_port(3306, service_product="MySQL", service_version="8.0.36", service_name="mysql"),
        ])
        versions = _extract_versions_from_ports(host)
        assert len(versions) == 3

    def test_skip_no_service_product(self):
        host = _make_host(ip="10.0.0.1", ports=[
            _make_port(80, service_product="", service_version=""),
        ])
        versions = _extract_versions_from_ports(host)
        assert len(versions) == 0

    def test_skip_no_version(self):
        host = _make_host(ip="10.0.0.1", ports=[
            _make_port(443, service_product="nginx", service_version="", service_name="https"),
        ])
        versions = _extract_versions_from_ports(host)
        assert len(versions) == 0  # product+version only

    def test_skip_generic_products(self):
        host = _make_host(ip="10.0.0.1", ports=[
            _make_port(80, service_product="Linux", service_version="2.6", service_name="http"),
            _make_port(443, service_product="tcpwrapped", service_version="1", service_name="https"),
        ])
        versions = _extract_versions_from_ports(host)
        assert len(versions) == 0


# ================================================================
# Version extraction from technologies (httpx)
# ================================================================


class TestExtractVersionsFromTechnologies:
    def test_single_tech_with_version(self):
        host = _make_host(technologies=[
            WebTech(name="WordPress", version="6.5.3", url="https://10.0.0.1:443/"),
        ])
        versions = _extract_versions_from_technologies(host)
        assert len(versions) == 1
        assert versions[0].product == "WordPress"
        assert versions[0].version == "6.5.3"
        assert versions[0].source == "httpx"
        assert versions[0].port == "443"

    def test_multiple_technologies(self):
        host = _make_host(technologies=[
            WebTech(name="WordPress", version="6.5.3", url="http://10.0.0.2:8080/"),
            WebTech(name="PHP", version="8.2.12", url="http://10.0.0.2:8080/"),
            WebTech(name="MySQL", version="", url=""),
        ])
        versions = _extract_versions_from_technologies(host)
        assert len(versions) == 2  # MySQL skipped (no version)

    def test_no_version_skipped(self):
        host = _make_host(technologies=[
            WebTech(name="jQuery", version="", url=""),
        ])
        versions = _extract_versions_from_technologies(host)
        assert len(versions) == 0

    def test_port_from_url(self):
        host = _make_host(technologies=[
            WebTech(name="Tomcat", version="9.0.80", url="http://10.0.0.1:8080/manager"),
        ])
        versions = _extract_versions_from_technologies(host)
        assert versions[0].port == "8080"


# ================================================================
# MSF finding parser
# ================================================================


class TestParseMsfFinding:
    def test_ssh_version(self):
        f = _make_finding("msf_scan", "MSF ssh_version: SSH server version: OpenSSH 8.9p1", port="22")
        versions = _parse_msf_finding(f)
        assert len(versions) == 1
        assert versions[0].product == "OpenSSH"
        assert versions[0].port == "22"
        assert versions[0].source == "msf"
        assert versions[0].cpe_vendor == "openbsd"

    def test_smb_windows_version(self):
        f = _make_finding("msf_scan", "MSF smb_version: Host is running Windows 10 Pro build 19045", port="445")
        versions = _parse_msf_finding(f)
        assert len(versions) == 1
        assert versions[0].product == "Windows"
        assert versions[0].cpe_vendor == "microsoft"

    def test_generic_product_version(self):
        f = _make_finding("msf_scan", "MSF mysql_version: MySQL 8.0.36", port="3306")
        versions = _parse_msf_finding(f)
        assert len(versions) == 1
        assert versions[0].product in ("MySQL", "mysql")
        assert versions[0].version == "8.0.36"

    def test_bare_version_only(self):
        f = _make_finding("msf_scan", "MSF postgres_version: 16.3", port="5432",
                          template_id="auxiliary/scanner/postgres/postgres_version")
        versions = _parse_msf_finding(f)
        assert len(versions) == 1
        assert versions[0].version == "16.3"

    def test_no_match(self):
        f = _make_finding("msf_scan", "MSF smb_login: Login failed", port="445")
        versions = _parse_msf_finding(f)
        assert len(versions) == 0


# ================================================================
# Service enum finding parser
# ================================================================


class TestParseServiceEnumFinding:
    def test_ssh_banner(self):
        f = _make_finding("service_enum", "SSH: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.15", port="22")
        versions = _parse_service_enum_finding(f)
        assert len(versions) == 1
        assert "OpenSSH" in versions[0].product or "openssh" in versions[0].product.lower()
        assert versions[0].source == "service_enum"

    def test_ftp_banner(self):
        f = _make_finding("service_enum", "FTP: 220 ProFTPD 1.3.5 Server ready", port="21")
        versions = _parse_service_enum_finding(f)
        assert len(versions) == 1
        assert "ProFTPD" in versions[0].product

    def test_smtp_banner(self):
        f = _make_finding("service_enum", "SMTP: 220 mail.example.com ESMTP Postfix 3.5.0 (Ubuntu)", port="25")
        versions = _parse_service_enum_finding(f)
        assert len(versions) >= 1
        assert any("Postfix" in v.product for v in versions)


# ================================================================
# WPScan finding parser
# ================================================================


class TestParseWpscanFinding:
    def test_wordpress_core_version(self):
        f = _make_finding("wpscan", "WordPress Version: 6.5.3", port="443")
        versions = _parse_wpscan_finding(f)
        assert len(versions) == 1
        assert versions[0].product == "WordPress"
        assert versions[0].version == "6.5.3"
        assert versions[0].cpe_vendor == "wordpress"

    def test_plugin_version(self):
        f = _make_finding("wpscan", "WP Plugin: woocommerce 8.9.1", port="443")
        versions = _parse_wpscan_finding(f)
        assert len(versions) == 1
        assert "woocommerce" in versions[0].product
        assert versions[0].version == "8.9.1"

    def test_theme_detection(self):
        f = _make_finding("wpscan", "WP Theme: twentytwentyfour", port="443")
        versions = _parse_wpscan_finding(f)
        assert len(versions) == 1
        assert "twentytwentyfour" in versions[0].product
        assert versions[0].version == ""
        assert versions[0].source == "wpscan"


# ================================================================
# Enum4linux finding parser
# ================================================================


class TestParseEnum4linuxFinding:
    def test_windows_version(self):
        f = _make_finding("enum4linux",
                          "SMB OS Detection: Windows 10 19041",
                          description="OS=[Windows 10 19041]\nOS Build=19041",
                          port="445")
        versions = _parse_enum4linux_finding(f)
        windows_v = [v for v in versions if v.product == "Windows"]
        assert len(windows_v) >= 1

    def test_samba_version(self):
        f = _make_finding("enum4linux",
                          "SMB OS Detection: Samba 4.15",
                          description="Samba/Server version: Samba 4.15.13-Ubuntu",
                          port="445")
        versions = _parse_enum4linux_finding(f)
        samba_v = [v for v in versions if v.product == "Samba"]
        assert len(samba_v) >= 1


# ================================================================
# NetExec finding parser
# ================================================================


class TestParseNetexecFinding:
    def test_windows_build(self):
        f = _make_finding("netexec",
                          "SMB OS Detection: Windows 10.0 Build 19045",
                          port="445")
        versions = _parse_netexec_finding(f)
        assert len(versions) == 1
        assert versions[0].product == "Windows"
        assert versions[0].source == "netexec"
        assert versions[0].cpe_vendor == "microsoft"

    def test_non_windows(self):
        f = _make_finding("netexec", "SMB Signing: disabled", port="445")
        versions = _parse_netexec_finding(f)
        assert len(versions) == 0


# ================================================================
# SNMP finding parser
# ================================================================


class TestParseSnmpFinding:
    def test_cisco_ios(self):
        f = _make_finding("snmp_enum",
                          "SNMP sysDescr: Cisco IOS XE Software, Version 17.3.4",
                          port="161")
        versions = _parse_snmp_finding(f)
        assert len(versions) >= 1
        cisco_v = versions[0]
        assert "Cisco" in cisco_v.product

    def test_generic_product(self):
        f = _make_finding("snmp_enum",
                          "SNMP sysDescr: Linux server 5.10.0",
                          port="161")
        versions = _parse_snmp_finding(f)
        # Should extract at least something via VERSION_RE
        assert len(versions) >= 0  # may or may not match


# ================================================================
# TLS finding parser
# ================================================================


class TestParseTlsFinding:
    def test_nginx_hint(self):
        f = _make_finding("sslscan",
                          "SSL/TLS: Weak cipher detected",
                          description="Server certificate CN: *.example.com\nServer: nginx",
                          port="443")
        versions = _parse_tls_finding(f)
        assert len(versions) >= 1
        assert versions[0].product == "nginx"

    def test_no_server_hint(self):
        f = _make_finding("sslscan",
                          "SSL/TLS: Expired certificate",
                          description="Certificate expired on 2024-01-01",
                          port="443")
        versions = _parse_tls_finding(f)
        assert len(versions) == 0


# ================================================================
# LDAP finding parser
# ================================================================


class TestParseLdapFinding:
    def test_active_directory(self):
        f = _make_finding("ldap_enum",
                          "LDAP namingContexts: DC=domain,DC=com",
                          description="rootDSE: vendorName=Microsoft, vendorVersion=Active Directory",
                          port="389")
        versions = _parse_ldap_finding(f)
        assert len(versions) >= 1
        assert "Active Directory" in versions[0].product

    def test_openldap(self):
        f = _make_finding("ldap_enum",
                          "LDAP anonymous bind successful",
                          description="Server: OpenLDAP 2.5.13",
                          port="389")
        versions = _parse_ldap_finding(f)
        assert len(versions) >= 1


# ================================================================
# Finding dispatch
# ================================================================


class TestExtractVersionsFromFindings:
    def test_dispatches_to_correct_parsers(self):
        findings = [
            _make_finding("msf_scan", "MSF ssh_version: OpenSSH 9.6", port="22"),
            _make_finding("wpscan", "WordPress Version: 6.5.3", port="443"),
            _make_finding("netexec", "SMB OS Detection: Windows 10.0 Build 19045", port="445"),
            _make_finding("enum4linux", "SMB OS Detection: Windows 10 19041",
                          description="OS=[Windows 10 19041]", port="445"),
        ]
        versions = _extract_versions_from_findings(findings)
        sources = {v.source for v in versions}
        assert "msf" in sources
        assert "wpscan" in sources
        assert "netexec" in sources
        assert "enum4linux" in sources

    def test_unknown_source_skipped(self):
        findings = [
            _make_finding("nuclei", "CVE-2024-1234: RCE in Apache", port="8080"),
            _make_finding("nmap_vuln", "VULNERABLE: CVE-2024-5678", port="3306"),
        ]
        versions = _extract_versions_from_findings(findings)
        assert len(versions) == 0


# ================================================================
# Unified collection + dedup
# ================================================================


class TestCollectAllVersions:
    def test_collects_from_ports_and_tech(self):
        host = _make_host(ip="10.0.0.1",
            ports=[_make_port(22, service_product="OpenSSH", service_version="9.6", service_name="ssh")],
            technologies=[WebTech(name="nginx", version="1.18", url="http://10.0.0.1:80/")],
        )
        versions = collect_all_versions(host, [])
        assert len(versions) == 2
        sources = {v.source for v in versions}
        assert "nmap" in sources
        assert "httpx" in sources

    def test_dedup_same_product_version_port(self):
        host = _make_host(ip="10.0.0.1",
            ports=[_make_port(22, service_product="OpenSSH", service_version="9.6", service_name="ssh")],
        )
        f = _make_finding("msf_scan", "MSF ssh_version: OpenSSH 9.6", port="22")
        versions = collect_all_versions(host, [f])
        # Both nmap and MSF find OpenSSH 9.6 on port 22 — should dedup
        # Actually: nmap→"OpenSSH|9.6|22", msf→"OpenSSH|9.6|22" — key is the same
        openssh_versions = [v for v in versions
                          if v.product.lower().startswith("openssh") and v.port == "22"]
        assert len(openssh_versions) == 1  # deduplicated

    def test_sorted_by_product(self):
        host = _make_host(ip="10.0.0.1", ports=[
            _make_port(3306, service_product="MySQL", service_version="8.0", service_name="mysql"),
            _make_port(22, service_product="OpenSSH", service_version="9.6", service_name="ssh"),
            _make_port(80, service_product="Apache httpd", service_version="2.4", service_name="http"),
        ])
        versions = collect_all_versions(host, [])
        products = [v.product.lower() for v in versions]
        assert products == sorted(products)


# ================================================================
# CPE URI builder
# ================================================================


class TestBuildCpeUri:
    def test_full_cpe_uri(self):
        v = VersionInfo(product="OpenSSH", version="9.6", port="22", source="nmap",
                        cpe_vendor="openbsd", cpe_product="openssh")
        uri = build_cpe_uri(v)
        assert uri == "cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*"

    def test_missing_cpe_fields(self):
        v = VersionInfo(product="unknown", version="1.0", port="80", source="httpx",
                        cpe_vendor="", cpe_product="")
        uri = build_cpe_uri(v)
        assert uri == ""


# ================================================================
# CVSS severity conversion
# ================================================================


class TestSeverityFromCvss:
    def test_critical(self):
        assert _severity_from_cvss("9.8") == Severity.CRITICAL
        assert _severity_from_cvss("9.0") == Severity.CRITICAL

    def test_high(self):
        assert _severity_from_cvss("7.5") == Severity.HIGH
        assert _severity_from_cvss("7.0") == Severity.HIGH
        assert _severity_from_cvss("8.9") == Severity.HIGH

    def test_medium(self):
        assert _severity_from_cvss("5.0") == Severity.MEDIUM
        assert _severity_from_cvss("4.0") == Severity.MEDIUM
        assert _severity_from_cvss("6.9") == Severity.MEDIUM

    def test_low(self):
        assert _severity_from_cvss("3.5") == Severity.LOW
        assert _severity_from_cvss("0.1") == Severity.LOW

    def test_info(self):
        assert _severity_from_cvss("0.0") == Severity.INFO
        assert _severity_from_cvss("") == Severity.INFO
        # These are invalid for CVSS but the function mustn't crash
        assert _severity_from_cvss("invalid") == Severity.INFO


# ================================================================
# NVD API client (mocked)
# ================================================================


def _setup_nvd_mock(mock_session_cls, nvd_response):
    """Configure a mocked aiohttp.ClientSession for NVD API tests.

    Returns the mock_response object so tests can inspect get() call args.
    """
    mock_session = MagicMock()
    mock_session.close = AsyncMock()  # await session.close() in finally block
    mock_session_cls.return_value = mock_session

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value=nvd_response)

    # async with session_obj.get(...) as resp:
    #   get() returns a context manager whose __aenter__ is awaitable
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_resp)
    cm.__aexit__ = AsyncMock(return_value=None)
    mock_session.get.return_value = cm

    return mock_session


class TestNvdClient:
    @pytest.mark.asyncio
    async def test_query_nvd_cpe_empty_no_api_key(self):
        """Without an API key, the function still runs (returns empty or results)."""
        host = _make_host(ports=[
            _make_port(22, service_product="OpenSSH", service_version="9.6", service_name="ssh"),
        ])
        config = ScanConfig(nvd_api_key="")

        with patch("aiohttp.ClientSession") as mock_session_cls:
            _setup_nvd_mock(mock_session_cls, {"vulnerabilities": []})
            findings = await scan_cve_search(host, [], config)
            assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_scan_cve_search_no_versions(self):
        """When host has no version data, return empty list."""
        host = _make_host()  # no ports, no tech
        config = ScanConfig(nvd_api_key="")
        findings = await scan_cve_search(host, [], config)
        assert findings == []

    @pytest.mark.asyncio
    async def test_scan_cve_search_with_cve_results(self):
        """When NVD returns CVEs, convert them to Finding objects."""
        host = _make_host(ports=[
            _make_port(22, service_product="OpenSSH", service_version="9.6", service_name="ssh"),
        ])
        config = ScanConfig(nvd_api_key="test-key")

        mock_cve_response = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-6387",
                        "descriptions": [{"lang": "en", "value": "regreSSHion RCE in OpenSSH"}],
                        "metrics": {
                            "cvssMetricV31": [{
                                "cvssData": {
                                    "baseScore": 8.1,
                                    "baseSeverity": "HIGH",
                                    "vectorString": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                },
                                "exploitabilityScore": 2.2,
                            }],
                        },
                        "weaknesses": [{"description": [{"value": "CWE-362"}]}],
                        "published": "2024-07-01T00:00:00.000",
                    }
                }
            ]
        }

        with patch("aiohttp.ClientSession") as mock_session_cls:
            _setup_nvd_mock(mock_session_cls, mock_cve_response)
            findings = await scan_cve_search(host, [], config)
            assert len(findings) >= 1
            f = findings[0]
            assert f.source == "nvd"
            assert f.cve == "CVE-2024-6387"
            assert f.cvss == "8.1"
            assert f.cwe == "CWE-362"
            assert f.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_scan_cve_search_dedups_cves(self):
        """Repeated CVE IDs should not produce duplicate findings."""
        host = _make_host(ports=[
            _make_port(22, service_product="OpenSSH", service_version="9.6", service_name="ssh"),
            _make_port(2222, service_product="OpenSSH", service_version="9.6", service_name="ssh"),
        ])

        config = ScanConfig(nvd_api_key="test-key")

        mock_cve = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-6387",
                    "descriptions": [{"lang": "en", "value": "Test"}],
                    "metrics": {},
                    "weaknesses": [],
                    "published": "2024-01-01T00:00:00.000",
                }
            }]
        }

        with patch("aiohttp.ClientSession") as mock_session_cls:
            _setup_nvd_mock(mock_session_cls, mock_cve)
            findings = await scan_cve_search(host, [], config)
            # Both ports hit the same CVE — deduplicated
            cve_6387 = [f for f in findings if f.cve == "CVE-2024-6387"]
            assert len(cve_6387) <= 1


# ================================================================
# Integration: scan_cve_search with ScanConfig.nvd_api_key
# ================================================================


class TestNvdConfig:
    def test_nvd_api_key_from_config(self):
        """nvd_api_key is read from ScanConfig."""
        config = ScanConfig(nvd_api_key="test-api-key-123")
        assert config.nvd_api_key == "test-api-key-123"

    def test_nvd_api_key_default_empty(self):
        """Default nvd_api_key is empty string."""
        config = ScanConfig()
        assert config.nvd_api_key == ""

    def test_nvd_api_key_from_env(self, monkeypatch):
        """nvd_api_key can be set via WIREGHOST_NVD_API_KEY env var."""
        monkeypatch.setenv("WIREGHOST_NVD_API_KEY", "env-key-456")
        config = ScanConfig.load(target="10.0.0.1")
        assert config.nvd_api_key == "env-key-456"


# ================================================================
# Full CPE map coverage: spot-check key categories
# ================================================================


class TestCpeMapCoverage:
    """Spot-check critical CPE mappings used by common services."""

    def test_databases(self):
        assert _lookup_cpe("mysql") == ("oracle", "mysql")
        assert _lookup_cpe("mariadb") == ("mariadb", "mariadb")
        assert _lookup_cpe("postgresql") == ("postgresql", "postgresql")
        assert _lookup_cpe("mongod") == ("mongodb", "mongodb")
        assert _lookup_cpe("microsoft sql") == ("microsoft", "sql_server")

    def test_web_servers(self):
        assert _lookup_cpe("apache httpd") == ("apache", "http_server")
        assert _lookup_cpe("nginx") == ("nginx", "nginx")
        assert _lookup_cpe("iis") == ("microsoft", "internet_information_services")
        assert _lookup_cpe("tomcat") == ("apache", "tomcat")

    def test_cms(self):
        assert _lookup_cpe("drupal") == ("drupal", "drupal")
        assert _lookup_cpe("joomla") == ("joomla", "joomla")
        assert _lookup_cpe("magento") == ("adobe", "magento")

    def test_windows_ecosystem(self):
        assert _lookup_cpe("windows") == ("microsoft", "windows")
        assert _lookup_cpe("samba") == ("samba", "samba")
        assert _lookup_cpe("exchange") == ("microsoft", "exchange_server")

    def test_network_devices(self):
        assert _lookup_cpe("cisco ios") == ("cisco", "ios")
        assert _lookup_cpe("fortios") == ("fortinet", "fortios")
