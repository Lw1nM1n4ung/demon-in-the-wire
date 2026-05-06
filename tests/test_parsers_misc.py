"""Tests for parsers: sslscan, showmount, snmpwalk, arpscan, netdiscover."""

from __future__ import annotations

from pathlib import Path

from wireghost.models.severity import Severity
from wireghost.parsers.arpscan import parse_arpscan
from wireghost.parsers.netdiscover import parse_netdiscover
from wireghost.parsers.showmount import parse_showmount
from wireghost.parsers.snmpwalk import extract_system_info, parse_snmpwalk
from wireghost.parsers.sslscan import _cipher_is_weak, parse_sslscan


# ================================================================
# sslscan parser
# ================================================================


_SSLSCAN_XML_TEMPLATE = """\
<?xml version="1.0"?>
<document>
 <ssltest host="10.0.0.1" port="443">
  {body}
 </ssltest>
</document>
"""


def _sslscan_xml(body: str, tmp_path: Path) -> Path:
    xml_path = tmp_path / "sslscan.xml"
    xml_path.write_text(_SSLSCAN_XML_TEMPLATE.format(body=body), encoding="utf-8")
    return xml_path


class TestParseSslscanWeakCiphers:
    def test_weak_cipher_rc4(self, tmp_path: Path):
        body = '<cipher status="accepted" sslversion="TLSv1.2" cipher="RC4-SHA" bits="128" />'
        findings = parse_sslscan(_sslscan_xml(body, tmp_path), "10.0.0.1", 443)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "Weak TLS ciphers" in findings[0].title
        assert "RC4" in findings[0].description

    def test_weak_cipher_des(self, tmp_path: Path):
        body = '<cipher status="preferred" sslversion="TLSv1.0" cipher="DES-CBC3-SHA" bits="56" />'
        findings = parse_sslscan(_sslscan_xml(body, tmp_path), "10.0.0.1", 443)
        assert len(findings) == 1
        assert "DES" in findings[0].description

    def test_weak_cipher_null(self, tmp_path: Path):
        body = '<cipher status="accepted" sslversion="TLSv1.2" cipher="NULL-SHA256" bits="0" />'
        findings = parse_sslscan(_sslscan_xml(body, tmp_path), "10.0.0.1", 443)
        assert len(findings) == 1

    def test_sslv2_cipher_weak(self, tmp_path: Path):
        body = '<cipher status="accepted" sslversion="SSLv2" cipher="AES128-SHA" bits="128" />'
        findings = parse_sslscan(_sslscan_xml(body, tmp_path), "10.0.0.1", 443)
        assert len(findings) == 1
        assert "SSLv2" in findings[0].description

    def test_strong_cipher_not_flagged(self, tmp_path: Path):
        body = '<cipher status="accepted" sslversion="TLSv1.3" cipher="TLS_AES_256_GCM_SHA384" bits="256" />'
        findings = parse_sslscan(_sslscan_xml(body, tmp_path), "10.0.0.1", 443)
        assert len(findings) == 0

    def test_rejected_cipher_not_flagged(self, tmp_path: Path):
        body = '<cipher status="rejected" sslversion="TLSv1.2" cipher="RC4-SHA" bits="128" />'
        findings = parse_sslscan(_sslscan_xml(body, tmp_path), "10.0.0.1", 443)
        assert len(findings) == 0

    def test_multiple_weak_ciphers_single_finding(self, tmp_path: Path):
        body = (
            '<cipher status="accepted" sslversion="TLSv1.0" cipher="RC4-SHA" bits="128" />'
            '<cipher status="accepted" sslversion="TLSv1.0" cipher="DES-CBC-SHA" bits="56" />'
        )
        findings = parse_sslscan(_sslscan_xml(body, tmp_path), "10.0.0.1", 443)
        assert len(findings) == 1
        assert "(2)" in findings[0].title


class TestParseSslscanProtocols:
    def test_sslv2_enabled(self, tmp_path: Path):
        body = '<sslv2 enabled="1" />'
        findings = parse_sslscan(_sslscan_xml(body, tmp_path), "10.0.0.1", 443)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "SSLv2" in findings[0].title

    def test_sslv3_enabled(self, tmp_path: Path):
        body = '<sslv3 enabled="1" />'
        findings = parse_sslscan(_sslscan_xml(body, tmp_path), "10.0.0.1", 443)
        assert len(findings) == 1
        assert "SSLv3" in findings[0].title

    def test_sslv2_disabled_no_finding(self, tmp_path: Path):
        body = '<sslv2 enabled="0" />'
        findings = parse_sslscan(_sslscan_xml(body, tmp_path), "10.0.0.1", 443)
        assert len(findings) == 0


class TestParseSslscanCertificate:
    def test_self_signed(self, tmp_path: Path):
        body = '<certificate><self-signed>true</self-signed></certificate>'
        findings = parse_sslscan(_sslscan_xml(body, tmp_path), "10.0.0.1", 443)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "Self-signed" in findings[0].title

    def test_not_self_signed(self, tmp_path: Path):
        body = '<certificate><self-signed>false</self-signed></certificate>'
        findings = parse_sslscan(_sslscan_xml(body, tmp_path), "10.0.0.1", 443)
        assert len(findings) == 0

    def test_expired_cert(self, tmp_path: Path):
        body = '<certificate><not-valid-after>Jan  1 00:00:00 2020 GMT</not-valid-after></certificate>'
        findings = parse_sslscan(_sslscan_xml(body, tmp_path), "10.0.0.1", 443)
        assert len(findings) == 1
        assert "Expired" in findings[0].title

    def test_weak_signature_md5(self, tmp_path: Path):
        body = '<certificate><signature-algorithm>md5WithRSAEncryption</signature-algorithm></certificate>'
        findings = parse_sslscan(_sslscan_xml(body, tmp_path), "10.0.0.1", 443)
        assert len(findings) == 1
        assert "Weak certificate signature" in findings[0].title

    def test_weak_signature_sha1(self, tmp_path: Path):
        body = '<certificate><signature-algorithm>sha1WithRSAEncryption</signature-algorithm></certificate>'
        findings = parse_sslscan(_sslscan_xml(body, tmp_path), "10.0.0.1", 443)
        assert len(findings) == 1

    def test_strong_signature_not_flagged(self, tmp_path: Path):
        body = '<certificate><signature-algorithm>sha256WithRSAEncryption</signature-algorithm></certificate>'
        findings = parse_sslscan(_sslscan_xml(body, tmp_path), "10.0.0.1", 443)
        assert len(findings) == 0


class TestParseSslscanHeartbleed:
    def test_heartbleed_vulnerable(self, tmp_path: Path):
        body = '<heartbleed sslversion="TLSv1.1" vulnerable="1" />'
        findings = parse_sslscan(_sslscan_xml(body, tmp_path), "10.0.0.1", 443)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "Heartbleed" in findings[0].title
        assert findings[0].cve == "CVE-2014-0160"

    def test_heartbleed_not_vulnerable(self, tmp_path: Path):
        body = '<heartbleed sslversion="TLSv1.1" vulnerable="0" />'
        findings = parse_sslscan(_sslscan_xml(body, tmp_path), "10.0.0.1", 443)
        assert len(findings) == 0


class TestParseSslscanEdgeCases:
    def test_missing_file(self, tmp_path: Path):
        findings = parse_sslscan(tmp_path / "missing.xml", "10.0.0.1", 443)
        assert findings == []

    def test_malformed_xml(self, tmp_path: Path):
        bad_xml = tmp_path / "bad.xml"
        bad_xml.write_text("not valid xml at all", encoding="utf-8")
        findings = parse_sslscan(bad_xml, "10.0.0.1", 443)
        assert findings == []

    def test_empty_ssltest(self, tmp_path: Path):
        findings = parse_sslscan(_sslscan_xml("", tmp_path), "10.0.0.1", 443)
        assert findings == []

    def test_host_and_port_set(self, tmp_path: Path):
        body = '<heartbleed sslversion="TLSv1.1" vulnerable="1" />'
        findings = parse_sslscan(_sslscan_xml(body, tmp_path), "192.168.1.1", 8443)
        assert findings[0].host == "192.168.1.1"
        assert findings[0].port == "8443"
        assert findings[0].source == "sslscan"

    def test_all_findings_combined(self, tmp_path: Path):
        body = (
            '<sslv3 enabled="1" />'
            '<cipher status="accepted" sslversion="TLSv1.0" cipher="RC4-SHA" bits="128" />'
            '<certificate><self-signed>true</self-signed></certificate>'
            '<heartbleed sslversion="TLSv1.1" vulnerable="1" />'
        )
        findings = parse_sslscan(_sslscan_xml(body, tmp_path), "10.0.0.1", 443)
        assert len(findings) == 4
        severities = {f.severity for f in findings}
        assert Severity.CRITICAL in severities
        assert Severity.HIGH in severities
        assert Severity.MEDIUM in severities


class TestCipherIsWeak:
    def test_rc4(self):
        assert _cipher_is_weak("RC4-SHA") is True

    def test_null(self):
        assert _cipher_is_weak("NULL-SHA256") is True

    def test_export(self):
        assert _cipher_is_weak("EXP-RC4-MD5") is True
        assert _cipher_is_weak("EXPORT1024-DES-CBC-SHA") is True

    def test_strong(self):
        assert _cipher_is_weak("ECDHE-RSA-AES256-GCM-SHA384") is False

    def test_case_insensitive(self):
        assert _cipher_is_weak("rc4-sha") is True


# ================================================================
# showmount parser
# ================================================================


class TestParseShowmount:
    def test_world_readable_export(self):
        output = "Export list for 10.0.0.1:\n/home    *\n"
        findings = parse_showmount(output, "10.0.0.1")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "/home" in findings[0].title
        assert findings[0].port == "2049"

    def test_restricted_export(self):
        output = "Export list for 10.0.0.1:\n/backups 10.0.0.0/24\n"
        findings = parse_showmount(output, "10.0.0.1")
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "10.0.0.0/24" in findings[0].description

    def test_everyone_export(self):
        output = "Export list:\n/data (everyone)\n"
        findings = parse_showmount(output, "10.0.0.1")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_multiple_exports(self):
        output = (
            "Export list for 10.0.0.1:\n"
            "/home    *\n"
            "/var/log 10.0.0.0/24\n"
            "/tmp     *\n"
        )
        findings = parse_showmount(output, "10.0.0.1")
        assert len(findings) == 3
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        assert high_count == 2

    def test_header_line_skipped(self):
        output = "Export list for 10.0.0.1:\n"
        findings = parse_showmount(output, "10.0.0.1")
        assert findings == []

    def test_empty_output(self):
        assert parse_showmount("", "10.0.0.1") == []

    def test_whitespace_only(self):
        assert parse_showmount("  \n  ", "10.0.0.1") == []

    def test_source_is_nfs_enum(self):
        output = "/data *\n"
        findings = parse_showmount(output, "10.0.0.1")
        assert findings[0].source == "nfs_enum"

    def test_no_allowed_hosts_treated_as_world(self):
        output = "/share\n"
        findings = parse_showmount(output, "10.0.0.1")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH


# ================================================================
# snmpwalk parser
# ================================================================


class TestParseSnmpwalk:
    def test_system_info_parsed(self):
        output = (
            '.1.3.6.1.2.1.1.1.0 = "Linux router 5.15"\n'
            '.1.3.6.1.2.1.1.5.0 = "core-router"\n'
        )
        result = parse_snmpwalk(output)
        assert ".1.3.6.1.2.1.1.1.0" in result
        assert result[".1.3.6.1.2.1.1.1.0"] == "Linux router 5.15"
        assert result[".1.3.6.1.2.1.1.5.0"] == "core-router"

    def test_non_system_oid_excluded(self):
        output = '.1.3.6.1.2.1.99.99.1 = "some random value"\n'
        result = parse_snmpwalk(output)
        assert len(result) == 0

    def test_interface_oids_captured(self):
        output = '.1.3.6.1.2.1.2.2.1.2.1 = "eth0"\n'
        result = parse_snmpwalk(output)
        assert ".1.3.6.1.2.1.2.2.1.2.1" in result
        assert result[".1.3.6.1.2.1.2.2.1.2.1"] == "eth0"

    def test_timeout_lines_skipped(self):
        output = "Timeout: No Response from 10.0.0.1\n"
        result = parse_snmpwalk(output)
        assert len(result) == 0

    def test_empty_output(self):
        assert parse_snmpwalk("") == {}

    def test_no_equals_sign_skipped(self):
        output = "some garbage line without equals\n"
        result = parse_snmpwalk(output)
        assert len(result) == 0

    def test_quotes_stripped(self):
        output = '.1.3.6.1.2.1.1.4.0 = "admin@company.com"\n'
        result = parse_snmpwalk(output)
        assert result[".1.3.6.1.2.1.1.4.0"] == "admin@company.com"


class TestExtractSystemInfo:
    def test_extracts_fields(self):
        oid_map = {
            ".1.3.6.1.2.1.1.1.0": "Linux server 5.15",
            ".1.3.6.1.2.1.1.4.0": "admin@company.com",
            ".1.3.6.1.2.1.1.5.0": "web-server-01",
            ".1.3.6.1.2.1.1.6.0": "DC1-Rack4",
        }
        info = extract_system_info(oid_map)
        assert info["sysDescr"] == "Linux server 5.15"
        assert info["sysContact"] == "admin@company.com"
        assert info["sysName"] == "web-server-01"
        assert info["sysLocation"] == "DC1-Rack4"

    def test_empty_map(self):
        assert extract_system_info({}) == {}

    def test_partial_info(self):
        oid_map = {".1.3.6.1.2.1.1.5.0": "router-1"}
        info = extract_system_info(oid_map)
        assert info == {"sysName": "router-1"}


# ================================================================
# arpscan parser
# ================================================================


class TestParseArpscan:
    def test_basic_output(self):
        output = "10.0.0.1\t00:11:22:33:44:55\tCisco Systems\n"
        result = parse_arpscan(output)
        assert len(result) == 1
        ip, mac, vendor = result[0]
        assert ip == "10.0.0.1"
        assert mac == "00:11:22:33:44:55"
        assert vendor == "Cisco Systems"

    def test_no_vendor(self):
        output = "10.0.0.1\t00:11:22:33:44:55\n"
        result = parse_arpscan(output)
        assert len(result) == 1
        assert result[0][2] == ""

    def test_multiple_hosts(self):
        output = (
            "10.0.0.1\taa:bb:cc:dd:ee:ff\tVendor A\n"
            "10.0.0.2\t11:22:33:44:55:66\tVendor B\n"
            "10.0.0.3\t77:88:99:aa:bb:cc\tVendor C\n"
        )
        result = parse_arpscan(output)
        assert len(result) == 3
        ips = [r[0] for r in result]
        assert ips == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    def test_empty_output(self):
        assert parse_arpscan("") == []

    def test_single_column_skipped(self):
        output = "just-an-ip\n"
        result = parse_arpscan(output)
        assert len(result) == 0

    def test_whitespace_stripped(self):
        output = "  10.0.0.1  \t  00:11:22:33:44:55  \t  Vendor  \n"
        result = parse_arpscan(output)
        assert result[0][0] == "10.0.0.1"
        assert result[0][1] == "00:11:22:33:44:55"
        assert result[0][2] == "Vendor"


# ================================================================
# netdiscover parser
# ================================================================


class TestParseNetdiscover:
    def test_basic_output(self):
        output = (
            "_____________________________________________________________________________\n"
            "   IP            At MAC Address     Count     Len  MAC Vendor / Hostname\n"
            " 10.0.0.1/00:11:22:33:44:55/1/60/Cisco Systems\n"
        )
        result = parse_netdiscover(output)
        assert len(result) == 1
        assert result[0][0] == "10.0.0.1"
        assert result[0][1] == "00:11:22:33:44:55"
        assert result[0][2] == "Cisco Systems"

    def test_multiple_hosts(self):
        output = (
            "10.0.0.1/aa:bb:cc:dd:ee:ff/1/60/Vendor A\n"
            "10.0.0.2/11:22:33:44:55:66/2/120/Vendor B\n"
        )
        result = parse_netdiscover(output)
        assert len(result) == 2

    def test_header_lines_skipped(self):
        output = (
            "_____________________________________________\n"
            "IP          At MAC Address ...\n"
        )
        result = parse_netdiscover(output)
        assert result == []

    def test_empty_output(self):
        assert parse_netdiscover("") == []

    def test_no_vendor(self):
        output = "10.0.0.1/aa:bb:cc:dd:ee:ff/1/60\n"
        result = parse_netdiscover(output)
        assert len(result) == 1
        assert result[0][2] == ""

    def test_short_line_no_vendor(self):
        output = "10.0.0.1/aa:bb:cc:dd:ee:ff\n"
        result = parse_netdiscover(output)
        assert len(result) == 1
        assert result[0][2] == ""
