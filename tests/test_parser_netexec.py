"""Tests for wireghost.parsers.netexec."""

from __future__ import annotations

from pathlib import Path

from wireghost.models.severity import Severity
from wireghost.parsers.netexec import parse_netexec_output

FIXTURE_DIR = Path(__file__).parent / "fixtures"


class TestParseNetexecSmb:
    def _smb_output(self) -> str:
        return (FIXTURE_DIR / "netexec_smb_output.txt").read_text()

    def test_parses_os_info(self):
        findings = parse_netexec_output(self._smb_output(), host_ip="10.0.0.1", protocol="smb")
        os_findings = [f for f in findings if "OS Detection" in f.title]
        assert len(os_findings) == 1
        assert "Windows 10 Build 19041" in os_findings[0].title
        assert os_findings[0].severity == Severity.INFO

    def test_parses_signing_disabled(self):
        findings = parse_netexec_output(self._smb_output(), host_ip="10.0.0.1", protocol="smb")
        signing = [f for f in findings if "Signing Disabled" in f.title]
        assert len(signing) == 1
        assert signing[0].severity == Severity.MEDIUM
        assert signing[0].template_id == "NXC-SMB-SIGNING"

    def test_parses_smbv1_enabled(self):
        findings = parse_netexec_output(self._smb_output(), host_ip="10.0.0.1", protocol="smb")
        v1 = [f for f in findings if "SMBv1 Enabled" in f.title]
        assert len(v1) == 1
        assert v1[0].severity == Severity.HIGH

    def test_parses_null_session(self):
        findings = parse_netexec_output(self._smb_output(), host_ip="10.0.0.1", protocol="smb")
        null_sess = [f for f in findings if "Null/Guest Session" in f.title]
        assert len(null_sess) == 1
        assert null_sess[0].severity == Severity.HIGH

    def test_parses_accessible_shares(self):
        findings = parse_netexec_output(self._smb_output(), host_ip="10.0.0.1", protocol="smb")
        shares = [f for f in findings if "Accessible Shares" in f.title]
        assert len(shares) == 1
        assert "Backups" in shares[0].description
        assert shares[0].severity == Severity.MEDIUM

    def test_all_sources_netexec(self):
        findings = parse_netexec_output(self._smb_output(), host_ip="10.0.0.1", protocol="smb")
        assert all(f.source == "netexec" for f in findings)

    def test_all_ports_445(self):
        findings = parse_netexec_output(self._smb_output(), host_ip="10.0.0.1", protocol="smb")
        assert all(f.port == "445" for f in findings)

    def test_host_ip_set(self):
        findings = parse_netexec_output(self._smb_output(), host_ip="10.0.0.1", protocol="smb")
        assert all(f.host == "10.0.0.1" for f in findings)

    def test_tags_present(self):
        findings = parse_netexec_output(self._smb_output(), host_ip="10.0.0.1", protocol="smb")
        for f in findings:
            assert len(f.tags) > 0


class TestParseNetexecMs17010:
    def test_ms17010_detected(self):
        output = "SMB  10.0.0.1  445  DC01  [+] MS17-010 VULNERABLE"
        findings = parse_netexec_output(output, host_ip="10.0.0.1", protocol="smb")
        ms17 = [f for f in findings if "MS17-010" in f.title]
        assert len(ms17) == 1
        assert ms17[0].severity == Severity.CRITICAL
        assert ms17[0].cve == "CVE-2017-0144"
        assert ms17[0].cvss == "9.8"

    def test_ms17010_not_detected(self):
        output = "SMB  10.0.0.1  445  DC01  [-] MS17-010 not vulnerable"
        findings = parse_netexec_output(output, host_ip="10.0.0.1", protocol="smb")
        ms17 = [f for f in findings if "MS17-010" in f.title]
        assert len(ms17) == 0


class TestParseNetexecFtp:
    def test_ftp_anonymous(self):
        output = "FTP  10.0.0.1  21  [+] Anonymous login allowed"
        findings = parse_netexec_output(output, host_ip="10.0.0.1", protocol="ftp")
        anon = [f for f in findings if "Anonymous" in f.title]
        assert len(anon) == 1
        assert anon[0].severity == Severity.MEDIUM
        assert anon[0].port == "21"

    def test_ftp_banner(self):
        output = "[*] Banner: vsftpd 3.0.3"
        findings = parse_netexec_output(output, host_ip="10.0.0.1", protocol="ftp")
        banner = [f for f in findings if "Banner" in f.title]
        assert len(banner) == 1
        assert "vsftpd 3.0.3" in banner[0].title
        assert banner[0].severity == Severity.INFO


class TestParseNetexecRdp:
    def test_rdp_nla_disabled(self):
        output = "RDP  10.0.0.1  3389  [*] nla: False"
        findings = parse_netexec_output(output, host_ip="10.0.0.1", protocol="rdp")
        nla = [f for f in findings if "Network Level Authentication" in f.title]
        assert len(nla) == 1
        assert nla[0].severity == Severity.MEDIUM
        assert nla[0].port == "3389"

    def test_rdp_guest_enabled(self):
        output = "RDP  10.0.0.1  3389  GUEST account is enabled"
        findings = parse_netexec_output(output, host_ip="10.0.0.1", protocol="rdp")
        guest = [f for f in findings if "Guest" in f.title]
        assert len(guest) == 1
        assert guest[0].severity == Severity.MEDIUM

    def test_rdp_nla_enabled_no_finding(self):
        output = "RDP  10.0.0.1  3389  [*] nla: True"
        findings = parse_netexec_output(output, host_ip="10.0.0.1", protocol="rdp")
        nla = [f for f in findings if "NLA" in f.title]
        assert len(nla) == 0


class TestParseNetexecMssql:
    def test_mssql_info(self):
        output = "[*] Windows 10 Build 19041 (name:SQLSRV)"
        findings = parse_netexec_output(output, host_ip="10.0.0.1", protocol="mssql")
        info = [f for f in findings if "MSSQL Host" in f.title]
        assert len(info) == 1
        assert info[0].port == "1433"
        assert info[0].severity == Severity.INFO

    def test_mssql_auth_success(self):
        output = "[+] Login successful\n[*] Windows 10 Build 19041 (name:SQLSRV)"
        findings = parse_netexec_output(output, host_ip="10.0.0.1", protocol="mssql")
        auth = [f for f in findings if "Login Succeeded" in f.title]
        assert len(auth) == 1
        assert auth[0].severity == Severity.HIGH

    def test_mssql_login_failed_no_auth_finding(self):
        output = "[-] Login failed for sa"
        findings = parse_netexec_output(output, host_ip="10.0.0.1", protocol="mssql")
        auth = [f for f in findings if "Login Succeeded" in f.title]
        assert len(auth) == 0


class TestParseNetexecEdgeCases:
    def test_empty_string_returns_empty(self):
        assert parse_netexec_output("") == []

    def test_whitespace_only_returns_empty(self):
        assert parse_netexec_output("   \n\n  ") == []

    def test_unknown_protocol_returns_empty(self):
        assert parse_netexec_output("some output", protocol="ssh") == []

    def test_default_host_ip_empty(self):
        output = "FTP  10.0.0.1  21  [+] Anonymous login allowed"
        findings = parse_netexec_output(output, protocol="ftp")
        assert findings[0].host == ""
