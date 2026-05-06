"""Tests for MSF integration: parser, module selection, RC generation, dedup."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from wireghost.config import ScanConfig
from wireghost.models.finding import Finding
from wireghost.models.scan import Host, Port, Service
from wireghost.models.severity import Severity
from wireghost.parsers.msf import parse_msf_output
from wireghost.pipeline.msf_scan import (
    MsfModule,
    _build_rc_script,
    _lookup_metadata_modules,
    _select_modules,
    scan_msf,
)
from wireghost.pipeline.orchestrator import _dedup_findings


# ================================================================
# Parser: parse_msf_output
# ================================================================


class TestParseMsfOutput:
    def test_happy_path_multi_module(self):
        output = (
            "# ===MODULE:auxiliary/scanner/smb/smb_ms17_010:445===\n"
            "[*] 10.0.0.1:445 - SMB Detected (versions:1, 2, 3)\n"
            "[+] 10.0.0.1:445 - Host is likely VULNERABLE to MS17-010!\n"
            "# ===END_MODULE===\n"
            "# ===MODULE:auxiliary/scanner/ssh/ssh_version:22===\n"
            "[*] 10.0.0.1:22 - SSH server version: SSH-2.0-OpenSSH_8.9p1\n"
            "# ===END_MODULE===\n"
        )
        findings = parse_msf_output(output, "10.0.0.1")
        assert len(findings) == 3
        assert all(f.source == "msf_scan" for f in findings)
        assert all(f.host == "10.0.0.1" for f in findings)

    def test_critical_keyword_vulnerable(self):
        output = (
            "# ===MODULE:auxiliary/scanner/smb/smb_ms17_010:445===\n"
            "[+] 10.0.0.1:445 - Host is likely VULNERABLE to MS17-010!\n"
            "# ===END_MODULE===\n"
        )
        findings = parse_msf_output(output, "10.0.0.1")
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_critical_keyword_bluekeep(self):
        output = (
            "# ===MODULE:auxiliary/scanner/rdp/cve_2019_0708_bluekeep:3389===\n"
            "[+] 10.0.0.1:3389 - The target is vulnerable to BlueKeep\n"
            "# ===END_MODULE===\n"
        )
        findings = parse_msf_output(output, "10.0.0.1")
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_high_keyword_anonymous(self):
        output = (
            "# ===MODULE:auxiliary/scanner/ftp/anonymous:21===\n"
            "[+] 10.0.0.1:21 - Anonymous login successful\n"
            "# ===END_MODULE===\n"
        )
        findings = parse_msf_output(output, "10.0.0.1")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_plus_default_high(self):
        output = (
            "# ===MODULE:auxiliary/scanner/redis/redis_server:6379===\n"
            "[+] 10.0.0.1:6379 - Found open Redis instance\n"
            "# ===END_MODULE===\n"
        )
        findings = parse_msf_output(output, "10.0.0.1")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_star_version_info(self):
        output = "[*] 10.0.0.1:22 - SSH server version: SSH-2.0-OpenSSH_8.9p1\n"
        findings = parse_msf_output(output, "10.0.0.1")
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO

    def test_star_noise_filtered(self):
        output = "[*] 10.0.0.1:445 - Scanned 1 of 1 hosts (100% complete)\n"
        findings = parse_msf_output(output, "10.0.0.1")
        assert len(findings) == 0

    def test_bang_medium(self):
        output = (
            "# ===MODULE:auxiliary/scanner/smtp/smtp_enum:25===\n"
            "[!] 10.0.0.1:25 - Users found: root, admin\n"
            "# ===END_MODULE===\n"
        )
        findings = parse_msf_output(output, "10.0.0.1")
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_minus_skipped(self):
        output = "[-] 10.0.0.1:3306 - Login failed for 'root':''\n"
        findings = parse_msf_output(output, "10.0.0.1")
        assert len(findings) == 0

    def test_noise_prefixes_filtered(self):
        output = (
            "[*] 10.0.0.1:445 - Connecting to host...\n"
            "[*] 10.0.0.1:445 - Scanning target IP range\n"
            "[*] 10.0.0.1:445 - auxiliary module execution completed\n"
        )
        findings = parse_msf_output(output, "10.0.0.1")
        assert len(findings) == 0

    def test_dedup_same_message(self):
        output = (
            "# ===MODULE:auxiliary/scanner/ssh/ssh_version:22===\n"
            "[*] 10.0.0.1:22 - SSH server version: SSH-2.0-OpenSSH_8.9p1\n"
            "[*] 10.0.0.1:22 - SSH server version: SSH-2.0-OpenSSH_8.9p1\n"
            "# ===END_MODULE===\n"
        )
        findings = parse_msf_output(output, "10.0.0.1")
        assert len(findings) == 1

    def test_empty_output(self):
        assert parse_msf_output("", "10.0.0.1") == []

    def test_whitespace_only_output(self):
        assert parse_msf_output("   \n\n  ", "10.0.0.1") == []

    def test_no_result_lines(self):
        output = "Some random msfconsole banner text\nLoading modules...\n"
        findings = parse_msf_output(output, "10.0.0.1")
        assert len(findings) == 0

    def test_empty_message_skipped(self):
        output = "[+] 10.0.0.1:22 - \n"
        findings = parse_msf_output(output, "10.0.0.1")
        assert len(findings) == 0

    def test_port_from_output_overrides_marker(self):
        output = (
            "# ===MODULE:auxiliary/scanner/ssh/ssh_version:22===\n"
            "[*] 10.0.0.1:2222 - SSH server version: SSH-2.0-OpenSSH_8.9p1\n"
            "# ===END_MODULE===\n"
        )
        findings = parse_msf_output(output, "10.0.0.1")
        assert len(findings) == 1
        assert findings[0].port == "2222"

    def test_port_fallback_to_marker(self):
        output = (
            "# ===MODULE:auxiliary/scanner/ssh/ssh_version:22===\n"
            "[*] 10.0.0.1 - SSH server version: SSH-2.0-OpenSSH_8.9p1\n"
            "# ===END_MODULE===\n"
        )
        findings = parse_msf_output(output, "10.0.0.1")
        assert len(findings) == 1
        assert findings[0].port == "22"

    def test_template_id_from_module_marker(self):
        output = (
            "# ===MODULE:auxiliary/scanner/smb/smb_ms17_010:445===\n"
            "[+] 10.0.0.1:445 - Host is VULNERABLE to MS17-010\n"
            "# ===END_MODULE===\n"
        )
        findings = parse_msf_output(output, "10.0.0.1")
        assert findings[0].template_id == "auxiliary/scanner/smb/smb_ms17_010"

    def test_title_contains_module_short_name(self):
        output = (
            "# ===MODULE:auxiliary/scanner/smb/smb_ms17_010:445===\n"
            "[+] 10.0.0.1:445 - Host is VULNERABLE\n"
            "# ===END_MODULE===\n"
        )
        findings = parse_msf_output(output, "10.0.0.1")
        assert "smb_ms17_010" in findings[0].title

    def test_no_marker_uses_msf_prefix(self):
        output = "[+] 10.0.0.1:445 - Found open SMB share\n"
        findings = parse_msf_output(output, "10.0.0.1")
        assert len(findings) == 1
        assert findings[0].title.startswith("MSF msf:")

    def test_star_without_version_keywords_filtered(self):
        output = "[*] 10.0.0.1:445 - Some random informational status\n"
        findings = parse_msf_output(output, "10.0.0.1")
        assert len(findings) == 0

    def test_star_detected_keyword(self):
        output = "[*] 10.0.0.1:80 - Web server detected on target\n"
        findings = parse_msf_output(output, "10.0.0.1")
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO

    def test_star_name_keyword(self):
        output = "[*] 10.0.0.1:445 - Name: WORKGROUP\n"
        findings = parse_msf_output(output, "10.0.0.1")
        assert len(findings) == 1


# ================================================================
# Module selection: _select_modules
# ================================================================


def _make_host(ports: list[tuple[int, str | None]]) -> Host:
    """Helper: create a Host with given (port_number, service_name) pairs."""
    port_list = []
    for num, svc_name in ports:
        svc = Service(name=svc_name) if svc_name else None
        port_list.append(Port(number=num, service=svc))
    return Host(ip="10.0.0.1", ports=port_list)


class TestSelectModules:
    def test_ssh_service_selects_ssh_modules(self):
        host = _make_host([(22, "ssh")])
        cfg = ScanConfig(msf_metadata_path="/nonexistent")
        modules = _select_modules(host, cfg)
        paths = [m.path for m, _ in modules]
        assert "auxiliary/scanner/ssh/ssh_version" in paths
        assert "auxiliary/scanner/ssh/ssh_enumusers" in paths

    def test_smb_on_nonstandard_port(self):
        host = _make_host([(9999, "microsoft-ds")])
        cfg = ScanConfig(msf_metadata_path="/nonexistent")
        modules = _select_modules(host, cfg)
        paths = [m.path for m, _ in modules]
        assert "auxiliary/scanner/smb/smb_ms17_010" in paths
        assert all(port == 9999 for _, port in modules)

    def test_no_services_returns_empty(self):
        host = _make_host([(12345, None)])
        cfg = ScanConfig(msf_metadata_path="/nonexistent")
        assert _select_modules(host, cfg) == []

    def test_unknown_service_skipped(self):
        host = _make_host([(9999, "unknown-svc")])
        cfg = ScanConfig(msf_metadata_path="/nonexistent")
        assert _select_modules(host, cfg) == []

    def test_multiple_services(self):
        host = _make_host([(22, "ssh"), (445, "microsoft-ds"), (80, "http")])
        cfg = ScanConfig(msf_metadata_path="/nonexistent")
        modules = _select_modules(host, cfg)
        paths = {m.path for m, _ in modules}
        assert "auxiliary/scanner/ssh/ssh_version" in paths
        assert "auxiliary/scanner/smb/smb_ms17_010" in paths
        assert "auxiliary/scanner/http/http_version" in paths

    def test_dedup_same_module_same_port(self):
        host = _make_host([(445, "microsoft-ds")])
        cfg = ScanConfig(msf_metadata_path="/nonexistent")
        modules = _select_modules(host, cfg)
        keys = [f"{m.path}:{p}" for m, p in modules]
        assert len(keys) == len(set(keys))

    def test_rdp_gets_bluekeep(self):
        host = _make_host([(3389, "ms-wbt-server")])
        cfg = ScanConfig(msf_metadata_path="/nonexistent")
        modules = _select_modules(host, cfg)
        paths = [m.path for m, _ in modules]
        assert "auxiliary/scanner/rdp/cve_2019_0708_bluekeep" in paths

    def test_vnc_gets_none_auth(self):
        host = _make_host([(5900, "vnc")])
        cfg = ScanConfig(msf_metadata_path="/nonexistent")
        modules = _select_modules(host, cfg)
        paths = [m.path for m, _ in modules]
        assert "auxiliary/scanner/vnc/vnc_none_auth" in paths


# ================================================================
# Dynamic metadata lookup: _lookup_metadata_modules
# ================================================================


class TestLookupMetadataModules:
    def test_missing_file_returns_empty(self):
        result = _lookup_metadata_modules({"ssh"}, "/no/such/file.json")
        assert result == []

    def test_invalid_json_returns_empty(self, tmp_path: Path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json", encoding="utf-8")
        result = _lookup_metadata_modules({"ssh"}, str(bad))
        assert result == []

    def test_service_match(self, tmp_path: Path):
        metadata = {
            "mod1": {
                "fullname": "auxiliary/scanner/ssh/ssh_test_mod",
                "autofilter_services": ["ssh"],
                "rank_name": "great",
                "rport": "22",
            },
        }
        meta_file = tmp_path / "meta.json"
        meta_file.write_text(json.dumps(metadata), encoding="utf-8")
        result = _lookup_metadata_modules({"ssh"}, str(meta_file))
        assert len(result) == 1
        assert result[0].path == "auxiliary/scanner/ssh/ssh_test_mod"
        assert result[0].severity == Severity.HIGH

    def test_no_service_match(self, tmp_path: Path):
        metadata = {
            "mod1": {
                "fullname": "auxiliary/scanner/http/http_test",
                "autofilter_services": ["http"],
                "rank_name": "good",
            },
        }
        meta_file = tmp_path / "meta.json"
        meta_file.write_text(json.dumps(metadata), encoding="utf-8")
        result = _lookup_metadata_modules({"ssh"}, str(meta_file))
        assert result == []

    def test_blocklisted_module_excluded(self, tmp_path: Path):
        metadata = {
            "mod1": {
                "fullname": "auxiliary/scanner/http/dir_scanner",
                "autofilter_services": ["http"],
                "rank_name": "good",
            },
        }
        meta_file = tmp_path / "meta.json"
        meta_file.write_text(json.dumps(metadata), encoding="utf-8")
        result = _lookup_metadata_modules({"http"}, str(meta_file))
        assert result == []

    def test_non_scanner_module_excluded(self, tmp_path: Path):
        metadata = {
            "mod1": {
                "fullname": "exploit/windows/smb/ms17_010_eternalblue",
                "autofilter_services": ["microsoft-ds"],
                "rank_name": "excellent",
            },
        }
        meta_file = tmp_path / "meta.json"
        meta_file.write_text(json.dumps(metadata), encoding="utf-8")
        result = _lookup_metadata_modules({"microsoft-ds"}, str(meta_file))
        assert result == []

    def test_severity_mapping(self, tmp_path: Path):
        metadata = {
            "mod1": {
                "fullname": "auxiliary/scanner/ssh/ssh_a",
                "autofilter_services": ["ssh"],
                "rank_name": "excellent",
            },
            "mod2": {
                "fullname": "auxiliary/scanner/ssh/ssh_b",
                "autofilter_services": ["ssh"],
                "rank_name": "normal",
            },
            "mod3": {
                "fullname": "auxiliary/scanner/ssh/ssh_c",
                "autofilter_services": ["ssh"],
                "rank_name": "low",
            },
        }
        meta_file = tmp_path / "meta.json"
        meta_file.write_text(json.dumps(metadata), encoding="utf-8")
        result = _lookup_metadata_modules({"ssh"}, str(meta_file))
        by_path = {m.path.split("/")[-1]: m for m in result}
        assert by_path["ssh_a"].severity == Severity.CRITICAL
        assert by_path["ssh_b"].severity == Severity.LOW
        assert by_path["ssh_c"].severity == Severity.INFO


# ================================================================
# RC script generation: _build_rc_script
# ================================================================


class TestBuildRcScript:
    def test_basic_structure(self):
        modules = [
            (MsfModule("auxiliary/scanner/ssh/ssh_version", Severity.INFO), 22),
        ]
        rc = _build_rc_script("10.0.0.1", modules, Path("/tmp/spool.txt"))
        assert "spool /tmp/spool.txt" in rc
        assert "setg THREADS 5" in rc
        assert "setg ConnectTimeout 10" in rc
        assert "use auxiliary/scanner/ssh/ssh_version" in rc
        assert "set RHOSTS 10.0.0.1" in rc
        assert "set RPORT 22" in rc
        assert "run" in rc
        assert "spool off" in rc
        assert "exit" in rc

    def test_module_markers(self):
        modules = [
            (MsfModule("auxiliary/scanner/ssh/ssh_version", Severity.INFO), 22),
        ]
        rc = _build_rc_script("10.0.0.1", modules, Path("/tmp/spool.txt"))
        assert "# ===MODULE:auxiliary/scanner/ssh/ssh_version:22===" in rc
        assert "# ===END_MODULE===" in rc

    def test_options_emitted(self):
        modules = [
            (MsfModule("auxiliary/scanner/mysql/mysql_login", Severity.HIGH,
                       {"BLANK_PASSWORDS": "true", "USERNAME": "root"}), 3306),
        ]
        rc = _build_rc_script("10.0.0.1", modules, Path("/tmp/spool.txt"))
        assert "set BLANK_PASSWORDS true" in rc
        assert "set USERNAME root" in rc

    def test_underscore_options_skipped(self):
        modules = [
            (MsfModule("auxiliary/scanner/ssh/ssh_test", Severity.INFO,
                       {"_rport": "22", "THREADS": "3"}), 22),
        ]
        rc = _build_rc_script("10.0.0.1", modules, Path("/tmp/spool.txt"))
        assert "_rport" not in rc
        assert "set THREADS 3" in rc

    def test_empty_option_value_skipped(self):
        modules = [
            (MsfModule("auxiliary/scanner/smb/smb_login", Severity.HIGH,
                       {"SMBUser": "", "SMBPass": ""}), 445),
        ]
        rc = _build_rc_script("10.0.0.1", modules, Path("/tmp/spool.txt"))
        assert "set SMBUser" not in rc
        assert "set SMBPass" not in rc

    def test_multiple_modules(self):
        modules = [
            (MsfModule("auxiliary/scanner/ssh/ssh_version", Severity.INFO), 22),
            (MsfModule("auxiliary/scanner/smb/smb_ms17_010", Severity.CRITICAL), 445),
        ]
        rc = _build_rc_script("10.0.0.1", modules, Path("/tmp/spool.txt"))
        assert rc.count("# ===MODULE:") == 2
        assert rc.count("# ===END_MODULE===") == 2
        assert rc.count("run") == 2


# ================================================================
# scan_msf entry point (async, mocked externals)
# ================================================================


class TestScanMsf:
    async def test_skip_flag_returns_empty(self):
        host = _make_host([(22, "ssh")])
        cfg = ScanConfig(skip_msf_scan=True)
        import asyncio
        sem = asyncio.Semaphore(1)
        result = await scan_msf(host, cfg, None, sem)
        assert result == []

    async def test_no_open_ports_returns_empty(self):
        host = Host(ip="10.0.0.1", ports=[])
        cfg = ScanConfig()
        import asyncio
        sem = asyncio.Semaphore(1)
        with patch("wireghost.pipeline.msf_scan.shutil.which", return_value="/usr/bin/msfconsole"):
            result = await scan_msf(host, cfg, None, sem)
        assert result == []

    async def test_msfconsole_not_found_returns_empty(self):
        host = _make_host([(22, "ssh")])
        cfg = ScanConfig()
        import asyncio
        sem = asyncio.Semaphore(1)
        with patch("wireghost.pipeline.msf_scan.shutil.which", return_value=None):
            result = await scan_msf(host, cfg, None, sem)
        assert result == []


# ================================================================
# Cross-tool deduplication: _dedup_findings
# ================================================================


class TestDedupFindings:
    def _finding(self, **kwargs) -> Finding:
        defaults = dict(
            source="nmap_vuln", host="10.0.0.1", port="445",
            protocol="tcp", severity=Severity.HIGH,
            title="Test", description="desc",
        )
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_cve_dedup(self):
        f1 = self._finding(source="nmap_vuln", title="Nmap: EternalBlue", cve="CVE-2017-0144")
        f2 = self._finding(source="msf_scan", title="MSF smb_ms17_010: VULNERABLE", cve="CVE-2017-0144")
        result = _dedup_findings([f1, f2])
        assert len(result) == 1
        assert result[0].source == "nmap_vuln"

    def test_title_based_dedup(self):
        f1 = self._finding(source="nmap_vuln", title="Nmap: http-enum results")
        f2 = self._finding(source="msf_scan", title="MSF http-enum results")
        result = _dedup_findings([f1, f2])
        assert len(result) == 1
        assert result[0].source == "nmap_vuln"

    def test_nxc_prefix_stripped(self):
        f1 = self._finding(source="netexec", title="NXC: Anonymous login")
        f2 = self._finding(source="msf_scan", title="MSF Anonymous login")
        result = _dedup_findings([f1, f2])
        assert len(result) == 1

    def test_different_ports_not_deduped(self):
        f1 = self._finding(port="445", title="SMB thing", cve="CVE-2017-0144")
        f2 = self._finding(port="139", title="SMB thing", cve="CVE-2017-0144")
        result = _dedup_findings([f1, f2])
        assert len(result) == 2

    def test_different_cves_not_deduped(self):
        f1 = self._finding(cve="CVE-2017-0144")
        f2 = self._finding(cve="CVE-2019-0708")
        result = _dedup_findings([f1, f2])
        assert len(result) == 2

    def test_empty_list(self):
        assert _dedup_findings([]) == []

    def test_single_finding(self):
        f = self._finding()
        result = _dedup_findings([f])
        assert len(result) == 1

    def test_all_unique(self):
        f1 = self._finding(title="Finding A", port="22")
        f2 = self._finding(title="Finding B", port="80")
        f3 = self._finding(title="Finding C", port="443")
        result = _dedup_findings([f1, f2, f3])
        assert len(result) == 3
