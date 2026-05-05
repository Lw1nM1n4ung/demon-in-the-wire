"""Tests for scanner.msf_matcher — Metasploit module matching."""

from __future__ import annotations

from unittest.mock import patch

from django.test import TestCase

from scanner import msf_matcher


def _fake_module(
    fullname: str = "exploit/linux/ssh/test",
    name: str = "Test Exploit",
    mod_type: str = "exploit",
    rank: int = 300,
    references: list | None = None,
    rport: int | None = 22,
    disclosure_date: str = "2024-01-01",
    description: str = "A test module",
    platform: str = "linux",
) -> dict:
    return {
        "fullname": fullname,
        "name": name,
        "type": mod_type,
        "rank": rank,
        "references": references or [],
        "rport": rport,
        "disclosure_date": disclosure_date,
        "description": description,
        "platform": platform,
    }


def _reset_indexes():
    msf_matcher._cve_index = None
    msf_matcher._product_index = None
    msf_matcher._port_index = None


class TestSlimModule(TestCase):
    def test_extracts_required_fields(self):
        mod = _fake_module(references=["CVE-2021-41773", "EDB-50383"])
        slim = msf_matcher._slim_module(mod)
        self.assertEqual(slim["module_fullname"], "exploit/linux/ssh/test")
        self.assertEqual(slim["module_name"], "Test Exploit")
        self.assertEqual(slim["module_type"], "exploit")
        self.assertEqual(slim["module_rank"], 300)
        self.assertEqual(slim["module_rank_name"], "Normal")
        self.assertEqual(slim["rport"], 22)
        self.assertEqual(slim["references"], ["CVE-2021-41773"])

    def test_filters_non_cve_references(self):
        mod = _fake_module(references=["CVE-2021-41773", "EDB-50383", "URL-http://example.com"])
        slim = msf_matcher._slim_module(mod)
        self.assertEqual(slim["references"], ["CVE-2021-41773"])

    def test_truncates_description(self):
        mod = _fake_module(description="A" * 1000)
        slim = msf_matcher._slim_module(mod)
        self.assertEqual(len(slim["description"]), 500)

    def test_handles_missing_fields(self):
        slim = msf_matcher._slim_module({})
        self.assertEqual(slim["module_fullname"], "")
        self.assertEqual(slim["module_name"], "")
        self.assertEqual(slim["module_rank"], 0)
        self.assertEqual(slim["module_rank_name"], "Manual")

    def test_rank_name_mapping(self):
        for rank_val, rank_name in msf_matcher.RANK_NAMES.items():
            mod = _fake_module(rank=rank_val)
            slim = msf_matcher._slim_module(mod)
            self.assertEqual(slim["module_rank_name"], rank_name)

    def test_unknown_rank_uses_string(self):
        mod = _fake_module(rank=999)
        slim = msf_matcher._slim_module(mod)
        self.assertEqual(slim["module_rank_name"], "999")


class TestBuildIndexes(TestCase):
    def setUp(self):
        _reset_indexes()

    def tearDown(self):
        _reset_indexes()

    @patch.object(msf_matcher, "MSF_JSON_PATH")
    def test_missing_json_sets_empty_indexes(self, mock_path):
        mock_path.exists.return_value = False
        msf_matcher._build_indexes()
        self.assertEqual(msf_matcher._cve_index, {})
        self.assertEqual(msf_matcher._product_index, {})
        self.assertEqual(msf_matcher._port_index, {})

    @patch("builtins.open")
    @patch("json.load")
    @patch.object(msf_matcher, "MSF_JSON_PATH")
    def test_exploit_modules_indexed(self, mock_path, mock_json, mock_open):
        mock_path.exists.return_value = True
        mock_json.return_value = {
            "mod1": _fake_module(
                fullname="exploit/multi/http/apache_traversal",
                references=["CVE-2021-41773"],
                rport=80,
            ),
        }
        msf_matcher._build_indexes()
        self.assertIn("CVE-2021-41773", msf_matcher._cve_index)
        self.assertIn(80, msf_matcher._port_index)

    @patch("builtins.open")
    @patch("json.load")
    @patch.object(msf_matcher, "MSF_JSON_PATH")
    def test_non_exploit_non_aux_skipped(self, mock_path, mock_json, mock_open):
        mock_path.exists.return_value = True
        mock_json.return_value = {
            "mod1": _fake_module(mod_type="post", references=["CVE-2021-41773"]),
        }
        msf_matcher._build_indexes()
        self.assertEqual(msf_matcher._cve_index, {})

    @patch("builtins.open")
    @patch("json.load")
    @patch.object(msf_matcher, "MSF_JSON_PATH")
    def test_auxiliary_with_cve_indexed(self, mock_path, mock_json, mock_open):
        mock_path.exists.return_value = True
        mock_json.return_value = {
            "mod1": _fake_module(
                mod_type="auxiliary",
                references=["CVE-2020-1234"],
                fullname="auxiliary/scanner/http/check",
            ),
        }
        msf_matcher._build_indexes()
        self.assertIn("CVE-2020-1234", msf_matcher._cve_index)

    @patch("builtins.open")
    @patch("json.load")
    @patch.object(msf_matcher, "MSF_JSON_PATH")
    def test_auxiliary_without_cve_skipped(self, mock_path, mock_json, mock_open):
        mock_path.exists.return_value = True
        mock_json.return_value = {
            "mod1": _fake_module(mod_type="auxiliary", references=[]),
        }
        msf_matcher._build_indexes()
        self.assertEqual(msf_matcher._cve_index, {})


class TestMatchExploits(TestCase):
    def setUp(self):
        _reset_indexes()

    def tearDown(self):
        _reset_indexes()

    def _set_indexes(self, cve=None, product=None, port=None):
        msf_matcher._cve_index = cve or {}
        msf_matcher._product_index = product or {}
        msf_matcher._port_index = port or {}

    def _slim(self, **overrides):
        base = msf_matcher._slim_module(_fake_module(**overrides))
        return base

    def test_empty_indexes_returns_empty(self):
        self._set_indexes()
        result = msf_matcher.match_exploits([], [])
        self.assertEqual(result, [])

    def test_cve_match_high_confidence(self):
        slim = self._slim(
            fullname="exploit/multi/http/apache_traversal",
            references=["CVE-2021-41773"],
        )
        self._set_indexes(cve={"CVE-2021-41773": [slim]})
        findings = [{"cve": "CVE-2021-41773", "host_ip": "10.0.0.1", "port": "80"}]
        result = msf_matcher.match_exploits([], findings)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["confidence"], "high")
        self.assertIn("CVE-2021-41773", result[0]["match_reason"])

    def test_cve_match_sets_host_and_port(self):
        slim = self._slim(references=["CVE-2021-41773"])
        self._set_indexes(cve={"CVE-2021-41773": [slim]})
        findings = [{"cve": "CVE-2021-41773", "host_ip": "10.0.0.5", "port": "443"}]
        result = msf_matcher.match_exploits([], findings)
        self.assertEqual(result[0]["host_ip"], "10.0.0.5")
        self.assertEqual(result[0]["port_number"], 443)

    def test_comma_separated_cves(self):
        slim1 = self._slim(fullname="exploit/a", references=["CVE-2021-41773"])
        slim2 = self._slim(fullname="exploit/b", references=["CVE-2017-0144"])
        self._set_indexes(cve={
            "CVE-2021-41773": [slim1],
            "CVE-2017-0144": [slim2],
        })
        findings = [{"cve": "CVE-2021-41773, CVE-2017-0144", "host_ip": "10.0.0.1"}]
        result = msf_matcher.match_exploits([], findings)
        self.assertEqual(len(result), 2)

    def test_product_match_medium_confidence(self):
        slim = self._slim(fullname="exploit/linux/ssh/openssh", rport=22)
        self._set_indexes(product={"openssh": [slim]})
        ports = [{
            "number": 22,
            "service_name": "ssh",
            "service_product": "OpenSSH",
            "host_ip": "10.0.0.1",
        }]
        result = msf_matcher.match_exploits(ports, [])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["confidence"], "medium")

    def test_product_match_requires_port_match(self):
        slim = self._slim(fullname="exploit/linux/ssh/openssh", rport=22)
        self._set_indexes(product={"openssh": [slim]})
        ports = [{
            "number": 2222,
            "service_name": "ssh",
            "service_product": "OpenSSH",
            "host_ip": "10.0.0.1",
        }]
        result = msf_matcher.match_exploits(ports, [])
        self.assertEqual(len(result), 0)

    def test_low_match_for_restricted_service(self):
        slim = self._slim(fullname="exploit/unix/ftp/vsftpd_234", rport=21)
        self._set_indexes(port={21: [slim]})
        ports = [{
            "number": 21,
            "service_name": "ftp",
            "service_product": "",
            "host_ip": "10.0.0.1",
        }]
        result = msf_matcher.match_exploits(ports, [])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["confidence"], "low")

    def test_low_match_skips_http(self):
        slim = self._slim(fullname="exploit/multi/http/something", rport=80)
        self._set_indexes(port={80: [slim]})
        ports = [{
            "number": 80,
            "service_name": "http",
            "service_product": "",
            "host_ip": "10.0.0.1",
        }]
        result = msf_matcher.match_exploits(ports, [])
        self.assertEqual(len(result), 0)

    def test_deduplication(self):
        slim = self._slim(
            fullname="exploit/multi/http/apache_traversal",
            references=["CVE-2021-41773"],
        )
        self._set_indexes(cve={"CVE-2021-41773": [slim]})
        findings = [
            {"cve": "CVE-2021-41773", "host_ip": "10.0.0.1", "port": "80"},
            {"cve": "CVE-2021-41773", "host_ip": "10.0.0.1", "port": "80"},
        ]
        result = msf_matcher.match_exploits([], findings)
        self.assertEqual(len(result), 1)

    def test_sort_order_confidence_then_rank(self):
        slim_high = self._slim(
            fullname="exploit/a",
            references=["CVE-2021-41773"],
            rank=300,
        )
        slim_low = self._slim(
            fullname="exploit/unix/ftp/vsftpd",
            rport=21,
            rank=500,
        )
        self._set_indexes(
            cve={"CVE-2021-41773": [slim_high]},
            port={21: [slim_low]},
        )
        findings = [{"cve": "CVE-2021-41773", "host_ip": "10.0.0.1", "port": "80"}]
        ports = [{"number": 21, "service_name": "ftp", "service_product": "", "host_ip": "10.0.0.1"}]
        result = msf_matcher.match_exploits(ports, findings)
        self.assertEqual(result[0]["confidence"], "high")

    def test_non_cve_string_ignored(self):
        self._set_indexes(cve={})
        findings = [{"cve": "not-a-cve", "host_ip": "10.0.0.1"}]
        result = msf_matcher.match_exploits([], findings)
        self.assertEqual(result, [])

    def test_empty_cve_field(self):
        self._set_indexes(cve={})
        findings = [{"cve": "", "host_ip": "10.0.0.1"}]
        result = msf_matcher.match_exploits([], findings)
        self.assertEqual(result, [])

    def test_missing_cve_field(self):
        self._set_indexes(cve={})
        findings = [{"host_ip": "10.0.0.1"}]
        result = msf_matcher.match_exploits([], findings)
        self.assertEqual(result, [])

    def test_unknown_product_ignored(self):
        slim = self._slim(fullname="exploit/linux/ssh/openssh", rport=22)
        self._set_indexes(product={"openssh": [slim]})
        ports = [{
            "number": 22,
            "service_name": "ssh",
            "service_product": "unknown",
            "host_ip": "10.0.0.1",
        }]
        result = msf_matcher.match_exploits(ports, [])
        self.assertEqual(len(result), 0)

    def test_port_as_string_converted(self):
        slim = self._slim(references=["CVE-2021-41773"])
        self._set_indexes(cve={"CVE-2021-41773": [slim]})
        findings = [{"cve": "CVE-2021-41773", "host_ip": "10.0.0.1", "port": "8080"}]
        result = msf_matcher.match_exploits([], findings)
        self.assertEqual(result[0]["port_number"], 8080)

    def test_no_port_sets_none(self):
        slim = self._slim(references=["CVE-2021-41773"])
        self._set_indexes(cve={"CVE-2021-41773": [slim]})
        findings = [{"cve": "CVE-2021-41773", "host_ip": "10.0.0.1"}]
        result = msf_matcher.match_exploits([], findings)
        self.assertIsNone(result[0]["port_number"])


class TestLowMatchServices(TestCase):
    def test_http_not_in_low_match(self):
        self.assertNotIn("http", msf_matcher.LOW_MATCH_SERVICES)
        self.assertNotIn("https", msf_matcher.LOW_MATCH_SERVICES)

    def test_expected_services_present(self):
        for svc in ("ssh", "ftp", "smb", "mysql", "redis", "rdp", "telnet", "ldap"):
            self.assertIn(svc, msf_matcher.LOW_MATCH_SERVICES)
