"""Tests for ScanCreateSerializer — SSRF validation and input sanitization."""
from django.test import TestCase
from rest_framework.exceptions import ValidationError as DRFValidationError

from scanner.serializers import ScanCreateSerializer


class ScanTargetValidationTests(TestCase):
    """ScanCreateSerializer.validate_target must block SSRF vectors."""

    def _validate(self, target):
        s = ScanCreateSerializer(data={'target': target})
        s.is_valid(raise_exception=True)
        return s.validated_data['target']

    def _assert_blocked(self, target, msg_fragment=None):
        with self.assertRaises(DRFValidationError) as ctx:
            self._validate(target)
        if msg_fragment:
            flat = str(ctx.exception.detail)
            self.assertIn(msg_fragment, flat.lower(), f'Expected "{msg_fragment}" in: {flat}')

    # ── Valid targets (should pass) ──

    def test_valid_ipv4(self):
        self.assertEqual(self._validate('8.8.8.8'), '8.8.8.8')

    def test_valid_cidr(self):
        self.assertEqual(self._validate('10.0.0.0/24'), '10.0.0.0/24')

    def test_valid_hostname(self):
        self.assertEqual(self._validate('example.com'), 'example.com')

    def test_valid_hostname_with_subdomain(self):
        self.assertEqual(self._validate('sub.domain.example.com'), 'sub.domain.example.com')

    # ── SSRF: Loopback ──

    def test_blocks_localhost_ip(self):
        self._assert_blocked('127.0.0.1', 'loopback')

    def test_blocks_localhost_range(self):
        self._assert_blocked('127.255.255.255', 'loopback')

    def test_blocks_localhost_hostname(self):
        self._assert_blocked('localhost', 'blocked')

    # ── SSRF: Link-local / Cloud metadata ──

    def test_blocks_link_local(self):
        self._assert_blocked('169.254.169.254', 'link-local')

    def test_blocks_link_local_cidr(self):
        self._assert_blocked('169.254.0.0/16', 'link-local')

    # ── SSRF: Alternative IP notations ──

    def test_blocks_hex_ip(self):
        self._assert_blocked('0x7f000001', 'hex')

    def test_blocks_decimal_ip(self):
        self._assert_blocked('2130706433', 'decimal')

    def test_blocks_octal_ip(self):
        self._assert_blocked('0177.0.0.01', 'octal')

    def test_blocks_short_form_ip_two_parts(self):
        self._assert_blocked('127.1', 'short-form')

    def test_blocks_short_form_ip_three_parts(self):
        self._assert_blocked('127.0.1', 'short-form')

    # ── SSRF: DNS rebinding domains ──

    def test_blocks_nip_io(self):
        self._assert_blocked('127.0.0.1.nip.io', 'blocked')

    def test_blocks_xip_io(self):
        self._assert_blocked('10.0.0.1.xip.io', 'rebinding')

    def test_blocks_sslip_io(self):
        self._assert_blocked('192.168.1.1.sslip.io', 'rebinding')

    def test_blocks_localtest_me(self):
        self._assert_blocked('localtest.me', 'blocked')

    # ── SSRF: Multicast / Reserved ──

    def test_blocks_multicast(self):
        self._assert_blocked('224.0.0.1', 'multicast')

    def test_blocks_unspecified(self):
        self._assert_blocked('0.0.0.0', 'unspecified')

    # ── Input validation ──

    def test_blocks_empty_target(self):
        self._assert_blocked('', 'blank')

    def test_blocks_whitespace_only(self):
        self._assert_blocked('   ', 'blank')

    def test_blocks_special_chars(self):
        self._assert_blocked('example.com; whoami', 'invalid')

    def test_blocks_url_format(self):
        self._assert_blocked('http://example.com', 'invalid')

    def test_blocks_pipe_injection(self):
        self._assert_blocked('8.8.8.8 | cat /etc/passwd', 'invalid')

    def test_blocks_backtick_injection(self):
        self._assert_blocked('`whoami`.example.com', 'invalid')

    # ── Other serializer fields ──

    def test_default_values(self):
        s = ScanCreateSerializer(data={'target': '8.8.8.8'})
        s.is_valid(raise_exception=True)
        d = s.validated_data
        self.assertEqual(d['scan_type'], 'full')
        self.assertEqual(d['parallelism'], 10)
        self.assertEqual(d['timeout'], 3600)
        self.assertTrue(d['version_detect'])

    def test_parallelism_bounds(self):
        s = ScanCreateSerializer(data={'target': '8.8.8.8', 'parallelism': 0})
        self.assertFalse(s.is_valid())
        s = ScanCreateSerializer(data={'target': '8.8.8.8', 'parallelism': 101})
        self.assertFalse(s.is_valid())

    def test_timeout_bounds(self):
        s = ScanCreateSerializer(data={'target': '8.8.8.8', 'timeout': 59})
        self.assertFalse(s.is_valid())
        s = ScanCreateSerializer(data={'target': '8.8.8.8', 'timeout': 86401})
        self.assertFalse(s.is_valid())

    def test_invalid_scan_type(self):
        s = ScanCreateSerializer(data={'target': '8.8.8.8', 'scan_type': 'evil'})
        self.assertFalse(s.is_valid())
