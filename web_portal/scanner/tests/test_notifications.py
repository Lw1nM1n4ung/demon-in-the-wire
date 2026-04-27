"""Tests for notification dispatch — chat_id validation, rendering, SSRF safety."""
from unittest.mock import patch, MagicMock

from django.test import TestCase

from scanner.notifications import (
    NotificationError, _validate_chat_id, send_telegram, _render,
)


class ChatIdValidationTests(TestCase):
    """_validate_chat_id must accept valid Telegram IDs and reject injection."""

    def test_valid_positive_id(self):
        _validate_chat_id('123456789')

    def test_valid_negative_channel_id(self):
        _validate_chat_id('-1001234567890')

    def test_valid_username_ref(self):
        _validate_chat_id('@my_channel')

    def test_rejects_empty(self):
        with self.assertRaises(NotificationError):
            _validate_chat_id('')

    def test_rejects_none(self):
        with self.assertRaises(NotificationError):
            _validate_chat_id(None)

    def test_rejects_url_injection(self):
        with self.assertRaises(NotificationError):
            _validate_chat_id('123; curl evil.com')

    def test_rejects_newline_injection(self):
        with self.assertRaises(NotificationError):
            _validate_chat_id('123\n456')

    def test_rejects_short_username(self):
        with self.assertRaises(NotificationError):
            _validate_chat_id('@abc')

    def test_rejects_spaces(self):
        with self.assertRaises(NotificationError):
            _validate_chat_id('123 456')


class SendTelegramTests(TestCase):
    """send_telegram must validate inputs and handle network errors gracefully."""

    def test_raises_on_missing_bot_token(self):
        with self.assertRaises(NotificationError):
            send_telegram('123456', 'hello', bot_token='')

    def test_raises_on_none_bot_token(self):
        with self.assertRaises(NotificationError):
            send_telegram('123456', 'hello', bot_token=None)

    def test_raises_on_invalid_chat_id(self):
        with self.assertRaises(NotificationError):
            send_telegram('not-valid!', 'hello', bot_token='fake-token')

    @patch('scanner.notifications.urllib.request.urlopen')
    def test_success_returns_ok(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"ok":true,"result":{}}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = send_telegram('123456', 'test msg', bot_token='fake-token')
        self.assertTrue(result['ok'])
        self.assertIsNone(result['error'])

    @patch('scanner.notifications.urllib.request.urlopen')
    def test_network_error_returns_error_dict(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError('Connection refused')

        result = send_telegram('123456', 'test', bot_token='fake-token')
        self.assertFalse(result['ok'])
        self.assertIn('network error', result['error'])

    @patch('scanner.notifications.urllib.request.urlopen')
    def test_timeout_returns_error_dict(self, mock_urlopen):
        mock_urlopen.side_effect = TimeoutError('timed out')

        result = send_telegram('123456', 'test', bot_token='fake-token')
        self.assertFalse(result['ok'])


class RenderTests(TestCase):
    """_render must HTML-escape user content and handle all event types."""

    def _mock_scan(self, **kwargs):
        scan = MagicMock()
        scan.name = kwargs.get('name', 'Test Scan')
        scan.target = kwargs.get('target', '10.0.0.0/24')
        scan.hosts_count = kwargs.get('hosts_count', 5)
        scan.findings_count = kwargs.get('findings_count', 12)
        scan.critical_count = kwargs.get('critical_count', 2)
        scan.high_count = kwargs.get('high_count', 3)
        scan.medium_count = kwargs.get('medium_count', 4)
        scan.duration_seconds = kwargs.get('duration_seconds', 120)
        scan.error_message = kwargs.get('error_message', None)
        return scan

    def test_scan_complete_renders(self):
        text = _render('scan.complete', scan=self._mock_scan())
        self.assertIn('Scan complete', text)
        self.assertIn('Test Scan', text)
        self.assertIn('10.0.0.0/24', text)

    def test_scan_failed_renders(self):
        text = _render('scan.failed', scan=self._mock_scan(error_message='timeout'))
        self.assertIn('Scan failed', text)
        self.assertIn('timeout', text)

    def test_critical_discovered_renders(self):
        text = _render('critical.discovered', scan=self._mock_scan())
        self.assertIn('Critical', text)

    def test_unknown_event_renders_safely(self):
        text = _render('unknown.event')
        self.assertIn('unknown.event', text)

    def test_html_escapes_scan_name(self):
        text = _render('scan.complete', scan=self._mock_scan(name='<script>alert(1)</script>'))
        self.assertNotIn('<script>', text)
        self.assertIn('&lt;script&gt;', text)

    def test_html_escapes_target(self):
        text = _render('scan.complete', scan=self._mock_scan(target='<img onerror=x>'))
        self.assertNotIn('<img', text)

    def test_error_message_truncated(self):
        long_err = 'x' * 500
        text = _render('scan.failed', scan=self._mock_scan(error_message=long_err))
        self.assertLessEqual(len(text), 600)
