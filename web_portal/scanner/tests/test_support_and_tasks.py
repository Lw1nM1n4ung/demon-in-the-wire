"""Tests for support.py redaction, tools_health._extract_version, and tasks.py helpers."""
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'wireghost_web.settings')

import django
django.setup()

from datetime import datetime, time, timedelta, timezone as dt_timezone
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from scanner.support import redact
from scanner.tasks import _sev_str, _compute_risk, _calc_next_run, _compute_deadline
from scanner.tools_health import _extract_version


# ---------------------------------------------------------------------------
# redact() — all 6 REDACTION_PATTERNS
# ---------------------------------------------------------------------------

class RedactAuthorizationHeaderTests(TestCase):
    """Pattern 1: Authorization headers (Bearer/Basic/Digest/Token)."""

    def test_bearer_token_redacted(self):
        text = 'Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.abc.def'
        result = redact(text)
        self.assertIn('[REDACTED]', result)
        self.assertNotIn('eyJhbGciOiJSUzI1NiJ9', result)
        self.assertIn('Authorization: Bearer', result)

    def test_basic_auth_redacted(self):
        text = 'Authorization: Basic dXNlcjpwYXNz'
        result = redact(text)
        self.assertEqual(result, 'Authorization: Basic [REDACTED]')

    def test_digest_auth_redacted(self):
        text = 'Authorization: Digest abc123secret'
        result = redact(text)
        self.assertEqual(result, 'Authorization: Digest [REDACTED]')

    def test_token_auth_redacted(self):
        text = 'Authorization: Token t0k3n_v4lu3'
        result = redact(text)
        self.assertEqual(result, 'Authorization: Token [REDACTED]')

    def test_case_insensitive(self):
        text = 'authorization: bearer lowercased_tok'
        result = redact(text)
        self.assertIn('[REDACTED]', result)
        self.assertNotIn('lowercased_tok', result)


class RedactCookieTests(TestCase):
    """Pattern 2: Session / CSRF / app-specific cookies."""

    def test_sessionid_redacted(self):
        text = 'Cookie: sessionid=abc123def456; other=keep'
        result = redact(text)
        self.assertIn('sessionid=[REDACTED]', result)
        self.assertIn('other=keep', result)

    def test_csrftoken_redacted(self):
        text = 'csrftoken=tok3n_value'
        result = redact(text)
        self.assertEqual(result, 'csrftoken=[REDACTED]')

    def test_wg_user_info_redacted(self):
        text = 'wg_user_info=some_secret_data'
        result = redact(text)
        self.assertEqual(result, 'wg_user_info=[REDACTED]')

    def test_wg_session_redacted(self):
        text = 'wg_session=s3ss10n_v4lue'
        result = redact(text)
        self.assertEqual(result, 'wg_session=[REDACTED]')


class RedactJsonPasswordTests(TestCase):
    """Pattern 3: JSON password / token fields."""

    def test_password_field_redacted(self):
        text = '{"password": "my_secret_pass"}'
        result = redact(text)
        self.assertIn('"[REDACTED]"', result)
        self.assertNotIn('my_secret_pass', result)

    def test_api_key_field_redacted(self):
        text = '{"api_key": "k3y_v4lue"}'
        result = redact(text)
        self.assertNotIn('k3y_v4lue', result)

    def test_secret_field_redacted(self):
        text = '{"secret": "top_secret_value"}'
        result = redact(text)
        self.assertNotIn('top_secret_value', result)

    def test_api_token_field_redacted(self):
        text = '{"api_token": "tok3n"}'
        result = redact(text)
        self.assertNotIn('tok3n', result)


class RedactXHeaderTests(TestCase):
    """Pattern 4: X-API-Key / X-Auth-Token style headers."""

    def test_x_api_key_redacted(self):
        text = 'X-API-Key: superSecretKey123'
        result = redact(text)
        self.assertIn('[REDACTED]', result)
        self.assertNotIn('superSecretKey123', result)

    def test_x_auth_token_redacted(self):
        text = 'X-Auth-Token: auth_tok_value'
        result = redact(text)
        self.assertIn('[REDACTED]', result)
        self.assertNotIn('auth_tok_value', result)

    def test_x_session_redacted(self):
        text = 'X-Session: sess_val_42'
        result = redact(text)
        self.assertIn('[REDACTED]', result)
        self.assertNotIn('sess_val_42', result)

    def test_x_csrf_token_redacted(self):
        text = 'X-CSRF-Token: csrf_abc'
        result = redact(text)
        self.assertIn('[REDACTED]', result)
        self.assertNotIn('csrf_abc', result)


class RedactDSNTests(TestCase):
    """Pattern 5: DSN-style credentials in URLs."""

    def test_postgres_dsn_redacted(self):
        text = 'postgres://admin:s3cret@db.host:5432/mydb'
        result = redact(text)
        self.assertIn('[REDACTED]', result)
        self.assertNotIn('s3cret', result)
        self.assertIn('admin', result)  # username is preserved
        self.assertIn('db.host', result)

    def test_redis_dsn_redacted(self):
        text = 'redis://user:p4ssw0rd@redis.local:6379/0'
        result = redact(text)
        self.assertNotIn('p4ssw0rd', result)
        self.assertIn('[REDACTED]', result)

    def test_https_dsn_redacted(self):
        text = 'https://deploy:token123@registry.example.com/v2'
        result = redact(text)
        self.assertNotIn('token123', result)
        self.assertIn('[REDACTED]', result)


class RedactEdgeCaseTests(TestCase):
    """Edge cases: empty input, no-match passthrough, multiple patterns."""

    def test_empty_string_returns_empty(self):
        self.assertEqual(redact(''), '')

    def test_none_returns_none(self):
        self.assertIsNone(redact(None))

    def test_no_match_passthrough(self):
        text = 'Just a normal log line with an IP 10.0.0.1 and path /var/log/app.log'
        self.assertEqual(redact(text), text)

    def test_multiple_patterns_in_same_text(self):
        text = (
            'Authorization: Bearer eyJ123 | '
            'sessionid=abc; csrftoken=xyz | '
            '{"password": "hunter2"} | '
            'X-API-Key: key99 | '
            'postgres://u:pw@host'
        )
        result = redact(text)
        self.assertNotIn('eyJ123', result)
        self.assertIn('sessionid=[REDACTED]', result)
        self.assertIn('csrftoken=[REDACTED]', result)
        self.assertNotIn('hunter2', result)
        self.assertNotIn('key99', result)
        self.assertNotIn(':pw@', result)
        # Count redactions — at least 5 distinct patterns triggered
        self.assertGreaterEqual(result.count('[REDACTED]'), 5)


# ---------------------------------------------------------------------------
# _extract_version()
# ---------------------------------------------------------------------------

class ExtractVersionTests(TestCase):
    """tools_health._extract_version: first non-empty line, truncated to 120."""

    def test_empty_string_returns_empty(self):
        self.assertEqual(_extract_version(''), '')

    def test_none_returns_empty(self):
        # not output evaluates truthy for None
        self.assertEqual(_extract_version(None), '')

    def test_single_line(self):
        self.assertEqual(_extract_version('Nmap 7.94'), 'Nmap 7.94')

    def test_multiline_returns_first_nonempty(self):
        out = 'httpx v1.3.7\nother info\nmore'
        self.assertEqual(_extract_version(out), 'httpx v1.3.7')

    def test_leading_blank_lines_skipped(self):
        out = '\n  \n\nNuclei 3.1.0'
        self.assertEqual(_extract_version(out), 'Nuclei 3.1.0')

    def test_long_line_truncated_to_120(self):
        long_line = 'A' * 200
        result = _extract_version(long_line)
        self.assertEqual(len(result), 120)
        self.assertEqual(result, 'A' * 120)

    def test_all_whitespace_lines_returns_empty(self):
        out = '   \n  \n\t\n'
        self.assertEqual(_extract_version(out), '')


# ---------------------------------------------------------------------------
# _sev_str()
# ---------------------------------------------------------------------------

class SevStrTests(TestCase):
    """tasks._sev_str: normalize severity enum or string to lowercase string."""

    def test_plain_string_lowered(self):
        self.assertEqual(_sev_str('HIGH'), 'high')

    def test_already_lowercase(self):
        self.assertEqual(_sev_str('medium'), 'medium')

    def test_mixed_case(self):
        self.assertEqual(_sev_str('Critical'), 'critical')

    def test_enum_like_value(self):
        """An object with .value attribute (like Severity enum)."""
        class FakeSev:
            value = 'HIGH'
        self.assertEqual(_sev_str(FakeSev()), 'high')

    def test_enum_like_lowercase_value(self):
        class FakeSev:
            value = 'info'
        self.assertEqual(_sev_str(FakeSev()), 'info')

    def test_integer_gives_numeric_string(self):
        # The function does str(sev).lower(), not an integer-to-name mapping
        self.assertEqual(_sev_str(1), '1')

    def test_info_string(self):
        self.assertEqual(_sev_str('info'), 'info')

    def test_unknown_string(self):
        self.assertEqual(_sev_str('unknown'), 'unknown')


# ---------------------------------------------------------------------------
# _compute_risk()
# ---------------------------------------------------------------------------

class ComputeRiskTests(TestCase):
    """tasks._compute_risk: 0..100 risk score from counts."""

    def test_zero_everything(self):
        self.assertEqual(_compute_risk(0, 0, 0), 0)

    def test_critical_dominates(self):
        # 4 critical = 4 * 30 = 120, clamped to 100
        self.assertEqual(_compute_risk(4, 0, 4), 100)

    def test_single_critical(self):
        # 1 critical * 30 = 30
        self.assertEqual(_compute_risk(1, 0, 1), 30)

    def test_single_high(self):
        # 1 high * 10 = 10
        self.assertEqual(_compute_risk(0, 1, 1), 10)

    def test_mixed_findings(self):
        # 1 critical(30) + 2 high(20) + 3 other(6) = 56
        self.assertEqual(_compute_risk(1, 2, 6), 56)

    def test_all_other(self):
        # 10 other * 2 = 20
        self.assertEqual(_compute_risk(0, 0, 10), 20)

    def test_clamped_at_100(self):
        self.assertEqual(_compute_risk(10, 10, 20), 100)

    def test_negative_other_clamped_to_zero(self):
        # total < critical + high should not produce negative other
        # other = max(0, 1 - 1 - 1) = 0; risk = 30 + 10 = 40
        self.assertEqual(_compute_risk(1, 1, 1), 40)


# ---------------------------------------------------------------------------
# _calc_next_run()
# ---------------------------------------------------------------------------

class CalcNextRunTests(TestCase):
    """tasks._calc_next_run: daily/weekly/monthly next-run calculation."""

    def _mock_now(self):
        """Return a fixed aware datetime: 2026-04-27 10:00:00 UTC."""
        return datetime(2026, 4, 27, 10, 0, 0, tzinfo=dt_timezone.utc)

    @patch('scanner.tasks.timezone.now')
    def test_daily_future_today(self, mock_now):
        """run_time later today => returns today's datetime."""
        mock_now.return_value = self._mock_now()
        run_time = time(14, 0)  # 14:00 UTC, still in the future
        result = _calc_next_run('daily', run_time)
        self.assertEqual(result.hour, 14)
        self.assertEqual(result.minute, 0)
        self.assertEqual(result.day, 27)

    @patch('scanner.tasks.timezone.now')
    def test_daily_past_today_advances(self, mock_now):
        """run_time already past today => advances by 1 day."""
        mock_now.return_value = self._mock_now()
        run_time = time(8, 0)  # 08:00 UTC, already past 10:00
        result = _calc_next_run('daily', run_time)
        self.assertEqual(result.day, 28)
        self.assertEqual(result.hour, 8)

    @patch('scanner.tasks.timezone.now')
    def test_weekly_past_advances_7_days(self, mock_now):
        mock_now.return_value = self._mock_now()
        run_time = time(8, 0)
        result = _calc_next_run('weekly', run_time)
        expected_day = 27 + 7  # May 4
        self.assertEqual(result.day, 4)
        self.assertEqual(result.month, 5)

    @patch('scanner.tasks.timezone.now')
    def test_monthly_past_advances_month(self, mock_now):
        mock_now.return_value = self._mock_now()
        run_time = time(8, 0)
        result = _calc_next_run('monthly', run_time)
        self.assertEqual(result.month, 5)  # April -> May
        self.assertEqual(result.day, 27)

    @patch('scanner.tasks.timezone.now')
    def test_result_is_utc_aware(self, mock_now):
        mock_now.return_value = self._mock_now()
        run_time = time(14, 0)
        result = _calc_next_run('daily', run_time)
        self.assertIsNotNone(result.tzinfo)
        self.assertEqual(result.utcoffset(), timedelta(0))


# ---------------------------------------------------------------------------
# _compute_deadline()
# ---------------------------------------------------------------------------

class ComputeDeadlineTests(TestCase):
    """tasks._compute_deadline: stop_time string to UTC-aware datetime."""

    @patch('scanner.tasks.timezone.now')
    def test_future_stop_time_same_day(self, mock_now):
        mock_now.return_value = datetime(2026, 4, 27, 10, 0, 0, tzinfo=dt_timezone.utc)
        stop = time(18, 0)
        result = _compute_deadline(stop)
        self.assertEqual(result.hour, 18)
        self.assertEqual(result.day, 27)

    @patch('scanner.tasks.timezone.now')
    def test_past_stop_time_rolls_to_next_day(self, mock_now):
        mock_now.return_value = datetime(2026, 4, 27, 10, 0, 0, tzinfo=dt_timezone.utc)
        stop = time(6, 0)  # 06:00 is already past
        result = _compute_deadline(stop)
        self.assertEqual(result.day, 28)
        self.assertEqual(result.hour, 6)

    def test_none_returns_none(self):
        self.assertIsNone(_compute_deadline(None))

    @patch('scanner.tasks.timezone.now')
    def test_result_is_utc_aware(self, mock_now):
        mock_now.return_value = datetime(2026, 4, 27, 10, 0, 0, tzinfo=dt_timezone.utc)
        stop = time(22, 0)
        result = _compute_deadline(stop)
        self.assertIsNotNone(result.tzinfo)
        self.assertEqual(result.utcoffset(), timedelta(0))
