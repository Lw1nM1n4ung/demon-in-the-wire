from datetime import datetime, timezone, timedelta
from unittest import TestCase
from unittest.mock import patch
from scanner.bot.formatting import (
    esc,
    severity_emoji,
    severity_line,
    short_id,
    status_icon,
    truncate_list,
    format_duration,
    time_ago,
    progress_bar,
)


class TestEsc:
    def test_escapes_angle_brackets(self):
        assert esc('<script>') == '&lt;script&gt;'

    def test_escapes_ampersand(self):
        assert esc('a & b') == 'a &amp; b'

    def test_escapes_quotes(self):
        assert '&quot;' in esc('"hello"')

    def test_leaves_plain_text_alone(self):
        assert esc('hello world') == 'hello world'

    def test_handles_empty_string(self):
        assert esc('') == ''

    def test_coerces_non_string(self):
        assert esc(12345) == '12345'


class TestSeverityEmoji:
    def test_critical(self):
        assert severity_emoji('critical') == '🔴'

    def test_high(self):
        assert severity_emoji('high') == '🟠'

    def test_medium(self):
        assert severity_emoji('medium') == '🟡'

    def test_low(self):
        assert severity_emoji('low') == '🔵'

    def test_info(self):
        assert severity_emoji('info') == 'ℹ️'

    def test_unknown_returns_empty(self):
        assert severity_emoji('whatever') == ''


class TestSeverityLine:
    def test_formats_counts(self):
        result = severity_line(critical=3, high=8, medium=19, low=17)
        assert '🔴 3' in result
        assert '🟠 8' in result
        assert '🟡 19' in result
        assert '🔵 17' in result

    def test_skips_zero_counts(self):
        result = severity_line(critical=0, high=5, medium=0, low=0)
        assert '🔴' not in result
        assert '🟠 5' in result


class TestShortId:
    def test_returns_first_8_chars(self):
        assert short_id('a1b2c3d4-e5f6-7890-abcd-ef1234567890') == 'a1b2c3d4'

    def test_handles_short_string(self):
        assert short_id('abc') == 'abc'


class TestStatusIcon:
    def test_completed(self):
        assert status_icon('completed') == '✅'

    def test_running(self):
        assert status_icon('running') == '🔄'

    def test_failed(self):
        assert status_icon('failed') == '❌'

    def test_cancelled(self):
        assert status_icon('cancelled') == '⏸'

    def test_pending(self):
        assert status_icon('pending') == '⏳'


class TestTruncateList:
    def test_returns_all_when_under_limit(self):
        items = ['a', 'b', 'c']
        assert truncate_list(items, limit=5) == (['a', 'b', 'c'], 0)

    def test_truncates_and_returns_remainder(self):
        items = list(range(20))
        shown, remaining = truncate_list(items, limit=10)
        assert len(shown) == 10
        assert remaining == 10


class TestFormatDuration:
    def test_seconds_only(self):
        assert format_duration(45) == '45s'

    def test_minutes_and_seconds(self):
        assert format_duration(754) == '12m 34s'

    def test_hours(self):
        assert format_duration(3661) == '1h 1m 1s'

    def test_zero(self):
        assert format_duration(0) == '0s'

    def test_none_returns_dash(self):
        assert format_duration(None) == '—'


class TestTimeAgo:
    def test_none_returns_dash(self):
        assert time_ago(None) == '—'

    def test_false_returns_dash(self):
        assert time_ago(False) == '—'

    @patch('django.utils.timezone.now')
    def test_seconds_ago(self, mock_now):
        mock_now.return_value = datetime(2026, 1, 1, 12, 0, 30, tzinfo=timezone.utc)
        dt = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        assert time_ago(dt) == '30s ago'

    @patch('django.utils.timezone.now')
    def test_minutes_ago(self, mock_now):
        mock_now.return_value = datetime(2026, 1, 1, 12, 5, 0, tzinfo=timezone.utc)
        dt = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        assert time_ago(dt) == '5m ago'

    @patch('django.utils.timezone.now')
    def test_hours_ago(self, mock_now):
        mock_now.return_value = datetime(2026, 1, 1, 15, 0, 0, tzinfo=timezone.utc)
        dt = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        assert time_ago(dt) == '3h ago'

    @patch('django.utils.timezone.now')
    def test_days_ago(self, mock_now):
        mock_now.return_value = datetime(2026, 1, 4, 12, 0, 0, tzinfo=timezone.utc)
        dt = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        assert time_ago(dt) == '3d ago'

    @patch('django.utils.timezone.now')
    def test_future_returns_just_now(self, mock_now):
        mock_now.return_value = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        dt = datetime(2026, 1, 1, 12, 5, 0, tzinfo=timezone.utc)
        assert time_ago(dt) == 'just now'


class TestProgressBar:
    def test_zero_total_returns_empty(self):
        assert progress_bar(0, 0) == '░' * 10

    def test_full_bar(self):
        assert progress_bar(100, 100) == '▓' * 10

    def test_half_bar(self):
        result = progress_bar(50, 100)
        assert result.count('▓') == 5
        assert result.count('░') == 5

    def test_custom_width(self):
        result = progress_bar(50, 100, width=20)
        assert len(result) == 20
        assert result.count('▓') == 10

    def test_zero_done_all_empty(self):
        assert progress_bar(0, 100) == '░' * 10

    def test_width_preserved(self):
        for done in range(0, 101, 7):
            result = progress_bar(done, 100, 10)
            assert len(result) == 10
