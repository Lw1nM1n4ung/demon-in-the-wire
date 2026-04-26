import pytest
from scanner.bot.formatting import (
    escape_md,
    severity_emoji,
    severity_line,
    short_id,
    status_icon,
    truncate_list,
    format_duration,
)


class TestEscapeMd:
    def test_escapes_special_chars(self):
        assert escape_md('hello_world') == 'hello\\_world'

    def test_escapes_all_mdv2_chars(self):
        for ch in '_*[]()~`>#+-=|{}.!':
            assert f'\\{ch}' in escape_md(ch)

    def test_leaves_plain_text_alone(self):
        assert escape_md('hello world') == 'hello world'

    def test_handles_empty_string(self):
        assert escape_md('') == ''


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
