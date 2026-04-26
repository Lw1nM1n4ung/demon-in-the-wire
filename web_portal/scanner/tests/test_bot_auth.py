import json
from unittest.mock import patch
from django.test import TestCase
from scanner.models import User, UserPreference, AuditLog
from scanner.bot.auth import resolve_user, link_account, unlink_account, check_rate_limit


class TestResolveUser(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testbot', password='pass1234', role='engineer',
        )
        self.prefs = UserPreference.for_user(self.user)

    def test_returns_user_when_linked(self):
        self.prefs.telegram_user_id = 12345
        self.prefs.save()
        user = resolve_user(12345)
        assert user is not None
        assert user.username == 'testbot'

    def test_returns_none_when_not_linked(self):
        assert resolve_user(99999) is None

    def test_returns_none_when_user_inactive(self):
        self.prefs.telegram_user_id = 12345
        self.prefs.save()
        self.user.is_active = False
        self.user.save()
        assert resolve_user(12345) is None


class TestLinkAccount(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='linktest', password='pass1234', role='viewer',
        )
        UserPreference.for_user(self.user)

    @patch('scanner.bot.auth.cache')
    def test_link_success(self, mock_cache):
        mock_cache.get.side_effect = lambda key, *a: (
            json.dumps({'user_id': str(self.user.id)}) if key.startswith('tg:link:') else 0
        )
        ok, msg = link_account(tg_user_id=11111, tg_chat_id=22222, code='123456')
        assert ok is True
        assert 'linktest' in msg
        self.user.preferences.refresh_from_db()
        assert self.user.preferences.telegram_user_id == 11111

    @patch('scanner.bot.auth.cache')
    def test_link_invalid_code(self, mock_cache):
        mock_cache.get.side_effect = lambda key, *a: (
            None if key.startswith('tg:link:') else 0
        )
        ok, msg = link_account(tg_user_id=11111, tg_chat_id=22222, code='000000')
        assert ok is False
        assert 'Invalid' in msg or 'expired' in msg

    @patch('scanner.bot.auth.cache')
    def test_link_rate_limited(self, mock_cache):
        mock_cache.get.side_effect = lambda key, *a: (
            3 if key.startswith('tg:linkfail:') else None
        )
        ok, msg = link_account(tg_user_id=11111, tg_chat_id=22222, code='123456')
        assert ok is False
        assert 'Too many' in msg


class TestUnlinkAccount(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='unlinktest', password='pass1234', role='engineer',
        )
        prefs = UserPreference.for_user(self.user)
        prefs.telegram_user_id = 12345
        prefs.telegram_chat_id = '67890'
        prefs.telegram_enabled = True
        prefs.save()

    def test_unlink_clears_fields(self):
        ok, msg = unlink_account(tg_user_id=12345)
        assert ok is True
        self.user.preferences.refresh_from_db()
        assert self.user.preferences.telegram_user_id is None
        assert self.user.preferences.telegram_chat_id == ''

    def test_unlink_not_linked(self):
        ok, msg = unlink_account(tg_user_id=99999)
        assert ok is False


class TestCheckRateLimit(TestCase):
    @patch('scanner.bot.auth.cache')
    def test_allows_under_limit(self, mock_cache):
        mock_cache.incr.return_value = 1
        assert check_rate_limit('test:', 'key', 5, 60) is True

    @patch('scanner.bot.auth.cache')
    def test_blocks_at_limit(self, mock_cache):
        mock_cache.incr.return_value = 6
        assert check_rate_limit('test:', 'key', 5, 60) is False

    @patch('scanner.bot.auth.cache')
    def test_creates_key_on_first_call(self, mock_cache):
        mock_cache.incr.side_effect = ValueError('Key not found')
        mock_cache.set.return_value = True
        assert check_rate_limit('test:', 'key', 5, 60) is True
        mock_cache.set.assert_called_once_with('test:key', 1, 60)
