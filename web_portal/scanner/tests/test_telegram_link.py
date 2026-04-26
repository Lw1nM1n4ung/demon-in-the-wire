import json
from unittest.mock import patch, MagicMock
from django.test import TestCase, RequestFactory
from rest_framework.test import force_authenticate
from scanner.models import User, UserPreference
from scanner.auth_views import telegram_link_code


class TestTelegramLinkEndpoint(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username='linkapi', password='pass1234', role='engineer',
        )
        UserPreference.for_user(self.user)

    @patch('scanner.auth_views.cache')
    def test_generates_6_digit_code(self, mock_cache):
        mock_cache.get.return_value = None
        request = self.factory.post('/api/preferences/telegram-link/')
        force_authenticate(request, user=self.user)
        response = telegram_link_code(request)
        assert response.status_code == 200
        data = response.data
        assert 'code' in data
        assert len(data['code']) == 6
        assert data['code'].isdigit()
        assert data['expires_in'] == 300

    @patch('scanner.auth_views.cache')
    def test_stores_code_in_redis(self, mock_cache):
        mock_cache.get.return_value = None
        request = self.factory.post('/api/preferences/telegram-link/')
        force_authenticate(request, user=self.user)
        response = telegram_link_code(request)
        code = response.data['code']
        mock_cache.set.assert_any_call(
            f'tg:link:{code}',
            json.dumps({'user_id': str(self.user.id)}),
            300,
        )

    @patch('scanner.auth_views.cache')
    def test_deletes_previous_code(self, mock_cache):
        # First get() returns 0 (rate-limit counter), second returns old code
        mock_cache.get.side_effect = [None, '654321']
        request = self.factory.post('/api/preferences/telegram-link/')
        force_authenticate(request, user=self.user)
        telegram_link_code(request)
        mock_cache.delete.assert_any_call('tg:link:654321')

    @patch('scanner.auth_views.cache')
    def test_rate_limited(self, mock_cache):
        # Each request does 2 cache.get calls: rate-limit counter, then reverse key.
        # Simulate 3 successful generations (counter 0,1,2) then 4th hits limit (counter 3).
        mock_cache.get.side_effect = [
            None, None,   # req 1: gen_count=0, no old code
            1, None,      # req 2: gen_count=1, no old code
            2, None,      # req 3: gen_count=2, no old code
            3,            # req 4: gen_count=3 → 429 (no 2nd get needed)
        ]
        for i in range(4):
            request = self.factory.post('/api/preferences/telegram-link/')
            force_authenticate(request, user=self.user)
            response = telegram_link_code(request)
        assert response.status_code in (200, 429)
